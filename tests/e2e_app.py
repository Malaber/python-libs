from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from uuid import UUID, uuid4

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from jinja2 import Environment
from starlette.middleware.sessions import SessionMiddleware

from fastpasskey import (
    FastPasskey,
    PasskeyConflictError,
    PasskeyCredential,
    PasskeyRouterConfig,
    create_passkey_router,
    install_fastpasskey_templates,
)


@dataclass
class MemoryPasskey:
    name: str
    credential_id: str
    public_key: bytes
    sign_count: int
    id: UUID = field(default_factory=uuid4)
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    last_used_at: datetime | None = None
    user: MemoryUser | None = None


@dataclass
class MemoryUser:
    id: UUID
    email: str
    display_name: str
    is_admin: bool = False
    is_active: bool = True
    passkeys: list[MemoryPasskey] = field(default_factory=list)


class MemoryRepository:
    def __init__(self) -> None:
        self.users: dict[UUID, MemoryUser] = {}
        self.add_link_active = True

    def _add(self, user: MemoryUser, name: str, credential: PasskeyCredential) -> MemoryPasskey:
        passkey = MemoryPasskey(
            name=name,
            credential_id=credential.credential_id,
            public_key=credential.public_key,
            sign_count=credential.sign_count,
            user=user,
        )
        user.passkeys.append(passkey)
        return passkey

    async def user_by_email(self, email: str) -> MemoryUser | None:
        return next((user for user in self.users.values() if user.email == email), None)

    async def user_by_id(self, user_id: UUID) -> MemoryUser | None:
        return self.users.get(user_id)

    async def passkey_by_credential_id(self, credential_id: str) -> MemoryPasskey | None:
        return next(
            (
                passkey
                for user in self.users.values()
                for passkey in user.passkeys
                if passkey.credential_id == credential_id
            ),
            None,
        )

    async def register_user(
        self,
        *,
        user_id: UUID,
        email: str,
        display_name: str,
        passkey_name: str,
        credential: PasskeyCredential,
    ) -> MemoryUser:
        if await self.user_by_email(email) or await self.passkey_by_credential_id(
            credential.credential_id
        ):
            raise PasskeyConflictError
        user = MemoryUser(id=user_id, email=email, display_name=display_name)
        self.users[user.id] = user
        self._add(user, passkey_name, credential)
        return user

    async def replace_passkeys(
        self,
        *,
        user_id: UUID,
        passkey_name: str,
        credential: PasskeyCredential,
    ) -> MemoryUser:
        user = self.users[user_id]
        user.passkeys.clear()
        self._add(user, passkey_name, credential)
        return user

    async def add_passkey(
        self,
        *,
        user_id: UUID,
        name: str,
        credential: PasskeyCredential,
    ) -> MemoryPasskey:
        return self._add(self.users[user_id], name, credential)

    async def record_passkey_use(self, passkey: MemoryPasskey, *, new_sign_count: int) -> None:
        passkey.sign_count = new_sign_count
        passkey.last_used_at = datetime.now(UTC)

    async def rename_passkey(
        self, passkey: MemoryPasskey, *, name: str, new_sign_count: int
    ) -> MemoryPasskey:
        passkey.name = name
        passkey.sign_count = new_sign_count
        passkey.last_used_at = datetime.now(UTC)
        return passkey

    async def delete_passkey(
        self,
        *,
        user_id: UUID,
        passkey_id: UUID,
        confirming_passkey: MemoryPasskey,
        new_sign_count: int,
    ) -> None:
        confirming_passkey.sign_count = new_sign_count
        confirming_passkey.last_used_at = datetime.now(UTC)
        user = self.users[user_id]
        user.passkeys[:] = [passkey for passkey in user.passkeys if passkey.id != passkey_id]

    async def add_link_user(self, token: str) -> MemoryUser | None:
        if token != "e2e-token" or not self.add_link_active:
            return None
        return next(iter(self.users.values()), None)

    async def complete_add_link(
        self,
        *,
        token: str,
        user_id: UUID,
        name: str,
        credential: PasskeyCredential,
    ) -> MemoryUser | None:
        user = await self.add_link_user(token)
        if user is None or user.id != user_id:
            return None
        self._add(user, name, credential)
        self.add_link_active = False
        return user

    async def authenticate(self, request: Request, user: MemoryUser) -> MemoryUser:
        request.session["user_id"] = str(user.id)
        return user

    async def logout(self, request: Request) -> None:
        request.session.clear()

    def access_token(self, user: MemoryUser) -> str:
        return f"e2e-{user.id}"


repository = MemoryRepository()
service = FastPasskey(rp_name="FastPasskey E2E")


def get_repository() -> MemoryRepository:
    return repository


async def get_current_user(request: Request) -> MemoryUser:
    raw_user_id = request.session.get("user_id")
    if not raw_user_id:
        raise HTTPException(status_code=401, detail="Authentication required")
    user = await repository.user_by_id(UUID(raw_user_id))
    if user is None:
        raise HTTPException(status_code=401, detail="Authentication required")
    return user


templates = Environment(autoescape=True)
install_fastpasskey_templates(templates)


def translate(key: str, **values: object) -> str:
    messages = {
        "auth.login.create_account_tab": "Create account",
        "auth.login.create_passkey_button": "Create passkey",
        "auth.login.sign_in_button": "Sign in",
        "auth.passkey_add.create_additional_button": "Create additional passkey",
        "common.cancel": "Cancel",
        "common.close": "Close",
        "common.continue": "Continue",
        "common.delete": "Delete",
        "settings.add_another": "Add another passkey",
        "settings.continue_to_verification": "Continue to verification",
        "settings.rename": "Rename",
        "settings.save_and_verify": "Save and verify",
    }
    return messages.get(key, key).format(**values)


templates.globals["t"] = translate
login_template = templates.from_string(
    '{% from "fastpasskey/login.html" import passkey_login with context %}'
    '{{ passkey_login("/settings") }}'
)
management_template = templates.from_string(
    '{% from "fastpasskey/management.html" import passkey_management with context %}'
    "<section data-user-settings>{{ passkey_management() }}</section>"
)
add_link_template = templates.from_string(
    '{% from "fastpasskey/add_link.html" import passkey_add_link with context %}'
    "{{ passkey_add_link(token, email, display_name) }}"
)


def page(body: str) -> str:
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>FastPasskey E2E</title>
<link rel="stylesheet" href="/auth/assets/fastpasskey.css"></head>
<body>{body}
<script type="module">
import {{ initFastPasskey }} from "/auth/assets/fastpasskey.js";
initFastPasskey({{
  apiBase: "/auth",
  locale: () => "en-US",
  navigate: (url) => window.location.assign(url),
  translate: (_key, _values, fallback) => fallback,
}});
</script></body></html>"""


app = FastAPI()
app.add_middleware(SessionMiddleware, secret_key="fastpasskey-e2e-secret")
app.include_router(
    create_passkey_router(
        PasskeyRouterConfig(
            service_factory=lambda: service,
            repository_dependency=get_repository,
            current_user_dependency=get_current_user,
            add_link_repository_dependency=get_repository,
        )
    )
)


@app.get("/healthz")
async def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/")
async def home() -> RedirectResponse:
    return RedirectResponse("/settings")


@app.get("/login", response_class=HTMLResponse)
async def login() -> str:
    return page(login_template.render())


@app.get("/settings", response_class=HTMLResponse)
async def settings(request: Request):
    try:
        await get_current_user(request)
    except HTTPException:
        return RedirectResponse("/login", status_code=303)
    return page(management_template.render())


@app.get("/add/{token}", response_class=HTMLResponse)
async def add_link(token: str):
    user = await repository.add_link_user(token)
    if user is None:
        raise HTTPException(status_code=404)
    return page(
        add_link_template.render(
            token=token,
            email=user.email,
            display_name=user.display_name,
        )
    )
