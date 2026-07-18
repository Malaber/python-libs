from datetime import UTC, datetime
from types import SimpleNamespace
from uuid import uuid4

from fastapi import FastAPI
from fastapi.testclient import TestClient
from jinja2 import DictLoader, Environment
from starlette.middleware.sessions import SessionMiddleware
from webauthn.helpers import bytes_to_base64url

from fastpasskey import (
    CeremonyStart,
    PasskeyRouterConfig,
    create_passkey_router,
    install_fastpasskey_templates,
)


class FakeService:
    def __init__(self) -> None:
        self.registration_count = 0

    def begin_registration(self, *, state_payload=None, **kwargs):
        return CeremonyStart(
            options={"challenge": "register", "user": {"id": "user"}},
            state={"issued_at": "now", **dict(state_payload or {})},
        )

    def begin_authentication(self, *, state_payload=None, **kwargs):
        return CeremonyStart(
            options={"challenge": "authenticate"},
            state={"issued_at": "now", **dict(state_payload or {})},
        )

    def state_is_valid(self, state):
        return isinstance(state, dict) and state.get("issued_at") == "now"

    def verify_registration(self, **kwargs):
        self.registration_count += 1
        return SimpleNamespace(
            credential_id=f"credential-{self.registration_count}".encode(),
            credential_public_key=b"public-key",
            sign_count=1,
        )

    def verify_authentication(self, **kwargs):
        return SimpleNamespace(new_sign_count=kwargs["credential_current_sign_count"] + 1)


class FakeRepository:
    def __init__(self) -> None:
        self.user = None
        self.passkeys = []
        self.link_active = True
        self.authenticated = 0
        self.logged_out = 0

    @staticmethod
    def _passkey(name, credential):
        return SimpleNamespace(
            id=uuid4(),
            name=name,
            credential_id=credential.credential_id,
            public_key=credential.public_key,
            sign_count=credential.sign_count,
            created_at=datetime(2026, 7, 18, 12, 0, tzinfo=UTC),
            last_used_at=None,
            user=None,
        )

    def _attach(self, passkey):
        passkey.user = self.user
        self.passkeys.append(passkey)
        self.user.passkeys = self.passkeys
        return passkey

    async def user_by_email(self, email):
        return self.user if self.user and self.user.email == email else None

    async def user_by_id(self, user_id):
        return self.user if self.user and self.user.id == user_id else None

    async def passkey_by_credential_id(self, credential_id):
        return next(
            (entry for entry in self.passkeys if entry.credential_id == credential_id),
            None,
        )

    async def register_user(self, *, user_id, email, display_name, passkey_name, credential):
        self.user = SimpleNamespace(
            id=user_id,
            email=email,
            display_name=display_name,
            is_admin=False,
            is_active=True,
            passkeys=self.passkeys,
        )
        self._attach(self._passkey(passkey_name, credential))
        return self.user

    async def replace_passkeys(self, *, user_id, passkey_name, credential):
        self.passkeys.clear()
        self._attach(self._passkey(passkey_name, credential))
        return self.user

    async def add_passkey(self, *, user_id, name, credential):
        return self._attach(self._passkey(name, credential))

    async def record_passkey_use(self, passkey, *, new_sign_count):
        passkey.sign_count = new_sign_count

    async def rename_passkey(self, passkey, *, name, new_sign_count):
        passkey.name = name
        passkey.sign_count = new_sign_count
        return passkey

    async def delete_passkey(self, *, user_id, passkey_id, confirming_passkey, new_sign_count):
        confirming_passkey.sign_count = new_sign_count
        self.passkeys[:] = [entry for entry in self.passkeys if entry.id != passkey_id]

    async def add_link_user(self, token):
        return self.user if token == "valid" and self.link_active else None

    async def complete_add_link(self, *, token, user_id, name, credential):
        if token != "valid" or not self.link_active:
            return None
        self._attach(self._passkey(name, credential))
        self.link_active = False
        return self.user

    async def authenticate(self, request, user):
        self.authenticated += 1
        return user

    async def logout(self, request):
        self.logged_out += 1

    def access_token(self, user):
        return f"token-{user.id}"


def build_client():
    service = FakeService()
    repository = FakeRepository()

    def get_repository():
        return repository

    def get_current_user():
        return repository.user

    app = FastAPI()
    app.add_middleware(SessionMiddleware, secret_key="test-secret")
    app.include_router(
        create_passkey_router(
            PasskeyRouterConfig(
                service_factory=lambda: service,
                repository_dependency=get_repository,
                current_user_dependency=get_current_user,
            )
        )
    )
    return TestClient(app), repository


def finish_payload(credential_id="ignored"):
    return {"credential": {"id": credential_id, "response": {}}}


def test_complete_router_happy_path_and_packaged_asset() -> None:
    client, repository = build_client()

    asset = client.get("/auth/assets/fastpasskey.js")
    assert asset.status_code == 200
    assert "initFastPasskey" in asset.text

    options = client.post(
        "/auth/register/options",
        json={"email": "owner@example.com", "display_name": "Owner"},
    )
    assert options.json()["challenge"] == "register"
    registered = client.post("/auth/register/verify", json=finish_payload())
    assert registered.status_code == 200
    assert registered.json()["email"] == "owner@example.com"

    login_options = client.post("/auth/login/options", json={})
    assert login_options.json()["challenge"] == "authenticate"
    credential_id = repository.passkeys[0].credential_id
    login = client.post("/auth/login/verify", json=finish_payload(credential_id))
    assert login.status_code == 200
    assert login.json()["access_token"].startswith("token-")

    assert client.get("/auth/me").status_code == 200
    assert len(client.get("/auth/passkeys").json()) == 1

    assert (
        client.post("/auth/passkeys/register/options", json={"name": "Laptop"}).status_code == 200
    )
    added = client.post("/auth/passkeys/register/verify", json=finish_payload())
    assert added.json()["name"] == "Laptop"

    laptop = repository.passkeys[-1]
    assert (
        client.post(
            f"/auth/passkeys/{laptop.id}/rename/options", json={"name": "Travel"}
        ).status_code
        == 200
    )
    renamed = client.post(
        f"/auth/passkeys/{laptop.id}/rename/verify",
        json=finish_payload(laptop.credential_id),
    )
    assert renamed.json()["name"] == "Travel"

    target = repository.passkeys[0]
    confirming = repository.passkeys[1]
    assert client.post(f"/auth/passkeys/{target.id}/delete/options").status_code == 200
    deleted = client.post(
        f"/auth/passkeys/{target.id}/delete/verify",
        json=finish_payload(confirming.credential_id),
    )
    assert deleted.json() == {"message": "passkey deleted"}

    assert client.post("/auth/settings/passkey/options").status_code == 200
    assert client.post("/auth/settings/passkey/verify", json=finish_payload()).status_code == 200

    assert client.post("/auth/passkey-add/valid/options").status_code == 200
    assert client.post("/auth/passkey-add/valid/verify", json=finish_payload()).status_code == 200

    password_payload = {"email": "owner@example.com", "passkey": "password"}
    assert client.post("/auth/register", json=password_payload).status_code == 400
    assert client.post("/auth/login", json=password_payload).status_code == 400
    assert client.post("/auth/logout").json() == {"message": "logged out"}
    assert repository.logged_out == 1


def test_router_rejects_expired_and_missing_resources() -> None:
    client, repository = build_client()
    assert client.post("/auth/register/verify", json=finish_payload()).status_code == 400
    assert client.post("/auth/login/verify", json=finish_payload()).status_code == 400
    assert client.post("/auth/passkey-add/missing/options").status_code == 404

    client.post("/auth/login/options", json={})
    missing = bytes_to_base64url(b"missing")
    assert client.post("/auth/login/verify", json=finish_payload(missing)).status_code == 404

    repository.user = SimpleNamespace(
        id=uuid4(),
        email="owner@example.com",
        display_name="Owner",
        is_admin=False,
        is_active=True,
        passkeys=[],
    )
    assert client.post("/auth/passkeys/register/options", json={"name": "   "}).status_code == 400


def test_template_loader_preserves_application_overrides() -> None:
    environment = Environment(loader=DictLoader({"fastpasskey/login.html": "override"}))
    install_fastpasskey_templates(environment)
    assert environment.get_template("fastpasskey/login.html").render() == "override"
    source, _, _ = environment.loader.get_source(environment, "fastpasskey/management.html")
    assert "passkey_management" in source

    empty_environment = Environment(loader=None)
    install_fastpasskey_templates(empty_environment)
    assert empty_environment.get_template("fastpasskey/add_link.html") is not None
