from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from importlib.resources import files
from typing import Any, Protocol
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_serializer
from webauthn.helpers import bytes_to_base64url

from fastpasskey.core import (
    FastPasskey,
    PasskeyConfigurationError,
    PasskeyNameError,
    PasskeyPayloadError,
    PasskeyUser,
    credential_id_from_payload,
    default_passkey_name,
    validate_passkey_name,
)


class PasskeyConflictError(Exception):
    """A repository rejected a duplicate user or credential."""


@dataclass(frozen=True, slots=True)
class PasskeyCredential:
    """Verified credential fields a repository must persist."""

    credential_id: str
    public_key: bytes
    sign_count: int


class PasskeyRecord(Protocol):
    id: UUID
    name: str
    credential_id: str
    public_key: bytes
    sign_count: int
    created_at: datetime
    last_used_at: datetime | None


class PasskeyUserRecord(Protocol):
    id: UUID
    email: str
    display_name: str
    is_admin: bool
    is_active: bool
    passkeys: Sequence[PasskeyRecord]


class PasskeyRepository(Protocol):
    """Application persistence and session hooks used by the router."""

    async def user_by_email(self, email: str) -> PasskeyUserRecord | None: ...

    async def user_by_id(self, user_id: UUID) -> PasskeyUserRecord | None: ...

    async def passkey_by_credential_id(self, credential_id: str) -> PasskeyRecord | None: ...

    async def register_user(
        self,
        *,
        user_id: UUID,
        email: str,
        display_name: str,
        passkey_name: str,
        credential: PasskeyCredential,
    ) -> PasskeyUserRecord: ...

    async def replace_passkeys(
        self,
        *,
        user_id: UUID,
        passkey_name: str,
        credential: PasskeyCredential,
    ) -> PasskeyUserRecord: ...

    async def add_passkey(
        self,
        *,
        user_id: UUID,
        name: str,
        credential: PasskeyCredential,
    ) -> PasskeyRecord: ...

    async def record_passkey_use(self, passkey: PasskeyRecord, *, new_sign_count: int) -> None: ...

    async def rename_passkey(
        self, passkey: PasskeyRecord, *, name: str, new_sign_count: int
    ) -> PasskeyRecord: ...

    async def delete_passkey(
        self,
        *,
        user_id: UUID,
        passkey_id: UUID,
        confirming_passkey: PasskeyRecord,
        new_sign_count: int,
    ) -> None: ...

    async def authenticate(
        self, request: Request, user: PasskeyUserRecord
    ) -> PasskeyUserRecord: ...

    async def logout(self, request: Request) -> None: ...

    def access_token(self, user: PasskeyUserRecord) -> str: ...


class PasskeyAddLinkRepository(PasskeyRepository, Protocol):
    """Optional persistence hooks used only when add-link routes are enabled."""

    async def add_link_user(self, token: str) -> PasskeyUserRecord | None: ...

    async def complete_add_link(
        self,
        *,
        token: str,
        user_id: UUID,
        name: str,
        credential: PasskeyCredential,
    ) -> PasskeyUserRecord | None: ...


class PasskeyRegisterStartRequest(BaseModel):
    email: EmailStr
    display_name: str


class PasskeyLoginStartRequest(BaseModel):
    email: EmailStr | None = None


class PasskeyNameRequest(BaseModel):
    name: str = Field(min_length=1)


class PasskeyFinishRequest(BaseModel):
    credential: dict[str, Any]


class PasswordAuthRequest(BaseModel):
    email: EmailStr
    passkey: str = Field(min_length=8)


class PasskeyOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    name: str
    created_at: datetime
    last_used_at: datetime | None

    @field_serializer("created_at", "last_used_at")
    def serialize_utc_datetime(self, value: datetime | None) -> str | None:
        if value is None:
            return None
        if value.tzinfo is None:
            value = value.replace(tzinfo=UTC)
        else:
            value = value.astimezone(UTC)
        return value.isoformat().replace("+00:00", "Z")


class UserOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    email: EmailStr
    display_name: str
    is_admin: bool
    is_active: bool


class TokenOut(BaseModel):
    access_token: str
    token_type: str = "bearer"


@dataclass(frozen=True, slots=True)
class PasskeyRouterConfig:
    """Dependencies and policy for a reusable passkey API router."""

    service_factory: Callable[[], FastPasskey]
    repository_dependency: Callable[..., PasskeyRepository]
    current_user_dependency: Callable[..., PasskeyUserRecord]
    add_link_repository_dependency: Callable[..., PasskeyAddLinkRepository] | None = None
    enable_add_link_routes: bool = True
    prefix: str = "/auth"
    initial_passkey_name: str = "Passkey 1"


_REGISTER_SESSION_KEY = "passkey_register"
_LOGIN_SESSION_KEY = "passkey_login"
_SETTINGS_SESSION_KEY = "passkey_settings"
_PASSKEY_ADD_SESSION_KEY = "passkey_add"
_PASSKEY_DELETE_SESSION_KEY = "passkey_delete"
_PASSKEY_RENAME_SESSION_KEY = "passkey_rename"
_PASSKEY_LINK_SESSION_KEY = "passkey_add_link"
_REGISTRATION_FAILURE_DETAIL = (
    "Could not create that account. Try signing in with an existing "
    "passkey or use a different email."
)


def _http_configuration_error(exc: PasskeyConfigurationError) -> HTTPException:
    return HTTPException(status_code=400, detail=str(exc))


def _verified_credential(verified: Any) -> PasskeyCredential:
    return PasskeyCredential(
        credential_id=bytes_to_base64url(verified.credential_id),
        public_key=verified.credential_public_key,
        sign_count=verified.sign_count,
    )


def _credential_id(payload: PasskeyFinishRequest) -> str:
    try:
        return credential_id_from_payload(payload.credential)
    except PasskeyPayloadError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


def _passkey_name(raw_name: str) -> str:
    try:
        return validate_passkey_name(raw_name)
    except PasskeyNameError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


def _user_start(
    service: FastPasskey,
    request: Request,
    user: PasskeyUserRecord,
    *,
    exclude: Iterable[str] = (),
    state: Mapping[str, object] | None = None,
):
    try:
        return service.begin_registration(
            user=PasskeyUser(
                id=user.id.bytes,
                name=user.email,
                display_name=user.display_name,
            ),
            request_host=request.url.hostname,
            request_base_url=str(request.base_url),
            exclude_credential_ids=exclude,
            state_payload=state,
        )
    except PasskeyConfigurationError as exc:
        raise _http_configuration_error(exc) from exc


def _authentication_start(
    service: FastPasskey,
    request: Request,
    *,
    allow: Iterable[str] | None = None,
    state: Mapping[str, object] | None = None,
):
    try:
        return service.begin_authentication(
            request_host=request.url.hostname,
            request_base_url=str(request.base_url),
            allow_credential_ids=allow,
            state_payload=state,
        )
    except PasskeyConfigurationError as exc:
        raise _http_configuration_error(exc) from exc


def _pending(
    request: Request,
    service: FastPasskey,
    key: str,
    expired_detail: str,
    **expected: str,
) -> Mapping[str, object]:
    state = request.session.get(key)
    if not service.state_is_valid(state) or any(
        state.get(name) != value for name, value in expected.items()
    ):
        request.session.pop(key, None)
        raise HTTPException(status_code=400, detail=expired_detail)
    return state


def _find_passkey(user: PasskeyUserRecord, passkey_id: UUID) -> PasskeyRecord:
    passkey = next((entry for entry in user.passkeys if entry.id == passkey_id), None)
    if passkey is None:
        raise HTTPException(status_code=404, detail="Passkey not found")
    return passkey


async def _loaded_user(repository: PasskeyRepository, user: PasskeyUserRecord) -> PasskeyUserRecord:
    refreshed = await repository.user_by_id(user.id)
    if refreshed is None:
        raise HTTPException(status_code=404, detail="User not found")
    return refreshed


def create_passkey_router(config: PasskeyRouterConfig) -> APIRouter:
    """Create the complete passkey API, including the packaged browser client."""

    router = APIRouter(prefix=config.prefix, tags=["auth"])
    repository_dependency = config.repository_dependency
    current_user_dependency = config.current_user_dependency

    @router.get("/assets/fastpasskey.js", include_in_schema=False)
    async def browser_client() -> Response:
        source = files("fastpasskey").joinpath("static/fastpasskey.js").read_text("utf-8")
        return Response(source, media_type="application/javascript")

    @router.get("/assets/fastpasskey.css", include_in_schema=False)
    async def browser_styles() -> Response:
        source = files("fastpasskey").joinpath("static/fastpasskey.css").read_text("utf-8")
        return Response(source, media_type="text/css")

    @router.post("/register/options")
    async def begin_registration(
        payload: PasskeyRegisterStartRequest,
        request: Request,
        _: PasskeyRepository = Depends(repository_dependency),
    ) -> dict[str, object]:
        user_id = uuid4()
        service = config.service_factory()
        try:
            start = service.begin_registration(
                user=PasskeyUser(
                    id=user_id.bytes,
                    name=str(payload.email),
                    display_name=payload.display_name,
                ),
                request_host=request.url.hostname,
                request_base_url=str(request.base_url),
                state_payload={
                    "email": str(payload.email),
                    "display_name": payload.display_name,
                    "user_id": str(user_id),
                },
            )
        except PasskeyConfigurationError as exc:
            raise _http_configuration_error(exc) from exc
        request.session[_REGISTER_SESSION_KEY] = start.state
        return start.options

    @router.post("/register/verify", response_model=UserOut)
    async def finish_registration(
        payload: PasskeyFinishRequest,
        request: Request,
        repository: PasskeyRepository = Depends(repository_dependency),
    ) -> PasskeyUserRecord:
        service = config.service_factory()
        state = _pending(request, service, _REGISTER_SESSION_KEY, "Registration session expired")
        if await repository.user_by_email(str(state["email"])) is not None:
            raise HTTPException(status_code=400, detail=_REGISTRATION_FAILURE_DETAIL)
        try:
            verified = service.verify_registration(credential=payload.credential, state=state)
        except Exception as exc:
            raise HTTPException(status_code=400, detail="Passkey registration failed") from exc
        credential = _verified_credential(verified)
        if await repository.passkey_by_credential_id(credential.credential_id) is not None:
            raise HTTPException(status_code=400, detail=_REGISTRATION_FAILURE_DETAIL)
        try:
            user = await repository.register_user(
                user_id=UUID(str(state["user_id"])),
                email=str(state["email"]),
                display_name=str(state["display_name"]),
                passkey_name=config.initial_passkey_name,
                credential=credential,
            )
        except PasskeyConflictError as exc:
            raise HTTPException(status_code=400, detail=_REGISTRATION_FAILURE_DETAIL) from exc
        request.session.pop(_REGISTER_SESSION_KEY, None)
        return await repository.authenticate(request, user)

    @router.post("/login/options")
    async def begin_login(_: PasskeyLoginStartRequest, request: Request) -> dict[str, object]:
        service = config.service_factory()
        start = _authentication_start(service, request)
        request.session[_LOGIN_SESSION_KEY] = start.state
        return start.options

    @router.post("/login/verify", response_model=TokenOut)
    async def finish_login(
        payload: PasskeyFinishRequest,
        request: Request,
        repository: PasskeyRepository = Depends(repository_dependency),
    ) -> TokenOut:
        service = config.service_factory()
        state = _pending(request, service, _LOGIN_SESSION_KEY, "Login session expired")
        passkey = await repository.passkey_by_credential_id(_credential_id(payload))
        if passkey is None:
            raise HTTPException(status_code=404, detail="No passkey found for that credential")
        user = getattr(passkey, "user", None)
        if user is None:
            raise HTTPException(status_code=404, detail="No user found for that passkey")
        try:
            verified = service.verify_authentication(
                credential=payload.credential,
                state=state,
                credential_public_key=passkey.public_key,
                credential_current_sign_count=passkey.sign_count,
            )
        except Exception as exc:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid passkey"
            ) from exc
        await repository.record_passkey_use(passkey, new_sign_count=verified.new_sign_count)
        user = await repository.authenticate(request, user)
        request.session.pop(_LOGIN_SESSION_KEY, None)
        return TokenOut(access_token=repository.access_token(user))

    @router.post("/settings/passkey/options")
    async def begin_replace(
        request: Request,
        user: PasskeyUserRecord = Depends(current_user_dependency),
        repository: PasskeyRepository = Depends(repository_dependency),
    ) -> dict[str, object]:
        user = await _loaded_user(repository, user)
        service = config.service_factory()
        start = _user_start(
            service,
            request,
            user,
            exclude=(passkey.credential_id for passkey in user.passkeys),
            state={"user_id": str(user.id)},
        )
        request.session[_SETTINGS_SESSION_KEY] = start.state
        return start.options

    @router.post("/settings/passkey/verify", response_model=UserOut)
    async def finish_replace(
        payload: PasskeyFinishRequest,
        request: Request,
        user: PasskeyUserRecord = Depends(current_user_dependency),
        repository: PasskeyRepository = Depends(repository_dependency),
    ) -> PasskeyUserRecord:
        service = config.service_factory()
        state = _pending(
            request,
            service,
            _SETTINGS_SESSION_KEY,
            "Passkey settings session expired",
            user_id=str(user.id),
        )
        await _loaded_user(repository, user)
        try:
            verified = service.verify_registration(credential=payload.credential, state=state)
        except Exception as exc:
            raise HTTPException(status_code=400, detail="Passkey update failed") from exc
        credential = _verified_credential(verified)
        if await repository.passkey_by_credential_id(credential.credential_id) is not None:
            raise HTTPException(status_code=400, detail="That passkey is already registered")
        user = await repository.replace_passkeys(
            user_id=user.id,
            passkey_name=config.initial_passkey_name,
            credential=credential,
        )
        request.session.pop(_SETTINGS_SESSION_KEY, None)
        return user

    @router.post("/register", response_model=None)
    async def password_registration_disabled(_: PasswordAuthRequest) -> None:
        raise HTTPException(
            status_code=400,
            detail=(
                "Password-based auth is disabled. Use the passkey registration "
                "and login endpoints."
            ),
        )

    @router.post("/login", response_model=None)
    async def password_login_disabled(_: PasswordAuthRequest) -> None:
        raise HTTPException(
            status_code=400,
            detail=(
                "Password-based auth is disabled. Use the passkey registration "
                "and login endpoints."
            ),
        )

    @router.post("/logout")
    async def logout(
        request: Request,
        repository: PasskeyRepository = Depends(repository_dependency),
    ) -> dict[str, str]:
        await repository.logout(request)
        request.session.clear()
        return {"message": "logged out"}

    @router.get("/passkeys", response_model=list[PasskeyOut])
    async def list_passkeys(
        user: PasskeyUserRecord = Depends(current_user_dependency),
        repository: PasskeyRepository = Depends(repository_dependency),
    ) -> Sequence[PasskeyRecord]:
        return (await _loaded_user(repository, user)).passkeys

    @router.post("/passkeys/register/options")
    async def begin_add_passkey(
        payload: PasskeyNameRequest,
        request: Request,
        user: PasskeyUserRecord = Depends(current_user_dependency),
        repository: PasskeyRepository = Depends(repository_dependency),
    ) -> dict[str, object]:
        user = await _loaded_user(repository, user)
        service = config.service_factory()
        start = _user_start(
            service,
            request,
            user,
            exclude=(passkey.credential_id for passkey in user.passkeys),
            state={"user_id": str(user.id), "name": _passkey_name(payload.name)},
        )
        request.session[_PASSKEY_ADD_SESSION_KEY] = start.state
        return start.options

    @router.post("/passkeys/register/verify", response_model=PasskeyOut)
    async def finish_add_passkey(
        payload: PasskeyFinishRequest,
        request: Request,
        user: PasskeyUserRecord = Depends(current_user_dependency),
        repository: PasskeyRepository = Depends(repository_dependency),
    ) -> PasskeyRecord:
        service = config.service_factory()
        state = _pending(
            request,
            service,
            _PASSKEY_ADD_SESSION_KEY,
            "Passkey registration session expired",
            user_id=str(user.id),
        )
        try:
            verified = service.verify_registration(credential=payload.credential, state=state)
        except Exception as exc:
            raise HTTPException(status_code=400, detail="Passkey registration failed") from exc
        credential = _verified_credential(verified)
        if await repository.passkey_by_credential_id(credential.credential_id) is not None:
            raise HTTPException(status_code=400, detail="That passkey is already registered")
        passkey = await repository.add_passkey(
            user_id=user.id, name=str(state["name"]), credential=credential
        )
        request.session.pop(_PASSKEY_ADD_SESSION_KEY, None)
        return passkey

    add_link_repository_dependency = config.add_link_repository_dependency or repository_dependency
    if config.enable_add_link_routes:

        @router.post("/passkey-add/{token}/options")
        async def begin_add_link(
            token: str,
            request: Request,
            repository: PasskeyAddLinkRepository = Depends(add_link_repository_dependency),
        ) -> dict[str, object]:
            user = await repository.add_link_user(token)
            if user is None:
                raise HTTPException(status_code=404, detail="Passkey add link not found")
            service = config.service_factory()
            start = _user_start(
                service,
                request,
                user,
                state={"user_id": str(user.id), "token": token},
            )
            request.session[_PASSKEY_LINK_SESSION_KEY] = start.state
            return start.options

        @router.post("/passkey-add/{token}/verify", response_model=UserOut)
        async def finish_add_link(
            token: str,
            payload: PasskeyFinishRequest,
            request: Request,
            repository: PasskeyAddLinkRepository = Depends(add_link_repository_dependency),
        ) -> PasskeyUserRecord:
            service = config.service_factory()
            state = _pending(
                request,
                service,
                _PASSKEY_LINK_SESSION_KEY,
                "Passkey add session expired",
                token=token,
            )
            user = await repository.add_link_user(token)
            if user is None or str(user.id) != state.get("user_id"):
                request.session.pop(_PASSKEY_LINK_SESSION_KEY, None)
                raise HTTPException(status_code=404, detail="Passkey add link not found")
            try:
                verified = service.verify_registration(credential=payload.credential, state=state)
            except Exception as exc:
                raise HTTPException(status_code=400, detail="Passkey add failed") from exc
            credential = _verified_credential(verified)
            if await repository.passkey_by_credential_id(credential.credential_id) is not None:
                raise HTTPException(status_code=400, detail="That passkey is already registered")
            completed = await repository.complete_add_link(
                token=token,
                user_id=user.id,
                name=default_passkey_name(len(user.passkeys)),
                credential=credential,
            )
            if completed is None:
                raise HTTPException(status_code=404, detail="Passkey add link not found")
            request.session.pop(_PASSKEY_LINK_SESSION_KEY, None)
            return await repository.authenticate(request, completed)

    @router.post("/passkeys/{passkey_id}/rename/options")
    async def begin_rename(
        passkey_id: UUID,
        payload: PasskeyNameRequest,
        request: Request,
        user: PasskeyUserRecord = Depends(current_user_dependency),
        repository: PasskeyRepository = Depends(repository_dependency),
    ) -> dict[str, object]:
        user = await _loaded_user(repository, user)
        target = _find_passkey(user, passkey_id)
        service = config.service_factory()
        start = _authentication_start(
            service,
            request,
            allow=[target.credential_id],
            state={
                "user_id": str(user.id),
                "passkey_id": str(passkey_id),
                "name": _passkey_name(payload.name),
            },
        )
        request.session[_PASSKEY_RENAME_SESSION_KEY] = start.state
        return start.options

    @router.post("/passkeys/{passkey_id}/rename/verify", response_model=PasskeyOut)
    async def finish_rename(
        passkey_id: UUID,
        payload: PasskeyFinishRequest,
        request: Request,
        user: PasskeyUserRecord = Depends(current_user_dependency),
        repository: PasskeyRepository = Depends(repository_dependency),
    ) -> PasskeyRecord:
        service = config.service_factory()
        state = _pending(
            request,
            service,
            _PASSKEY_RENAME_SESSION_KEY,
            "Passkey rename session expired",
            user_id=str(user.id),
            passkey_id=str(passkey_id),
        )
        target = _find_passkey(await _loaded_user(repository, user), passkey_id)
        if payload.credential.get("id") != target.credential_id:
            raise HTTPException(
                status_code=400,
                detail="Confirm the rename with the passkey you are renaming",
            )
        try:
            verified = service.verify_authentication(
                credential=payload.credential,
                state=state,
                credential_public_key=target.public_key,
                credential_current_sign_count=target.sign_count,
            )
        except Exception as exc:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Could not verify that passkey before renaming",
            ) from exc
        passkey = await repository.rename_passkey(
            target,
            name=str(state["name"]),
            new_sign_count=verified.new_sign_count,
        )
        request.session.pop(_PASSKEY_RENAME_SESSION_KEY, None)
        return passkey

    @router.post("/passkeys/{passkey_id}/delete/options")
    async def begin_delete(
        passkey_id: UUID,
        request: Request,
        user: PasskeyUserRecord = Depends(current_user_dependency),
        repository: PasskeyRepository = Depends(repository_dependency),
    ) -> dict[str, object]:
        user = await _loaded_user(repository, user)
        _find_passkey(user, passkey_id)
        if len(user.passkeys) <= 1:
            raise HTTPException(status_code=400, detail="You cannot delete your last passkey")
        service = config.service_factory()
        start = _authentication_start(
            service,
            request,
            allow=[passkey.credential_id for passkey in user.passkeys if passkey.id != passkey_id],
            state={"user_id": str(user.id), "passkey_id": str(passkey_id)},
        )
        request.session[_PASSKEY_DELETE_SESSION_KEY] = start.state
        return start.options

    @router.post("/passkeys/{passkey_id}/delete/verify")
    async def finish_delete(
        passkey_id: UUID,
        payload: PasskeyFinishRequest,
        request: Request,
        user: PasskeyUserRecord = Depends(current_user_dependency),
        repository: PasskeyRepository = Depends(repository_dependency),
    ) -> dict[str, str]:
        service = config.service_factory()
        state = _pending(
            request,
            service,
            _PASSKEY_DELETE_SESSION_KEY,
            "Passkey deletion session expired",
            user_id=str(user.id),
            passkey_id=str(passkey_id),
        )
        user = await _loaded_user(repository, user)
        _find_passkey(user, passkey_id)
        if len(user.passkeys) <= 1:
            raise HTTPException(status_code=400, detail="You cannot delete your last passkey")
        confirming_id = _credential_id(payload)
        confirming = next(
            (
                passkey
                for passkey in user.passkeys
                if passkey.credential_id == confirming_id and passkey.id != passkey_id
            ),
            None,
        )
        if confirming is None:
            raise HTTPException(
                status_code=400,
                detail="Confirm deletion with one of your other passkeys",
            )
        try:
            verified = service.verify_authentication(
                credential=payload.credential,
                state=state,
                credential_public_key=confirming.public_key,
                credential_current_sign_count=confirming.sign_count,
            )
        except Exception as exc:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Could not verify another passkey before deletion",
            ) from exc
        await repository.delete_passkey(
            user_id=user.id,
            passkey_id=passkey_id,
            confirming_passkey=confirming,
            new_sign_count=verified.new_sign_count,
        )
        request.session.pop(_PASSKEY_DELETE_SESSION_KEY, None)
        return {"message": "passkey deleted"}

    @router.get("/me", response_model=UserOut)
    async def me(
        user: PasskeyUserRecord = Depends(current_user_dependency),
    ) -> PasskeyUserRecord:
        return user

    return router
