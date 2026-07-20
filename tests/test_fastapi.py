from datetime import UTC, datetime, timedelta, timezone
from types import SimpleNamespace
from uuid import uuid4

from fastapi import FastAPI
from fastapi.testclient import TestClient
from jinja2 import DictLoader, Environment
from starlette.middleware.sessions import SessionMiddleware
from webauthn.helpers import bytes_to_base64url

from fastpasskey import (
    CeremonyStart,
    PasskeyConfigurationError,
    PasskeyConflictError,
    PasskeyOut,
    PasskeyRouterConfig,
    create_passkey_router,
    install_fastpasskey_templates,
)


class FakeService:
    def __init__(self) -> None:
        self.registration_count = 0
        self.begin_registration_error = None
        self.begin_authentication_error = None
        self.verify_registration_error = None
        self.verify_authentication_error = None
        self.credential_id = None

    def begin_registration(self, *, state_payload=None, **kwargs):
        if self.begin_registration_error:
            raise self.begin_registration_error
        return CeremonyStart(
            options={"challenge": "register", "user": {"id": "user"}},
            state={"issued_at": "now", **dict(state_payload or {})},
        )

    def begin_authentication(self, *, state_payload=None, **kwargs):
        if self.begin_authentication_error:
            raise self.begin_authentication_error
        return CeremonyStart(
            options={"challenge": "authenticate"},
            state={"issued_at": "now", **dict(state_payload or {})},
        )

    def state_is_valid(self, state):
        return isinstance(state, dict) and state.get("issued_at") == "now"

    def verify_registration(self, **kwargs):
        if self.verify_registration_error:
            raise self.verify_registration_error
        self.registration_count += 1
        return SimpleNamespace(
            credential_id=self.credential_id or f"credential-{self.registration_count}".encode(),
            credential_public_key=b"public-key",
            sign_count=1,
        )

    def verify_authentication(self, **kwargs):
        if self.verify_authentication_error:
            raise self.verify_authentication_error
        return SimpleNamespace(new_sign_count=kwargs["credential_current_sign_count"] + 1)


class FakeRepository:
    def __init__(self) -> None:
        self.user = None
        self.passkeys = []
        self.link_active = True
        self.authenticated = 0
        self.logged_out = 0
        self.missing_user_by_id = False
        self.registration_conflict = False
        self.complete_link_none = False
        self.duplicate_credential_ids = set()

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
        if self.missing_user_by_id:
            return None
        return self.user if self.user and self.user.id == user_id else None

    async def passkey_by_credential_id(self, credential_id):
        if credential_id in self.duplicate_credential_ids:
            return SimpleNamespace(credential_id=credential_id)
        return next(
            (entry for entry in self.passkeys if entry.credential_id == credential_id),
            None,
        )

    async def register_user(self, *, user_id, email, display_name, passkey_name, credential):
        if self.registration_conflict:
            raise PasskeyConflictError
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
        if token != "valid" or not self.link_active or self.complete_link_none:
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


def build_client(*, add_links=True):
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
                add_link_repository_dependency=get_repository if add_links else None,
                enable_add_link_routes=add_links,
            )
        )
    )
    return TestClient(app), repository, service


def finish_payload(credential_id="ignored"):
    return {"credential": {"id": credential_id, "response": {}}}


def register(client):
    client.post(
        "/auth/register/options",
        json={"email": "owner@example.com", "display_name": "Owner"},
    )
    return client.post("/auth/register/verify", json=finish_payload())


def test_complete_router_happy_path_and_packaged_asset() -> None:
    client, repository, _ = build_client()

    asset = client.get("/auth/assets/fastpasskey.js")
    assert asset.status_code == 200
    assert "initFastPasskey" in asset.text
    styles = client.get("/auth/assets/fastpasskey.css")
    assert styles.status_code == 200
    assert "[hidden]" in styles.text

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
    client, repository, _ = build_client()
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


def test_add_link_routes_are_absent_unless_explicitly_enabled() -> None:
    client, _, _ = build_client(add_links=False)
    assert client.post("/auth/passkey-add/valid/options").status_code == 404
    assert client.post("/auth/passkey-add/valid/verify", json=finish_payload()).status_code == 404


def test_registration_rejects_configuration_verification_and_repository_conflicts() -> None:
    client, repository, service = build_client()
    service.begin_registration_error = PasskeyConfigurationError("bad registration config")
    response = client.post(
        "/auth/register/options",
        json={"email": "owner@example.com", "display_name": "Owner"},
    )
    assert response.status_code == 400
    assert response.json()["detail"] == "bad registration config"
    service.begin_registration_error = None

    assert register(client).status_code == 200
    client.post(
        "/auth/register/options",
        json={"email": "owner@example.com", "display_name": "Owner"},
    )
    assert client.post("/auth/register/verify", json=finish_payload()).status_code == 400

    repository.user = None
    client.post(
        "/auth/register/options",
        json={"email": "owner@example.com", "display_name": "Owner"},
    )
    service.verify_registration_error = ValueError("bad attestation")
    assert client.post("/auth/register/verify", json=finish_payload()).status_code == 400
    service.verify_registration_error = None

    service.credential_id = b"duplicate"
    repository.duplicate_credential_ids.add(bytes_to_base64url(b"duplicate"))
    client.post(
        "/auth/register/options",
        json={"email": "owner@example.com", "display_name": "Owner"},
    )
    assert client.post("/auth/register/verify", json=finish_payload()).status_code == 400
    repository.duplicate_credential_ids.clear()

    repository.registration_conflict = True
    client.post(
        "/auth/register/options",
        json={"email": "owner@example.com", "display_name": "Owner"},
    )
    assert client.post("/auth/register/verify", json=finish_payload()).status_code == 400


def test_login_rejects_configuration_payload_owner_and_verification_errors() -> None:
    client, repository, service = build_client()
    assert register(client).status_code == 200
    passkey = repository.passkeys[0]

    service.begin_authentication_error = PasskeyConfigurationError("bad authentication config")
    response = client.post("/auth/login/options", json={})
    assert response.status_code == 400
    assert response.json()["detail"] == "bad authentication config"
    service.begin_authentication_error = None

    client.post("/auth/login/options", json={})
    assert client.post("/auth/login/verify", json={"credential": {}}).status_code == 400

    passkey.user = None
    client.post("/auth/login/options", json={})
    assert (
        client.post("/auth/login/verify", json=finish_payload(passkey.credential_id)).status_code
        == 404
    )
    passkey.user = repository.user

    service.verify_authentication_error = ValueError("bad assertion")
    client.post("/auth/login/options", json={})
    assert (
        client.post("/auth/login/verify", json=finish_payload(passkey.credential_id)).status_code
        == 401
    )


def test_authenticated_routes_reject_missing_users_names_and_duplicate_credentials() -> None:
    client, repository, service = build_client()
    assert register(client).status_code == 200
    repository.missing_user_by_id = True
    assert client.get("/auth/passkeys").status_code == 404
    repository.missing_user_by_id = False

    missing_id = uuid4()
    assert (
        client.post(
            f"/auth/passkeys/{missing_id}/rename/options", json={"name": "Missing"}
        ).status_code
        == 404
    )
    assert client.post(f"/auth/passkeys/{missing_id}/delete/options").status_code == 404
    assert (
        client.post(f"/auth/passkeys/{repository.passkeys[0].id}/delete/options").status_code == 400
    )

    service.begin_registration_error = PasskeyConfigurationError("bad user registration")
    assert client.post("/auth/settings/passkey/options").status_code == 400
    service.begin_registration_error = None

    client.post("/auth/settings/passkey/options")
    service.verify_registration_error = ValueError("bad replacement")
    assert client.post("/auth/settings/passkey/verify", json=finish_payload()).status_code == 400
    service.verify_registration_error = None

    service.credential_id = b"duplicate"
    repository.duplicate_credential_ids.add(bytes_to_base64url(b"duplicate"))
    client.post("/auth/settings/passkey/options")
    assert client.post("/auth/settings/passkey/verify", json=finish_payload()).status_code == 400

    repository.duplicate_credential_ids.clear()
    client.post("/auth/passkeys/register/options", json={"name": "Laptop"})
    service.verify_registration_error = ValueError("bad added key")
    assert client.post("/auth/passkeys/register/verify", json=finish_payload()).status_code == 400
    service.verify_registration_error = None

    repository.duplicate_credential_ids.add(bytes_to_base64url(b"duplicate"))
    client.post("/auth/passkeys/register/options", json={"name": "Laptop"})
    assert client.post("/auth/passkeys/register/verify", json=finish_payload()).status_code == 400


def test_add_link_rejects_stale_failed_duplicate_and_consumed_links() -> None:
    client, repository, service = build_client()
    assert register(client).status_code == 200

    client.post("/auth/passkey-add/valid/options")
    repository.link_active = False
    assert client.post("/auth/passkey-add/valid/verify", json=finish_payload()).status_code == 404
    repository.link_active = True

    client.post("/auth/passkey-add/valid/options")
    repository.user.id = uuid4()
    assert client.post("/auth/passkey-add/valid/verify", json=finish_payload()).status_code == 404

    client.post("/auth/passkey-add/valid/options")
    service.verify_registration_error = ValueError("bad link key")
    assert client.post("/auth/passkey-add/valid/verify", json=finish_payload()).status_code == 400
    service.verify_registration_error = None

    service.credential_id = b"duplicate"
    repository.duplicate_credential_ids.add(bytes_to_base64url(b"duplicate"))
    client.post("/auth/passkey-add/valid/options")
    assert client.post("/auth/passkey-add/valid/verify", json=finish_payload()).status_code == 400
    repository.duplicate_credential_ids.clear()

    repository.complete_link_none = True
    client.post("/auth/passkey-add/valid/options")
    assert client.post("/auth/passkey-add/valid/verify", json=finish_payload()).status_code == 404


def test_rename_and_delete_reject_stale_or_unverified_credentials() -> None:
    client, repository, service = build_client()
    assert register(client).status_code == 200
    client.post("/auth/passkeys/register/options", json={"name": "Laptop"})
    assert client.post("/auth/passkeys/register/verify", json=finish_payload()).status_code == 200
    first, second = repository.passkeys

    service.begin_authentication_error = PasskeyConfigurationError("bad rename config")
    assert (
        client.post(f"/auth/passkeys/{first.id}/rename/options", json={"name": "Phone"}).status_code
        == 400
    )
    service.begin_authentication_error = None

    client.post(f"/auth/passkeys/{first.id}/rename/options", json={"name": "Phone"})
    assert (
        client.post(
            f"/auth/passkeys/{second.id}/rename/verify",
            json=finish_payload(second.credential_id),
        ).status_code
        == 400
    )

    client.post(f"/auth/passkeys/{first.id}/rename/options", json={"name": "Phone"})
    assert (
        client.post(
            f"/auth/passkeys/{first.id}/rename/verify",
            json=finish_payload(second.credential_id),
        ).status_code
        == 400
    )

    service.verify_authentication_error = ValueError("bad rename assertion")
    client.post(f"/auth/passkeys/{first.id}/rename/options", json={"name": "Phone"})
    assert (
        client.post(
            f"/auth/passkeys/{first.id}/rename/verify",
            json=finish_payload(first.credential_id),
        ).status_code
        == 401
    )
    service.verify_authentication_error = None

    client.post(f"/auth/passkeys/{first.id}/delete/options")
    repository.passkeys.remove(second)
    assert (
        client.post(
            f"/auth/passkeys/{first.id}/delete/verify",
            json=finish_payload(second.credential_id),
        ).status_code
        == 400
    )
    repository.passkeys.append(second)

    client.post(f"/auth/passkeys/{first.id}/delete/options")
    assert (
        client.post(
            f"/auth/passkeys/{first.id}/delete/verify",
            json=finish_payload(first.credential_id),
        ).status_code
        == 400
    )

    service.verify_authentication_error = ValueError("bad delete assertion")
    client.post(f"/auth/passkeys/{first.id}/delete/options")
    assert (
        client.post(
            f"/auth/passkeys/{first.id}/delete/verify",
            json=finish_payload(second.credential_id),
        ).status_code
        == 401
    )


def test_passkey_output_serializes_naive_and_offset_datetimes_as_utc() -> None:
    output = PasskeyOut.model_validate(
        SimpleNamespace(
            id=uuid4(),
            name="Phone",
            created_at=datetime(2026, 7, 18, 12, 0),
            last_used_at=datetime(2026, 7, 18, 14, 0, tzinfo=timezone(timedelta(hours=2))),
        )
    )
    assert output.model_dump(mode="json")["created_at"] == "2026-07-18T12:00:00Z"
    assert output.model_dump(mode="json")["last_used_at"] == "2026-07-18T12:00:00Z"


def test_template_loader_preserves_application_overrides() -> None:
    environment = Environment(loader=DictLoader({"fastpasskey/login.html": "override"}))
    install_fastpasskey_templates(environment)
    assert environment.get_template("fastpasskey/login.html").render() == "override"
    source, _, _ = environment.loader.get_source(environment, "fastpasskey/management.html")
    assert "passkey_management" in source

    empty_environment = Environment(loader=None)
    install_fastpasskey_templates(empty_environment)
    assert empty_environment.get_template("fastpasskey/add_link.html") is not None
    empty_environment.globals["t"] = lambda key, **_: key
    custom_login = empty_environment.from_string(
        '{% from "fastpasskey/login.html" import passkey_login with context %}'
        '{{ passkey_login("/home", "/features") }}'
    ).render()
    assert 'data-next-url="/home"' in custom_login
    assert 'href="/features"' in custom_login
    login_without_capabilities = empty_environment.from_string(
        '{% from "fastpasskey/login.html" import passkey_login with context %}'
        "{{ passkey_login(capabilities_url=none) }}"
    ).render()
    assert "auth.login.capabilities_link" not in login_without_capabilities
