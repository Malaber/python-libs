import json
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest
from webauthn.helpers import bytes_to_base64url

from fastpasskey import (
    FastPasskey,
    PasskeyConfigurationError,
    PasskeyNameError,
    PasskeyPayloadError,
    PasskeyStateError,
    PasskeyUser,
    ceremony_state_is_valid,
    credential_descriptor,
    credential_id_from_payload,
    default_passkey_name,
    expected_origins,
    new_ceremony_state,
    validate_passkey_name,
)


NOW = datetime(2026, 7, 18, 12, 0, tzinfo=UTC)


def options_serializer(options) -> str:
    return json.dumps({"challenge": bytes_to_base64url(options.challenge)})


def make_server(**overrides) -> FastPasskey:
    arguments = {
        "rp_name": "Example App",
        "flow_ttl": timedelta(minutes=5),
        "now": lambda: NOW,
        "options_serializer": options_serializer,
    }
    arguments.update(overrides)
    return FastPasskey(**arguments)


def test_state_helpers_validate_timezone_age_and_shape() -> None:
    state = new_ceremony_state(now=NOW, challenge="abc")
    assert state == {"challenge": "abc", "issued_at": "2026-07-18T12:00:00+00:00"}
    assert ceremony_state_is_valid(state, ttl=timedelta(minutes=5), now=NOW)
    assert (
        ceremony_state_is_valid(
            state,
            ttl=timedelta(minutes=5),
            now=NOW + timedelta(minutes=5),
        )
        is False
    )
    assert (
        ceremony_state_is_valid(
            state,
            ttl=timedelta(minutes=5),
            now=NOW - timedelta(seconds=1),
        )
        is False
    )
    assert ceremony_state_is_valid(None, ttl=timedelta(minutes=5), now=NOW) is False
    assert ceremony_state_is_valid([], ttl=timedelta(minutes=5), now=NOW) is False
    assert ceremony_state_is_valid({}, ttl=timedelta(minutes=5), now=NOW) is False
    assert ceremony_state_is_valid({"issued_at": 1}, ttl=timedelta(minutes=5), now=NOW) is False
    assert ceremony_state_is_valid({"issued_at": "bad"}, ttl=timedelta(minutes=5), now=NOW) is False
    assert (
        ceremony_state_is_valid(
            {"issued_at": "2026-07-18T12:00:00"},
            ttl=timedelta(minutes=5),
            now=NOW,
        )
        is False
    )
    with pytest.raises(PasskeyStateError, match="timezone"):
        new_ceremony_state(now=datetime(2026, 7, 18, 12, 0))


def test_payload_name_and_descriptor_helpers() -> None:
    credential_id = bytes_to_base64url(b"credential")
    assert credential_id_from_payload({"id": credential_id}) == credential_id
    descriptor = credential_descriptor(credential_id)
    assert descriptor.id == b"credential"
    for invalid in ({}, {"id": ""}, {"id": 123}):
        with pytest.raises(PasskeyPayloadError, match="Credential id"):
            credential_id_from_payload(invalid)
    assert validate_passkey_name(" Laptop ") == "Laptop"
    assert validate_passkey_name("ab", max_length=2) == "ab"
    with pytest.raises(PasskeyNameError, match="required"):
        validate_passkey_name("  ")
    with pytest.raises(PasskeyNameError, match="2 characters"):
        validate_passkey_name("abc", max_length=2)
    assert default_passkey_name(0) == "Passkey 1"
    assert default_passkey_name(2) == "Passkey 3"
    with pytest.raises(PasskeyNameError, match="negative"):
        default_passkey_name(-1)


def test_expected_origins_filters_and_deduplicates() -> None:
    assert expected_origins({}) == []
    assert expected_origins({"origin": 1, "rp_id": []}) == []
    assert expected_origins({"origin": "http://localhost", "rp_id": "localhost"}) == [
        "http://localhost",
        "https://localhost",
    ]
    assert expected_origins({"origin": "https://example.com", "rp_id": "example.com"}) == [
        "https://example.com"
    ]


def test_constructor_and_context_validation() -> None:
    with pytest.raises(PasskeyConfigurationError, match="name"):
        FastPasskey(rp_name=" ")
    with pytest.raises(PasskeyConfigurationError, match="TTL"):
        FastPasskey(rp_name="App", flow_ttl=timedelta(0))

    dynamic = make_server()
    assert dynamic.resolve_context(
        request_host="localhost", request_base_url="http://localhost:8000/"
    ) == ("localhost", "http://localhost:8000")
    configured = make_server(origin="https://app.example.com/", rp_id=None)
    assert configured.resolve_context(request_host="ignored", request_base_url="ignored") == (
        "app.example.com",
        "https://app.example.com",
    )
    explicit = make_server(rp_id="login.example.com", origin="https://app.example.com/")
    assert explicit.resolve_context(request_host=None, request_base_url="") == (
        "login.example.com",
        "https://app.example.com",
    )
    with pytest.raises(PasskeyConfigurationError, match="host"):
        dynamic.resolve_context(request_host=None, request_base_url="http://localhost")
    with pytest.raises(PasskeyConfigurationError, match="base URL"):
        make_server(rp_id="example.com").resolve_context(request_host=None, request_base_url="")


def test_begin_registration_builds_secure_options_and_state() -> None:
    captured = {}

    def generate(**arguments):
        captured.update(arguments)
        return SimpleNamespace(challenge=b"register")

    server = make_server(registration_generator=generate)
    existing_id = bytes_to_base64url(b"existing")
    start = server.begin_registration(
        user=PasskeyUser(id=b"user-id", name="a@example.com", display_name="A"),
        request_host="localhost",
        request_base_url="http://localhost:8000/",
        exclude_credential_ids=[existing_id],
        state_payload={"user_id": "123"},
    )
    assert start.options == {"challenge": bytes_to_base64url(b"register")}
    assert start.state == {
        "challenge": bytes_to_base64url(b"register"),
        "origin": "http://localhost:8000",
        "rp_id": "localhost",
        "user_id": "123",
        "issued_at": "2026-07-18T12:00:00+00:00",
    }
    assert captured["rp_id"] == "localhost"
    assert captured["rp_name"] == "Example App"
    assert captured["user_name"] == "a@example.com"
    assert captured["user_id"] == b"user-id"
    assert captured["user_display_name"] == "A"
    assert captured["exclude_credentials"][0].id == b"existing"
    selection = captured["authenticator_selection"]
    assert selection.resident_key.value == "required"
    assert selection.user_verification.value == "required"


def test_begin_authentication_supports_discoverable_and_allowed_credentials() -> None:
    calls = []

    def generate(**arguments):
        calls.append(arguments)
        return SimpleNamespace(challenge=b"authenticate")

    server = make_server(authentication_generator=generate)
    discoverable = server.begin_authentication(
        request_host="localhost",
        request_base_url="http://localhost:8000",
    )
    assert "allow_credentials" not in calls[0]
    assert discoverable.state["challenge"] == bytes_to_base64url(b"authenticate")

    credential_id = bytes_to_base64url(b"allowed")
    server.begin_authentication(
        request_host="localhost",
        request_base_url="http://localhost:8000",
        allow_credential_ids=[credential_id],
        state_payload={"passkey_id": "123"},
    )
    assert calls[1]["allow_credentials"][0].id == b"allowed"
    assert calls[1]["user_verification"].value == "required"


def test_start_rejects_bad_serializer_and_missing_challenge() -> None:
    server = make_server(
        authentication_generator=lambda **_: SimpleNamespace(challenge=b"x"),
        options_serializer=lambda _: "[]",
    )
    with pytest.raises(PasskeyStateError, match="object"):
        server.begin_authentication(request_host="localhost", request_base_url="http://localhost")

    server = make_server(
        authentication_generator=lambda **_: SimpleNamespace(challenge="x"),
        options_serializer=lambda _: "{}",
    )
    with pytest.raises(PasskeyStateError, match="byte challenge"):
        server.begin_authentication(request_host="localhost", request_base_url="http://localhost")


def valid_state(**overrides) -> dict[str, object]:
    state = {
        "challenge": bytes_to_base64url(b"challenge"),
        "origin": "http://localhost:8000",
        "rp_id": "localhost",
        "issued_at": NOW.isoformat(),
    }
    state.update(overrides)
    return state


def test_registration_verification_retries_origins() -> None:
    calls = []
    result = object()

    def verify(**arguments):
        calls.append(arguments)
        if arguments["expected_origin"] == "http://localhost:8000":
            raise ValueError("wrong origin")
        return result

    server = make_server(registration_verifier=verify)
    assert server.verify_registration(credential={"id": "id"}, state=valid_state()) is result
    assert [call["expected_origin"] for call in calls] == [
        "http://localhost:8000",
        "https://localhost",
    ]
    assert calls[-1]["expected_challenge"] == b"challenge"
    assert calls[-1]["expected_rp_id"] == "localhost"
    assert calls[-1]["require_user_verification"] is True


def test_authentication_verification_passes_credential_state() -> None:
    captured = {}
    result = object()

    def verify(**arguments):
        captured.update(arguments)
        return result

    server = make_server(authentication_verifier=verify)
    assert (
        server.verify_authentication(
            credential={"id": "id"},
            state=valid_state(origin="https://localhost"),
            credential_public_key=b"public",
            credential_current_sign_count=3,
        )
        is result
    )
    assert captured["credential_public_key"] == b"public"
    assert captured["credential_current_sign_count"] == 3
    assert captured["expected_origin"] == "https://localhost"


def test_verification_rejects_expired_or_incomplete_state() -> None:
    server = make_server()
    expired = valid_state(issued_at=(NOW - timedelta(minutes=5)).isoformat())
    with pytest.raises(PasskeyStateError, match="expired"):
        server.verify_registration(credential={}, state=expired)

    for state, message in (
        (valid_state(challenge=""), "challenge"),
        (valid_state(rp_id=""), "relying-party"),
        (valid_state(origin="", rp_id=""), "relying-party"),
    ):
        with pytest.raises(PasskeyStateError, match=message):
            server.verify_registration(credential={}, state=state)


def test_verification_surfaces_last_failure_and_empty_origin_guard() -> None:
    failure = RuntimeError("verification failed")

    def verify(**_):
        raise failure

    server = make_server(registration_verifier=verify)
    with pytest.raises(RuntimeError, match="verification failed"):
        server.verify_registration(credential={}, state=valid_state())
    with pytest.raises(PasskeyStateError, match="origin"):
        server._verify_across_origins(verify, origins=[])
