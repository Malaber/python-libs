from __future__ import annotations

import json
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import urlparse

from webauthn import (
    generate_authentication_options,
    generate_registration_options,
    options_to_json,
    verify_authentication_response,
    verify_registration_response,
)
from webauthn.helpers import base64url_to_bytes, bytes_to_base64url
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    PublicKeyCredentialDescriptor,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)


class PasskeyError(ValueError):
    """Base error raised by FastPassKey."""


class PasskeyConfigurationError(PasskeyError):
    """Relying-party configuration or request context is incomplete."""


class PasskeyStateError(PasskeyError):
    """WebAuthn ceremony state is missing, malformed, or expired."""


class PasskeyPayloadError(PasskeyError):
    """WebAuthn credential payload is malformed."""


class PasskeyNameError(PasskeyError):
    """Human-readable passkey name is invalid."""


@dataclass(frozen=True, slots=True)
class PasskeyUser:
    """User fields required to generate WebAuthn registration options."""

    id: bytes
    name: str
    display_name: str


@dataclass(frozen=True, slots=True)
class CeremonyStart:
    """JSON-safe browser options plus server-side state for one ceremony."""

    options: dict[str, Any]
    state: dict[str, object]


def new_ceremony_state(*, now: datetime | None = None, **payload: object) -> dict[str, object]:
    issued_at = now or datetime.now(UTC)
    if issued_at.tzinfo is None:
        raise PasskeyStateError("Ceremony issue time must include a timezone")
    return {**payload, "issued_at": issued_at.astimezone(UTC).isoformat()}


def ceremony_state_is_valid(
    state: Mapping[str, object] | None,
    *,
    ttl: timedelta,
    now: datetime | None = None,
) -> bool:
    if state is None or not isinstance(state, Mapping):
        return False
    issued_at_raw = state.get("issued_at")
    if not isinstance(issued_at_raw, str):
        return False
    try:
        issued_at = datetime.fromisoformat(issued_at_raw)
    except ValueError:
        return False
    if issued_at.tzinfo is None:
        return False
    current_time = (now or datetime.now(UTC)).astimezone(UTC)
    age = current_time - issued_at.astimezone(UTC)
    return timedelta(0) <= age < ttl


def expected_origins(state: Mapping[str, object]) -> list[str]:
    origin = state.get("origin")
    rp_id = state.get("rp_id")
    origins: list[str] = []
    if isinstance(origin, str) and origin:
        origins.append(origin)
    if isinstance(rp_id, str) and rp_id:
        rp_origin = f"https://{rp_id}"
        if rp_origin not in origins:
            origins.append(rp_origin)
    return origins


def credential_id_from_payload(credential: Mapping[str, object]) -> str:
    credential_id = credential.get("id")
    if not isinstance(credential_id, str) or not credential_id:
        raise PasskeyPayloadError("Credential id is required")
    return credential_id


def credential_descriptor(credential_id: str) -> PublicKeyCredentialDescriptor:
    return PublicKeyCredentialDescriptor(id=base64url_to_bytes(credential_id))


def validate_passkey_name(raw_name: str, *, max_length: int = 120) -> str:
    name = raw_name.strip()
    if not name:
        raise PasskeyNameError("Passkey name is required")
    if len(name) > max_length:
        raise PasskeyNameError(f"Passkey name must be {max_length} characters or fewer")
    return name


def default_passkey_name(existing_count: int) -> str:
    if existing_count < 0:
        raise PasskeyNameError("Existing passkey count cannot be negative")
    return f"Passkey {existing_count + 1}"


class FastPasskey:
    """Generate and verify reusable WebAuthn passkey ceremonies."""

    def __init__(
        self,
        *,
        rp_name: str,
        rp_id: str | None = None,
        origin: str | None = None,
        flow_ttl: timedelta = timedelta(minutes=5),
        now: Callable[[], datetime] | None = None,
        registration_generator: Callable[..., Any] = generate_registration_options,
        authentication_generator: Callable[..., Any] = generate_authentication_options,
        registration_verifier: Callable[..., Any] = verify_registration_response,
        authentication_verifier: Callable[..., Any] = verify_authentication_response,
        options_serializer: Callable[[Any], str] = options_to_json,
    ) -> None:
        if not rp_name.strip():
            raise PasskeyConfigurationError("Relying-party name is required")
        if flow_ttl <= timedelta(0):
            raise PasskeyConfigurationError("Ceremony TTL must be positive")
        self.rp_name = rp_name
        self.rp_id = rp_id
        self.origin = origin.rstrip("/") if origin else None
        self.flow_ttl = flow_ttl
        self._now = now or (lambda: datetime.now(UTC))
        self._registration_generator = registration_generator
        self._authentication_generator = authentication_generator
        self._registration_verifier = registration_verifier
        self._authentication_verifier = authentication_verifier
        self._options_serializer = options_serializer

    def resolve_context(
        self,
        *,
        request_host: str | None,
        request_base_url: str,
    ) -> tuple[str, str]:
        configured_host = urlparse(self.origin).hostname if self.origin else None
        rp_id = self.rp_id or configured_host or request_host
        if not rp_id:
            raise PasskeyConfigurationError("Request host is required for passkeys")
        origin = self.origin or request_base_url.rstrip("/")
        if not origin:
            raise PasskeyConfigurationError("Request base URL is required for passkeys")
        return rp_id, origin

    def begin_registration(
        self,
        *,
        user: PasskeyUser,
        request_host: str | None,
        request_base_url: str,
        exclude_credential_ids: Iterable[str] = (),
        state_payload: Mapping[str, object] | None = None,
    ) -> CeremonyStart:
        rp_id, origin = self.resolve_context(
            request_host=request_host,
            request_base_url=request_base_url,
        )
        options = self._registration_generator(
            rp_id=rp_id,
            rp_name=self.rp_name,
            user_name=user.name,
            user_id=user.id,
            user_display_name=user.display_name,
            authenticator_selection=AuthenticatorSelectionCriteria(
                resident_key=ResidentKeyRequirement.REQUIRED,
                user_verification=UserVerificationRequirement.REQUIRED,
            ),
            exclude_credentials=[
                credential_descriptor(credential_id) for credential_id in exclude_credential_ids
            ],
        )
        return self._start(options, rp_id=rp_id, origin=origin, payload=state_payload)

    def begin_authentication(
        self,
        *,
        request_host: str | None,
        request_base_url: str,
        allow_credential_ids: Iterable[str] | None = None,
        state_payload: Mapping[str, object] | None = None,
    ) -> CeremonyStart:
        rp_id, origin = self.resolve_context(
            request_host=request_host,
            request_base_url=request_base_url,
        )
        arguments: dict[str, object] = {
            "rp_id": rp_id,
            "user_verification": UserVerificationRequirement.REQUIRED,
        }
        if allow_credential_ids is not None:
            arguments["allow_credentials"] = [
                credential_descriptor(credential_id) for credential_id in allow_credential_ids
            ]
        options = self._authentication_generator(**arguments)
        return self._start(options, rp_id=rp_id, origin=origin, payload=state_payload)

    def state_is_valid(self, state: Mapping[str, object] | None) -> bool:
        return ceremony_state_is_valid(state, ttl=self.flow_ttl, now=self._now())

    def verify_registration(
        self,
        *,
        credential: Mapping[str, object],
        state: Mapping[str, object],
    ) -> Any:
        self._require_valid_state(state)
        common = self._verification_context(state)
        return self._verify_across_origins(
            self._registration_verifier,
            credential=credential,
            expected_challenge=common["challenge"],
            expected_rp_id=common["rp_id"],
            origins=common["origins"],
            require_user_verification=True,
        )

    def verify_authentication(
        self,
        *,
        credential: Mapping[str, object],
        state: Mapping[str, object],
        credential_public_key: bytes,
        credential_current_sign_count: int,
    ) -> Any:
        self._require_valid_state(state)
        common = self._verification_context(state)
        return self._verify_across_origins(
            self._authentication_verifier,
            credential=credential,
            expected_challenge=common["challenge"],
            expected_rp_id=common["rp_id"],
            origins=common["origins"],
            credential_public_key=credential_public_key,
            credential_current_sign_count=credential_current_sign_count,
            require_user_verification=True,
        )

    def _start(
        self,
        options: Any,
        *,
        rp_id: str,
        origin: str,
        payload: Mapping[str, object] | None,
    ) -> CeremonyStart:
        serialized = json.loads(self._options_serializer(options))
        if not isinstance(serialized, dict):
            raise PasskeyStateError("WebAuthn options must serialize to an object")
        challenge = getattr(options, "challenge", None)
        if not isinstance(challenge, bytes):
            raise PasskeyStateError("WebAuthn options must include a byte challenge")
        state = new_ceremony_state(
            now=self._now(),
            challenge=bytes_to_base64url(challenge),
            origin=origin,
            rp_id=rp_id,
            **dict(payload or {}),
        )
        return CeremonyStart(options=serialized, state=state)

    def _require_valid_state(self, state: Mapping[str, object]) -> None:
        if not self.state_is_valid(state):
            raise PasskeyStateError("Passkey ceremony state expired")

    @staticmethod
    def _verification_context(state: Mapping[str, object]) -> dict[str, object]:
        challenge = state.get("challenge")
        rp_id = state.get("rp_id")
        if not isinstance(challenge, str) or not challenge:
            raise PasskeyStateError("Passkey ceremony challenge is required")
        if not isinstance(rp_id, str) or not rp_id:
            raise PasskeyStateError("Passkey ceremony relying-party ID is required")
        origins = expected_origins(state)
        return {
            "challenge": base64url_to_bytes(challenge),
            "rp_id": rp_id,
            "origins": origins,
        }

    @staticmethod
    def _verify_across_origins(
        verifier: Callable[..., Any],
        *,
        origins: Iterable[str],
        **arguments: object,
    ) -> Any:
        last_error: Exception | None = None
        for expected_origin in origins:
            try:
                return verifier(expected_origin=expected_origin, **arguments)
            except Exception as exc:
                last_error = exc
        if last_error is None:
            raise PasskeyStateError("Passkey ceremony origin is required")
        raise last_error
