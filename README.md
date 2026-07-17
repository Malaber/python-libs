# Python libs

Reusable, independently versioned Python packages maintained by Malaber.

## FastPasskey

`fastpasskey` provides framework-neutral WebAuthn ceremony helpers for passkey
registration, login, and credential management. Applications keep ownership of
their HTTP routes, persistence, and user model while FastPasskey handles:

- relying-party ID and origin resolution;
- secure resident-key registration and authentication options;
- short-lived ceremony state;
- verification against configured and relying-party origins;
- credential descriptors, payload validation, and passkey labels.

### Install from GitHub

Pin a release tag so builds remain reproducible:

```toml
dependencies = [
  "fastpasskey @ git+https://github.com/Malaber/python-libs.git@fastpasskey-v0.1.0",
]
```

### Basic use

```python
from datetime import timedelta

from fastpasskey import FastPasskey, PasskeyUser

passkeys = FastPasskey(
    rp_name="Example App",
    rp_id="example.com",
    origin="https://example.com",
    flow_ttl=timedelta(minutes=5),
)

start = passkeys.begin_registration(
    user=PasskeyUser(
        id=user.id.bytes,
        name=user.email,
        display_name=user.display_name,
    ),
    request_host=request.url.hostname,
    request_base_url=str(request.base_url),
    exclude_credential_ids=(credential.id for credential in user.passkeys),
    state_payload={"user_id": str(user.id)},
)

request.session["passkey_registration"] = start.state
return start.options
```

Complete flows by reading saved state and calling `verify_registration()` or
`verify_authentication()`. Both reject expired state before WebAuthn verification.

FastPasskey deliberately contains no FastAPI or SQLAlchemy dependency. This keeps
it usable in Starlette, Django, Flask, workers, and other Python services.

## Development

Requires Python 3.11 or newer.

```bash
python -m pip install -e '.[dev]'
python -m invoke verify
```

Tests enforce 100% branch coverage.
