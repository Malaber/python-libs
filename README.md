# FastPasskey

Reusable, versioned passkey authentication for FastAPI applications. FastPasskey
ships the complete WebAuthn stack instead of asking each application to copy it:

- registration, discoverable login, add, rename, replace, and safe delete routes;
- one-time add-link support and application session hooks;
- WebAuthn option generation, expiring ceremony state, and multi-origin verification;
- a browser ES module for registration, login, and passkey management;
- default Jinja macros for login, add-link, and management screens;
- Pydantic request/response models and a storage-agnostic repository protocol.

Applications retain their user/passkey database models, access-token policy, and
session implementation behind `PasskeyRepository`. No submodule or copied source
is required.

## Install from GitHub

Pin a release wheel and its SHA-256 digest for reproducible builds:

```toml
dependencies = [
  "fastpasskey @ https://github.com/Malaber/python-libs/releases/download/fastpasskey-v<version>/fastpasskey-<version>-py3-none-any.whl#sha256=<release-sha256>",
]
```

The same GitHub Release includes an installable browser/testing tarball:

```bash
npm install https://github.com/Malaber/python-libs/releases/download/fastpasskey-v<version>/malaber-fastpasskey-<version>.tgz
```

## FastAPI integration

Implement `PasskeyRepository` for your persistence layer, then supply three
dependencies. The repository methods are the only application-specific adapter.

```python
from datetime import timedelta

from fastpasskey import FastPasskey, PasskeyRouterConfig, create_passkey_router


def passkey_service():
    return FastPasskey(
        rp_name="Example App",
        rp_id="example.com",
        origin="https://example.com",
        flow_ttl=timedelta(minutes=5),
    )


app.include_router(
    create_passkey_router(
        PasskeyRouterConfig(
            service_factory=passkey_service,
            repository_dependency=get_passkey_repository,
            current_user_dependency=get_current_user,
        )
    ),
    prefix="/api/v1",
)
```

The router exposes its browser client at
`/api/v1/auth/assets/fastpasskey.js` and minimal structural styles at
`/api/v1/auth/assets/fastpasskey.css`. Connect application translation, locale,
and navigation functions once. Fallback messages interpolate `{name}` and
`{date}` values even when no application translation callback is supplied:

```html
<link rel="stylesheet" href="/api/v1/auth/assets/fastpasskey.css" />
<script type="module">
  import { initFastPasskey } from "/api/v1/auth/assets/fastpasskey.js";
  initFastPasskey({ translate, locale, navigate });
</script>
```

## Overridable templates

Install the package loader after creating `Jinja2Templates`:

```python
from fastpasskey import install_fastpasskey_templates

templates = Jinja2Templates(directory="app/templates")
install_fastpasskey_templates(templates.env)
```

Then use the packaged macros:

```jinja2
{% from "fastpasskey/login.html" import passkey_login with context %}
{{ passkey_login(next_url) }}
```

Application templates have precedence. To customize a fragment, provide a file
with the same path (`fastpasskey/login.html`, `fastpasskey/add_link.html`, or
`fastpasskey/management.html`) in the application template directory.

The login macro accepts both destinations, so consumers do not need a
`/capabilities` route:

```jinja2
{{ passkey_login(next_url="/dashboard", capabilities_url="/features") }}
```

Pass `capabilities_url=none` to omit that link. Consumers may replace the
packaged CSS entirely; if they do, `[hidden] { display: none !important; }` is
the only required global visibility rule. The remaining classes are styling
hooks, not application dependencies.

## Optional add links

Ordinary consumers implement only `PasskeyRepository`; add-link methods live in
the separate `PasskeyAddLinkRepository` protocol. Existing integrations retain
add-link routes by default. Consumers that do not expose them disable the routes
without no-op repository methods:

```python
PasskeyRouterConfig(
    service_factory=passkey_service,
    repository_dependency=get_passkey_repository,
    current_user_dependency=get_current_user,
    enable_add_link_routes=False,
)
```

Applications that issue one-time add links may provide a dedicated dependency:

```python
PasskeyRouterConfig(
    service_factory=passkey_service,
    repository_dependency=get_passkey_repository,
    current_user_dependency=get_current_user,
    add_link_repository_dependency=get_passkey_repository,
)
```

## Playwright fixture

The GitHub browser tarball exports a tested virtual-authenticator fixture. It
owns CDP setup and cleanup, and `replace()` models adding a passkey from a second
authenticator without duplicating that choreography in every consumer:

```javascript
import { test as baseTest } from "playwright/test";
import { withFastPasskeyAuthenticator } from "@malaber/fastpasskey/playwright";

const test = withFastPasskeyAuthenticator(baseTest);

test("adds a second passkey", async ({ page, fastPasskeyAuthenticator }) => {
  await page.goto("/login");
  // Register the first passkey, then simulate a second device.
  await fastPasskeyAuthenticator.replace();
});
```

## Framework-neutral core

`FastPasskey` remains usable without the router when an application needs custom
HTTP flows. It provides relying-party/origin resolution, secure resident-key
options, ceremony state, credential validation, and verification helpers.

## Development

Requires Python 3.11+ and Node 24.

```bash
python -m pip install -e '.[dev]'
python -m invoke install-js
python -m invoke install-browser
python -m invoke verify
```

The Python suite enforces 100% statement and branch coverage over the WebAuthn
core, complete FastAPI router, schemas, assets, and template loader. The Node 24
suite separately enforces 100% statement, branch, function, and line coverage
over the packaged browser module.

The Chromium e2e suite uses a virtual CTAP2 authenticator against a live FastAPI
server on `localhost`. It covers account registration, adding a credential from
a second authenticator, renaming, deletion confirmed by another credential,
discoverable login, and one-time add-link consumption through the real packaged
JavaScript and templates.

Successful pushes to `main` publish only after Python 3.11 and 3.14 unit tests,
Node 24 browser unit tests, and Chromium WebAuthn e2e all pass. CI derives the
next patch version from Git tags, builds the wheel from the tested commit with a
commit-derived build timestamp, writes SHA-256 checksums, creates the version
tag, and publishes the Python wheel plus browser/testing tarball as a GitHub
Release. Releases require no source version edit or local build/tag/release
command.
