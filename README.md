# Hermes Secure Handoff Telegram

Hermes Secure Handoff Telegram is a standalone Hermes plugin and static Telegram Mini App for owner-scoped handoffs into a dedicated local browser profile.

It supports staged authentication, one-time codes, encrypted general-form entry, registrant/billing fields, and supported payment fields. Generic forms and ordinary checkout are fill-only: recognizing a field never authorizes a submission. An explicitly armed, source-bound observed checkout can expose a separate **Complete purchase** approval for one guarded browser action.

The plugin stays provider-neutral. It does not hardcode provider URLs, account names, or site-specific selectors.

## What ships

- `plugin/` — Hermes plugin, browser controller, semantic field adapters, connection check, and CLI.
- `web/` — static Telegram Mini App with WebCrypto encryption and native autofill metadata.
- `plugin.yaml` — directory-install manifest.
- `pyproject.toml` — Python package and Hermes entry point.
- `tests/` — Python, browser, cryptographic, frontend, and synthetic checkout coverage.

## Architecture

```text
Telegram bot + Hermes gateway
        │
        ├── short-lived public Mini App manifest
        │       └── v3 typed auth/form/checkout fields
        │
        └── Hermes plugin ── loopback CDP ── dedicated Chrome profile
                                      ~/.hermes/chrome-debug
```

- The Telegram bot token stays in Hermes's native gateway setup.
- The Mini App is static. It has no backend, database, cookies, analytics, or bot token.
- The page encrypts submitted values locally with AES-GCM and RSA-OAEP before calling Telegram `sendData()`.
- Hermes decrypts only at the browser mutation boundary and never writes values to model prompts, logs, receipts, screenshots, or chat.
- Each handoff is bound to one owner ID, private chat/thread identity, browser page, document generation, origin, and one-time request key.
- Browser action targets are revalidated immediately before mutation.

## Local candidate: agent-composed entry

The current source adds `attach` with `mode: "compose"`, opaque field discovery,
`present_composition`, and component status/cancellation. The agent chooses
optional fields, visual order, finite group headings and stack/section layouts;
required fields cannot be omitted. Inputs start empty. Supported native payment
controls may live in vetted HTTPS child frames; the agent receives only bounded
frame ordinals, never frame URLs or selectors. This is encrypted **ENTRY only**,
not completed remote purchase support. See the exact
[composition API and limits](docs/composition.md).

A separate local observed-action candidate now integrates real public-fact
registries, `inspect_purchase` / `compose_purchase`, a fresh Mini App approval,
and an encrypted one-shot guarded action. A private acquisition bridge now joins
explicitly selected source refs to composed ENTRY; ordinary composition is still
fill-only. The agent can propose an exact opaque catalog source via
`discover_catalog_sources` / `request_source_approval`; the owner must review the
original browser page and explicitly allow it through the encrypted Mini App.
This source-selection lease is not privacy certification or purchase authority.
Without the owner grant, source discovery fails closed. See the exact
[acquisition API and supported shapes](docs/purchase-acquisition.md).
The legacy certified-summary registry remains empty. See [observed-action scope and prerequisites](docs/observed-purchase-status.md)
for the exact API, synthetic evidence, public-metadata boundary and remaining gaps.

## Supported handoff modes

### General forms

Use `mode: "form"` with `attach` or `present` for explicit encrypted fill-only entry. This is the safe choice for registration, settings, surveys, and forms whose eventual submission has consequences. The Mini App sends strings for typed text, textarea, checkbox, radio-as-select, native select, and supported date/time/URL/color/range controls. Native selects with more than 64 enabled choices use a bounded exact-label text entry mode; the option values remain private in the browser and are never put in the Telegram launch URL. `filled` means the fields were applied, not that the form was submitted.

The plugin does not explicitly click Submit, Save, Delete, Pay, or press Enter in this mode. The destination website can still react to ordinary input/change events; fill-only is not a sandbox against a malicious or auto-submitting site. Unsupported, stale, or ambiguous controls fail closed rather than falling back to plaintext browser tools.

See [the compatibility matrix](docs/compatibility.md) for supported control shapes and limits. This is not a claim that every web form or custom widget works.

### Authentication

The controller can publish a bounded stage containing typed `identifier`, `password`, `one_time_code`, email, phone, and other supported controls. It rebinds after React-style rerenders and mints a fresh request for the next stage.

### Checkout

The controller recognizes a generic checkout shape from visible semantic fields and a single exact payment action such as `Buy`, `Pay`, `Purchase`, `Place order`, or `Complete purchase`. Version 1.1 supports visible native controls in the exact checkout scope, including controls in HTTPS child frames. Each frame is privately pinned by object identity, origin, document and iframe-host chain; the Mini App sees only generic kinds, required status, ordinal and a bounded frame ordinal.

The frame path does not support HTTP frames, visible custom widgets, shadow controls, browser dialogs, or provider challenges. Non-rendered helper frames are ignored as inactive; if one becomes rendered inside the bound scope, the mutation epoch invalidates the lease. Browsers provide no truly atomic JavaScript transaction spanning out-of-process cross-origin frames, so the final parent action uses a conservative two-phase lease: every frame is revalidated immediately before the parent click, the capability is consumed before dispatch, mutations invalidate it, and ambiguous dispatch is never retried. This is not proof of universal checkout compatibility or payment success; live provider/3DS behavior remains a separate gate.

The flow is deliberately two-step:

1. The Mini App submits the typed checkout fields through an encrypted `mode: checkout` or composed-entry request.
2. Hermes fills the bound browser controls but does not click the purchase action.
3. For ordinary checkout, Hermes scrubs the request/key/bindings and returns `human_action_required`; the user completes the transaction in the provider page.
4. For an explicitly source-authorized observed checkout, the agent selects only runtime-issued facts and the Mini App publishes a fresh review. The user's separate **Complete purchase** tap authorizes one exact guarded browser action.

Legacy `payment_confirmation` messages are blocked by the Mini App and cannot execute a purchase in the controller. The observed-action path requires a fresh runtime-bound fact set, explicit source authorization, a separate user-visible review, and an exact encrypted capability—not just an origin and a boolean.

A submitted action is not proof that a provider accepted payment. CAPTCHA, 3DS, MFA, passkeys, provider redirects, and final purchase results remain user/provider-owned checkpoints.

## iOS keyboard and Apple Passwords

The Mini App uses platform-standard metadata:

- authentication identifiers: `name="username"`, `autocomplete="username"`;
- login secrets: `name="password"`, `autocomplete="current-password"`;
- one-time codes: `autocomplete="one-time-code"`, numeric input mode;
- payment fields: `autocomplete="cc-number"`, `cc-exp`, and `cc-csc`.

This lets Telegram's iOS WebView show the keyboard, OTP suggestion, and Passwords UI when the OS permits it. Apple still scopes saved credentials and payment autofill to the Mini App's own origin. No shared Mini App can make Apple treat an arbitrary target-site origin as the current origin. Device, Telegram version, WebView, and password-manager settings control the final suggestion behavior.

The target origin is shown as metadata for the user to review, but it is not used to bypass Apple origin matching.

## Install

### Prerequisites

1. Install Hermes Agent and enable its Telegram gateway.
2. Install Chrome, Chromium, Brave, or Edge.
3. Run a dedicated browser with a loopback DevTools HTTP endpoint.
4. Use a private Telegram chat and one numeric owner ID per Hermes/browser profile.

### Hermes plugin installer

```bash
hermes plugins install jmogainz/hermes-secure-handoff-telegram --enable
telegram-secure-handoff setup --user-id 123456789
```

For a reviewed immutable source, pin the repository commit:

```bash
hermes plugins install jmogainz/hermes-secure-handoff-telegram \
  --ref <40-character-commit-sha> --enable
```

### Python package

Build and install the wheel from reviewed source (the commands below do not assume a PyPI release exists):

```bash
python -m build --wheel
python -m pip install dist/hermes_telegram_secure_handoff-1.1.0-py3-none-any.whl
hermes plugins enable telegram-secure-handoff
```

Install declared dependencies into the same Python environment as Hermes when the doctor reports one missing:

```bash
python -m pip install \
  'cryptography>=42,<48' \
  'playwright>=1.58,<2' \
  'python-telegram-bot>=21,<23'
```

## Configure

The setup command uses the official shared Mini App by default:

```bash
telegram-secure-handoff setup --user-id 123456789
```

Current shared deployment name:

```text
https://hermes-secure-handoff-telegram.vercel.app
```

The planned custom domain is:

```text
https://hermessecurehandoff.xyz
```

Self-hosting remains available:

```bash
telegram-secure-handoff setup \
  --mini-app-url https://handoff.example \
  --user-id 123456789
```

The wizard writes and reads back namespaced settings under:

```text
plugins.entries.telegram-secure-handoff.settings
```

It never accepts a bot token, password, payment detail, OTP, or browser credential. Hermes's native gateway setup owns bot-token configuration.

## Dedicated browser

Chrome 136+ requires a non-default user-data directory for remote debugging:

```bash
# macOS
"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" \
  --remote-debugging-port=9222 \
  --user-data-dir="$HOME/.hermes/chrome-debug" \
  --no-first-run --no-default-browser-check

# Linux
google-chrome \
  --remote-debugging-port=9222 \
  --user-data-dir="$HOME/.hermes/chrome-debug" \
  --no-first-run --no-default-browser-check
```

The plugin accepts only loopback HTTP CDP URLs such as `http://127.0.0.1:9222`. It does not start a second production browser, export cookies, or use the operator's everyday profile.

## Verify

```bash
telegram-secure-handoff doctor
hermes plugins doctor telegram-secure-handoff --ci
```

The controller exposes `telegram_secure_handoff`. `open` starts a fresh navigation; never use it to recover an active form. `attach` binds an existing exact HTTPS origin and, when multiple tabs match, an opaque Chrome target ID in `ref`. `present` republishes the attached stage without navigation. Pass `mode: "form"` for encrypted fill-only handling. `read` returns safe status rather than raw page text; `close` releases the handoff, preserving browser tabs. Legacy direct `type`/`click` actions are not a bypass around encrypted entry or authorization.

`/handoffcheck` tests Telegram transport with a fixed non-secret marker. `/handoffcancel` cancels an owner-scoped active handoff or connection test. A status such as `session_missing` is not evidence that a gateway restart is required; attach the intended existing tab first. Installed Python changes require an external gateway reload, whereas a static frontend deployment alone does not.

## Trust boundary

The official Mini App is shared static code. A shared host cannot read the encrypted payload after `sendData()`, but its JavaScript can read values before encryption. Use a self-hosted deployment if you do not want to trust the official host publisher, especially for card fields.

The secure handoff is transport encryption, not a guarantee that the destination site is honest. Review the target origin and the browser page before entering data or approving any transaction. Keep the Telegram owner allowlist narrow and the Chrome profile dedicated.

## Security exclusions

This project does not provide:

- bot-token collection in the Mini App;
- plaintext values in model context, logs, receipts, screenshots, fixtures, or chat;
- cookie or storage export between browser profiles;
- CAPTCHA, 3DS, MFA, passkey, or provider-security automation;
- arbitrary cross-origin field binding without HTTPS/frame/scope checks;
- automatic claim of a successful purchase from a browser click alone;
- a public listener on the operator's Mac;
- a second Telegram polling loop.

## Development and release checks

```bash
python -m pip install -e '.[dev]'
python -m pytest tests/ -q -o 'addopts='
npm ci
PLAYWRIGHT_CHANNEL=chromium npm test
npm run test:qa-real-sdk
python -m build --sdist --wheel
python scripts/release_check.py
hermes plugins doctor . --ci
```

Before publishing:

- run the full Python suite and frontend suite;
- verify the real Telegram SDK/WebCrypto path;
- build exactly one wheel and source archive;
- inspect archive names for stale identifiers, local Vercel metadata, reports, receipts, and environment files;
- test a clean temporary Hermes home and loopback CDP browser;
- deploy the static frontend and verify HTTPS, CSP, HTML, JavaScript, and no unexpected network/storage behavior;
- update the live Hermes installation only after the release commit and deployment pass.

## License

MIT. See [`LICENSE`](LICENSE).
