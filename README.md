# Hermes Secure Handoff Telegram

Hermes Secure Handoff Telegram is a standalone Hermes plugin and static Telegram Mini App for owner-scoped handoffs into a dedicated local browser profile.

It supports staged authentication, one-time codes, generic checkout forms, registrant and billing fields, card number, expiration, and security-code fields. Checkout uses a second field-free confirmation request before Hermes can activate a bound purchase action.

The plugin stays provider-neutral. It does not contain selectors, URLs, account names, or site-specific adapters.

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
        ├── short-lived encrypted Mini App request
        │       └── v3 typed auth/checkout fields
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

## Supported handoff modes

### Authentication

The controller can publish a bounded stage containing typed `identifier`, `password`, `one_time_code`, email, phone, and other supported controls. It rebinds after React-style rerenders and mints a fresh request for the next stage.

### Checkout

The controller recognizes a generic checkout shape from visible semantic fields and a single exact payment action such as `Buy`, `Pay`, `Purchase`, `Place order`, or `Complete purchase`. It can bind fields in the top-level document and eligible visible payment fields inside HTTPS child frames.

The flow is deliberately two-step:

1. The Mini App submits the typed checkout fields through an encrypted `mode: checkout` request.
2. Hermes fills the bound browser controls but does not click the purchase action.
3. Hermes publishes a fresh `mode: payment_confirmation` request containing no fields and accepts only `{ "confirm": true }`.
4. Hermes revalidates the live checkout and clicks the exact bound action once.

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

```bash
python -m pip install hermes-telegram-secure-handoff==1.0.0
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

The controller exposes the `telegram_secure_handoff` tool with `open`, `attach`, `present`, `read`, `click`, `type`, `wait`, and `close`. `open` starts a fresh navigation. Use `attach` or `present` to republish an already-live password, OTP, CAPTCHA, MFA, provider, or checkout stage without reloading it.

## Trust boundary

The official Mini App is shared static code. A shared host cannot read the encrypted payload after `sendData()`, but its JavaScript can read values before encryption. Use a self-hosted deployment if you do not want to trust the official host publisher, especially for card fields.

The secure handoff is transport encryption, not a guarantee that the destination site is honest. Review the target origin and the browser page before confirming a checkout. Keep the Telegram owner allowlist narrow and the Chrome profile dedicated.

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
