# Hermes Telegram Browser Login

A standalone Hermes plugin and Telegram Mini App for secure, owner-scoped browser login handoffs.

The operator keeps credentials, passkeys, MFA codes, and CAPTCHA interaction in Telegram's encrypted Mini App. Hermes never asks the model to read or type those secrets. After the user completes a stage, the plugin applies it to the same dedicated Chromium profile Hermes uses for browser work.

## What ships

- `plugin/` — native Hermes plugin implementation and first-run CLI.
- `web/` — static, secret-free Telegram Mini App.
- `plugin.yaml` — directory-install manifest.
- `pyproject.toml` — pip package and `hermes_agent.plugins` entry point.
- `tests/` — Python, browser-fixture, cryptographic, and frontend regression tests.

## Architecture and trust boundary

```text
Telegram bot + Hermes gateway
        │
        ├── encrypted Mini App handoff (stage-scoped, one-time request/key)
        │
        └── Hermes plugin ── local CDP ── dedicated Chrome profile
                                      ~/.hermes/chrome-debug
```

- The bot token belongs to Hermes's normal Telegram gateway setup.
- The Mini App is static and contains no bot token, API key, cookie, or backend.
- Website credentials are entered only in Telegram's Mini App and are decrypted locally by the plugin immediately before the browser mutation.
- The plugin is scoped to exactly one numeric Telegram owner and that owner's private chat/thread identity per Hermes profile.
- The browser session is the dedicated Hermes Chrome profile, not the operator's everyday Chrome profile.
- A `submitted` receipt means the encrypted apply was accepted; authenticated reuse is verified separately by the browser flow.

## Fastest setup for an operator

### Prerequisites

1. Install Hermes Agent and enable its Telegram gateway.
2. Install Google Chrome, Chromium, Brave, or Edge.
3. Host `web/` at an HTTPS origin. You may use one official shared deployment for all operators, or self-host it per operator. See [`web/README.md`](web/README.md) for the tradeoff.
4. Obtain the operator's numeric Telegram user ID from `@userinfobot` or `@get_id_bot`.

### Install the plugin

For a published repository, use Hermes's native plugin installer:

```bash
hermes plugins install jmogainz/hermes-remote-web-login-telegram --enable
cd ~/.hermes/plugins/telegram-browser-login
python -m plugin.cli setup \
  --user-id 123456789
```

For a reproducible install, add `--ref <40-character-commit-sha>` to pin the
repository to a reviewed commit. The default `setup` command uses the official
shared Mini App at `https://hermes-remote-web-login-telegram.vercel.app`.

```bash
python -m pip install hermes-telegram-browser-login==0.2.0
hermes plugins enable telegram-browser-login
```

Hermes does not silently install arbitrary plugin dependencies. If the plugin doctor reports a missing dependency, install the declared package into the Hermes environment:

```bash
python -m pip install \
  'cryptography>=42,<48' \
  'playwright>=1.58,<2' \
  'python-telegram-bot>=21,<23'
```

### Run the setup wizard

The published build uses the official shared Mini App automatically:

```bash
telegram-browser-login setup \
  --user-id 123456789
```

The default Mini App is:

```text
https://hermes-remote-web-login-telegram.vercel.app
```

For a self-hosted frontend, override that default explicitly:

```bash
telegram-browser-login setup \
  --mini-app-url https://your-mini-app.example \
  --user-id 123456789
```

The wizard:

1. Enables `telegram-browser-login`.
2. Writes namespaced plugin settings under `plugins.entries.telegram-browser-login.settings`.
3. Reads the URL and allowlist back to verify the write.
4. Launches `hermes gateway setup` so the operator enters the Telegram bot token in Hermes's own setup flow.
5. Checks the dedicated local Chrome CDP endpoint.
6. Restarts the gateway after configuration.

The bot token is never a command-line argument to this plugin. Website credentials are never accepted by this wizard.

For a fully interactive run, omit the URL and user ID flags:

```bash
telegram-browser-login setup
```

For CI or a staged machine image, skip interactive gateway setup and runtime checks:

```bash
telegram-browser-login setup \
  --user-id 123456789 \
  --skip-gateway --skip-browser --no-restart
```

### Start the dedicated browser

If Hermes's CDP endpoint is not already running, start a dedicated profile. Chrome 136+ requires a non-default user-data directory:

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

Then run `/browser connect` from the Hermes CLI. The plugin accepts only a loopback HTTP CDP URL such as `http://127.0.0.1:9222`.

### Verify

```bash
telegram-browser-login doctor
hermes plugins doctor telegram-browser-login --ci
```

Send the Telegram bot a normal request that requires a website login. When Hermes reaches a supported login stage, use the newest **Open browser login** Mini App button. Do not paste a password or code into Telegram chat.

## Hosting the Mini App

`web/` is static and can be served by Vercel, GitHub Pages, Netlify, S3/CloudFront, or any equivalent HTTPS host. You can deploy it once as an official shared Mini App URL for all operators, or have each operator deploy their own copy. Each operator still uses a separate Telegram bot, Hermes gateway, owner ID, and dedicated Chrome profile.

Shared hosting is convenient, but the domain owner is a trusted code publisher: the Mini App receives what the user types before it encrypts the submission for Hermes. Self-hosting reduces that shared-host trust and limits the blast radius of a compromised deployment.

Vercel example (use a local Vercel login, or load only `VERCEL_TOKEN`; never source the complete Hermes environment):

```bash
vercel link --yes --project <your-project-name>
VERCEL_TOKEN="$VERCEL_TOKEN" vercel deploy ./web --prod
```

Use the official shared URL `https://hermes-remote-web-login-telegram.vercel.app` unless you intentionally self-host a copy. The URL must not include a query string or fragment. See [`web/README.md`](web/README.md) for the shared-host trust tradeoff.

## Development and release checks

```bash
python -m pip install -e '.[dev]'
python -m pytest tests/ -q -o 'addopts='
npm ci
npm test
python -m build --sdist --wheel
python scripts/release_check.py
```

Before publishing a release:

- run the full Python and frontend suites;
- run `hermes plugins doctor . --ci` against the directory-install shape;
- build a wheel and verify its Hermes entry point and package data in a clean environment;
- verify `telegram-browser-login setup --help` and `doctor` without real credentials;
- verify the static frontend has no secrets, network writes, analytics, or credential storage;
- test the installed plugin against a clean temporary `HERMES_HOME` before changing a live gateway;
- publish the frontend first, then publish the plugin package/repository with the matching setup instructions.

## Security notes

This project intentionally does not provide:

- bot-token collection in the Mini App;
- credential values in model prompts, logs, receipts, screenshots, or test fixtures;
- cookie/storage export between browser profiles;
- automated CAPTCHA, passkey, MFA, or provider security checks;
- a public listener on the operator's Mac;
- a second Telegram polling loop.

The encrypted Mini App is a transport boundary, not a sandbox. Only install the plugin from a source you trust, and keep the Telegram allowlist narrow.
