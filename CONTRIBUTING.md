# Contributing

## Development setup

Use Python 3.11 or newer and Node.js 20 or newer for the frontend harness:

```bash
python -m pip install -e '.[dev]'
npm ci
```

Run the checks before submitting a change:

```bash
python -m pytest tests/ -q -o 'addopts='
npm test
python -m build --sdist --wheel
python scripts/release_check.py
```

Hermes-specific changes should also pass:

```bash
hermes plugins doctor . --ci
```

## Security and scope

Do not add credentials, bot tokens, cookies, real Mini App payloads, provider
account identifiers, or private deployment URLs to source, tests, logs, or
fixtures. CAPTCHA, passkey, and MFA interaction remains user-owned. Keep the
plugin on Hermes's existing Telegram gateway; do not create a second poller or
public listener.

Keep changes focused, add regression coverage for behavior changes, and update
README/SECURITY/compatibility documentation when setup or trust boundaries
change.
