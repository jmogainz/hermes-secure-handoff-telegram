# Compatibility

## Tested baseline

- Hermes Agent: local v0.20.6 plugin loader/installer behavior.
- Python: 3.11 or newer.
- Node.js: 20 or newer for the static frontend test harness.
- Browser: Google Chrome/Chromium with a dedicated persistent profile and
  loopback DevTools HTTP endpoint. The plugin does not install Chrome or start
  a second browser service.
- Telegram: an already configured Hermes Telegram gateway using its existing
  `python-telegram-bot` application.

## Install paths

- Native Git plugin: the repository root contains `plugin.yaml` and
  `__init__.py`; use `hermes plugins install OWNER/REPOSITORY --ref <40-char-sha> --enable`.
- Pip plugin: install `hermes-telegram-browser-login==0.2.0` into the same Python
  environment that runs Hermes, then enable `telegram-browser-login` with Hermes.

The Git installer on Hermes v0.20.6 requires a manifest compatible with version
1. The source manifest intentionally uses `manifest_version: 1`; do not change
it to version 2 without verifying the target Hermes installer first.

## Platform scope

The Python/plugin path is intended to be cross-platform, but the release gate
currently exercises macOS and local Chrome. Windows, Linux, Brave, Edge, and
remote browser hosts need a separate verification pass before being advertised
as supported. The Mini App itself requires an HTTPS static host and Telegram's
WebApp runtime.
