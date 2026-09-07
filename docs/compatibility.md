# Compatibility

## Tested baseline

- Hermes Agent: local v0.20.6 plugin loader and installer behavior.
- Python: 3.11 or newer.
- Node.js: 20 or newer for the static frontend harness.
- Browser: Chrome/Chromium with a dedicated persistent profile and loopback DevTools HTTP endpoint. The plugin does not install Chrome or start a second browser service.
- Telegram: an already configured Hermes Telegram gateway using its existing `python-telegram-bot` application.

## Install paths

- Native Git plugin: the repository root contains `plugin.yaml` and `__init__.py`. Use `hermes plugins install OWNER/REPOSITORY --ref <40-char-sha> --enable`.
- Python package: install `hermes-telegram-secure-handoff==1.0.0` into the same Python environment that runs Hermes, then enable `telegram-secure-handoff`.

The source manifest uses `manifest_version: 1` because that is the loader contract exercised by Hermes v0.20.6. Do not change it without verifying the target Hermes installer.

## Protocol support

- Telegram connection checks use the fixed v1 marker transport.
- Secure auth and checkout use v3 typed requests with one-time RSA keys and AES-GCM payloads.
- Checkout includes a field-free confirmation request before the bound payment action.
- Native iOS autofill metadata is best-effort and remains subject to Telegram WebView and Apple origin-scoping behavior.

## Platform scope

The Python/plugin path is intended to be cross-platform, but the release gate exercises macOS and local Chromium. Windows, Linux, Brave, Edge, remote browsers, physical iOS devices, and provider-specific payment frames need separate verification before being advertised as tested. The Mini App requires an HTTPS static host and Telegram's WebApp runtime.
