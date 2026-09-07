# AGENT.md

This repository contains a standalone Hermes plugin and a static Telegram Mini
App. Read `README.md`, `SECURITY.md`, and `docs/compatibility.md` before making
release or authentication changes.

## Rules

- Never put bot tokens, website credentials, passkeys, MFA codes, cookies,
  private keys, or real Mini App payloads in source, tests, logs, screenshots,
  fixtures, or documentation.
- Use Hermes's existing Telegram gateway and dedicated loopback Chrome profile;
  do not create a second Telegram poller or public CDP listener.
- Keep one Telegram owner per Hermes/Chrome profile.
- CAPTCHA, passkey, and MFA steps are user-owned and must not be automated or
  bypassed.
- Run the focused tests, full Python suite, frontend tests, build, and release
  artifact checker after changes.
- Do not publish, push, deploy, or change live Hermes runtime state without an
  explicit user request and a verifiable target.
