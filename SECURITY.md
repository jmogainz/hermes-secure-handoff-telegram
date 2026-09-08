# Security policy

## Scope

This project moves user-entered authentication, registrant, billing, and
supported payment fields between a private Telegram bot chat and the operator's
local Hermes browser profile. The Mini App is a transport boundary, not a
general credential manager or payment processor.

## Deployment boundary

- General forms use encrypted fill-only entry. There is no inferred authorization
  to click arbitrary submit, save, delete, or payment actions. Input events may
  still cause destination-owned side effects; the destination origin must be trusted.
- Ordinary tool results are status-only, not a DOM/body dump. All field entry
  belongs in the encrypted Mini App; direct tool typing is not a secret channel.
- Unsupported widgets fail closed. File selection, signatures, native wallets,
  passkeys, CAPTCHA and 3DS need separately reviewed human-owned capabilities.

- A single official HTTPS frontend deployment may serve every operator because
  it is static and has no shared backend, bot token, account, or database.
- The operator must choose whether to trust that shared frontend publisher. The
  page can read what a user types before encrypting it for Hermes. Self-hosting
  is the stronger isolation option and limits the impact of a compromised host.
- Shared frontend hosting does **not** mean shared Telegram access. Each
  operator needs one Telegram owner, one bot/gateway, one Hermes profile, and
  one dedicated Chrome profile.
- Keep Chrome DevTools Protocol on loopback (`http://127.0.0.1:9222` or another
  loopback port). Remote and websocket CDP endpoints are rejected.
- Enter the Telegram bot token only through Hermes's gateway setup. Never put
  it in the Mini App, repository, chat, CLI arguments, or screenshots.
- Never paste website credentials or one-time codes into Telegram chat, model
  prompts, terminals, logs, receipts, screenshots, or issue reports.
- Top-document checkout fields are filled only after an encrypted v3 request
  is accepted. Final purchase execution and embedded/cross-frame publication
  are blocked in v1.1. A field-free boolean confirmation lacks bound transaction
  terms; no claim of payment authorization or completion follows from field fill.
- CAPTCHA, 3DS, MFA, passkeys, provider security screens, and payment outcomes
  remain user/provider-owned. The plugin never solves or bypasses them.
- The Mini App uses standard iOS `autocomplete` metadata, but Apple Passwords
  and payment autofill remain scoped to the Mini App's own origin. A target
  website origin cannot override that browser rule.

## Reporting

Do not open a public issue for a suspected credential leak, authentication
bypass, remote-CDP access issue, or Mini App transport flaw. After publication,
use the repository owner's private security-report channel and include only a
redacted reproduction. Until a public security contact is configured, contact
the project maintainer privately through the distribution channel.

## Release checks

Before publishing a release, run the full Python and frontend suites, the
Hermes Plugin Doctor, `python -m build --sdist --wheel`, and the release artifact
checker. Review the generated archive contents and run a secret scanner against
the committed tree and Git history.
