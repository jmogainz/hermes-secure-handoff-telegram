# Security policy

## Scope

This project moves user-entered website credentials, passkeys, MFA codes, and
CAPTCHA checkpoints between a private Telegram bot chat and the operator's
local Hermes browser profile. The Mini App is a transport boundary, not a
sandbox or a general credential manager.

## Required deployment boundary

- Use a frontend deployment controlled by the same operator as the Telegram bot.
  Do not use a shared/test alias for real credentials.
- Use one Telegram owner, one Hermes profile, one gateway, and one dedicated
  Chrome profile per deployment.
- Keep Chrome DevTools Protocol on loopback (`http://127.0.0.1:9222` or another
  loopback port). Remote and websocket CDP endpoints are rejected.
- Enter the Telegram bot token only through Hermes's gateway setup. Never put
  it in the Mini App, repository, chat, CLI arguments, or screenshots.
- Never paste website credentials or one-time codes into Telegram chat, model
  prompts, terminals, logs, receipts, screenshots, or issue reports.

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
