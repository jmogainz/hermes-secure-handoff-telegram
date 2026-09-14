# Hermes Secure Handoff Telegram

A transport-only encrypted bridge from a Telegram Mini App into Jacob’s dedicated Hermes Chrome profile.

The plugin does not classify websites, infer provider stages, validate whether values “stuck,” or decide whether authentication or another workflow succeeded. It accepts an agent-composed operation plan, attempts the exact browser operations once, emits a mechanical receipt, and wakes Goku to inspect the live browser.

## v4 flow

```text
attach exact existing HTTPS target
  → inventory generic browser controls
  → Goku selects opaque refs and composes a versioned data-only Mini App view
  → owner submits encrypted values or an action approval
  → plugin validates transport authority
  → plugin attempts the exact operations once
  → execution_complete
  → Goku inspects the live browser and discusses next steps
```

## Tool actions

- `attach` — bind one exact existing Chrome target; never navigates.
- `inventory` — return generic structural metadata and short-lived opaque refs.
- `present_entry` — publish encrypted fields, optional `secure-handoff.ui/1` layout, and exact private bindings.
- `present_action` — publish a separate one-shot approval for one exact action ref.
- `read` — return safe status or the latest mechanical receipt.
- `close` — scrub controller state without closing the browser tab.

`attach` returns a fresh opaque `session_ref` for that flow. Every later action
uses that ref, so multiple independent flows may share the same owner/chat/topic
while remaining isolated to their exact browser targets. A target can still be
attached to only one flow at a time.

The former auth/form/checkout classifiers, mutation epochs, stage machine, action rediscovery, purchase observer, and webpage-success statuses have been removed.

## Status contract

`execution_complete` means only that a valid encrypted submission was accepted and every bounded browser operation was attempted once. It does not mean a field was accepted, a button took effect, a provider request was sent, authentication succeeded, or a purchase completed.

## Agent-composed UI

Version 2.1 adds a safe component registry, a versioned layout tree, and optional character fan-out. Goku can compose new field groupings and layouts per live page without provider code. The first composite control is a required 4–12 character segmented code that emits one encrypted value.

The Mini App does not run request-supplied HTML, JavaScript, CSS, URLs, event handlers, or network resources. New layouts are data. New executable renderers still require a reviewed Mini App release. See [docs/components.md](docs/components.md) for the exact node, binding, lifecycle, and extension contract.

`rejected` is reserved for transport or authorization failures before execution: wrong owner/chat/topic, invalid or expired request, replay, invalid crypto, ambiguous target, stale inventory, or an unauthorized control ref. It is never a website or provider verdict.

## Security boundary

Retained:

- AES-256-GCM payload encryption with RSA-OAEP-SHA-256 key wrapping;
- exact Telegram owner/private-chat/topic binding;
- expiry and one-time request consumption;
- loopback-only Chrome CDP connection;
- exact existing HTTPS target attachment;
- opaque control refs with no selectors or values in model output;
- no secrets in request metadata, receipts, logs, wakeups, or tool output;
- separate explicit owner approval for consequential actions;
- no plugin-selected submit after field entry. Any applied input, selection, or check may activate destination handlers, including submission or navigation.

After every wakeup, Goku must inspect the same live target and make the webpage judgment. Passkeys, MFA, CAPTCHA, and provider security prompts remain user-operated.

See [SECURE_HANDOFF_CONTRACT.md](SECURE_HANDOFF_CONTRACT.md), [SECURE_HANDOFF_PROTOCOL.md](SECURE_HANDOFF_PROTOCOL.md), [docs/components.md](docs/components.md), and [SECURITY.md](SECURITY.md).

## Install

```bash
python -m pip install .
playwright install chromium
hermes plugins enable telegram-secure-handoff
hermes gateway restart
```

Configure exactly one Telegram owner ID, the HTTPS Mini App URL, and the local loopback CDP endpoint. The default CDP endpoint is `http://127.0.0.1:9222`.

## Development smoke

```bash
python -m pytest -q -o 'addopts='
PLAYWRIGHT_CHANNEL=chromium node tests/frontend.test.mjs
python -m build
python scripts/release_check.py
```

Development and synthetic smoke checks must not use the live Chrome profile or real credentials.
