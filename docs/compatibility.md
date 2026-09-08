# Compatibility and safety boundaries

Version 1.1.0 expands encrypted entry, not the authority to submit arbitrary forms.
The protocol is v1 for connection diagnostics and v3 for secure handoff. v2 is rejected.

## Supported shapes

| Shape | Behavior | Verification |
|---|---|---|
| Identifier, password, combined login | Exact positively classified stage; encrypted fill and bound continuation | Synthetic real Chromium + Mini App/controller round trip |
| Split OTP, including no-button auto-submit | One logical secret mapped privately to digit nodes | Synthetic staged browser fixtures |
| General native form or one form-less scope | Explicit `mode: form`, encrypted fill only | Synthetic real Chromium, typed-control and stale-node regressions |
| Text, email, phone, number, password, OTP, textarea | Bounded string values | Python + frontend contract tests |
| Checkbox | Encrypted `"true"` or `"false"`; required checkbox must be true | Python + frontend tests |
| Native single select | Exact published choices, including empty only if published | Python + frontend tests |
| Radio group | One logical select with opaque choice IDs; no guessed default | Browser fixture + same wire select renderer |
| Date, time, local datetime, month, week, URL, search, color, range | Native controls and bounded values | Synthetic Chromium; physical iPhone behavior not verified |
| Checkout details | Top-document encrypted fill; terminal `human_action_required`, no purchase click | Top-document fixtures; embedded frames reject publication |
| Exact existing Chrome tab | `attach` with origin and target ID in `ref`, no navigation | Real disposable CDP target and mock ambiguity regressions |
| React auth input replacement | Same original form/document/action node and full semantic manifest | Narrow same-form fixture; whole form/action replacement requires remint |
| Cancel / timeout / teardown | Invalidates request and prevents later replay; preserves operator tabs | Concurrency, expiry, cleanup regressions |

## Deliberate limits

- Generic Submit/Continue/Next never grant auth authority, even with username/current-password autofill hints. They remain fill-only; the user advances the original page. Meaningful supported Sign in/Log in actions can be bound. Bare Verify is not guaranteed by every discovery path.

- No arbitrary JavaScript, CSS selectors, plaintext field values or click commands from the model-facing handoff tool. Legacy `type`/`click` return forbidden; `read` is status/origin only.
- General form binding is top-document only. Multiple candidate scopes, file inputs, multi-select, contenteditable, custom ARIA widgets and ambiguous groups are rejected. Shadow roots, nested/cross-origin general forms and native browser dialogs are not promised.
- Embedded/cross-frame checkout publication is blocked in v1.1: atomic parent/child commit authorization is not established. No old request may transfer to a replacement form or payment document.
- Up to 24 logical fields, 64 choices per select, 512 characters per value, 2048 UTF-8 plaintext bytes and 4096 envelope bytes. Oversized forms and long country lists can require a smaller provider stage; the plugin does not silently drop unsupported fields.
- The current wire does not carry arbitrary source min/max/step/pattern constraints. Range is supported only for the Mini App's default 0–100 integer domain; incompatible source ranges fail closed. Source constraints and complex calendars remain a compatibility limit, not a universal-form claim.
- Filling can trigger the site's own input/change handlers, autosave or automatic submission. The plugin does not explicitly click submit in form/checkout mode, but cannot sandbox hostile destination JavaScript.
- Final payments are NOT executed. Legacy field-free payment confirmations are blocked because they lack bound amount/currency/merchant/recurrence/terms.
- CAPTCHA, passkeys, native wallets, MFA/3DS challenges, consent, account-security enrollment and purchase approval remain human-owned.
- iOS autofill attributes are present, but passwords belong to the Mini App origin; this is not a cross-origin password-manager bridge. Physical iPhone, keyboard, WebKit and live Telegram client behavior require human verification.

## Operational status

`waiting_for_handoff` means Telegram accepted publication, not that a particular client rendered it.
`filled` means encrypted general fields were applied without an explicit submit click.
`submitted` means an auth-stage action was applied, not that the provider authenticated.
`human_action_required` means the final transaction must be reviewed/completed in the provider page.
`unsupported_stage` can mean ambiguous target or rejected binding; it does not prove expiry or an unloaded plugin.
`unavailable` with `session_missing` means attach is needed, not necessarily a restart.

## Privacy and trust

No real account, password, card, billing data or OTP is a test fixture. Tests use disposable browsers and intercepted/synthetic sites, not the operator's live profile. Hosting JavaScript, the Telegram SDK, the local gateway/CDP endpoint and destination website remain distinct trust boundaries. Browser/JavaScript strings cannot be guaranteed zeroized; cleanup is best effort, with references and byte buffers cleared where possible.
