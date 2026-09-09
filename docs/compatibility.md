# Compatibility and safety boundaries

Version 1.1.0 expands encrypted entry, not the authority to submit arbitrary forms.
The protocol is v1 for connection diagnostics and v3 for secure handoff. v2 is rejected.

## Composed ENTRY candidate

`mode: compose` adds agent-selected optional fields and bounded grouping/order
with stack/sections layouts; required fields must remain visible. Supported
native fields start empty. Color/range/checkbox defaults and large search-selects
are not supported in this path; legacy form support below is unchanged.
See [the complete composition contract](composition.md). Real disposable browser
and frontend crypto/controller roundtrips cover both layouts; no live install or
physical phone verification is implied. A separate local observed-action path now
integrates real registry → controller tools → Mini App → encrypted approval → one
guarded click. The private [acquisition bridge](purchase-acquisition.md) now
supports explicitly selected source refs and composed-entry continuation for
restricted table/definition-list checkout shapes. An exact owner-selected public
catalog document is still required via `discover_catalog_sources` and
`request_source_approval`; ordinary attach/composition cannot infer that grant.
The encrypted source-selection approval is not privacy or financial certification
and grants no purchase authority. See [the API and remaining prerequisites](observed-purchase-status.md).

## Supported shapes

| Shape | Behavior | Verification |
|---|---|---|
| Identifier, password, combined login | Exact positively classified stage; encrypted fill and bound continuation | Synthetic real Chromium + Mini App/controller round trip |
| Split OTP, including no-button auto-submit | One logical secret mapped privately to digit nodes | Synthetic staged browser fixtures |
| General native form or one form-less scope | Explicit `mode: form`, encrypted fill only | Synthetic real Chromium, typed-control and stale-node regressions |
| Text, email, phone, number, password, OTP, textarea | Bounded string values | Python + frontend contract tests |
| Checkbox | Encrypted `"true"` or `"false"`; required checkbox must be true | Python + frontend tests |
| Native single select | Exact published choices, including empty only if published; lists with 65–512 enabled choices use private exact-label search entry | Python + frontend contract tests |
| Radio group | One logical select with opaque choice IDs; no guessed default | Browser fixture + same wire select renderer |
| Date, time, local datetime, month, week, URL, search, color, range | Native controls and bounded values | Synthetic Chromium; physical iPhone behavior not verified |
| Checkout details | Encrypted fill for visible native controls in the exact top-document checkout scope, including vetted HTTPS child frames; ordinary checkout terminates at `human_action_required`; explicitly source-authorized observed checkout may publish a separate encrypted approval for one guarded click | Real separate-origin Chromium entry and observed-action fixtures; live providers not established |
| Exact existing Chrome tab | `attach` with origin and target ID in `ref`, no navigation | Real disposable CDP target and mock ambiguity regressions |
| React auth input replacement | Same original form/document/action node and full semantic manifest | Narrow same-form fixture; whole form/action replacement requires remint |
| Cancel / timeout / teardown | Invalidates request and prevents later replay; preserves operator tabs | Concurrency, expiry, cleanup regressions |

## Deliberate limits

- Generic Submit/Continue/Next never grant auth authority, even with username/current-password autofill hints. They remain fill-only; the user advances the original page. Meaningful supported Sign in/Log in actions can be bound. Bare Verify is not guaranteed by every discovery path.

- No arbitrary JavaScript, CSS selectors, plaintext field values or click commands from the model-facing handoff tool. Legacy `type`/`click` return forbidden; `read` is status/origin only.
- General form binding is top-document only. Multiple candidate scopes, file inputs, multi-select, contenteditable, custom ARIA widgets and ambiguous groups are rejected. Shadow roots, nested/cross-origin general forms and native browser dialogs are not promised.
- HTTPS child-frame checkout controls are supported only when the iframe host is a visible descendant of the exact original checkout scope and the frame exposes visible editable native `input`, `textarea`, or `select` controls with a supported semantic kind. The private lease pins frame object ordinal, full frame URL/document, origin and iframe-host chain; document/navigation/host replacement, A→B→A epochs, HTTP/invisible frames, custom widgets, shadow controls and ambiguous frames fail closed. No old request transfers to a replacement frame or document.
- Cross-origin browser frames do not provide one atomic JavaScript evaluation across OOPIFs. The observed purchase lease checks every child guard immediately before the parent action, consumes before dispatch and never retries an ambiguous dispatch. A narrow last-moment race between the final child check and parent click cannot be eliminated by this browser primitive and is explicitly not claimed away; provider-specific payment/3DS verification remains separate.
- Up to 24 logical fields, 64 published choices per normal select, 512 enabled choices per private exact-label select, 512 characters per value, 2048 UTF-8 plaintext bytes and 4096 envelope bytes. Large selects must have unique labels after Unicode/whitespace normalization; lists over 512 or ambiguous labels fail closed. The browser-side option values are never published in the Telegram URL.
- The current wire does not carry arbitrary source min/max/step/pattern constraints. Range is supported only for the Mini App's default 0–100 integer domain; incompatible source ranges fail closed. Source constraints and complex calendars remain a compatibility limit, not a universal-form claim.
- Filling can trigger the site's own input/change handlers, autosave or automatic submission. The plugin does not explicitly click submit in form/checkout mode, but cannot sandbox hostile destination JavaScript.
- Ordinary checkout and legacy field-free payment confirmations do not execute payments. The observed-action candidate can dispatch one exact guarded click only after an owner source-selection grant, runtime-issued refs, fresh review, and encrypted **Complete purchase** approval. `purchase_submitted` is not proof of payment or ownership; `outcome_unknown` is never retried.
- CAPTCHA, passkeys, native wallets, MFA/3DS challenges, consent, account-security enrollment and purchase approval remain human-owned.
- iOS autofill attributes are present, but passwords belong to the Mini App origin; this is not a cross-origin password-manager bridge. Physical iPhone, keyboard, WebKit and live Telegram client behavior require human verification.

## Operational status

`waiting_for_handoff` means Telegram accepted publication, not that a particular client rendered it.
`filled` means encrypted general fields were applied without an explicit submit click.
`submitted` means an auth-stage action was applied, not that the provider authenticated.
`human_action_required` means the final transaction must be reviewed/completed in the provider page.
After checkout fill, `read` can include `public_fact_source_unavailable` (no
trusted public source) or `purchase_binding_unsupported` (reviewed source/binding
rejected). These are bounded diagnostics, not retry or purchase capabilities.
See [observed purchase status](observed-purchase-status.md).
`unsupported_stage` can mean ambiguous target or rejected binding; it does not prove expiry or an unloaded plugin.
`unavailable` with `session_missing` means attach is needed, not necessarily a restart.

## Privacy and trust

No real account, password, card, billing data or OTP is a test fixture. Tests use disposable browsers and intercepted/synthetic sites, not the operator's live profile. Hosting JavaScript, the Telegram SDK, the local gateway/CDP endpoint and destination website remain distinct trust boundaries. Browser/JavaScript strings cannot be guaranteed zeroized; cleanup is best effort, with references and byte buffers cleared where possible.
