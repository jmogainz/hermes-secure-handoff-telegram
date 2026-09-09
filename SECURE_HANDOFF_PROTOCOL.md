# Hermes Secure Handoff Telegram protocol

## Request lifecycle

```text
fresh HTTPS browser page
  -> semantic stage scan
  -> exact target/frame/document binding
  -> v3 Mini App request with public metadata only
  -> user enters values through Telegram's Mini App
  -> local AES-GCM encryption + RSA-OAEP key wrapping
  -> Telegram WebApp.sendData()
  -> owner/chat/thread/request validation
  -> live preflight
  -> decrypt immediately before browser mutation
  -> fill exact controls
  -> rebind and preflight again
  -> next stage or terminal status
```

`open` is for a fresh navigation. `attach` and `present` republish a live stage without navigation. A request ID and private key are single-use. A new stage always receives a new ID/key.

## Public v3 shape

```json
{
  "v": 3,
  "id": "sh_<opaque-id>",
  "publicKey": {"kty":"RSA","n":"<base64url>","e":"AQAB"},
  "expiresAt": 0,
  "origin": "https://target.example",
  "provider": "generic",
  "stage": "checkout_details",
  "mode": "checkout",
  "actionLabel": "Review purchase",
  "fields": [
    {
      "id": "f0",
      "label": "Card number",
      "type": "card_number",
      "required": true,
      "autocomplete": "cc-number",
      "inputMode": "numeric"
    }
  ],
  "demo": false
}
```

The controller bounds request size, field count, labels, options, IDs, action labels, TTL, and origin. It publishes semantic metadata rather than selectors, HTML, query strings, or current values.

## Field vocabulary

- `text`, `email`, `tel`, and `number` cover ordinary form controls.
- `password` and `otp` cover authentication secrets and one-time codes.
- `card_number`, `card_expiry`, and `cvc` cover supported payment inputs.
- `select` covers native option lists. Up to 64 enabled choices are published as a normal picker; larger lists up to 512 enabled choices use `selectionMode: "search"`, where the user types the exact visible option label and the browser-side value mapping stays private.
- `textarea`, `checkbox`, `date`, `time`, `datetime-local`, `month`, `week`, `url`, `search`, `color` and `range` extend native generic forms. Radio groups use one `select` with opaque choice IDs.

## Generic form state machine

`mode: "form"`, `stage: "general_form"`, `actionLabel: "Fill fields"` uses the same encrypted values envelope. Every value is a string; checkbox values are exactly `"true"` or `"false"`. A required checkbox must be true. Normal select values must occur in published options, including empty values. A large native select uses `selectionMode: "search"` and is resolved against a private, immutable option map by normalized exact label; duplicate labels fail closed. The controller binds one exact native form or form-less scope, fills its supported controls without a submit/click/Enter action, then returns `filled`. Current values/defaults and large-select option values are never published. Unsupported/ambiguous controls and changed node identities fail closed. Website-owned input/change handlers can still run.

Bounds: 24 logical fields, 64 published select options, 512 private enabled options for exact-label selects, 512 characters per value, 2048 UTF-8 plaintext bytes, 4096 envelope bytes. Source min/max/step/pattern constraints are not part of this wire revision.

A browser adapter can classify these types from standard control semantics: `autocomplete`, `name`, `id`, accessible label, placeholder, input mode, and native input type. The core has no named-site selectors or provider branches.

## Authentication state machine

```text
auth stage visible
  -> waiting_for_handoff
  -> encrypted values accepted
  -> exact controls filled
  -> stage rebind
  -> next auth stage published with a fresh ID/key
  -> submitted or authenticated state verified separately
```

The controller prefers visible secret stages over leftover identifier fields, rejects disabled/inert/readonly/hidden controls, and can group bounded split OTP controls as one logical `otp` field. Auto-submit OTP stages do not invent a submit button.

## Checkout state machine

```text
checkout_details visible
  -> waiting_for_handoff
  -> encrypted registrant/billing/payment values accepted
  -> exact controls filled, no purchase click
  -> ordinary checkout: scrub key/request/bindings -> human_action_required -> user completes in provider page
  -> source-authorized observed checkout: fresh runtime fact review -> encrypted Complete purchase approval
  -> exact original action/document/scope revalidated synchronously -> one guarded native click
  -> purchase_submitted or outcome_unknown -> provider result verified separately
```

Checkout detection requires a single exact payment action plus payment semantics, supported payment fields, or a bounded multi-field billing shape. The action must stay in the same top-level origin and approved scope. Version 1.1 publishes visible native controls from the top document and vetted HTTPS child frames descended from that scope. Child controls are represented by opaque refs plus a bounded frame ordinal; frame URLs, selectors, labels and values remain private. A same-looking replacement form, iframe host or payment document never inherits old authority. Because browsers do not provide an atomic JavaScript operation across OOPIFs, observed purchase approval uses a short conservative parent/child two-phase lease and explicitly retains a residual last-moment race boundary rather than claiming atomicity.
Cross-origin child processors are treated as merchant-selected members of the top-page trust boundary; HTTPS is an eligibility gate, not an independent child-origin approval. The Mini App does not expose child URLs. Environments requiring separate processor approval must add that policy or disable cross-frame purchase authority.

Authentication stages use the same private frame/document/origin/iframe-host binding when a provider renders native identifier/password or OTP controls in one visible eligible HTTPS child frame, including a form-less staged surface. The public manifest remains generic and frame URLs stay private. A single explicit `Sign in`/`Log in` action may be guarded in the owning frame. When up to four eligible auth actions are visible, field handoff still proceeds; after encrypted fill the controller returns `action_selection_required` with only a bounded count, and a later owner-selected ordinal is revalidated against the private action/frame/form lease before one click. A single ambiguous `Continue`, `Next` or `Submit` remains fill-only unless the owner explicitly opts into that exact continuation on `open`/`attach`; multiple actions never cause a guessed click. `Verify` is accepted only for OTP stages. This action selector cannot authorize checkout.

The plugin never solves CAPTCHA, performs 3DS, chooses MFA/passkey options, or claims provider payment success. Legacy `payment_confirmation` is blocked in both frontend and controller. The observed-action path is limited to an explicitly source-authorized, runtime-bound checkout and one user-approved original action; `confirm: true` alone is not enough. `purchase_submitted` is an action receipt, not payment or ownership proof, and ambiguous dispatch becomes `outcome_unknown` without retry.

## Encryption

For v3 requests, the Mini App encrypts `{"values":{...}}`. The old field-free `{"confirm":true}` shape remains parseable for compatibility but is not an enabled purchase capability. The Mini App generates a fresh AES-GCM key and IV, wraps the raw AES key with the request RSA public key, authenticates the request ID as additional data, clears form controls and plaintext byte buffers, then calls Telegram `sendData()`. Public launch metadata is validated but not digitally signed; trusted hosting/Telegram delivery is part of the threat model.

The plugin checks the outer envelope against the live request, unwraps the AES key, authenticates the ciphertext, checks exact field IDs and value limits, and rejects every extra property. It holds plaintext only for the immediate Playwright fill/select call.

## Origin and identity

The browser origin in the request must be HTTPS and free of credentials, query strings, and fragments. The owner identity is the exact tuple `(Telegram user, private chat, thread)`. The bound page, document handle, form/scope, submit action, child frame, and document generation are checked again before every mutation.

## iOS autofill boundary

The Mini App uses semantic autocomplete metadata so Telegram's iOS WebView can offer platform keyboard, OTP, Passwords, and payment suggestions. Apple associates saved credentials and payment autofill with the Mini App origin. A target origin in metadata cannot cause Apple to surface that target site's saved credentials on a shared Mini App origin. This behavior is device/WebView/version dependent and is not treated as a protocol guarantee.

## Safe records

Receipts contain only protocol version, opaque request ID, status, originating thread, timestamp, and phase names. Wakeups contain only status and target origin. No field labels that contain values, decrypted values, ciphertext, keys, cookies, storage, exception text, or provider account data are written to logs or chat.
