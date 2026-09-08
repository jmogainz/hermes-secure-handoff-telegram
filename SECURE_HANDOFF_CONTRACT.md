# Secure Handoff Contract — v1.1

## Product boundary

Hermes Secure Handoff Telegram is an encrypted human-entry bridge with a separately gated, owner-approved observed checkout action. The operator owns one Telegram DM and one dedicated local Chrome profile. The Mini App renders one bounded request; the gateway decrypts only at private apply time. No passwords, OTPs, payment details, field values, cookies, raw DOM or decrypted payloads belong in model tools, logs, receipts, screenshots or memory.

## Modes

- **v1 connection check:** a fixed synthetic phrase tests RSA-OAEP/Telegram delivery. No credentials.
- **v3 auth:** one positively classified identifier/password/OTP stage. A bound auth action may be executed only after the human sends the encrypted stage. Split OTP can rely on the site's own final-digit action.
- **v3 form:** explicit `mode: form`, action label `Fill fields`. General encrypted entry only. No Submit, Save, Delete, Pay or Enter action is executed by the controller.
- **v3 checkout:** supported billing/payment fields are filled. Ordinary checkout then becomes `human_action_required`; an explicitly source-authorized observed checkout can instead receive a fresh review and separate encrypted approval for one guarded action.
- **Legacy v3 payment_confirmation:** recognized for safe rejection/compatibility only. The frontend cannot send it and the controller cannot execute a purchase. An origin plus `confirm: true` is insufficient transaction consent. Observed approval requires runtime-issued facts, explicit source authorization, a fresh user-visible review and an exact one-shot capability.

## Ownership and publication

Only an explicitly configured positive Telegram owner ID in its private DM can call the tool. Callback owner/chat/thread must match the request; omissions and mismatches do not relax scope. `open` starts a fresh navigation. `attach` binds an existing exact HTTPS origin plus optional 32-hex Chrome target ID in `ref`; ambiguous same-origin pages are not guessed. `present` binds/publishes without navigation. A missing session is reported distinctly from an ambiguous target or rejected binding.

Publication creates a fresh request ID and RSA key. Publication failure invalidates the request and key. Only bounded public metadata and the public key appear in the launch fragment; no current field values are copied. Telegram acceptance is not proof the phone displayed the keyboard.

## Private binding and apply

The controller pins exact top document, frame documents/origins, form/scope, action and control metadata. Generic and checkout controls do not get substituted with lookalikes. Limited auth rerender recovery checks the original document/origin and container/action before rebinding.

On encrypted submit:

1. Consume the native `sh_` request namespace before model dispatch, including late/unknown valid IDs.
2. Check exact callback identity and one-time request state under the session lock.
3. Validate original document/frame generations before any rebind or decryption.
4. Decode strict bounded JSON and decrypt authenticated AES-GCM with request ID as AAD.
5. Validate exact field IDs, string types, required values, checkbox vocabulary, typed formats and select membership.
6. Recheck expiry and immutable private authority at the synchronous browser mutation boundary before each mutation/event and permitted auth action. Top-document controls only; cross-frame publication is blocked pending a reviewed parent/child commit protocol.
7. Terminalize once, write only safe status/phase receipts, scrub key/request/bindings and wake the original conversation with status-only context.

Cancellation marks the session unusable before waiting for in-flight work to release its lock. Requests are invalidated on cancel, replacement, idle timeout and request deadline. The command `/handoffcancel` cancels the actual secure controller as well as connection tests. Operator browser tabs survive.

## Privacy and unavoidable limits

The dedicated tool's `read` result is status/origin only. Legacy ordinary `type`/`click` cannot mutate browser state. The plugin is not a sandbox against destination JavaScript, and ordinary input events may autosave or auto-submit. Plaintext briefly exists in the Mini App and gateway to perform the requested entry; strings/native browser memory cannot be guaranteed zeroized.

Static hosting uses no-store, no-referrer, nosniff, restrictive CSP and permissions policy. No analytics, storage, credential server or third-party credential broker is used. The hosting operator can change JavaScript; Telegram's SDK and the target provider remain trust boundaries. Self-hosting remains available.

## Evidence and limits

See `docs/compatibility.md` for the field matrix, size limits and unsupported controls. Synthetic Python/Chromium/Mini App/Telegram-dispatch tests are separate from physical iPhone and live-provider verification. A passing fixture, emitted status or HTTP 200 never proves successful authentication or purchase.
