# Security Policy

## Scope

Protocol v4 transports owner-entered sensitive values from a Telegram Mini App into exact controls in the dedicated local Hermes Chrome profile. The plugin is a transport and mechanical executor, not a webpage policy engine.

## Retained hard boundaries

- Exactly one configured positive Telegram owner ID.
- Exact owner and private-chat binding for callbacks. Flows may originate from an authorized group chat or forum topic, but the encrypted entry is always published to, and submissions are accepted only from, the owner's private chat; the recorded origin is used only for wakeups and exact cancellation and never authorizes a submission.
- If Telegram omits the topic from a Web App service message, the request ID must resolve to exactly one live flow for that owner/private chat; zero or duplicate matches reject without browser execution.
- Group-context cancellation (`/handoffcancel` in an authorized group or forum topic) matches only the exact owner and origin chat/topic recorded at attach time.
- HTTPS Mini App and browser origins.
- Loopback-only HTTP CDP endpoint.
- Existing-target attachment; no navigation by the secure-handoff tool.
- Fresh RSA-2048 request key; AES-256-GCM submission with request ID as AAD; RSA-OAEP SHA-256 key wrapping.
- Strict UTF-8 size, duplicate-key JSON, key-set, base64url, expiry, and replay validation in both the Mini App and backend.
- Short-lived opaque per-flow session, snapshot, field, and action refs.
- Request consumption before the first browser operation.
- Separate one-time owner approval for an exact consequential action.
- No plugin-selected submit following entry. Any applied input, selection, or check may activate destination handlers, including submission or navigation.
- Secret and private-ref cleanup after completion, rejection, expiry, cancellation, replacement, or close.
- Versioned `secure-handoff.ui/1` data-only views with exact key sets, node/depth/child bounds, total field coverage, and no request-supplied code or URLs.
- Visible metadata rejects control characters, Unicode format/invisible characters, bidirectional overrides, and URI schemes.
- At most 24 browser operations per entry request and a 10-second timeout per operation.

These boundaries may reject before browser execution begins. They protect transport authority; they are not website-success judgments.

## Removed webpage policy

The plugin does not:

- classify auth, registration, billing, checkout, or provider stages;
- infer field meaning from labels, autocomplete, routes, or forms;
- observe mutation epochs or reject because a page rerendered;
- read values back, call validity APIs, or decide whether a fill succeeded;
- rediscover or infer a submit action;
- inspect provider responses or declare authentication/payment success.

After `execution_complete`, Goku inspects the exact live browser and discusses the observed state with Jacob. Mechanical browser exceptions are reported only as bounded counts and the safe categories `detached`, `timeout`, or `browser_error`.

## Model-visible data

Allowed:

- sanitized top/frame origins;
- structural category and capabilities;
- frame/control ordinal;
- visible/enabled/editable booleans;
- agent-authored public labels and action summary;
- agent-authored bounded layout text and installed component metadata;
- mechanical status and operation counts.

Forbidden:

- field values, passwords, OTPs, card data, recovery phrases;
- selectors, HTML, full URLs with query/fragment data;
- cookies, storage, tokens, ciphertext, private keys;
- raw exception text or webpage text in receipts/wakeups.

## Agent-composed UI boundary

The Mini App renders only installed nodes and controls with fixed DOM construction and CSS classes. It inserts display strings with `textContent`. Request data cannot add HTML, Markdown, scripts, styles, event handlers, URLs, network requests, navigation, storage, hidden fields, conditional behavior, or submit controls.

Every entry field must appear exactly once in the optional view. The plugin converts private refs to generated field IDs before publication. Unknown schema versions, node kinds, component kinds, keys, refs, duplicates, and omissions reject before publication or before plaintext inputs mount.

Visible-text and value limits count Unicode code points in both runtimes. Segmented-code fields preserve exact user input. They do not silently strip, truncate, or change case, and the Mini App does not request OTP autofill on its bridge origin. The frontend invalidates in-flight encryption on cancel, page hide, freeze, and expiry, rechecks freshness after each asynchronous boundary, and clears mounted plaintext and tracked byte buffers.

Runtime executable extensions are not supported. A future extension loader would be a separate trust-boundary change and would need reproducible reviewed builds, pinned offline signing, a protected local allowlist, exact hash and version binding, revocation, and schema-checked public inputs. A signature alone would not make secret-handling code safe.

## Consequential actions

`present_action` binds one exact private action ref and publishes a fresh approval nonce. Approval is consumed before the click attempt and is never automatically retried. `execution_complete` remains outcome-unknown until live inspection. Passkeys, MFA, CAPTCHA, OS permission prompts, and provider security challenges remain user-operated.

## Reporting vulnerabilities

Do not include live credentials, tokens, cookies, Mini App payloads, or private browser data in an issue. Provide a synthetic reproduction using a disposable browser context.
