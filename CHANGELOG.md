# Changelog

## 2.2.0 — group-origin flows

- `attach`, `inventory`, `present_entry`, `present_action`, `read`, and `close` now accept authorized group-chat and forum-topic origins.
- The encrypted launch keyboard and every accepted submission remain bound to the owner's private chat; the Mini App is never published inside a group (Telegram permits `web_app` buttons and `web_app_data` callbacks only in private chats).
- Completion wakeups carry the recorded origin chat type (DM, group, or forum-topic routing) so the wake resumes the originating conversation instead of a parallel session.
- `/handoffcancel` works from the origin group (owner-only, exact chat/topic match) and stays silent when no flow matches; cancellation mirrors the Telegram adapter's routable-thread rules, including forum General-topic normalization.
- New transport tests cover group-origin publication, owner-DM submission acceptance and refusals, wake routing, and exact-scope cancellation.

## 2.1.0 — agent-composed component views

- Added a safe component registry with a required 4–12 character `segmented_code` control.
- Added the versioned `secure-handoff.ui/1` layout tree with `stack`, `row`, `section`, `text`, `divider`, and `field` nodes.
- Required every entry field to appear exactly once and rewrote private browser refs to generated field IDs before publication.
- Added explicit `split_chars` fan-out so one encrypted value can map mechanically to several exact controls.
- Rejected unknown UI versions, nodes, keys, components, refs, URI-bearing text, and Unicode format or invisible characters.
- Preserved exact segmented input with no silent stripping, truncation, case changes, or bridge-origin OTP autofill.
- Added live expiry timers, page-restoration checks, plaintext clearing on freeze/page hide, a 24-operation cap, and 10-second per-operation timeouts.
- Cancelled in-flight WebCrypto submissions on cancel, expiry, page hide, and freeze, with freshness checks after every asynchronous boundary.
- Aligned frontend/backend limits by Unicode code point and UTF-8 byte count, rejected duplicate JSON keys on both sides, and removed native input truncation.
- Serialized close, reattach, inventory, publication, and browser execution lifecycles; execution wakeups now use immutable receipt metadata.
- Tightened the public tool schema with action-specific requirements, exact field variants, and a closed recursive view-node union.
- Clarified that the plugin does not select submit during entry, while any applied input, selection, or check may activate destination handlers.

## 2.0.0 — transport-only executor

- Replaced the auth/form/checkout policy engine with protocol v4: exact target attachment, generic control inventory, agent-composed encrypted entry, and separate one-shot action approval.
- Removed deterministic form/provider classification, mutation epochs, stage inference, post-fill validation, automatic action discovery, purchase observers, and webpage-success verdicts.
- `execution_complete` now means only that an authorized submission was accepted and all exact browser operations were attempted once. Website outcome is always inspected by Goku afterward.
- Retained encryption, exact owner/chat/topic scope, expiry, replay prevention, loopback CDP, opaque exact refs, secret cleanup, and explicit consequential-action authorization.
- Rewrote the Mini App as a compact v1 diagnostic plus v4 encrypted entry/action client.
- Removed obsolete policy modules, fixtures, and provider/purchase-specific tests.

## 1.1.0 — superseded candidate

- Developed staged field/action lifecycle and cross-frame guards. Never released as proof of universal live-provider compatibility.

## 1.0.0 — prototype

- Initial encrypted Telegram Mini App and browser handoff prototype.
