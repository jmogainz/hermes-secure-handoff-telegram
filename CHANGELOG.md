# Changelog

## 1.1.0 — release candidate

- Added explicit encrypted fill-only general forms, native typed controls, checkbox and radio-as-select.
- Polished the mobile-first monochrome UI, destination/action hierarchy, field errors, accessible focus and touch sizing.
- Kept generic checkout and legacy boolean confirmations fill-only, while adding a separate source-authorized observed-action candidate: agent-selected runtime refs, fresh review, encrypted **Complete purchase** approval, and one synchronous guarded action with truthful `purchase_submitted`/`outcome_unknown` outcomes.
- Enabled provider-neutral embedded/cross-frame checkout entry for visible native controls in vetted HTTPS child frames, with per-frame guards and a conservative non-atomic OOPIF approval boundary; custom/provider challenge widgets remain unsupported.
- Extended provider-neutral auth discovery to form-less staged controls in one visible vetted HTTPS child frame, including multi-token autocomplete and extended CTA phrases; multiple eligible actions publish/fill fields first and require a bounded owner-selected ordinal with fresh exact-action revalidation.
- Blocked direct model type/click and raw page-text output from the handoff tool.
- Added original-document/frame binding, cancellation/expiry lifecycle, stricter JSON/choice/URL validation and publication budget regressions.
- Scoped checkout discovery to the sole visible billing dialog, filtered unsafe multi-token autocomplete metadata, and added private exact-label handling for native selects with 65–512 enabled choices so long country/state lists stay within the public launch budget.
- Wired `/handoffcancel` to the secure controller as well as diagnostic requests.
- Added static hosting no-store/no-referrer/CSP/permissions protections.
- Test browsers are disposable; development never changes the operator's live Chrome profile or uses real credentials.

## 1.0.0 — prototype

- Renamed the product to Hermes Secure Handoff Telegram.
- Added v3 typed authentication and checkout handoffs.
- Added registrant, billing, card number, expiration, CVC, select, email, phone, password, and OTP field support.
- Added native HTTPS child-frame binding for supported payment fields.
- Added a fresh field-free confirmation request before any bound purchase action.
- Added standard iOS keyboard, OTP, Passwords, and payment autofill metadata.
- Removed named-site adapter behavior and kept the browser controller provider-neutral.
- Added loopback-only CDP validation, one-owner-per-profile enforcement, and status-only receipts/wakeups.

Earlier prototype history is preserved in the source history and protocol contracts, not as a supported public API.
