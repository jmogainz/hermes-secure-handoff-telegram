# Changelog

## 1.1.0 — release candidate

- Added explicit encrypted fill-only general forms, native typed controls, checkbox and radio-as-select.
- Polished the mobile-first monochrome UI, destination/action hierarchy, field errors, accessible focus and touch sizing.
- Disabled final purchase execution: legacy boolean confirmations lack bound transaction terms. Checkout entry remains supported and ends in human-owned review.
- Blocked embedded/cross-frame field publication pending atomic parent/child authorization; top-document checkout remains supported.
- Blocked direct model type/click and raw page-text output from the handoff tool.
- Added original-document/frame binding, cancellation/expiry lifecycle, stricter JSON/choice/URL validation and publication budget regressions.
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
