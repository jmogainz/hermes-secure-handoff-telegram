# General forms and security hardening

## Authorization and scope

Jacob requested a whole-plugin robustness/general-form review and selected **audit, implement, and deploy verified fixes** in Telegram on 2026-09-07 (local time). Source baseline: `e33b50b`. Production target remains the existing `hermes-secure-handoff-telegram` Vercel project and renamed GitHub repository. Preserve all existing browser tabs and live checkout. Never use real field values in development. No real transaction is authorized by this maintenance task.

## Architecture decision

Separate structural field capabilities from inferred task semantics. Add an explicit `form` mode that publishes eligible live controls and applies encrypted user values without explicitly activating a submission control. It does not guarantee that a destination site's own input/change event handlers are side-effect-free. Keep auth staging and checkout confirmation separate. Unknown/custom/native controls remain unsupported unless exact semantics and mutation behavior can be validated; never guess from arbitrary page prose.

### Shared v3 extension

- Mode: `form`; action label: `Fill fields`.
- Existing scalar field types retained; extend with textarea, checkbox, native date/time/datetime-local/month/week, URL/search/color/range.
- All submitted field values remain strings; checkbox uses exactly `true` or `false` as strings.
- Radio groups use the existing select wire shape with bounded options and private physical-node mappings.
- All metadata is untrusted, bounded, and rendered as text. No DOM values or selectors in model-facing results.
- Exact owner/private-chat/thread/request/target/origin/document binding remains mandatory.
- Generic form selection must be explicit when auth inference could otherwise submit a registration or settings form.

## Parallel ownership

1. Read-only adversarial review: security findings and exact reproductions.
2. Backend: controller, semantic adapters, new generic-form regression suite.
3. Frontend: typed controls, validation, encryption lifecycle, accessible mobile UI, new browser suite.
4. Transport: connection check, config and CLI validation, new transport regressions.
5. Parent: integrate, independently verify, hosting headers, CI coverage, documentation, packaging/release and runtime provenance.

## Required gates

- RED/GREEN tests per change, including stale document, wrong target/origin/thread, replay/expiry, unsupported controls, model-output privacy, and publication failure.
- Real synthetic browser encryption/apply tests; mock-only target selection is insufficient live-compatibility proof.
- Full Python and frontend suites; official Telegram SDK/WebCrypto harness in CI.
- Build wheel/sdist, validate artifacts and clean isolated import/registration.
- Independent exact-tree security review after integration; unresolved critical findings block deployment.
- Deploy static canonical project and verify actual HTTP headers plus exact asset bytes.
- Push immutable commit and read back remote CI. Install pinned commit preserving config without exposing values.
- Report installed source separately from live gateway module adoption. Never bypass the self-restart guard or claim restarted merely from an enabled plugin entry.

## Honest compatibility boundary

This is not universal browser automation. File uploads, signatures, native wallets/passkeys, CAPTCHA/3DS, canvas widgets, arbitrary rich text, closed shadow roots, and framework-specific composites require separately reviewed capabilities or direct human control. A typed encrypted bridge does not confer destination-site trust or PCI certification. No claim of physical iPhone autofill or real payment E2E without direct evidence.
