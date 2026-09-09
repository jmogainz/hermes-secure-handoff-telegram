# Hermes Secure Handoff Telegram v1.0 Implementation Plan

> **For Hermes:** Execute this plan task-by-task with strict RED → GREEN → REFACTOR verification.

**Goal:** Rename the project to Hermes Secure Handoff Telegram and extend the encrypted Telegram Mini App from login/OTP-only handoffs to generic typed checkout handoffs, including card fields, with an explicit second confirmation before any purchase action.

**Architecture:** Keep the static Mini App as a secret-entry surface and the Hermes plugin as the only browser mutator. Use a new generic secure-handoff wire contract with short-lived RSA-OAEP/AES-GCM envelopes, owner/chat/thread/request binding, no values in model-facing data or receipts, and a two-stage checkout state machine: encrypted field submission → fresh payment-confirmation request → exact bound payment action. Bind visible editable fields in the top-level form and eligible HTTPS child frames without provider/site selectors; CAPTCHA, passkeys, MFA, 3DS, and signup remain user-owned checkpoints.

**Tech Stack:** Python 3.11+, Playwright, python-telegram-bot, cryptography, static HTML/CSS/JavaScript, WebCrypto, npm Playwright tests, pytest, GitHub Actions, Vercel static deployment.

## Canonical naming

- Product/brand: `Hermes Secure Handoff Telegram`
- Plugin ID: `telegram-secure-handoff`
- Python distribution: `hermes-telegram-secure-handoff`
- Python import package: `hermes_telegram_secure_handoff`
- CLI: `telegram-secure-handoff`
- Hermes tool/toolset: `telegram_secure_handoff`
- Repository: `jmogainz/hermes-secure-handoff-telegram`
- Vercel project/deployment: `hermes-secure-handoff-telegram`
- Intended domain: `hermessecurehandoff.xyz`
- Request prefix: `sh_`
- Legacy login names are intentionally not compatibility aliases; the hard rename may break old install/config/CLI paths as requested.

## Security invariants

- Never put card numbers, expiration values, CVCs, billing values, passwords, OTPs, cookies, tokens, or plaintext form values in model messages, tool results, logs, screenshots, fixtures, receipts, or documentation.
- Public request metadata contains only bounded field descriptors, labels, types, safe autocomplete/input hints, and optional bounded select options; it never contains prefilled values or raw frame URLs/query strings.
- Checkout values are accepted only in the encrypted envelope and are decrypted immediately before the exact private Playwright mutation; plaintext buffers and Mini App controls are cleared after encryption and on page teardown.
- A checkout field submission never clicks `Buy`, `Pay`, `Purchase`, or equivalent. It fills the exact bound fields and publishes a fresh, field-free `payment_confirmation` request.
- Only an explicit confirmation envelope for the same owner/chat/thread, page/frame/document generation, checkout scope, origin, and bound payment action may trigger the final click.
- Cross-origin child frames are considered only when their URL is HTTPS, visible/editable, semantically classified as supported secure/payment fields, and structurally contained by the top-level checkout scope. Non-rendered helper frames are ignored as inactive; blank, visible custom, detached, or provider-challenge frames reject the binding, and a helper becoming visible after binding invalidates the lease. No provider host, selector, API key, or site name is hardcoded.
- Auth stages may bind native identifier/password/OTP controls in one visible, structurally contained HTTPS child frame with private frame/document/origin/host identity. Generic Continue/Next/Submit remains fill-only unless the owner explicitly opts into one exact continuation on the open/attach call; the opt-in is consumed during binding and cannot authorize checkout.
- Provider chooser, CAPTCHA, passkey, MFA, 3DS, and signup controls are never solved or bypassed. A post-payment `submitted` status means the browser action was accepted, not that the charge or domain purchase succeeded.

---

### Task 1: Add failing contract tests for the new wire and field vocabulary

**Files:**
- Modify: `tests/test_secure_handoff.py` (renamed from `tests/test_secure_handoff.py`)
- Modify: `tests/test_handoff_adapters.py` (renamed from `tests/test_handoff_adapters.py`)
- Modify: `tests/frontend-checkout.test.mjs` (new)

**Steps:**
1. Write tests for request metadata with `v: 3`, `sh_` IDs, `mode: auth|checkout|payment_confirmation`, `actionLabel`, typed fields, bounded options, and zero-field confirmation requests.
2. Write tests for `email`, `tel`, `number`, `card_number`, `card_expiry`, `cvc`, `otp`, `select`, and generic text classification without provider-specific branches.
3. Write tests that reject unknown field types, duplicate IDs, oversized field lists/options, labels with unsafe bounds, and confirmation payloads containing values.
4. Run the focused tests and confirm they fail for the expected missing-contract reasons.

Run:

```bash
python -m pytest tests/test_secure_handoff.py tests/test_handoff_adapters.py -q
node tests/frontend-checkout.test.mjs
```

Expected: FAIL because the v3 contract and checkout field types do not exist yet.

### Task 2: Implement the generic secure-handoff contract and typed frontend fields

**Files:**
- Modify: `plugin/secure_handoff.py`
- Modify: `plugin/handoff_adapters.py`
- Modify: `web/app.js`
- Modify: `web/index.html`
- Modify: `web/styles.css`

**Steps:**
1. Implement bounded v3 request creation and encrypted submission validation with exact field-ID matching and a field-free confirmation payload.
2. Add typed descriptors for text, email, tel, number, password, OTP, card number, card expiry, CVC, and select fields; keep labels/options bounded and nonsecret.
3. Render semantic controls only after a valid request, using safe `autocomplete`, input mode, labels, required state, select options, keyboard behavior, and mobile sizing.
4. Render checkout copy and a field-free `Authorize purchase` confirmation state without exposing price, page HTML, frame URLs, or browser values.
5. Clear plaintext inputs and encoded plaintext buffers on successful send, failure, pagehide, expiry, and duplicate submission.
6. Run the focused Python and frontend tests; confirm GREEN, then refactor only while tests remain green.

### Task 3: Add frame-aware, provider-neutral checkout binding

**Files:**
- Modify: `plugin/secure_handoff.py`
- Modify: `plugin/handoff_adapters.py`
- Modify: `tests/test_secure_handoff.py`
- Modify: `plugin/demo_site.py`

**Steps:**
1. Add a bounded candidate scanner for main-frame and HTTPS child-frame inputs/selects/textareas, using semantic attributes and accessible labels only.
2. Keep ordinary login stages distinct from checkout stages; detect checkout from supported payment types or a bounded payment-action label plus billing/checkout semantics, never from a named site.
3. Store private frame, document, scope, origin, and element bindings; expose only safe field metadata and the top-level target origin.
4. Add preflight checks for frame attachment, exact document generation, connected editable controls, frame-origin integrity, scope containment, same-origin form/action, and unique submit action.
5. Add synthetic same-origin and cross-origin frame fixtures with visible card/expiry/CVC inputs and a top-level payment action; ensure hCaptcha-like non-rendered helper frames are ignored while visible unsupported frames reject and later helper visibility invalidates the lease.
6. Run focused binding/fixture tests and confirm no field values or frame query strings appear in results or receipts.

### Task 4: Implement the two-stage checkout confirmation gate

**Files:**
- Modify: `plugin/secure_handoff.py`
- Modify: `tests/test_secure_handoff.py`
- Modify: `tests/test_parent_secure_handoff_flow.py` (renamed from `tests/test_parent_secure_handoff_flow.py`)

**Steps:**
1. Change normal checkout submission to decrypt and fill only; never click the checkout action in the same request.
2. Rebind the live checkout target and publish a fresh field-free `payment_confirmation` request with a fresh RSA key and request ID.
3. Accept only `{confirm:true}` for the confirmation request; reject `{values:...}`, stale IDs, replayed IDs, wrong owner/chat/thread, expired requests, changed scope, changed form/action, or changed target/frame generations.
4. On valid confirmation, click the exact bound payment action once, clear private keys, and report only a status-only receipt/wakeup.
5. After the click, re-probe the same context. Publish only a newly visible supported stage; otherwise report `submitted` without claiming payment or authenticated reuse.
6. Add tests for no-click-on-first-submit, confirmation-required, confirmation replay, stale-node rejection, wrong sender/thread rejection, and final-click-once behavior.

### Task 5: Rename the plugin, package, commands, files, manifests, and docs

**Files:**
- Rename: `plugin/secure_handoff.py` → `plugin/secure_handoff.py`
- Rename: `plugin/handoff_adapters.py` → `plugin/handoff_adapters.py`
- Rename: `plugin/connection_check.py` → `plugin/connection_check.py`
- Rename: `tests/test_secure_handoff.py` → `tests/test_secure_handoff.py`
- Rename: `tests/test_secure_handoff_controls.py` → `tests/test_secure_handoff_controls.py`
- Rename: `tests/test_handoff_adapters.py` → `tests/test_handoff_adapters.py`
- Rename: `tests/test_parent_secure_handoff_flow.py` → `tests/test_parent_secure_handoff_flow.py`
- Rename: `tests/test_connection_check.py` → `tests/test_connection_check.py`
- Rename: `SECURE_HANDOFF_CONTRACT.md` and `SECURE_HANDOFF_PROTOCOL.md` are the canonical protocol documents.
- Modify: `__init__.py`, `plugin/__init__.py`, `plugin/config.py`, `plugin/cli.py`, `plugin.yaml`, `plugin/plugin.yaml`, `pyproject.toml`, `package.json`, `package-lock.json`, `scripts/release_check.py`, `README.md`, `SECURITY.md`, `CONTRIBUTING.md`, `CHANGELOG.md`, `docs/compatibility.md`, `web/README.md`, CI/release workflows

**Steps:**
1. Rename Python/import/entry-point/plugin/tool/CLI identifiers to the canonical naming map.
2. Rename connection-test commands to `/handoffcheck` and `/handoffcancel`, and rename receipt files/messages/filter labels without removing the connection-test capability.
3. Replace auth-only documentation with generic secure-handoff terminology while retaining precise authentication, OTP, and checkout capability descriptions.
4. Update all tests, packaging metadata, artifact paths, and release assertions.
5. Search tracked files and built artifacts for stale public identifiers; any remaining `login` occurrences must be functional provider/login semantics, not the old product/package/plugin/CLI identity.

### Task 6: Add release checks for checkout safety and hard-rename completeness

**Files:**
- Modify: `scripts/release_check.py`
- Modify: `tests/test_distribution.py`
- Modify: `tests/frontend.test.mjs`, `tests/frontend-checkout.test.mjs`, `tests/qa-real-sdk.cjs`

**Steps:**
1. Assert canonical package/plugin/CLI/tool/repository/deployment names and version `1.0.0`.
2. Assert the static HTML remains free of credential controls before a valid request and only Telegram SDK plus local assets are loaded.
3. Assert CSP includes `connect-src 'none'`, no analytics/storage/cookies/fetch/XHR, no provider-specific selectors, and no secret-like values.
4. Assert wheel/sdist names include the renamed package and secure-handoff frontend/contract files while excluding local Vercel metadata, reports, receipts, and cache paths.
5. Run the redacted secret/path scan over the committed tree and archive contents.

### Task 7: Run the complete local verification ladder

**Steps:**

```bash
PLAYWRIGHT_CHANNEL=chromium npm test
npm run test:qa-real-sdk
python -m pytest tests/ -q -o 'addopts='
python -m build --sdist --wheel
python scripts/release_check.py
hermes plugins doctor . --ci
python -m py_compile plugin/*.py scripts/release_check.py
python -m compileall -q plugin tests
python - <<'PY'
from pathlib import Path
for path in Path('.').rglob('*'):
    if path.is_file() and '.git' not in path.parts and 'node_modules' not in path.parts:
        text = path.read_text(errors='ignore')
        assert 'telegram-secure-handoff' in text or path.suffix not in {'.toml', '.yaml', '.yml', '.md'}
print('canonical identity scan: PASS')
PY
git diff --check
```

Expected: all tests/build/release/Doctor/security checks pass with no stale public identity markers.

### Task 8: Publish the renamed public repository and shared deployment

**Steps:**
1. Commit the verified local implementation before any external rename.
2. Rename the public GitHub repository to `jmogainz/hermes-secure-handoff-telegram` and verify the repository URL/description/default branch.
3. Update `origin`, package URLs, installer instructions, and GitHub workflows; push `main`.
4. Rename or recreate the Vercel project as `hermes-secure-handoff-telegram`, deploy the verified `web/` directory, and verify the stable HTTPS alias, CSP, HTML, and JavaScript fingerprint without exposing environment values.
5. Do not purchase the new domain automatically. Check availability/pricing for `hermessecurehandoff.xyz` and pause for explicit paid-action confirmation.

### Task 9: Update the live Hermes runtime only after release verification

**Steps:**
1. Install the renamed GitHub plugin pinned to the verified commit with `--enable`.
2. Migrate the existing owner/CDP settings into the renamed namespace, replacing only the Mini App URL and plugin identifiers; never print the owner ID or secrets.
3. Disable the old plugin and verify only `telegram-secure-handoff` is enabled with the new tool override/configuration.
4. Restart the externally supervised gateway only after local and deployment gates pass.
5. Verify the live PID, plugin list, standalone Doctor, loopback CDP, fresh connection test, synthetic login handoff, synthetic checkout field handoff, confirmation gate, and status-only wakeup.
6. Close only task-created browser tabs/windows after verification; preserve pre-existing user tabs and browser profile data.

### Task 10: Update durable project memory and report honest limits

**Files:**
- Update: GBrain page `projects/secure-handoff-telegram`

Record only the durable architecture, canonical names, security boundaries, stable deployment URL, verification state, and domain purchase status. Do not record card data, account credentials, bot tokens, frame URLs with query parameters, receipt payloads, or transient task logs. Report separately what was verified locally, what was verified in the installed/live runtime, and what still requires Jacob's browser/payment action.
