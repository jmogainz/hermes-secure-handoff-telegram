# V2 browser-login MVP contract

This supersedes v1's no-browser milestone while retaining `/logincheck` and v1 unchanged. The first real iPhone v1 encrypted transport test passed. V2 is a Telegram-specific plugin with no Semreh dependency, no Hermes core patch, no new public listener, and no second bot poller.

## Browser ownership

Hermes already runs the installed Google Chrome app at `/Applications/Google Chrome.app` with its own persistent profile at `~/.hermes/chrome-debug` and local CDP endpoint `http://127.0.0.1:9222`. The plugin **attaches to that existing Chrome** with Playwright `connect_over_cdp`; it never launches a second browser, creates an isolated production context, adopts Jacob's everyday Chrome profile, exports cookies, or closes the user's Chrome process.

The plugin reuses the Hermes Chrome default context and page targets for `telegram_browser.open/attach/present/read/click/type/wait/close`. `open` is for starting a fresh navigation; `attach` selects one existing page by exact HTTPS origin without navigating it, and `present` republishes the currently live stage without reloading it. Cookies, local storage, and authenticated site sessions therefore remain in the same Hermes browser profile and are available to later Hermes browser work. Closing a plugin session only clears its pending request and disconnects Playwright; it does not close Chrome or erase profile data. A site may still expire, revoke, or invalidate its session.

The controller is owner-scoped to the Telegram user/chat/thread and runs on the existing native Telegram gateway loop. Model tool dispatch schedules coroutines onto that loop. The controller has a 10-minute request TTL, 30-minute idle cleanup, max four logical sessions, and never reports success for an action it did not execute.

## Encrypted Mini App submission

Fragment remains `#request=<base64url UTF8 JSON>` and supports Telegram-appended hash parameters. Launch metadata is `{v:2,id:'bl_'+random,publicKey:<RSA public JWK>,expiresAt:<epoch ms>,origin:<HTTPS origin only>,fields:[{id:'f0',label:'Username or email',type:'text',required:true},...],demo:<boolean>}`. It includes only a flat safe field list; never HTML, selectors, prefilled values, query strings, or browser values.

The Mini App encrypts UTF-8 `{values:{f0:<string>,...}}` with a random AES-256-GCM key and request-ID AAD, wraps that key with RSA-OAEP/SHA-256, and sends only `{v:2,id,wrappedKey,iv,ciphertext}` through `Telegram.WebApp.sendData()`, capped at 4096 UTF-8 bytes. Plaintext is capped at 2048 bytes and each field at 512 characters. Values are cleared after encryption and on pagehide. No credential values are fetched, stored, logged, or returned to the model.

## Login binding and ordinary browsing

Probe eligible visible main-frame username/email, password, and one-time-code controls in one unambiguous target scope. A logical OTP stage may be represented by one control or a bounded contiguous group of digit inputs; group ordinal-labeled/numeric digit controls into one encrypted `one-time-code` field and never expose one Mini App field per digit. Grouped OTP widgets may auto-submit after the final digit and have no submit/action control, so the submit handle is optional only for that exact OTP stage; verify the resulting same-flow transition instead of inventing a click. Preserve the existing max-four logical fields, bounded OTP-part count, same form/scope/document/origin checks, target-aware rebind after rerenders, and staged auth rules. The core controller is target-neutral; small adapter descriptors supply provider-specific semantic hints for unusual controls without storing provider values in the protocol. Support native forms and explicitly adapter-approved form-less controls under the same document/scope/origin checks. Support one combined form or staged auth: username/email-only → fresh password/OTP-only, password/OTP-only, and standard username/email + password/OTP forms. After each stage submit or verified auto-submit, re-probe the live target and mint a new one-time request ID/key; never pre-request or predict a later secret. Exclude hidden, inert, transparent, disabled, readonly, pointer-events-none, and non-editable controls. Refuse ambiguous targets, ambiguous scopes, SSO/passkey/CAPTCHA-only flows, arbitrary widgets, and unsupported navigation. Hold exact ElementHandles and target/document/form-or-scope identity privately. Before decrypting and again before mutation, verify the same page/document/origin/group and exact logical stage; never log or return values.

When ordinary browser-tool work detects a login form, the plugin publishes the encrypted Mini App keyboard in the same Telegram thread and returns `waiting_for_login`; it reuses the existing page/request rather than launching a separate browser or duplicate prompt. Model `type` is restricted to nonsecret fields and cannot bypass the auth handoff. Safe snapshots omit forms, inputs, textareas, selects, scripts, styles, values, cookies, storage, screenshots, and auth-query URLs. Status-only receipts contain only version, request ID, status, thread, and timestamp.

The only plugin tool is `telegram_browser` with `open`, `attach(origin)`, `present`, `read`, `click(ref)`, `type(ref,text)` for nonsecret inputs, `wait(timeout<=90)`, and `close`. `attach`/`present` are the required path for an existing OAuth/SSO popup or other live stage; never call `open` on an active password, OTP, provider chooser, or signup stage. Plugin-specific `/browserdemo`, `/browserlogin`, `/browserstatus`, and `/browserclose` commands are removed. Hermes's built-in `/browser` command remains separate and is not modified.

## Testing fixture

`plugin/demo_site.py` remains a local synthetic HTTPS fixture for automated tests only. Its dummy credentials are `demo` / `demo-pass`; its protected page reports `Demo account verified`; callers close the fixture. Certificate-ignore behavior is enabled only for the synthetic test path. Real `/open` browser work continues to require normal valid HTTPS.

## Verification gates

The final gate must include the full Python suite, V1/V2 frontend tests, deployed asset verification, native encrypted web-app-data handling, real Playwright form fill/submit, same-context protected-page reuse, wrong sender/replay/stale-node/cancel cases, plugin loader/tool registration, and a live CDP attach probe that proves disconnecting the plugin does not close the Hermes Chrome endpoint. Actual phone V2 and any real-provider login remain user-owned checkpoints; never request real credentials in chat.
