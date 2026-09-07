# Telegram Login MVP — transport spike

Scope: prove real Telegram keyboard Mini App submission in user's private threaded chat; no browser login or real credentials in this first gate. No dependencies on Semreh code or edits to Hermes core. Plugin installed separately after verification. Use existing Telegram PTB Application, never getUpdates or a second poller.

## Shared wire contract (v1)
Launch URL fragment: `#request=<base64url(UTF8 JSON)>`.
JSON: `{v:1,id:<random opaque request id>,publicKey:<RSA public JWK>,expiresAt:<unix epoch milliseconds>}`.
RSA-OAEP SHA-256, 2048-bit key minimum. Never send private keys. URL metadata is public/nonsecret; possession is not authorization.
Frontend encrypts FIXED ASCII plaintext `telegram-roundtrip-ok` with WebCrypto RSA-OAEP. NO EDITABLE INPUT FIELDS; prominently 'Connection test — no passwords'. Plaintext must never be accepted from URL or input.
Telegram sendData JSON: `{v:1,id:<id>,ciphertext:<base64url RSA ciphertext>}`. Total <=4096 UTF8 bytes. Keyboard launch only. No fetch/POST to any backend. Telegram SDK via official https://telegram.org/js/telegram-web-app.js only; own JS/CSS same origin.
Plugin matches WEB_APP_DATA; rejects wrong sender, wrong chat, unknown/expired/used IDs, malformed keys/base64/oversize/ciphertext; does not print payload or decrypt result. It compares plaintext to fixed dummy marker. Return only status. Single use even on concurrent submissions; bound failure behavior, TTL 10 min, max pending 32, at most one active per user. Store in memory; restart invalidates pending entries. Safe local status receipt only IDs/status/time/thread, never ciphertext/key/value. This is not a security-isolation claim.

## UX
`/logincheck` (private allowlisted owner only) sends a ReplyKeyboardMarkup with KeyboardButton(web_app=WebAppInfo(url=...)) labelled 'Open connection test'; message clearly says no passwords and command to cancel `/logincancel`. Orig user/chat/thread mapping retained locally; reply success to original thread even if incoming service event arrives root/other thread. Remove keyboard on success/cancel. Use Telegram-native theme, big accessible button, 'Send test' button, expired/missing/unsupported errors. Telegram initData may be empty for keyboard launch: do not require it. Support via Telegram.WebView.initParams.tgWebAppData presence? Do not guess environment: official SDK sendData exists and Telegram.WebApp.platform != 'unknown' + init context; use tests to mimic keyboard launch. Never show success until Telegram service handler acknowledges in chat; UI can say 'Sending…'.

## Configuration
Plugin uses documented ctx.get_config() keys `mini_app_url` HTTPS host without credentials/query/fragment, `allowed_user_ids` explicit numeric array (fail closed missing). No bot tokens read by plugin; use context.bot / native Application. Add scoped native command and WEB_APP_DATA handlers with priority before core generic handlers, blocking Stop propagation after owned update. Preserve other commands/callbacks and unrelated web_app_data.

Paths: frontend developer owns web/* and frontend browser tests; plugin developer owns plugin/* and Python tests plus plugin docs; parent owns CONTRACT/README/deployment/orchestration. No workers modify ~/.hermes, configs, services, credentials, deploy, commit or push. Use existing Hermes venv for pytest/cryptography/PTB. Reports must identify tests actually run versus deferred real-device test.
