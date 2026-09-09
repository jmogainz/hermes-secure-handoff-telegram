# Hermes Secure Handoff Telegram Mini App

`web/` is a static, dependency-free Telegram Mini App. It can be deployed once at an official shared HTTPS URL or self-hosted by each operator.

## Hosting model

The page has no backend, database, cookies, analytics, account system, or bot token. Hermes puts a short-lived request in the URL fragment. The Mini App validates that request, creates the user-visible controls, encrypts the submitted payload locally, and sends it through Telegram `WebApp.sendData()`.

Each operator still has a separate:

- Telegram bot and gateway;
- owner Telegram ID and private chat/thread;
- Hermes profile;
- dedicated Chrome profile and loopback CDP endpoint;
- RSA request key and one-time request ID.

The request fragment must survive static hosting unchanged. Serve `index.html`, `app.js`, `styles.css`, and `vercel.json` from the same HTTPS origin.

## Official shared deployment

The canonical deployment is:

```text
https://hermes-secure-handoff-telegram.vercel.app
```

No custom domain registration or DNS attachment is established by this release.

The domain owner is a trusted code publisher. The page can read a value before it encrypts that value for Hermes. Self-host the Mini App if you do not want to trust the official deployment publisher, especially before entering card fields.

## Self-hosting

Any static HTTPS host works. The host must not add a query string, rewrite, or proxy request values.

```bash
# Link the repository root to a project whose Root Directory is web.
vercel link --yes --project <project-name> --token "$VERCEL_TOKEN"
vercel deploy --prod --token "$VERCEL_TOKEN"
```

Never upload `.env`, browser profiles, cookies, Hermes session files, or OAuth state. Configure the chosen URL with:

```bash
telegram-secure-handoff setup \
  --mini-app-url https://your-handoff.example \
  --user-id 123456789
```

## Native iOS autofill metadata

The Mini App creates standard fields only after validating a request:

- `username` / `autocomplete="username"` for authentication identifiers;
- `password` / `autocomplete="current-password"` for login secrets;
- `autocomplete="one-time-code"` with numeric input mode for OTP;
- `autocomplete="cc-number"`, `cc-exp`, and `cc-csc` for supported checkout fields.

These hints allow Telegram's iOS WebView to offer the keyboard, OTP suggestion, and Passwords UI when supported by the device and Telegram version. Apple still matches saved credentials and payment autofill to this Mini App origin. The target website origin in the request cannot override that browser security rule.

## Secure handoff modes

The frontend accepts:

- v1 fixed connection-test requests;
- v3 typed `auth` requests;
- v3 typed `form` requests, with fill-only authority;
- v3 typed `checkout` requests;
- v3 `purchase_approval` requests only when Hermes supplies a fresh immutable
  observed-action contract and the user explicitly taps **Complete purchase**;
- legacy v3 `payment_confirmation` metadata is recognized but blocked, with no
  submit action.

Checkout requests may contain bounded text, email, phone, number, password, OTP,
card number, card expiry, CVC, and select fields. Frame-aware checkout fields
may carry a bounded numeric `frameOrdinal` only; it is not a frame URL or a
selector. The frontend never receives prefilled values in request metadata.

General forms add textarea, checkbox, radio-as-select, date/time/month/week/local-datetime, URL, search, color and supported range controls. See `../docs/compatibility.md` for exact scope and limitations. Validation failures identify the field and clear entered values; cancellation/expiry/page teardown also scrub entries and prevent delayed encryption from sending.

## Security boundary

- The URL fragment is not sent to the static host's server in normal browser requests.
- The frontend makes no application network calls beyond the official Telegram SDK script.
- Values are encrypted with AES-GCM and an RSA-OAEP-wrapped key before `sendData()`.
- The frontend clears controls and plaintext byte buffers after encryption and on `pagehide`.
- CAPTCHA, 3DS, MFA, passkeys, provider security checks, and final payment results remain user/provider-owned.
