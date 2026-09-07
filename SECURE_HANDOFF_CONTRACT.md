# Hermes Secure Handoff Telegram contract

## Scope

Hermes Secure Handoff Telegram provides two Telegram Mini App transports:

1. a fixed v1 connection check for validating Telegram keyboard delivery;
2. a v3 encrypted handoff for typed authentication and checkout stages.

The plugin uses the existing Hermes Telegram application. It never starts a second Telegram polling loop and never accepts a bot token as a plugin argument.

## v1 connection check

The private owner-only `/handoffcheck` command sends a keyboard button labelled `Open connection test`. `/handoffcancel` clears the pending check. The request fragment contains a short-lived RSA public key and opaque request ID. The Mini App encrypts only the fixed marker `telegram-roundtrip-ok` with RSA-OAEP SHA-256 and sends it through Telegram `WebApp.sendData()`.

The plugin accepts the marker only from the exact owner, private chat, and originating thread that created the request. Requests expire, are single-use, and produce status-only receipts.

## v3 secure handoff

The launch fragment contains public metadata only:

```json
{
  "v": 3,
  "id": "sh_<opaque-id>",
  "publicKey": "<RSA public JWK>",
  "expiresAt": 0,
  "origin": "https://target.example",
  "provider": "generic",
  "stage": "identifier",
  "mode": "auth",
  "actionLabel": "Submit to browser",
  "fields": [
    {"id":"f0","label":"Username or email","type":"text","required":true}
  ],
  "demo": false
}
```

Supported modes are `auth`, `checkout`, and `payment_confirmation`. Supported field types are `text`, `email`, `tel`, `number`, `password`, `otp`, `card_number`, `card_expiry`, `cvc`, and `select`.

`payment_confirmation` requests must contain an empty `fields` array and accept only this decrypted body:

```json
{"confirm":true}
```

Normal v3 requests accept only:

```json
{"values":{"f0":"<user-entered-value>"}}
```

The server checks exact field IDs, required values, type/length limits, expiry, key binding, AES-GCM authentication, and one-time request use. It never logs the decrypted body.

## Checkout gate

A checkout stage may include registrant, billing, payment, and select fields. Hermes fills the exact live controls after decrypting the first request, then publishes a fresh confirmation request with a new key and ID. It does not click the bound `Buy`, `Pay`, `Purchase`, `Place order`, or equivalent action until the user submits the field-free confirmation request.

The final action remains subject to live origin, scope, frame, document-generation, visibility, editability, and action-target checks. A click is not proof that a provider accepted a charge.

## Browser and Telegram boundaries

- One positive owner Telegram ID is allowed per Hermes/browser profile.
- The full `(user, chat, thread)` identity owns each request.
- CDP accepts only loopback HTTP endpoints.
- The controller uses the existing dedicated browser context and does not export cookies or storage.
- Passwords, OTPs, card values, CVCs, CAPTCHA answers, passkeys, MFA values, cookies, tokens, and storage state never enter model messages, logs, screenshots, receipts, or chat.
- CAPTCHA, 3DS, MFA, passkeys, provider security pages, redirects, and purchase outcomes remain user/provider-owned.
- The static Mini App is a trusted code-publisher boundary. Self-host it when the official host should not see pre-encryption input.

## Native autofill

The Mini App uses `autocomplete="username"`, `current-password`, `one-time-code`, `cc-number`, `cc-exp`, and `cc-csc` where appropriate. Telegram's iOS WebView may show keyboard, OTP, or Passwords suggestions. Apple still matches saved credentials and payment autofill to the Mini App origin. The target website origin cannot override that rule.

## Status vocabulary

`waiting_for_handoff` means a new Mini App request was published. `waiting_for_confirmation` means checkout fields were applied and the browser is waiting for the separate authorization action. `submitted` means Hermes performed the bound browser action. `stage_submitted` means the page exposed another recognized stage. `rejected` means Hermes failed closed. None of these statuses alone proves authentication or payment success.
