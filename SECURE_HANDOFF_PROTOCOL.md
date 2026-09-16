# Secure Handoff Protocol v4

## Overview

Protocol v4 is an owner-scoped encrypted transport plus a generic browser executor. Browser interpretation is deliberately outside the protocol.

Telegram callbacks must match the publishing owner and the exact private handoff chat. A flow may be attached from an authorized group chat or forum topic: the encrypted entry is still published to, and submissions are still accepted only from, the owner's private chat; the recorded origin (chat, chat type, and routable topic) is used only for completion wakeups and exact cancellation. Telegram may omit the topic ID from a Web App service message. In that case, the request ID must resolve to exactly one live flow for the same owner and private chat; zero or duplicate matches reject without consuming or executing any flow.

## Tool actions

### `attach`

Input:

```json
{"action":"attach","origin":"https://example.com","ref":"<optional exact 32-hex target id>"}
```

Behavior:

- attaches to an existing HTTPS page without navigation;
- uses the exact target ID when supplied;
- rejects ambiguous origin-only attachment;
- returns a fresh opaque `session_ref` that identifies this flow;
- performs no form or stage discovery.

Every action after `attach` requires that returned `session_ref`. Multiple flows
may use the same owner/chat/topic, but each flow must have a different exact
browser target. A target lease is never shared or replaced.

### `inventory`

Input:

```json
{"action":"inventory","session_ref":"ss_..."}
```

Output contains generic controls only:

```json
{
  "status":"inventory_available",
  "snapshot_ref":"sn_...",
  "refs":[
    {
      "ref":"fr_...",
      "category":"editable",
      "capabilities":["keyboard","fill"],
      "frame_origin":"https://example.com",
      "frame_ordinal":0,
      "ordinal":1,
      "visible":true,
      "enabled":true,
      "editable":true
    }
  ]
}
```

No selector, value, HTML, full URL, cookie, or storage data is returned.

### `present_entry`

Input:

```json
{
  "action":"present_entry",
  "session_ref":"ss_...",
  "snapshot_ref":"sn_...",
  "fields":[
    {
      "ref":"fr_...",
      "label":"Account identifier",
      "type":"text",
      "required":true,
      "strategy":"keyboard"
    }
  ]
}
```

The browser ref remains private. The public Mini App request receives a generated field ID and the supplied UI metadata.

Each field may include a strictly validated `component`. Version 2.1 installs `segmented_code`, a required 4–12 character digits-only or ASCII-alphanumeric control. A field may also include `binding: {"mode":"split_chars","refs":[...]}`. The primary ref receives character zero and each additional exact ref receives the next character. The controller caps the entire entry plan at 24 browser operations.

`present_entry` may include a `secure-handoff.ui/1` data-only `view`. Its root is `stack`; nested node kinds are `stack`, `row`, `section`, `text`, `divider`, and `field`. Every field must appear exactly once. The plugin rewrites private refs to generated field IDs before publication. See [docs/components.md](docs/components.md).

### `present_action`

Input:

```json
{
  "action":"present_action",
  "session_ref":"ss_...",
  "snapshot_ref":"sn_...",
  "action_ref":"ar_...",
  "summary":"Perform the selected browser action"
}
```

This publishes a separate explicit approval request. Approval authorizes one attempt on that exact private ref. There is no selector rebinding and no retry after dispatch uncertainty.

### `read`

Input:

```json
{"action":"read","session_ref":"ss_..."}
```

Returns that flow's safe status. For completed execution, the result is mechanical evidence only:

```json
{
  "status":"execution_complete",
  "request_kind":"entry",
  "operations_requested":1,
  "browser_calls_returned":1,
  "browser_errors":0,
  "browser_error_categories":[]
}
```

### `close`

Input:

```json
{"action":"close","session_ref":"ss_..."}
```

Closes that flow's controller state and releases private refs. It does not close the browser page.

## Public Mini App request

Entry request:

```json
{
  "v":4,
  "id":"sh_...",
  "kind":"entry",
  "origin":"https://example.com",
  "expiresAt":0,
  "publicKey":{"kty":"RSA","n":"...","e":"AQAB"},
  "fields":[
    {
      "id":"f0",
      "label":"Verification code",
      "type":"tel",
      "required":true,
      "strategy":"keyboard",
      "component":{
        "kind":"segmented_code",
        "length":6,
        "alphabet":"digits"
      }
    }
  ],
  "view":{
    "schema":"secure-handoff.ui/1",
    "kind":"stack",
    "children":[{"kind":"field","field":"f0"}]
  }
}
```

Action approval request:

```json
{
  "v":4,
  "id":"sh_...",
  "kind":"action_approval",
  "origin":"https://example.com",
  "expiresAt":0,
  "publicKey":{"kty":"RSA","n":"...","e":"AQAB"},
  "approvalNonce":"approve_...",
  "summary":"Perform the selected browser action"
}
```

## Encrypted submission

Outer envelope:

```json
{
  "v":4,
  "id":"sh_...",
  "wrappedKey":"...",
  "iv":"...",
  "ciphertext":"..."
}
```

Cryptography:

- fresh AES-256-GCM key per submission;
- 96-bit IV;
- plaintext encrypted with request ID as AAD;
- AES key wrapped with request RSA-2048 public key using OAEP SHA-256;
- strict JSON parsing rejects duplicate keys, unknown members, invalid constants, malformed base64url, and oversized payloads.

Entry plaintext:

```json
{"values":{"f0":"<user-entered value>"}}
```

Action plaintext:

```json
{"approve":"approve_..."}
```

## Execution semantics

Once transport validation succeeds:

1. consume the request ID;
2. decrypt immediately before execution;
3. attempt each exact operation once with a 10-second per-operation timeout and a 24-operation request cap;
4. continue entry operations after bounded browser exceptions;
5. record only requested/returned/error counts and safe categories;
6. scrub plaintext, key material, request, and private control refs;
7. send a status-only acknowledgement and wakeup;
8. let Goku inspect the live browser.

The executor never performs value readback, validity checks, provider-stage inference, mutation-epoch checks, navigation-success inference, or automatic submit discovery. It never selects or clicks a continuation control during entry. Any applied keyboard, fill, selection, or check operation may activate destination handlers, including submission or navigation, so Goku must inspect the live result.

## Safe error categories

Only these browser-execution categories are exposed:

- `detached`
- `timeout`
- `browser_error`

Raw exception text is private and discarded.

## Rejection boundary

`rejected` is allowed only before execution starts for transport or authorization failures. Website behavior after execution starts is never converted into `rejected` and is never labeled success or failure by the plugin.
