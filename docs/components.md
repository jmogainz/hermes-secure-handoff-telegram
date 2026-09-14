# Agent-composed Mini App UI

## What "extensible" means

Goku builds each sensitive-entry view from live browser evidence. The request is data, not executable code. The static Mini App validates and renders that data, encrypts owner-entered values, and returns one bounded submission.

This supports new layouts and combinations without provider-specific frontend code. It does not execute request-supplied HTML, Markdown, JavaScript, CSS, URLs, templates, expressions, validators, event handlers, or network resources.

Literal support for every browser interaction is impossible without giving runtime-supplied code access to secrets. The safe target is broad data-entry coverage, plus direct user takeover for passkeys, CAPTCHAs, OS dialogs, file pickers, custom canvases, and other controls outside the installed executor.

## Contract layers

The system keeps three layers separate:

1. **Public UI description.** Field labels, field types, safe component metadata, the target origin, and an optional `secure-handoff.ui/1` layout tree.
2. **Private execution plan.** Exact opaque browser refs, retained element handles, strategies, and optional character fan-out. The Mini App never receives this plan.
3. **Value contract.** The plugin validates decrypted values against the public field description immediately before the fixed browser operations. Values never enter model context, chat, receipts, or logs.

The UI description cannot grant browser authority. Only refs from the latest attached inventory can enter the private plan.

## Core controls

A field uses one of the installed safe HTML control types and one mechanical strategy:

- text-like inputs and `textarea` with `keyboard` or `fill`;
- `select` with exact visible-label selection;
- checkbox or radio state with `check`;
- `segmented_code`, a required 4–12 character digits-only or ASCII-alphanumeric value with `keyboard`.

The agent may combine up to 24 fields. The controller allows at most 24 browser operations in one entry request. This bounds character fan-out as well as ordinary fields.

### Segmented code

`segmented_code` is a first-class Mini App control that collects one scalar value:

```json
{
  "ref": "fr_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
  "label": "Verification code",
  "type": "tel",
  "required": true,
  "strategy": "keyboard",
  "component": {
    "kind": "segmented_code",
    "length": 6,
    "alphabet": "digits"
  }
}
```

The Mini App preserves the exact characters entered. It does not silently strip separators, truncate, or change case. It does not use native `maxlength` truncation. The frontend and backend count Unicode code points consistently and validate the complete submitted sequence. The Mini App does not enable OTP autocomplete on its origin.

For controls that distribute keystrokes themselves, bind the whole value to the first exact ref as shown above. For independent browser inputs, Goku may request explicit mechanical character fan-out:

```json
{
  "ref": "fr_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
  "label": "Verification code",
  "type": "tel",
  "required": true,
  "strategy": "keyboard",
  "component": {
    "kind": "segmented_code",
    "length": 6,
    "alphabet": "digits"
  },
  "binding": {
    "mode": "split_chars",
    "refs": [
      "fr_BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
      "fr_CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC",
      "fr_DDDDDDDDDDDDDDDDDDDDDDDDDDDDDD",
      "fr_EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE",
      "fr_GGGGGGGGGGGGGGGGGGGGGGGGGGGGGG"
    ]
  }
}
```

The primary ref receives character zero. Each additional ref receives the next character. The plugin performs no OTP detection and makes no provider judgment.

## On-demand layout

`present_entry` may include a versioned layout tree:

```json
{
  "schema": "secure-handoff.ui/1",
  "kind": "stack",
  "children": [
    {
      "kind": "text",
      "text": "Enter the value shown by the destination service.",
      "tone": "muted"
    },
    {
      "kind": "section",
      "title": "Verification",
      "children": [
        {"kind": "field", "ref": "fr_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}
      ]
    }
  ]
}
```

Installed node kinds:

- `stack`
- `row`
- `section`
- `text`
- `divider`
- `field`

Limits:

- exact schema string `secure-handoff.ui/1`;
- root node must be `stack`;
- at most 64 nodes, depth 6, and 24 children per container;
- every requested field appears exactly once;
- field leaves use exact opaque refs in the tool call;
- the plugin rewrites refs to generated `fN` IDs before publication;
- unknown keys, node kinds, schema versions, duplicate fields, missing fields, and unknown refs reject before publication;
- visible agent-authored text rejects control characters, Unicode format/invisible characters, bidirectional overrides, and URI schemes.

The renderer uses `textContent` and fixed CSS classes. Agent content cannot position, hide, overlay, style, link, navigate, fetch, persist, submit, or run code.

## System-owned chrome

The request cannot modify:

- the displayed target origin;
- the encryption/privacy explanation;
- field-source labeling;
- Send and Cancel controls;
- action-approval UI;
- expiry/error screens;
- Telegram callback behavior.

Entry and action authority stay separate. A view tree cannot contain an action control.

## Lifecycle

The Mini App:

- rejects expired requests before mounting inputs;
- schedules a live expiry timer;
- rechecks expiry on `pageshow` after freeze or back-forward restoration;
- clears plaintext on send, cancel, errors other than local field correction, `pagehide`, `freeze`, and expiry;
- invalidates an in-flight WebCrypto submission on cancel, `pagehide`, `freeze`, or expiry and rechecks request identity, generation, and freshness after every asynchronous boundary;
- rejects duplicate JSON keys and plaintext over 2,048 UTF-8 bytes before encryption;
- removes fields when the request expires;
- treats JavaScript and Python memory clearing as best effort, not a guarantee against a hostile process with memory access.

The browser executor gives each browser operation a 10-second timeout and accepts at most 24 operations per request. It attempts operations in the approved order and reports only returned-call and error counts.

## Destination reaction caveat

The plugin never selects or clicks a submit or continuation control during entry. Any applied keyboard, fill, selection, or check operation may activate destination handlers, including submission or navigation. Goku must explain that risk when it matters and inspect the same live browser after the callback.

## Extension model

The current release does not load runtime extensions. New layouts are already created on demand from the installed node and field set.

A future executable extension system must be a separate trust-boundary change. At minimum it would require reviewed and reproducible builds, a pinned offline signing key, a locally protected allowlist, exact version and hash binding, schema-checked public parameters, revocation, and hard rejection of unknown extensions. A signature proves provenance, not safety. Any renderer that can see plaintext belongs in the audited Mini App release, not in request data.
