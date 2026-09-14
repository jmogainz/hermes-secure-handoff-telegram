# Secure Handoff Contract — Transport-Only v4

## Purpose

Secure Handoff moves user-entered sensitive values from a Telegram Mini App into exact browser controls without exposing those values to the model, chat, logs, receipts, or public request metadata.

The plugin is a **transport and mechanical executor**. It is not a webpage interpreter.

## Responsibilities

The plugin owns only:

- encrypted Mini App requests and submissions;
- exact Telegram owner and private-chat binding, plus exact topic binding when Telegram supplies it; a topicless Web App service callback is routed by a unique request ID within that owner/chat scope;
- request expiry, one-time use, and replay protection;
- exact attachment to one existing HTTPS Chrome target and a unique per-flow `session_ref`;
- short-lived opaque control refs produced by generic inventory;
- mechanical execution of the exact agent-selected operation strategy;
- separate, explicit, one-time owner approval for a consequential action;
- secret and private-handle cleanup;
- status-only acknowledgements, receipts, and wakeups.

The plugin does **not** decide:

- what kind of website or form is open;
- whether a field is an identifier, password, OTP, billing field, or provider stage;
- whether an input value “stuck” or passed site validation;
- whether a page rerender, route change, or button state is good or bad;
- whether authentication, registration, checkout, payment, or another workflow succeeded;
- what the next browser step should be.

Those judgments belong to Goku after inspecting the exact live browser, followed by discussion with Jacob when a decision or authorization is needed.

## State flow

```text
attach exact target
  -> receive a fresh session_ref
  -> inventory generic controls
  -> agent composes entry or action-approval request
  -> owner submits encrypted payload
  -> transport validates owner/session/request/crypto/expiry/replay
  -> executor attempts each exact operation once
  -> execution_complete
  -> status-only wakeup
  -> Goku inspects the live browser
```

Every action after `attach` is scoped by its returned `session_ref`. This allows
independent flows in the same Telegram topic without replacing one another;
the exact browser-target lease remains exclusive.

## Status meanings

### `attached`

The controller holds the exact existing Chrome target. It says nothing about page content.

### `inventory_available`

A generic inventory was captured and opaque refs were minted. It says nothing about which controls should be used.

### `waiting_for_handoff`

The Mini App request was published. It says nothing about Telegram rendering or callback delivery.

### `execution_complete`

The encrypted callback passed transport authorization, execution began, and every planned operation was attempted once.

It does **not** mean:

- fields were accepted;
- site validation passed;
- a provider request was sent;
- authentication succeeded;
- an action took effect;
- a purchase completed.

Mechanical browser exceptions may be summarized only as bounded counts and safe categories. They do not turn an accepted execution into a semantic webpage rejection.

### `rejected`

Reserved for failures before browser execution begins: wrong owner/chat/topic, wrong or stale session/request, invalid crypto or payload shape, expiry, replay, ambiguous target attachment, or unauthorized control reference.

`rejected` is never a provider or webpage decision.

## Entry execution

The agent selects opaque editable-control refs from the latest inventory and supplies only public UI metadata plus a strategy:

- `keyboard`
- `fill`
- `select`
- `check`

The plugin decrypts values only immediately before the matching browser call. It never returns or logs values and never reads them back to judge success. Entry execution never selects or clicks a submit, Continue, Sign In, Buy, or Pay control. Any applied keyboard, fill, selection, or check operation may activate destination handlers, including submission or navigation.

An entry field may use an installed data-only component descriptor. Version 2.1 includes `segmented_code`, which is required, 4–12 characters long, and either digits-only or ASCII alphanumeric. One value may bind to one exact control or use explicit `split_chars` fan-out across exact inventoried refs. The plugin does not detect OTPs or choose the binding.

An entry request may include a `secure-handoff.ui/1` view made from `stack`, `row`, `section`, `text`, `divider`, and `field` nodes. Every field must appear once. The plugin rewrites private refs to public field IDs. The view cannot contain actions, code, URLs, styles, hidden fields, or conditional behavior. Unknown schema versions or nodes reject before publication.

The controller accepts at most 24 browser operations per entry request and gives each operation a 10-second timeout.

## Consequential actions

Actions use a separate `action_approval` request bound to one exact opaque action ref and one approval nonce. The owner must explicitly approve it in the Mini App. The capability is consumed before the click attempt and is never automatically retried.

The receipt reports only mechanical completion. Provider outcome still requires live-browser inspection. Passkeys, MFA, CAPTCHA, and provider security prompts remain user-operated.

## Privacy

Public metadata may contain bounded labels, field types, strategies, installed component metadata, a versioned data-only layout, origins, and an agent-authored action summary. Visible strings reject control characters, Unicode format/invisible characters, bidirectional overrides, and URI schemes. Public metadata never contains browser selectors, HTML, current values, cookies, storage, tokens, ciphertext, private keys, or full URLs with query/fragment data.

Receipts and wakeups contain only status, request kind, operation counts, safe error categories, origin, and routing metadata. Exception text and DOM text never enter them.
