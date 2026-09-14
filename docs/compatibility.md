# Compatibility

## Supported contract

Version 2.1 uses protocol v4 for secure entry and action approval. The connection diagnostic remains protocol v1. Protocol v4 now accepts the versioned `secure-handoff.ui/1` layout tree while keeping legacy flat field lists valid.

The controller attaches to one existing HTTPS page in the configured loopback Chrome CDP context and inventories generic controls across the top document and reachable child frames.

Structural support:

- native text-like `input` and `textarea` controls;
- native `select` controls by exact visible option label;
- checkbox and radio controls;
- `contenteditable` controls;
- ARIA textbox/searchbox/combobox controls through keyboard delivery;
- focusable custom widgets through agent-selected keyboard delivery;
- buttons, links, and ARIA buttons through separate owner-approved action requests.
- one-value segmented code controls with exact 4–12 character validation;
- agent-composed `stack`, `row`, `section`, `text`, `divider`, and `field` layouts;
- optional mechanical `split_chars` fan-out from one segmented value to exact inventoried controls.

Strategies:

- `keyboard` — focus, select existing content, then type key events;
- `fill` — Playwright fill call;
- `select` — exact option-label selection;
- `check` — explicit true/false checked state;
- `click` — action approval only.

## Deliberate non-guarantees

No deterministic executor can prove compatibility with every custom widget, virtualized control, canvas UI, shadow-DOM component, provider event model, or mid-execution rerender. Protocol v4 handles that uncertainty by refusing to make a webpage verdict: it finishes the mechanical attempt, wakes Goku, and requires live inspection.

The data-only layout tree can compose new views at runtime, but it cannot add executable widget behavior. Passkeys, CAPTCHAs, OS dialogs, file pickers, custom canvas input, and unsupported browser operations stay user-operated until an audited executor release adds them. The Mini App never loads request-supplied code.

The plugin does not select or click submit after entry. Any applied keyboard, fill, selection, or check operation may activate destination handlers, including submission or navigation. That is provider behavior, not an implicit plugin action or proof of success.

A detached node, timeout, or browser exception does not become a provider rejection. It appears only as a safe mechanical error count/category. Goku may inspect, choose another strategy or fresh ref, and discuss a retry with Jacob.

## Cross-frame behavior

Each opaque ref points to the exact inventoried element handle in its owning frame. Frame origins are exposed without path/query/fragment data. The plugin does not automatically substitute a same-looking element after replacement. A stale handle produces a mechanical error; Goku decides what to do next.

## Status meanings

- `attached` — exact page held.
- `inventory_available` — generic refs minted.
- `waiting_for_handoff` — Mini App publication call returned successfully.
- `execution_complete` — valid callback accepted and every operation attempted once.
- `publication_failed` — Telegram publication call failed.
- `expired`, `cancelled`, `closed`, `unavailable` — controller lifecycle states.
- `rejected` — pre-execution transport or authorization refusal only.

None of these statuses proves website acceptance, provider authentication, or transaction completion.
