# Verification

Run the complete release gate:

```bash
python -m pytest -q -o 'addopts='
python -m pytest tests/test_declarative_components.py -q -o 'addopts='
PLAYWRIGHT_CHANNEL=chromium node tests/frontend.test.mjs
python -m compileall -q plugin
python -m build
python scripts/release_check.py
```

Coverage includes:

- encryption, exact owner/topic scope, expiry, replay, target and ref authority;
- mechanical `execution_complete` receipts and callback wiring;
- component-schema parity across Python, the action-specific public tool schema, and the Mini App;
- `secure-handoff.ui/1` schema, depth/node/coverage limits, and private-ref rewriting;
- segmented-code exact-value checks, character fan-out, and no silent normalization;
- Unicode code-point/UTF-8 boundaries, duplicate-key rejection, and no native input truncation;
- expiry timers, page-restoration checks, plaintext clearing, and cancellation during in-flight WebCrypto;
- per-flow `session_ref` routing, same-topic parallel isolation, and target-lease exclusivity;
- close/reattach/publication/execution concurrency and immutable wake metadata;
- browser-operation count and timeout bounds;
- continued entry execution after one bounded browser error;
- static-hosting protections, package metadata, and connection diagnostics.

Tests do not encode webpage-stage classifiers, provider success, mutation policy, or site-specific auth and checkout semantics. Goku inspects the live website after each wakeup.

Synthetic execution and a green build do not prove provider authentication. Installed source parity, gateway reload, exact-target attachment, callback delivery, and same-browser inspection are separate gates.
