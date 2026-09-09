# Private purchase-source acquisition (local candidate)

## Outcome and live prerequisite

The controller now has a real source issuer/resolver and tool route from attached
composed entry to observed purchase review and encrypted one-shot approval.
Tests exercise the actual attach, tool handlers, browser discovery, retained
native handles, fresh post-fill registry, static Mini App WebCrypto and guarded
click. They do not inject prepared registries or factories.

**Owner-issued source-selection authorization now has a production tool and
Telegram handler.** It does not certify that a page is public, nonpersonal,
truthful, or financially complete. The owner must review the exact original
browser page and select only a public, nonpersonal product source. Account,
billing, checkout and personal pages are excluded; approval cannot relax the
restricted source grammar or authorize disclosure of private data.

`discover_catalog_sources` issues exact, short-lived opaque candidate bindings;
`request_source_approval` publishes a fixed-copy Mini App containing only the
exact HTTPS origin, runtime browser-context ordinal and an opaque nonce (plus
standard request/key metadata). There are no fields or current values. Product
text, titles, paths, selectors and control labels are not published. Origin alone
does not identify a tab: the UI requires original-browser review and cancellation
if identification is ambiguous. The ordinal is the runtime context-list position,
not a promise about Chrome's visual tab order.

The owner's unchecked-by-default acknowledgment and **Allow selected source** tap
submit an encrypted exact nonce. The existing Telegram handler verifies owner,
private chat/thread, session, context, retained document, original checkout and
expiry before granting the source lease. **Cancel** sends an encrypted exact nonce
denial. `/handoffcancel` and close also revoke pending authority. Source approval
is not purchase authority. Discovery stays blocked before approval, and ordinary
checkout/entry remains fill-only. No model `public: true` override exists.

The prior in-process `authorize_purchase_catalog` helper remains for explicitly
trusted host integrations and fixture compatibility, but is not required by the
production tool/Telegram route and is not exported as a model tool.

## Exact tool flow

1. `attach` with `mode: compose`, exact HTTPS checkout origin and optional Chrome
   target ref. No navigation or publication; returns `session_ref`.
2. `discover_components` with that session ref, retaining field snapshot refs.
3. `{action: "discover_catalog_sources", session_ref}` returns
   `{status: "catalog_sources_available", refs: [{catalog_ref, origin, ordinal}]}`.
   The agent chooses an issued `cs_` candidate, then calls
   `{action: "request_source_approval", session_ref, catalog_ref}`. It returns
   `waiting_for_source_approval`; stop the model turn for owner review. The owner
   submits the encrypted approval; the Telegram handler restores
   `composition_available` and emits a status-only continuation wake. Retain the
   field snapshot from step 2 (rediscovery replaces it and revokes the grant).
   Catalog and original checkout documents must remain unchanged. There is no
   new browser context, relay, pairing, or cookie export.
4. `{action: "discover_purchase_sources", session_ref}` returns only
   `{status: "purchase_sources_available", source_revision, refs}` where each
   candidate is exactly `{source_ref, kind, ordinal}`. Kinds are
   `public_catalog_item`, `checkout_item`, `money_row`, `purchase_action`.
5. `{action: "select_purchase_sources", session_ref, source_revision,
   source_refs: [...]}` explicitly arms purchase intent. Supply every issued
   candidate exactly once. Currency and semantic roles come from the private
   restricted inventory, never from agent overrides. Selection is one-shot.
6. `present_composition` with existing field snapshot, chosen layout/groups.
   All fields start empty. Entry submission is encrypted and grants no click.
7. On accepted composed fill, a fresh `PurchaseFactRegistry` is created after
   `purchase_fill_completed`. Original source handles are revalidated; the public
   product is captured and matched to the checkout product; every supported money
   row and the original action are registered. Result: `purchase_review_ready`.
8. Existing `inspect_purchase` and `compose_purchase` select issued fact refs and
   publish a fresh review request/key. Only the user's explicit encrypted
   **Complete purchase** approval can trigger the single synchronous native click.

Ordinary composition without step 5 still ends `filled`. A group named payment,
an entry receipt, or a field's semantic hint never creates purchase authority.

## Local integration verification

Source-selection integration is covered by `tests/test_source_authorization.py`
and `tests/test_source_authorization_contract.py`: production tools → actual
Mini App WebCrypto grant/deny → Telegram owner handler → discovery/arm → empty
entry → fresh review → separate encrypted purchase approval → one synthetic
click. No direct host-authorization helper is used by that end-to-end route.
Negative cases include strict payloads, foreign owner/chat/thread, replay,
expiry, replacement, DOM and history A→B→A navigation, and cancellation during
publication/accept. Successful source approval wakes the owner task with status
only. These fixtures are not live Telegram, phone or provider proof.

## Supported structural grammar

- One separately retained catalog document with one schema.org `Product` and one
  plain visible `itemprop="name"` leaf, no native forms/inputs or iframe. The
  owner selects the source; neither the grant nor markup certifies privacy.
- One top-document native checkout form containing one matching Product/name.
  Its payment controls may be visible native inputs in the already-bound HTTPS
  child frames; the public product/fact grammar remains top-document-only and
  no child-frame text is published.
- Money rows use `table/tr/th/td` or `dl/dt/dd`, exact English labels `Total`,
  `Subtotal`, `Tax`, `Fee`, `Discount`, and exact ISO-prefixed numeric leaf tokens
  supported by `PurchaseFactRegistry`. Roles are unique; currencies must agree.
  If subtotal is supplied, integer minor-unit arithmetic must reconcile all rows.
- One original native submit button with exact supported purchase copy. No
  Submit/Continue inference. Same-origin action routing is privately pinned.
- Native entry controls supported by composed entry, including visible native
  controls in vetted HTTPS child frames. Field labels stay private; labels
  containing known material financial qualifiers block acquisition.
- Other visible text outside recognized summary/entry/action nodes blocks, even
  outside the checkout form. This deliberately rejects ordinary sites containing
  unrelated navigation, banners or unsupported legal copy instead of dropping it.

## Authority and lifecycle

Opaque `sr_` refs are private registry membership, not disguised CSS selectors.
A `ps_` revision binds owner/private chat/thread, Session object as task/flow,
original browser context/page/frame/document/node, allowed source role and expiry.
Only one active source lease per session; up to four host grants, with exactly
one required for unambiguous discovery. Leases last at most 120 seconds and
cannot outlive the grant. New discovery revokes old refs. Session replacement,
close/cancel/expiry/publication failure and terminal apply revoke/scrub resources.
Factories close partially allocated registries on failure and cancellation.

The acquisition mutation observer covers the checkout body and joins the final
synchronous purchase guard. Same-turn A→B→A DOM mutation and new outside-form
obligations invalidate the action. Source DOM mutations during field fill are
not repaired: reactive replacement/recalculated DOM needs a new workflow and is
currently unsupported. Normal property-only encrypted entry can proceed.

## Not established / unsupported

- No external `@eN`/auth-ref adoption, cross-task historical catalog store,
  arbitrary-page support, universal privacy or financial-semantic classifier.
  Owner source selection does not override private/control exclusions.
- No entry-free/saved-payment purchase, vanished catalog document, cross-context
  or cross-frame source, shadow/custom payment widget, multiple products or
  ambiguous catalogs, arbitrary currencies/symbols/number formats.
- No support for known recurring/renewal, estimated, additional due-now or other
  unsupported material text. Some unknown semantics embedded in merchant
  controls/attributes/scripts, CSS-generated text, images or server state are not
  established by this narrow DOM grammar. The observed-action warning is not a
  completeness certification or privacy declassifier.
- Public review facts remain public launch-fragment metadata. Only entry and
  approval submissions are encrypted. Billing values, private labels, raw page
  text, source URLs, handles and selectors never appear in discovery results.
- `purchase_submitted` means one browser action was dispatched, not payment,
  ownership or provider success. Unknown outcomes must not be retried.
- No live Chrome/profile, gateway/client installation, physical Telegram/iPhone,
  provider, or real purchase verification is implied by disposable fixtures.
