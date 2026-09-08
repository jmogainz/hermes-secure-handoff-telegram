# Observed-action purchase: local integration candidate

The local source now connects a real `PurchaseFactRegistry` to controller
`inspect_purchase` / `compose_purchase`, a discriminated `observed_action_v1`
Mini App, encrypted exact approval, and one synchronous guarded browser click.
The owner-issued source-selection route and retained-page acquisition bridge are
also wired through model-facing ref-only tools and the existing encrypted
Telegram callback. This is synthetic integration coverage, **not live any-site
acquisition or an installed/live-provider purchase claim**. The legacy
certified-summary source registry remains empty; there is no automatic
generic-text fallback.

## Trusted acquisition is still a prerequisite

`plugin/purchase_facts.py` accepts actual private ElementHandles. A trusted
integrator must select an authorized nonpersonal public product source, exclude
sensitive personal purchases, classify money roles/currency, select the actual
purchase action, and establish the original checkout scope. Structural leaf
checks supplement that decision; they cannot certify arbitrary text as public.
Do not pass model selectors, arbitrary research strings/URLs, a JSON registry,
`public: true`, or whole checkout text dumps to this boundary.

The registry captures an immutable public product observation and privately
matches the entire checkout item leaf to it. Only whole ISO-code monetary leaves
under explicit roles are publishable. Original checkout fact nodes are retained;
action text and control values never enter the public projection. Historical
catalog observations are not live external action authority: later catalog edits
do not rewrite their snapshot. All live checkout fact nodes must be inside the
original scope.

The production source/handle acquisition route is bounded rather than universal:
`discover_catalog_sources` and `request_source_approval` issue a short-lived,
owner/session/document-bound lease for an exact retained public nonpersonal
catalog page. The owner grant selects that source; it does not certify privacy,
merchant truth, financial completeness or sensitive-purchase classification. The
restricted acquisition grammar still rejects arbitrary recurrence/qualification
prose, known estimates, additional unresolved due-now charges, contradictory
roles/amounts, mixed/private sources and unsupported material facts. Saved-payment
entry-free setup, arbitrary page support and universal any-site classification
remain unsupported. No model boolean, selector, or raw text can manufacture the
source lease.

## Trusted API and lifecycle

```python
# In trusted runtime integration, with a currently bound checkout entry session:
await controller.arm_purchase_review(session, fresh_registry_factory)
# factory(session) runs only AFTER successful encrypted fill + base preflight.
# It creates and populates an actual PurchaseFactRegistry and returns it.
```

The factory has no model-facing endpoint. Its returned registry must have the
exact owner/session/page/scope/action, and must have been created after fill
completion. Failures reject and scrub rather than fall back to generic text.
`prepare_purchase(session, registry)` is also a trusted internal API: callers must
hold the session lock and retain the original checkout base guard. It requires
successful post-fill state, not a fake readiness/public boolean. Registry lifetime
and request expiry remain bounded. Ordinary checkout without the hook retains
its previous `human_action_required` behavior; composed generic ENTRY remains
fill-only. This increment does not infer purchase intent from a composed form.

After fill, `purchase_review_ready` retains the private original binding and an
opaque session ref, but discards the entry private key. `read`/`present` preserve
this state without refilling. The existing status-only wake includes the new
status; no facts or values are added to the wake.

## Model-facing API

```json
{"action":"inspect_purchase","session_ref":"<runtime ss_ ref>"}
```

Returns registry revision, vetted facts/actions and bounded reasons. No public
acquisition is attempted when no prepared registry exists.

```json
{"action":"compose_purchase","session_ref":"<runtime ss_ ref>",
 "revision":"<runtime pr_ revision>","fact_refs":["<runtime pf_ ref>","<runtime pf_ ref>"],
 "action_ref":"<runtime pa_ ref>"}
```

Schema and handler both restrict keys and types. Owner identity comes from the
runtime, never arguments. Composition may order facts, but must include every
registered fact and exactly the bound purchase action. It cannot introduce
values/selectors/JavaScript, approve the transaction, omit material registered
rows, or mix revisions. Publication creates a fresh request/key/capability.

## User-visible authorization

The Mini App shows website origin (not verified legal seller identity), item,
current displayed total/currency and any registered numeric rows. Renewal is
explicitly **Not established**. It states that only selected facts are shown,
that the currently selected website payment method is used without showing its
private details, and that a click may charge or start a subscription. It does not
promise a tax-inclusive final charge or complete legal review.

A separate initially unchecked unresolved-terms acknowledgment is required before
**Complete purchase** is enabled. Submission is still the existing encrypted
exact `{ "approve": "<tx capability>" }`; the acknowledgment is a UI gate, not a
privacy-declassification or independently signed attestation. The capability
privately binds the sealed full request, selection, warning version and action.
The public launch fragment contains public facts and the key's public half;
**only submission is encrypted**, not delivery of the summary.

## Atomic action and limits

The private lease retains the original base guard, scope/action, every live fact
node, registry epoch, control identities/values/check state/selection, expiry and
revocation. It observes scope mutations and input/change history, drains pending
records, compares private final state, checks action hit target, consumes the
lease, then calls the native click in one synchronous invocation. No await,
selector rebinding or Playwright actionability retry intervenes after validation.

Cancel/expiry/publication failure/terminal completion scrub controller authority
and close registry observers. Cancellation must reach the private lease before
its click linearization point; it cannot undo a dispatch. An uncertain dispatch
is `outcome_unknown`, never retry authority. Success is `purchase_submitted`, not
proof of payment or ownership. Replay cannot click again.

These guards cannot freeze merchant/server state or detect invisible property
A→B→A changes without events/mutations. They do not certify charges, product
fulfillment, or complete terms outside the selected observed scope. Provider
security challenges remain user-owned.

## Verification boundary

`tests/test_observed_purchase_integration.py` exercises the real registry,
post-fill continuation, actual tool handler, static Mini App renderer/WebCrypto,
exact encrypted approval and one disposable Chromium click. It covers stale
sources/form/action, same-turn mutation and input epochs, final private-value
checks, queued cancellation, replay, pre-fill/forged registries, public projection
tampering, publication failure and preserved pending review. Existing legacy
security tests remain in place. No live Chrome, config, secrets, install, commit,
deploy or real purchase was used. Full-suite, fresh artifact and independent
security review remain release gates, not implied by synthetic click success.
