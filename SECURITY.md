# Security policy

## Scope

This project moves user-entered authentication, registrant, billing, and
supported payment fields between a private Telegram bot chat and the operator's
local Hermes browser profile. The Mini App is a transport boundary, not a
general credential manager or payment processor.

## Deployment boundary

- General forms use encrypted fill-only entry. There is no inferred authorization
  to click arbitrary submit, save, delete, or payment actions. Input events may
  still cause destination-owned side effects; the destination origin must be trusted.
- Ordinary tool results are status-only, not a DOM/body dump. All field entry
  belongs in the encrypted Mini App; direct tool typing is not a secret channel.
- Unsupported widgets fail closed. File selection, signatures, native wallets,
  passkeys, CAPTCHA and 3DS need separately reviewed human-owned capabilities.

- A single official HTTPS frontend deployment may serve every operator because
  it is static and has no shared backend, bot token, account, or database.
- The operator must choose whether to trust that shared frontend publisher. The
  page can read what a user types before encrypting it for Hermes. Self-hosting
  is the stronger isolation option and limits the impact of a compromised host.
- Shared frontend hosting does **not** mean shared Telegram access. Each
  operator needs one Telegram owner, one bot/gateway, one Hermes profile, and
  one dedicated Chrome profile.
- Keep Chrome DevTools Protocol on loopback (`http://127.0.0.1:9222` or another
  loopback port). Remote and websocket CDP endpoints are rejected.
- Enter the Telegram bot token only through Hermes's gateway setup. Never put
  it in the Mini App, repository, chat, CLI arguments, or screenshots.
- Never paste website credentials or one-time codes into Telegram chat, model
  prompts, terminals, logs, receipts, screenshots, or issue reports.
- Top-document and vetted HTTPS child-frame checkout fields are filled only after
  an encrypted v3 request is accepted. Ordinary checkout remains fill-only. The
  observed-action path permits one final click only after an owner-approved source
  lease, runtime-issued facts, a fresh encrypted approval capability and synchronous
  exact-state checks across the parent and every participating child frame. Child
  ElementHandles never cross into a parent `page.evaluate`; each frame owns its
  own private guard. A field-free boolean confirmation lacks bound transaction
  terms; field fill never authorizes payment.
- CAPTCHA, 3DS, MFA, passkeys, provider security screens, and payment outcomes
  remain user/provider-owned. The plugin never solves or bypasses them.
- The Mini App uses standard iOS `autocomplete` metadata, but Apple Passwords
  and payment autofill remain scoped to the Mini App's own origin. A target
  website origin cannot override that browser rule.

## Composed ENTRY candidate

Composition exposes only opaque field refs, supported kind, required status and
ordinal; frame-aware checkout refs also carry a bounded numeric frame ordinal.
There are no current values or arbitrary destination text. The agent may select
optional fields and arrange finite headings/layouts but cannot omit required
fields, inject values, or grant a purchase click. Generic field/option labels
are runtime-owned. Original private browser mutation order is independent of
visual order. The launch fragment is public metadata; only submitted values
are encrypted. No new relay or device pairing is introduced.

The local observed-action candidate connects actual trusted public-fact registries
to ref-only controller tools, explicit Mini App acknowledgment, encrypted exact
approval and one guarded click. A private local source issuer now joins explicitly
selected source refs to composed entry; ordinary ENTRY does not imply purchase
intent. The production issuer requires an encrypted owner source-selection
approval for an exact retained public, nonpersonal product page. It publishes
only fixed copy, exact HTTPS origin and runtime tab ordinal, with no entry values
or page text. The owner must review the original browser page; ambiguous,
private, billing and account sources must not be approved. A grant cannot
certify privacy or financial truth or relax strict private/control exclusions. See [acquisition boundaries](docs/purchase-acquisition.md). See the [source trust boundary,
API and limits](docs/observed-purchase-status.md). An exact match to arbitrary
checkout text is not provenance. Trusted callers must exclude sensitive personal
sources and known unsupported/contradictory obligations before publication.

The approval launch fragment is public metadata, not encrypted summary delivery.
Only submitted approval is encrypted. Runtime-issued capabilities bind sealed
facts, warning version and original action; the model cannot provide selectors,
values or an approval. Scope mutation/input/change epochs and final private state
are checked across all bound frames before consuming and clicking. There is no
browser primitive for an atomic evaluate across OOPIFs, so the final parent
dispatch has a deliberately short residual race window; a frame change detected
before dispatch rejects, but the implementation does not claim mathematical
atomicity. These checks do not certify merchant charges or legal completeness.
Cancellation cannot undo a committed click. Synthetic integration is not a live
deployment/security approval.

Cross-origin HTTPS child frames are treated as merchant-selected members of the
top-page checkout trust boundary after exact iframe-host containment and frame
identity validation; the Mini App intentionally does not display or independently
ask the owner to approve each child origin. Deployments whose threat model does
not trust embedded processors must add an owner-visible child-origin policy or
disable cross-frame purchase authority. HTTPS and DOM containment alone are not a
universal provider-authority proof.

The same private frame identity checks may be used for one visible HTTPS child
frame containing native authentication controls. Auth action clicks are scoped to
the owning child frame; generic Continue/Next/Submit actions remain fill-only
unless the owner explicitly opts into one exact continuation on the attached
target. That opt-in is consumed during binding and never grants purchase
authority. Custom widgets, CAPTCHA, passkeys, MFA and provider challenges remain
human-owned.

## Reporting

Do not open a public issue for a suspected credential leak, authentication
bypass, remote-CDP access issue, or Mini App transport flaw. After publication,
use the repository owner's private security-report channel and include only a
redacted reproduction. Until a public security contact is configured, contact
the project maintainer privately through the distribution channel.

## Release checks

Before publishing a release, run the full Python and frontend suites, the
Hermes Plugin Doctor, `python -m build --sdist --wheel`, and the release artifact
checker. Review the generated archive contents and run a secret scanner against
the committed tree and Git history.
