"""Private, bounded observed-action fact registry; not a purchase executor.

TRUST BOUNDARY: create/capture/bind are trusted-runtime APIs, NOT model tools.
The caller selects an authorized nonpersonal public catalog leaf before calling
capture_public_product. This is a human/agent-authorized source-selection decision,
not semantic privacy certification. Never route model selectors, booleans, text,
URLs or serialized provenance to these constructors. Browser ElementHandles and
in-process issued object identity are required. Arbitrary Python execution in this
process is outside this boundary. Money role/currency and the action's purchase
meaning must likewise be explicitly classified by the trusted caller, not inferred
from digits/button shape. Only discover/compose projections cross the model wire.

Product snapshots are captured once, kept privately and compared byte-for-byte to
checkout leaves. Later public-source edits do not rewrite history. Checkout edits
invalidate the entire revision, including A->B->A DOM mutations. Money supports
whole ISO-code-prefixed tokens only (no symbols, grouping, estimates or prose).
No field values, arbitrary action copy, URLs or source handles are projected.

Integration: create a fresh registry AFTER entry; select refs via compose; retain
its opaque selection and revalidate before publication. validate is read-only,
NOT an atomic click guard. The controller must still bind the original document,
scope, controls/routing and refs at its synchronous one-shot mutation boundary.
This module neither authorizes nor clicks, certifies final charges/legal terms,
nor detects invisible merchant/server state. close on cancellation/expiry/teardown.
"""
from dataclasses import dataclass
from functools import wraps
import asyncio
import json
import math
import re
import secrets
import time
from urllib.parse import urlsplit
from typing import Any

from playwright.async_api import ElementHandle


class FactRejected(ValueError):
    """Only fixed reason codes; no browser exceptions or source text."""

    def __init__(self, reason):
        self.reason = reason
        super().__init__(reason)


class PublicProductObservation:
    """Opaque identity token. Only issuer membership gives this object authority."""
    __slots__ = ()


@dataclass(frozen=True, slots=True, repr=False, eq=False)
class PurchaseSelection:
    """Sealed display copy, not action authority. Returned data is always detached."""
    _wire: str

    def projection(self):
        return json.loads(self._wire)


@dataclass(frozen=True, repr=False)
class _Observation:
    value: str
    source_origin: str
    observation_id: str
    revision: str
    captured_at: float
    classification: str = 'trusted_selected_public_product'


@dataclass(frozen=True, repr=False)
class _Fact:
    kind: str
    role: str
    node: object
    snapshot: str
    wire: str
    observation: object = None


# Check shape before reading text. No inputs, surrounding DOM, accessible names,
# attributes, control values or mixed descendants are returned to Python.
_LEAF = r"""(e, publicSource) => {
    if (!(e instanceof HTMLElement) || !e.isConnected || e.children.length ||
        e.shadowRoot || e.closest('input,textarea,select,option,button,a,label,[contenteditable],[role="textbox"],[role="combobox"]') ||
        (publicSource && e.closest('form'))) return null;
    for (let n=e;n;n=n.parentElement) {
        const s=getComputedStyle(n);
        if(n.inert || n.hidden || n.getAttribute('aria-hidden')==='true' ||
           s.display==='none' || s.visibility!=='visible' || Number(s.opacity)<=0) return null;
    }
    if(!e.getClientRects().length) return null;
    const t=e.textContent;
    // Purchase display policy shared with web/app.js and purchase_display_cases.json.
    // Reject controls/formatting/default-ignorables, lone surrogates and line/paragraph
    // separators. Preserve all accepted identity text exactly; never strip or normalize.
    return t.length>0 && t.length<=160 && t===t.trim() && !/[\p{Cc}\p{Cf}\p{Cs}\p{Default_Ignorable_Code_Point}\p{Zl}\p{Zp}]/u.test(t) ? t : null;
}"""

_GUARD = r"""scope => {
    if (!(scope instanceof HTMLElement) || !scope.isConnected || scope.ownerDocument!==document ||
        scope.getRootNode()!==document) return null;
    const doc=document, url=location.href;
    let dirty=false;
    const observer=new MutationObserver(() => {dirty=true});
    observer.observe(scope,{subtree:true,childList:true,attributes:true,characterData:true});
    const event=()=>{dirty=true};
    scope.addEventListener('input',event,true); scope.addEventListener('change',event,true);
    const visible=e=>{
        if(!e || !e.isConnected || e.ownerDocument!==doc || !scope.contains(e) ||
           e.getRootNode()!==doc || !e.getClientRects().length) return false;
        for(let n=e;n;n=n.parentElement){
            const s=getComputedStyle(n);
            if(n.inert || n.hidden || n.matches(':disabled') || n.getAttribute('aria-disabled')==='true' ||
               n.getAttribute('aria-hidden')==='true' || s.display==='none' ||
               s.visibility!=='visible' || Number(s.opacity)<=0 || s.pointerEvents==='none') return false;
        }
        return true;
    };
    return {
        check(e, action) {
            if(observer.takeRecords().length) dirty=true;
            return !dirty && document===doc && location.href===url && scope.isConnected &&
              scope.ownerDocument===doc && visible(e) &&
              (!action || (e.tagName==='BUTTON' || (e.tagName==='INPUT' && ['submit','button'].includes(e.type))));
        },
        close(){dirty=true; observer.disconnect(); scope.removeEventListener('input',event,true); scope.removeEventListener('change',event,true)}
    };
}"""


def _mint(prefix):
    return prefix + secrets.token_urlsafe(24)


def _origin(url):
    p = urlsplit(url)
    if p.scheme != 'https' or not p.hostname or p.username or p.password:
        raise FactRejected('source_unavailable')
    return 'https://' + p.netloc


def _serialized(method):
    @wraps(method)
    async def call(self, *args, **kwargs):
        async with self._lock:
            return await method(self, *args, **kwargs)
    return call


class PurchaseFactRegistry:
    _lock: asyncio.Lock
    owner: Any
    session: Any
    revision: str
    _page: Any
    _scope: Any
    _guard: Any
    _clock: Any
    _created_at: float
    _deadline: float
    _closed: bool
    _facts: dict[str, _Fact]
    _observations: dict[PublicProductObservation, _Observation]
    _selections: dict[PurchaseSelection, tuple[str, tuple[str, ...]]]

    MAX_FACTS = 24
    MAX_OBSERVATIONS = 24
    MAX_SELECTIONS = 8
    CURRENCIES = {'USD': 2, 'EUR': 2, 'GBP': 2, 'CAD': 2, 'AUD': 2, 'NZD': 2, 'JPY': 0, 'KWD': 3}
    MONEY_ROLES = frozenset({'displayed_total', 'subtotal', 'tax', 'fee', 'discount'})

    @classmethod
    async def create(cls, *, owner, session, page, scope, ttl=120, clock=time.monotonic):
        if not isinstance(scope, ElementHandle) or not isinstance(ttl, (int, float)) or isinstance(ttl, bool) or not math.isfinite(ttl) or not 0 < ttl <= 300:
            raise FactRejected('invalid_binding')
        self = cls()
        self._lock = asyncio.Lock()
        self.owner, self.session = owner, session
        self._page, self._scope, self._clock = page, scope, clock
        self._created_at = time.monotonic()
        self._deadline, self._closed = clock() + ttl, False
        self.revision = _mint('pr_')
        self._facts, self._observations, self._selections = {}, {}, {}
        try:
            # Cross-frame handles are not eligible for this top-document increment.
            if await scope.owner_frame() != page.main_frame:
                raise FactRejected('invalid_binding')
            self._guard = await scope.evaluate_handle(_GUARD)
            if not await self._guard.evaluate('(g)=>g!==null'):
                raise FactRejected('invalid_binding')
        except Exception:
            raise FactRejected('invalid_binding') from None
        return self

    def _alive(self, owner, session):
        if owner != self.owner or session is not self.session:
            raise FactRejected('foreign_scope')
        if self._closed or self._clock() >= self._deadline:
            raise FactRejected('expired_revision')

    async def _check(self, node, action=False):
        self._alive(self.owner, self.session)
        if not isinstance(node, ElementHandle):
            raise FactRejected('invalid_binding')
        try:
            valid = await self._guard.evaluate('(g,a)=>g.check(a.node,a.action)', {'node': node, 'action': action})
        except Exception:
            valid = False
        self._alive(self.owner, self.session)
        if not valid:
            raise FactRejected('changed_binding')

    async def _leaf(self, node, public=False):
        if not isinstance(node, ElementHandle):
            raise FactRejected('invalid_binding')
        try:
            value = await node.evaluate(_LEAF, public)
        except Exception:
            value = None
        if not isinstance(value, str):
            raise FactRejected('ineligible_leaf')
        return value

    @_serialized
    async def capture_public_product(self, source_node):
        """Trusted capture of an explicitly authorized public, nonpersonal leaf.

        No `public=True`/`complete=True` flag or raw model text is accepted. Structural
        rejection supplements, but cannot replace, the caller's source decision.
        Source origin is evidence kept private, never automatically declassified.
        """
        self._alive(self.owner, self.session)
        if len(self._observations) >= self.MAX_OBSERVATIONS:
            raise FactRejected('registry_full')
        value = await self._leaf(source_node, public=True)
        try:
            origin = _origin(await source_node.evaluate('(e)=>e.ownerDocument.location.href'))
        except Exception:
            raise FactRejected('source_unavailable') from None
        self._alive(self.owner, self.session)
        token = PublicProductObservation()
        self._observations[token] = _Observation(value, origin, _mint('po_'), self.revision, self._clock())
        return token

    def _store(self, kind, role, node, snapshot, projection, observation=None):
        self._alive(self.owner, self.session)
        if len(self._facts) >= self.MAX_FACTS:
            raise FactRejected('registry_full')
        ref = _mint('pa_' if kind == 'action' else 'pf_')
        projection = {'ref': ref, **projection}
        self._facts[ref] = _Fact(kind, role, node, snapshot, json.dumps(projection), observation)
        return ref

    @_serialized
    async def bind_product(self, observation, checkout_node):
        if type(observation) is not PublicProductObservation or observation not in self._observations:
            raise FactRejected('missing_provenance')
        await self._check(checkout_node)
        await self._require_unambiguous_role(checkout_node, 'item')
        source = self._observations[observation]
        if await self._leaf(checkout_node) != source.value:
            raise FactRejected('product_mismatch')
        await self._check(checkout_node)
        return self._store('fact', 'item', checkout_node, source.value,
                           {'role': 'item', 'value': source.value, 'provenance': 'public_product_matched'}, observation)

    async def _require_unambiguous_role(self, node, role):
        for fact in tuple(self._facts.values()):
            if fact.role == role:
                continue
            try:
                same = await node.evaluate('(e, original)=>e===original', fact.node)
            except Exception:
                raise FactRejected('changed_binding') from None
            if same:
                raise FactRejected('ambiguous_provenance')

    @_serialized
    async def capture_money(self, checkout_node, *, role, currency):
        """Trusted explicit transaction role/currency; digits alone are not evidence."""
        if type(role) is not str or role not in self.MONEY_ROLES:
            raise FactRejected('ambiguous_role')
        if type(currency) is not str or currency not in self.CURRENCIES:
            raise FactRejected('ambiguous_currency')
        await self._check(checkout_node)
        await self._require_unambiguous_role(checkout_node, role)
        value = await self._leaf(checkout_node)
        places = self.CURRENCIES[currency]
        numeric = r'(?:0|[1-9][0-9]{0,8})' + (rf'\.[0-9]{{{places}}}' if places else '')
        match = re.fullmatch(re.escape(currency) + ' (' + numeric + ')', value, flags=re.ASCII)
        if not match:
            raise FactRejected('invalid_money_leaf')
        await self._check(checkout_node)
        return self._store('fact', role, checkout_node, value,
                           {'role': role, 'amount': match[1], 'currency': currency, 'provenance': 'checkout_observation'})

    @_serialized
    async def capture_action(self, action_node):
        """Trusted caller selected the purchase action; never reads its label/value."""
        await self._check(action_node, action=True)
        return self._store('action', 'purchase_action', action_node, '',
                           {'role': 'purchase_action', 'label': 'Bound purchase action'})

    async def _validate_facts(self):
        await self._check(self._scope)
        for fact in tuple(self._facts.values()):
            await self._check(fact.node, fact.kind == 'action')
            if fact.kind != 'action' and await self._leaf(fact.node) != fact.snapshot:
                raise FactRejected('changed_binding')
        await self._check(self._scope)

    def _reasons(self):
        roles = [f.role for f in self._facts.values()]
        reasons = []
        for role, name in [('item', 'item'), ('displayed_total', 'total'), ('purchase_action', 'action')]:
            count = roles.count(role)
            if count != 1:
                reasons.append(('missing_' if count == 0 else 'ambiguous_') + name)
        currencies = {json.loads(f.wire)['currency'] for f in self._facts.values() if f.role in self.MONEY_ROLES}
        if len(currencies) > 1:
            reasons.append('ambiguous_currency')
        return reasons

    @_serialized
    async def discover(self, *, owner, session):
        self._alive(owner, session)
        await self._validate_facts()
        reasons = self._reasons()
        return {'revision': self.revision, 'status': 'blocked' if reasons else 'ready', 'reasons': reasons,
                'facts': [json.loads(f.wire) for f in self._facts.values() if f.kind == 'fact'],
                'actions': [json.loads(f.wire) for f in self._facts.values() if f.kind == 'action']}

    @_serialized
    async def compose(self, payload, *, owner, session):
        self._alive(owner, session)
        if type(payload) is not dict or set(payload) != {'revision', 'fact_refs', 'action_ref'}:
            raise FactRejected('invalid_composition')
        refs = payload['fact_refs']
        if (type(payload['revision']) is not str or payload['revision'] != self.revision or
            type(payload['action_ref']) is not str or type(refs) is not list or not 2 <= len(refs) <= self.MAX_FACTS or
            any(type(r) is not str or len(r) > 80 for r in refs) or len(refs) != len(set(refs))):
            raise FactRejected('invalid_composition')
        if any(r not in self._facts or self._facts[r].kind != 'fact' for r in refs):
            raise FactRejected('foreign_ref')
        action = self._facts.get(payload['action_ref'])
        if action is None or action.kind != 'action':
            raise FactRejected('foreign_ref')
        reasons = self._reasons()
        if reasons:
            raise FactRejected(reasons[0])
        # All registered facts are material in this narrow version. The model may
        # order them, not silently discard tax/fee/discount or other disclosures.
        if set(refs) != {r for r, f in self._facts.items() if f.kind == 'fact'}:
            raise FactRejected('required_fact_omitted')
        await self._validate_facts()
        if len(self._selections) >= self.MAX_SELECTIONS:
            raise FactRejected('registry_full')
        wire = json.dumps({'contract': 'observed_action_v1', 'revision': self.revision,
                           'facts': [json.loads(self._facts[r].wire) for r in refs],
                           'action': json.loads(action.wire), 'coverage': 'selected_facts_only'})
        selected = PurchaseSelection(wire)
        self._selections[selected] = (wire, tuple(self._facts))
        return selected

    @_serialized
    async def validate(self, selection, *, owner, session):
        self._alive(owner, session)
        if type(selection) is not PurchaseSelection or selection not in self._selections:
            raise FactRejected('foreign_selection')
        wire, refs = self._selections[selection]
        if tuple(self._facts) != refs or selection.projection() != json.loads(wire):
            raise FactRejected('changed_selection')
        await self._validate_facts()
        return True

    @_serialized
    async def close(self):
        if self._closed:
            return
        self._closed = True
        self._facts.clear()
        self._observations.clear()
        self._selections.clear()
        try:
            await self._guard.evaluate('(g)=>g.close()')
            await self._guard.dispose()
        except Exception:
            pass  # Closed Python authority remains denied even after navigation.
