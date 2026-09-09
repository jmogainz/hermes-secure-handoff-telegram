"""Private source acquisition, not a model-controlled privacy declassifier.

The agent proposes an opaque catalog binding; the owner grants source selection
through the existing encrypted Mini App. Neither markup nor this grant certifies
privacy or financial truth. Private/control exclusions remain enforced. Without
owner authorization, purchase-source discovery fails closed.

Supported checkout grammar: one schema.org Product/name, table th/td or dl
dt/dd money rows, native labeled entry controls (including already-bound native
payment controls in vetted HTTPS child frames), and one explicit purchase
button. Unrecognized visible copy (including known estimates/renewals/extra
obligations) blocks rather than being dropped. Neither page text nor labels
cross discovery.
"""
import asyncio
import re
import time
from dataclasses import dataclass
from types import SimpleNamespace
from typing import Any, Awaitable, Callable, cast
try:
    from .purchase_facts import PurchaseFactRegistry, FactRejected, _LEAF, _mint, _origin
except ImportError:
    from purchase_facts import PurchaseFactRegistry, FactRejected, _LEAF, _mint, _origin

ACTIONS = {'discover_purchase_sources', 'select_purchase_sources', 'discover_catalog_sources', 'request_source_approval'}


def valid_payload(action, args):
    keys = {'action', 'session_ref'}
    if action == 'select_purchase_sources': keys |= {'source_revision', 'source_refs'}
    if action == 'request_source_approval': keys.add('catalog_ref')
    if action not in ACTIONS or type(args) is not dict or set(args) != keys: return False
    for key, prefix in [('session_ref', 'ss_'), ('source_revision', 'ps_'), ('catalog_ref', 'cs_')]:
        if key in keys and (type(args[key]) is not str or not re.fullmatch(prefix + r'[A-Za-z0-9_-]{32}', args[key])): return False
    if 'source_refs' in keys:
        refs = args['source_refs']
        if type(refs) is not list or not 4 <= len(refs) <= 24: return False
        if any(type(r) is not str or not re.fullmatch(r'sr_[A-Za-z0-9_-]{32}', r) for r in refs): return False
        if len(refs) != len(set(refs)): return False
    return True


# A source lease may span encrypted input events, but no DOM mutations. React
# replacement/recalculated DOM requires a fresh acquisition, not selector repair.
GUARD = r"""scope => {
    const doc=document,url=location.href;
    if(!scope || scope.ownerDocument!==doc || !scope.isConnected) throw Error('binding');
    let dirty=false,closed=false;
    // Navigation API events also record same-document history A→B→A. URL
    // equality alone cannot prove that this source lease survived no navigation.
    const nav=window.navigation;
    if(!nav) throw Error('unsupported navigation guard');
    const navigated=()=>{dirty=true};
    nav.addEventListener('currententrychange',navigated);
    const observer=new MutationObserver(()=>{dirty=true});
    observer.observe(scope,{subtree:true,childList:true,attributes:true,characterData:true});
    return {check(e){
        if(observer.takeRecords().length) dirty=true;
        if(closed||dirty||document!==doc||location.href!==url||!scope.isConnected||
           !e||!e.isConnected||e.ownerDocument!==doc||!scope.contains(e)) return false;
        for(let n=e;n;n=n.parentElement){const s=getComputedStyle(n);
            if(n.inert||n.hidden||n.matches(':disabled')||n.getAttribute('aria-disabled')==='true'||
               n.getAttribute('aria-hidden')==='true'||s.display==='none'||s.visibility!=='visible'||
               Number(s.opacity)<=0||s.pointerEvents==='none') return false;}
        return !!e.getClientRects().length;
    },close(){closed=true;observer.disconnect();nav.removeEventListener('currententrychange',navigated)}};
}"""

# Private browser-side inventory. No arbitrary selectors, action text, controls,
# source text or page dump returned to the model. Handles stay in this process.
CATALOG = r"""() => {
    const roots=[...document.querySelectorAll('[itemscope][itemtype="https://schema.org/Product"]')];
    if(roots.length!==1 || document.querySelector('input,textarea,select,form,[contenteditable],iframe')) throw Error('shape');
    const names=[...roots[0].querySelectorAll('[itemprop="name"]')];
    if(names.length!==1) throw Error('shape');
    return names[0];
}"""

CHECKOUT = r"""scope => {
    const leaf=LEAF_FUNCTION;
    const visible=e=>!!e.getClientRects().length && getComputedStyle(e).visibility==='visible' && getComputedStyle(e).display!=='none';
    if(!scope || scope.tagName!=='FORM') throw Error('shape');
    const allowed=new Set(), records=[];
    const names=[...scope.querySelectorAll('[itemscope][itemtype="https://schema.org/Product"] [itemprop="name"]')];
    if(names.length!==1 || leaf(names[0],false)===null) throw Error('shape');
    records.push({node:names[0],kind:'checkout_item',role:'item'}); allowed.add(names[0]);
    const roles={'Total':'displayed_total','Subtotal':'subtotal','Tax':'tax','Fee':'fee','Discount':'discount'};
    const seen=new Set(),amounts={}; let currency=null;
    const rows=[...scope.querySelectorAll('tr')].map(r=>[...r.children]);
    for(const dl of scope.querySelectorAll('dl')){
        const es=[...dl.children]; if(es.length%2) throw Error('shape');
        for(let i=0;i<es.length;i+=2){if(es[i].tagName!=='DT'||es[i+1].tagName!=='DD') throw Error('shape');rows.push([es[i],es[i+1]])}
    }
    for(const row of rows){
        if(row.length!==2 || !(row[0].tagName==='DT'||row[0].tagName==='TH') || !(row[1].tagName==='DD'||row[1].tagName==='TD')) throw Error('shape');
        const label=leaf(row[0],false), value=leaf(row[1],false), role=roles[label];
        if(!role || seen.has(role) || value===null) throw Error('role');
        const m=/^(USD|EUR|GBP|CAD|AUD|NZD|JPY|KWD) (?:0|[1-9][0-9]{0,8})(?:\.[0-9]{2,3})?$/.exec(value);
        if(!m || (currency && currency!==m[1])) throw Error('currency');
        currency=m[1];seen.add(role);allowed.add(row[0]);allowed.add(row[1]);
        const places=currency==='JPY'?0:currency==='KWD'?3:2;
        const parts=value.slice(4).split('.');
        if((places===0 && parts.length!==1) || (places>0 && (parts.length!==2 || parts[1].length!==places))) throw Error('precision');
        amounts[role]=BigInt(parts.join(''));
        records.push({node:row[1],kind:'money_row',role,currency});
    }
    if(!seen.has('displayed_total')) throw Error('total');
    if(seen.has('subtotal') && amounts.subtotal+(amounts.tax||0n)+(amounts.fee||0n)-(amounts.discount||0n)!==amounts.displayed_total) throw Error('contradiction');
    const actions=[...scope.querySelectorAll('button')].filter(visible);
    if(actions.length!==1 || actions[0].children.length || !['Buy','Pay','Purchase','Place order','Complete purchase'].includes(actions[0].textContent.trim()) || actions[0].type!=='submit') throw Error('action');
    const action=actions[0];
    if(action.form!==scope || new URL(action.formAction||scope.action).origin!==location.origin) throw Error('routing');
    allowed.add(action);records.push({node:action,kind:'purchase_action',role:'purchase_action',routing:action.formAction||scope.action});
    // Account/billing labels stay private, but they cannot swallow summary copy:
    // only native labels associated with an entry control may contain text.
    for(const label of scope.querySelectorAll('label')){
        if(!label.control || !scope.contains(label.control) || label.querySelector('table,dl,[itemprop],button')) throw Error('label');
        if(/\b(?:renew\w*|recurr\w*|subscri\w*|trial|estimat\w*|additional|tax\w*|fees?|subtotal|total|discount|due now)\b/i.test(label.textContent)) throw Error('material label');
        allowed.add(label);
    }
    const walker=document.createTreeWalker(document.body,NodeFilter.SHOW_TEXT);
    while(walker.nextNode()){
        const n=walker.currentNode,e=n.parentElement;
        if(!n.textContent.trim() || !visible(e) || e.closest('script,style,input,textarea,select,option')) continue;
        if(![...allowed].some(a=>a===e||a.contains(e))) throw Error('unsupported copy');
    }
    if(scope.querySelector('[contenteditable],[role=dialog]') || records.length>23) throw Error('shape');
    return records;
}""".replace('LEAF_FUNCTION', _LEAF)


@dataclass(repr=False)
class CatalogGrant:
    owner: tuple
    session: object
    page: object
    context: object
    guard: object
    scope: object
    deadline: float
    closed: bool = False

    def __post_init__(self):
        self.checkout_page=self.session.page
        def navigated(frame):
            if frame is self.checkout_page.main_frame: self.closed=True
        self.checkout_navigation=navigated
        self.checkout_page.on('framenavigated',navigated)

    async def check(self, s):
        if self.closed or time.monotonic() >= self.deadline or self.session is not s or self.owner != (s.user,s.chat,s.thread) or self.context is not s.context or self.page.context is not s.context or self.page.is_closed():
            raise FactRejected('source_unavailable')
        if not await self.guard.evaluate('(g,e)=>g.check(e)', self.scope): raise FactRejected('source_unavailable')

    async def close(self):
        self.closed=True
        try:
            self.checkout_page.remove_listener('framenavigated',self.checkout_navigation)
        except Exception:
            pass
        guard: Any = self.guard
        self.guard = None
        scope: Any = self.scope
        self.scope = None
        if guard is not None:
            try:
                await guard.evaluate('g=>g.close()')
            except Exception:
                pass
            finally:
                try: await guard.dispose()
                except Exception: pass
        if scope is not None:
            try: await scope.dispose()
            except Exception: pass


class PurchaseSourceLease:
    def __init__(self, s, grant, frame_validator=None):
        self.session=s; self.owner=(s.user,s.chat,s.thread); self.page=s.page; self.context=s.context
        self.grant=grant; self.frame_validator=frame_validator; self.revision=_mint('ps_'); self.deadline=min(grant.deadline,time.monotonic()+120)
        self.records={}; self.guard=None; self.closed=False; self.armed=False

    @classmethod
    async def create(cls, s, grant, frame_validator=None):
        self=cls(s,grant,frame_validator)
        try:
            await grant.check(s)
            root=await s.page.query_selector('body')
            try: self.guard=await root.evaluate_handle(GUARD)
            finally: await root.dispose()
            catalog=await grant.page.evaluate_handle(CATALOG)
            node=catalog.as_element()
            if node is None or await node.evaluate(_LEAF,True) is None: raise FactRejected('source_unavailable')
            self.records[_mint('sr_')]={'node':node,'kind':'public_catalog_item','role':'item'}
            result=await s.scope.evaluate_handle(CHECKOUT)
            try:
                for row in (await result.get_properties()).values():
                    try:
                        fields=await row.get_properties()
                        record={}
                        for key,value in fields.items():
                            if key=='node': record[key]=value.as_element()
                            else:
                                record[key]=await value.json_value()
                                await value.dispose()
                        self.records[_mint('sr_')]=record
                    finally: await row.dispose()
            finally: await result.dispose()
            await self.validate(s)
            return self
        except BaseException:
            await self.close()
            raise

    async def validate(self,s):
        if self.closed or time.monotonic()>=self.deadline or s is not self.session or self.owner!=(s.user,s.chat,s.thread) or self.page is not s.page or self.context is not s.context:
            raise FactRejected('expired_revision')
        if self.frame_validator is not None:
            await self.frame_validator(s)
        if getattr(s, "commit_guard", None) is not None:
            try:
                if await s.commit_guard.evaluate("g=>g.check()") is not True:
                    raise FactRejected('changed_binding')
            except FactRejected:
                raise
            except Exception:
                raise FactRejected('changed_binding') from None
        await self.grant.check(s)
        for r in self.records.values():
            guard=self.grant.guard if r['kind']=='public_catalog_item' else self.guard
            if not await guard.evaluate('(g,e)=>g.check(e)',r['node']): raise FactRejected('changed_binding')
        if self.closed or time.monotonic()>=self.deadline: raise FactRejected('expired_revision')

    def projection(self):
        return {'status':'purchase_sources_available','source_revision':self.revision,
                'refs':[{'source_ref':ref,'kind':r['kind'],'ordinal':i+1} for i,(ref,r) in enumerate(self.records.items())]}

    async def acquire(self,s):
        registry=None
        try:
            await self.validate(s)
            registry=await PurchaseFactRegistry.create(owner=self.owner,session=s,page=s.page,scope=s.scope,ttl=min(120,self.deadline-time.monotonic()))
            catalog=next(r for r in self.records.values() if r['kind']=='public_catalog_item')
            item=next(r for r in self.records.values() if r['kind']=='checkout_item')
            observation=await registry.capture_public_product(catalog['node'])
            await registry.bind_product(observation,item['node'])
            for row in self.records.values():
                if row['kind']=='money_row': await registry.capture_money(row['node'],role=row['role'],currency=row['currency'])
                if row['kind']=='purchase_action':
                    await registry.capture_action(row['node'])
                    # This is installed only AFTER composed form preflight, whose
                    # fill-only invariant correctly rejects a submit ref.
                    s.refs['submit']=row['node']
                    s.submit_action=row['routing']
            await self.validate(s)
            return registry
        except BaseException:
            if registry is not None: await registry.close()
            raise

    async def close(self):
        self.closed=True
        guard, self.guard = self.guard, None
        if guard is not None:
            try:
                await guard.evaluate('g=>g.close()')
            except Exception:
                pass
            finally:
                try:
                    await guard.dispose()
                except Exception:
                    pass
        for record in list(self.records.values()):
            node: Any = record.get('node')
            if node is not None:
                try:
                    await node.dispose()
                except Exception:
                    pass
        self.records.clear()


class PurchaseAcquisitionMixin:
    async def _catalog_candidates(self,s):
        # Candidates are NOT grants. Inspect only structural shape, never text.
        if s.catalog_grants or s.purchase_factory is not None: return {'status':'rejected'}
        for entry in s.catalog_candidates.values(): await entry['grant'].close()
        s.catalog_candidates.clear()
        pages=list(s.context.pages)
        if len(pages)>64: return {'status':'blocked','reason':'source_binding_unsupported'}
        try:
            for ordinal,page in enumerate(pages,1):
                if page is s.page or page.is_closed(): continue
                grant=None; scope=None; guard=None
                try:
                    origin=_origin(page.url)
                    scope=await page.query_selector('body')
                    guard=await scope.evaluate_handle(GUARD)
                    grant=CatalogGrant((s.user,s.chat,s.thread),s,page,s.context,guard,scope,time.monotonic()+120)
                    node=await page.evaluate_handle(CATALOG)
                    try:
                        if node.as_element() is None: raise FactRejected('source_unavailable')
                    finally: await node.dispose()
                    await grant.check(s)
                    self._assert_active(s)
                    s.catalog_candidates[_mint('cs_')]={'grant':grant,'origin':origin,'ordinal':ordinal}
                    grant=None; guard=None; scope=None
                except Exception:
                    pass  # No source text or exception leaves the runtime.
                finally:
                    if grant is not None: await grant.close()
                    elif guard is not None:
                        try: await guard.evaluate('g=>g.close()'); await guard.dispose()
                        except Exception: pass
                    if scope is not None and grant is None: await scope.dispose()
            self._assert_active(s)
            return {'status':'catalog_sources_available','refs':[
                {'catalog_ref':ref,'origin':entry['origin'],'ordinal':entry['ordinal']}
                for ref,entry in s.catalog_candidates.items()]}
        except BaseException:
            self._scrub_purchase_sources(s)
            raise

    async def _check_source_candidate(self,s,entry):
        await entry['grant'].check(s)
        page=entry['grant'].page
        if _origin(page.url)!=entry['origin'] or s.context.pages.index(page)+1!=entry['ordinal']:
            raise FactRejected('changed_binding')
        await s.commit_guard.evaluate('g=>g.check()')
        self._assert_active(s)

    async def _request_source_approval(self,s,ref):
        import json
        from types import SimpleNamespace
        try:
            from .secure_handoff import make_request, _b64
        except ImportError:
            from secure_handoff import make_request, _b64
        from telegram import KeyboardButton,ReplyKeyboardMarkup,WebAppInfo
        entry=s.catalog_candidates.get(ref)
        if entry is None or s.catalog_grants or s.purchase_factory is not None: return {'status':'rejected'}
        try:
            await self._preflight_form(s)
            await self._check_source_candidate(s,entry)
            request,key=make_request(entry['origin'],[],mode='payment_confirmation')
            request.update(mode='source_approval',stage='source_approval',actionLabel='Allow selected source',
                           source={'nonce':_mint('sg_'),'ordinal':entry['ordinal']})
            request['expiresAt']=min(request['expiresAt'],s.request['expiresAt'],
                int(time.time()*1000+max(0,entry['grant'].deadline-time.monotonic())*1000))
            s.source_entry=(s.request,s.key)
            s.source_pending=entry
            s.request,s.key=request,key
            s.status='waiting_for_source_approval'
            self._arm_deadline(s)
            launch=self.config.mini_app_url.rstrip('/')+'#request='+_b64(json.dumps(request,separators=(',',':')).encode())
            markup=ReplyKeyboardMarkup([[KeyboardButton('Review selected source',web_app=WebAppInfo(url=launch))]],resize_keyboard=True)
            if not await self._send(SimpleNamespace(bot=self.bot),s.chat,s.thread,
                'Review the original browser product page before allowing this source. No purchase is authorized.',markup):
                raise FactRejected('publication_failed')
            await self._check_source_candidate(s,entry)
            return {'status':'waiting_for_source_approval','session_ref':s.session_ref}
        except (Exception,asyncio.CancelledError) as error:
            if s.status not in {'cancelled','expired'}: s.status='publication_failed'
            self._scrub_binding(s)
            if isinstance(error,asyncio.CancelledError): raise
            return {'status':s.status}

    async def _accept_source_approval(self,s,raw,c):
        # Called under the existing owner-authenticated, one-shot Telegram lock.
        try:
            from .secure_handoff import decrypt_submission
        except ImportError:
            from secure_handoff import decrypt_submission
        try:
            entry=s.source_pending
            if s.status!='waiting_for_source_approval' or entry is None or s.source_entry is None:
                raise FactRejected('invalid_binding')
            await self._check_source_candidate(s,entry)
            decision=decrypt_submission(raw,s.request,s.key)
            if "deny" in decision:
                self._invalidate(s,"cancelled")
                self._scrub_binding(s)
                if s.wake: s.wake.set()
                self._schedule_wake(s)
                await self._send(c,s.chat,s.thread,"Source selection cancelled. No purchase is authorized.")
                return
            await self._check_source_candidate(s,entry)
            s.request,s.key=s.source_entry
            s.source_entry=None
            await self._preflight_form(s)
            await self._check_source_candidate(s,entry)
            self._assert_active(s)
            # No await from final active check to granting. Original deadline is
            # never extended. Approval selects a source, not private-data truth.
            s.catalog_grants.append(entry['grant'])
            others=[e['grant'] for e in s.catalog_candidates.values() if e is not entry]
            s.catalog_candidates.clear(); s.source_pending=None
            for grant in others:
                grant.closed=True; asyncio.get_running_loop().create_task(grant.close())
            s.status='composition_available'
            self._arm_deadline(s)
        except (Exception,asyncio.CancelledError) as error:
            if s.status not in {'cancelled','expired'}: s.status='rejected'
            self._scrub_binding(s)
            if isinstance(error,asyncio.CancelledError): raise
        if s.wake: s.wake.set()
        self._schedule_wake(s)
        await self._send(c,s.chat,s.thread,
            'Source selection accepted. Restricted metadata discovery may continue; no purchase is authorized.'
            if s.status=='composition_available' else 'Source selection rejected.')

    async def authorize_purchase_catalog(self,s,page):
        """HOST ONLY: caller attests nonpersonal/public product source for this task.

        Not exported as a tool or inferred from HTML/origin. Do not invoke from a
        model boolean or arbitrary browser refs. The production owner-selection
        issuer uses request_source_approval and the encrypted Telegram callback;
        this helper is retained for trusted integrations/fixture compatibility.
        """
        async with s.lock:
            if not self._current(s) or s.requested_mode!='compose' or page is s.page or page.context is not s.context or page.is_closed() or len(s.catalog_grants)>=4:
                raise FactRejected('invalid_binding')
            _origin(page.url)
            scope=await page.query_selector('body')
            guard=None
            try:
                guard=await scope.evaluate_handle(GUARD)
                grant=CatalogGrant((s.user,s.chat,s.thread),s,page,s.context,guard,scope,time.monotonic()+120)
                await grant.check(s)
                self._assert_active(s)
                s.catalog_grants.append(grant)
            except BaseException:
                if guard:
                    try: await guard.evaluate('g=>g.close()'); await guard.dispose()
                    except Exception: pass
                if scope: await scope.dispose()
                raise

    async def _validate_purchase_source_frames(self, s):
        """Keep source leases aligned with the already-bound checkout frames."""
        if not getattr(s, "cross_frame", False):
            return
        host_in_scope = cast(
            Callable[..., Awaitable[Any]], getattr(self, "_frame_host_in_scope", None)
        )
        validate_frame = cast(
            Callable[..., Awaitable[Any]], getattr(self, "_validate_frame_lease_entry", None)
        )
        if not callable(host_in_scope) or not callable(validate_frame):
            raise FactRejected('source_binding_unsupported')
        bound = {}
        for field_id, frame in s.field_frames.items():
            if field_id.startswith("f") and frame != s.page.main_frame:
                bound.setdefault(frame, field_id)
        for frame in s.page.frames:
            if frame == s.page.main_frame:
                continue
            try:
                host = await frame.frame_element()
                if host is None:
                    raise FactRejected('source_binding_unsupported')
                if await host_in_scope(s.page, frame, s.scope, host) is not True:
                    continue
                field_id = bound.get(frame)
                if field_id is None:
                    raise FactRejected('source_binding_unsupported')
                await validate_frame(s, SimpleNamespace(
                    frame=frame,
                    ordinal=s.field_frame_ordinals[field_id],
                    origin=s.field_origins[field_id],
                    document=s.field_documents[field_id],
                    host=s.field_hosts[field_id],
                ))
            except FactRejected:
                raise
            except Exception:
                raise FactRejected('source_binding_unsupported') from None

    async def _purchase_sources(self,action,args,ident):
        if not valid_payload(action,args): return {'status':'invalid'}
        s=self.sessions.get(ident)
        if not s or args['session_ref']!=s.session_ref: return {'status':'rejected'}
        async with s.lock:
            if not self._current(s) or s.status!='composition_available' or s.requested_mode!='compose': return {'status':'rejected'}
            try:
                self._assert_active(s)
                if action=='discover_catalog_sources': return await self._catalog_candidates(s)
                if action=='request_source_approval': return await self._request_source_approval(s,args['catalog_ref'])
                if action=='discover_purchase_sources':
                    if s.purchase_factory is not None: return {'status':'rejected'}
                    if len(s.catalog_grants)!=1: return {'status':'blocked','reason':'public_source_authorization_required'}
                    if s.purchase_sources is not None: await s.purchase_sources.close(); s.purchase_sources=None
                    lease=await PurchaseSourceLease.create(
                        s, s.catalog_grants[0], frame_validator=self._validate_purchase_source_frames
                    )
                    s.purchase_sources=lease
                    self._assert_active(s)
                    return lease.projection()
                lease=s.purchase_sources
                if lease is None or lease.armed or args['source_revision']!=lease.revision or set(args['source_refs'])!=set(lease.records): return {'status':'rejected'}
                await lease.validate(s)
                await self._preflight_form(s)
                self._assert_active(s)
                lease.armed=True
                s.purchase_factory=lease.acquire
                return {'status':'purchase_intent_armed','session_ref':s.session_ref}
            except (Exception,asyncio.CancelledError) as error:
                if s.purchase_sources is not None:
                    await s.purchase_sources.close(); s.purchase_sources=None
                s.purchase_factory=None
                if isinstance(error,asyncio.CancelledError): raise
                return {'status':'blocked','reason':'source_binding_unsupported'}

    def _scrub_purchase_sources(self,s):
        resources=list(s.catalog_grants) + [entry['grant'] for entry in s.catalog_candidates.values()]
        s.catalog_candidates.clear()
        s.source_pending=None
        s.source_entry=None
        s.catalog_grants.clear()
        if s.purchase_sources is not None: resources.append(s.purchase_sources); s.purchase_sources=None
        # Revocation precedes asynchronous disposal, including queued cancellation.
        for resource in resources:
            resource.closed=True
            asyncio.get_running_loop().create_task(resource.close())
