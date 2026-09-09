"""Observed-action integration, deliberately separate from certified summaries.

Only trusted in-process callers may arm a post-fill factory or prepare an actual
PurchaseFactRegistry. Public tools can only inspect/compose its issued refs.
The restricted source acquisition bridge lives in purchase_sources.py. It still
requires an explicit trusted-host public/nonpersonal catalog authorization.
"""
import asyncio
import json
import time
from types import SimpleNamespace
from typing import Any, Awaitable, Callable, cast
try:
    from .purchase_facts import PurchaseFactRegistry, FactRejected, _LEAF
    from .purchase_approval import approval_request
    from . import composition
    from .frame_lease import CrossFrameLease, NAVIGATION_WATCH, PARENT_GUARD
except ImportError:
    from purchase_facts import PurchaseFactRegistry, FactRejected, _LEAF
    from purchase_approval import approval_request
    import composition
    from frame_lease import CrossFrameLease, NAVIGATION_WATCH, PARENT_GUARD

ACTIONS = {'inspect_purchase', 'compose_purchase'}


def valid_payload(action, args):
    keys = {'action', 'session_ref'}
    if action == 'compose_purchase': keys |= {'revision', 'fact_refs', 'action_ref'}
    if action not in ACTIONS or type(args) is not dict or set(args) != keys: return False
    for key in keys - {'fact_refs'}:
        if type(args[key]) is not str or len(args[key]) > 80: return False
    if action == 'compose_purchase':
        refs = args['fact_refs']
        if type(refs) is not list or not 2 <= len(refs) <= 24 or any(type(r) is not str or len(r)>80 for r in refs): return False
    return True


# One synchronous browser call checks every original source and the base lease,
# drains mutation records, consumes authority, then invokes the native click.
PIN_OBSERVED = r"""({base,scope,originalScope,action,originalAction,facts,factGuard,sourceGuard,deadline}) => {
    if(scope!==originalScope || action!==originalAction) throw Error('foreign binding');
    const doc=document, url=location.href, nativeClick=HTMLElement.prototype.click;
    const leaf=LEAF_FUNCTION;
    const controls=[...doc.querySelectorAll('input,textarea,select')];
    const values=controls.map(e=>[e.value,e.checked,e.selectedIndex]);
    let dirty=false, revoked=false;
NAVIGATION_WATCH
    const observer=new MutationObserver(()=>{dirty=true});
    observer.observe(scope,{subtree:true,attributes:true,characterData:true,childList:true});
    // All registered checkout fact nodes are contained in this exact scope.
    // Public catalog observations are historical snapshots, not live authority.
    const event=e=>{if(scope.contains(e.target)||controls.includes(e.target)) dirty=true};
    doc.addEventListener('input',event,true); doc.addEventListener('change',event,true);
    const stop=()=>{observer.disconnect();doc.removeEventListener('input',event,true);doc.removeEventListener('change',event,true);releaseNavigation();values.length=0};
    const lease={deadline,consumed:false};
    Object.defineProperty(lease,'revoked',{get:()=>revoked,set:v=>{if(v){revoked=true;stop();factGuard.close();base.revoked=true}}});
    lease.check=()=>{
        if(observer.takeRecords().length) dirty=true;
        if(revoked || dirty || lease.consumed || Date.now()>=lease.deadline || document!==doc || location.href!==url || navigation?.currentEntry!==initialEntry) throw Error('stale approval');
        base.check();
        if(sourceGuard && !sourceGuard.check(scope)) throw Error('changed acquisition');
        if(!factGuard.check(scope,false) || !factGuard.check(action,true)) throw Error('changed source');
        for(const f of facts) if(!factGuard.check(f.node,f.action) || (!f.action && leaf(f.node,false)!==f.snapshot)) throw Error('changed source');
        const live=[...doc.querySelectorAll('input,textarea,select')];
        if(live.length!==controls.length || live.some((e,i)=>e!==controls[i] || e.value!==values[i][0] || e.checked!==values[i][1] || e.selectedIndex!==values[i][2])) throw Error('changed controls');
        return true;
    };
    lease.commit=({deadline})=>{
        lease.deadline=Math.min(lease.deadline,deadline);
        lease.check();
        const r=action.getBoundingClientRect(), hit=doc.elementFromPoint(r.left+r.width/2,r.top+r.height/2);
        if(!hit || !(hit===action || action.contains(hit))) throw Error('covered action');
        lease.check();
        lease.consumed=true;
        nativeClick.call(action);
        return true;
    };
    try {lease.check();return lease} catch(e){lease.revoked=true;throw Error('invalid approval')}
}""".replace('LEAF_FUNCTION', _LEAF).replace('NAVIGATION_WATCH', NAVIGATION_WATCH)


class ObservedPurchaseMixin:
    def _check_observed_request(self,s):
        if s.purchase_wire is not None and (s.request != json.loads(s.purchase_wire) or s.purchase_selection is None):
            raise FactRejected('changed_selection')

    async def arm_purchase_review(self, s, factory):
        """Trusted integration only. Factory must capture AFTER encrypted fill.

        Caller owns public/nonpersonal source selection, explicit money roles,
        currency and purchase-action meaning. Never accept factories from tools.
        """
        async with s.lock:
            if not self._current(s) or s.mode != 'checkout' or s.status != 'waiting_for_handoff' or not callable(factory):
                raise FactRejected('invalid_binding')
            s.purchase_factory = factory
            s.session_ref = s.session_ref or composition.mint('ss_')

    async def prepare_purchase(self, s, registry):
        """Trusted API for an actual fresh registry; no selectors or public flag.

        Called under the session lock by post-fill continuation. External trusted
        integrators must likewise hold that lock. Original base scope/action must
        already be bound. This method never acquires public source handles.
        """
        if type(registry) is not PurchaseFactRegistry:
            raise FactRejected('missing_provenance')
        self._assert_active(s)
        if not s.checkout_filled or s.purchase_registry is not None or registry._page is not s.page:
            raise FactRejected('invalid_binding')
        owner=(s.user,s.chat,s.thread)
        registry._alive(owner,s)
        if registry._created_at < s.purchase_fill_completed:
            raise FactRejected('stale_revision')
        found=await registry.discover(owner=owner,session=s)
        if found['status'] != 'ready': raise FactRejected(found['reasons'][0])
        action=next(f.node for f in registry._facts.values() if f.kind=='action')
        if not await s.page.evaluate('(a)=>a[0]===a[1] && a[2]===a[3]', [registry._scope,s.scope,action,s.refs['submit']]):
            raise FactRejected('foreign_scope')
        await s.commit_guard.evaluate('g=>g.check()')
        self._assert_active(s)
        s.purchase_registry=registry
        s.key=None
        s.status='purchase_review_ready'
        s.session_ref=s.session_ref or composition.mint('ss_')
        self._arm_deadline(s)
        return {'status':s.status,'session_ref':s.session_ref}

    async def _post_fill_purchase(self,s):
        factory,s.purchase_factory=s.purchase_factory,None
        s.purchase_fill_completed=time.monotonic()
        registry=None
        try:
            registry=await factory(s)
            return await self.prepare_purchase(s,registry)
        except (Exception,asyncio.CancelledError):
            if type(registry) is PurchaseFactRegistry: await registry.close()
            raise

    async def inspect_purchase(self,args,ident):
        if not valid_payload('inspect_purchase',args): return {'status':'invalid'}
        s=self.sessions.get(ident)
        if not s or not s.session_ref or args['session_ref']!=s.session_ref: return {'status':'rejected'}
        async with s.lock:
            if not self._current(s) or s.status!='purchase_review_ready' or s.purchase_registry is None:
                return {'status':'unavailable','reason':'public_source_acquisition_required'}
            try:
                self._assert_active(s)
                result=await s.purchase_registry.discover(owner=ident,session=s)
                self._assert_active(s)
                return result
            except FactRejected as e: return {'status':'rejected','reason':e.reason}
            except Exception: return {'status':'rejected'}

    async def compose_purchase(self,args,ident):
        if not valid_payload('compose_purchase',args): return {'status':'invalid'}
        s=self.sessions.get(ident)
        if not s or not s.session_ref or args['session_ref']!=s.session_ref: return {'status':'rejected'}
        async with s.lock:
            if not self._current(s) or s.status!='purchase_review_ready' or s.purchase_registry is None: return {'status':'rejected'}
            fresh_parent = None
            try:
                self._assert_active(s)
                registry=s.purchase_registry
                selection=await registry.compose({k:args[k] for k in ['revision','fact_refs','action_ref']},owner=ident,session=s)
                await registry.validate(selection,owner=ident,session=s)
                self._assert_active(s)
                deadline=min(s.request['expiresAt'],int(time.time()*1000+max(0,registry._deadline-registry._clock())*1000))
                action=next(f.node for f in registry._facts.values() if f.kind=='action')
                old=s.commit_guard
                if isinstance(old, CrossFrameLease):
                    parent_nodes = []
                    for field_id, frame in s.field_frames.items():
                        if field_id.startswith('f') and frame == s.page.main_frame:
                            parent_nodes.extend(s.field_parts.get(field_id) or [s.refs[field_id]])
                    fresh_parent = await s.page.evaluate_handle(PARENT_GUARD, {
                        'nodes': parent_nodes,
                        'form': s.form,
                        'scope': s.scope,
                        'doc': s.document,
                        'action': s.checkout_action or s.refs.get('submit'),
                        'deadline': deadline,
                        'submitAction': s.submit_action,
                        'allowClick': False,
                    })
                base = fresh_parent or old
                observed_parent=await s.page.evaluate_handle(PIN_OBSERVED,{'base':base,'scope':registry._scope,'originalScope':s.scope,
                    'action':action,'originalAction':s.refs['submit'],'factGuard':registry._guard,'deadline':deadline,
                    'sourceGuard':s.purchase_sources.guard if s.purchase_sources is not None else None,
                    'facts':[{'node':f.node,'snapshot':f.snapshot,'action':f.kind=='action'} for f in registry._facts.values()]})
                fresh_parent = None
                guard = observed_parent
                if isinstance(old, CrossFrameLease):
                    pin_cross_frame_guard = cast(
                        Callable[..., Awaitable[Any]],
                        getattr(self, "_pin_cross_frame_guard", None),
                    )
                    if not callable(pin_cross_frame_guard):
                        raise FactRejected("invalid_binding")
                    guard = await pin_cross_frame_guard(
                        s, parent_guard=observed_parent, allow_click=True, deadline=deadline
                    )
                # Own the new lease before another await; preserve cancellation.
                if not self._current(s):
                    await self._release_guard(guard)
                    raise FactRejected('expired_revision')
                s.commit_guard=guard
                await old.dispose()
                self._assert_active(s)
                try:
                    from .secure_handoff import make_request, _origin
                except ImportError:
                    from secure_handoff import make_request, _origin
                s.request,s.key=approval_request(make_request,_origin(s.page.url),{},deadline,bool(s.site))
                tx=selection.projection()
                tx['id']=s.request['transaction']['id']
                tx['warningVersion']='unresolved_terms_v1'
                s.request['transaction']=tx
                s.purchase_wire=json.dumps(s.request)
                s.purchase_selection=selection
                s.mode='purchase_approval'
                s.generation+=1
                self._arm_deadline(s)
                return await self._publish_purchase(s,SimpleNamespace(bot=self.bot))
            except (Exception,asyncio.CancelledError) as e:
                if fresh_parent is not None:
                    try:
                        await fresh_parent.evaluate('g=>{g.revoked=true;}')
                    except Exception:
                        pass
                    finally:
                        try: await fresh_parent.dispose()
                        except Exception: pass
                if s.status not in {'cancelled','expired'}: s.status='rejected'
                self._scrub_binding(s)
                if isinstance(e,asyncio.CancelledError): raise
                return {'status':s.status}
