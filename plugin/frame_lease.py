"""Private cross-frame browser leases.

The lease deliberately keeps every child-frame ElementHandle inside its owning
Playwright Frame. The parent page is evaluated only with handles that belong to
its own document (the checkout scope, iframe hosts, and parent action). There is
no atomic browser primitive for an OOPIF click: child guards are checked immediately
before the parent guard consumes and dispatches the one native action click.
"""
from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass
from typing import Any, Awaitable, Callable


class FrameLeaseError(ValueError):
    """Fixed, model-safe failure reason for a cross-frame lease."""

    def __init__(self, reason: str = "frame_stale") -> None:
        self.reason = reason if reason in {"frame_unsupported", "frame_stale", "expired"} else "frame_stale"
        super().__init__(self.reason)


# Installed separately in each document. The wrapper is reference-counted so
# parent/observed leases can coexist without leaving history methods patched.
NAVIGATION_WATCH = r"""
    const navKey=Symbol.for('hermes.secure_handoff.navigation');
    const navState=window[navKey] || {guards:new Set(),push:history.pushState,replace:history.replaceState};
    if(!window[navKey]){
      navState.pushWrapper=function(...args){const result=navState.push.apply(this,args);navState.guards.forEach(fn=>fn());return result};
      navState.replaceWrapper=function(...args){const result=navState.replace.apply(this,args);navState.guards.forEach(fn=>fn());return result};
      window[navKey]=navState;history.pushState=navState.pushWrapper;history.replaceState=navState.replaceWrapper;
    }
    const markNavigation=()=>{dirty=true};
    const navigation=window.navigation, initialEntry=navigation?.currentEntry;
    navState.guards.add(markNavigation);
    navigation?.addEventListener('currententrychange',markNavigation);
    window.addEventListener('popstate',markNavigation,true);window.addEventListener('hashchange',markNavigation,true);
    const releaseNavigation=()=>{
      navState.guards.delete(markNavigation);navigation?.removeEventListener('currententrychange',markNavigation);
      window.removeEventListener('popstate',markNavigation,true);window.removeEventListener('hashchange',markNavigation,true);
      if(!navState.guards.size && window[navKey]===navState){
        if(history.pushState===navState.pushWrapper)history.pushState=navState.push;
        if(history.replaceState===navState.replaceWrapper)history.replaceState=navState.replace;
        delete window[navKey];
      }
    };
"""

# These closures are evaluated in the parent document only.  Child handles are
# never included in their arguments.
PARENT_GUARD = r"""({nodes,form,scope,doc,action,deadline,submitAction,allowClick}) => {
    const attrs=['id','name','type','autocomplete','inputmode','placeholder',
      'aria-label','aria-labelledby','aria-describedby','aria-required','role',
      'min','max','step','pattern','maxlength','minlength','required','multiple',
      'form','formaction','formmethod','formtarget','formenctype'];
    const clean=t=>String(t||'').replace(/\s+/g,' ').trim(); const origin=location.origin, url=location.href;
    const signature=e=>JSON.stringify([e.tagName,attrs.map(k=>e.getAttribute(k)),
      e.labels?[...e.labels].map(l=>clean(l.textContent)):[],
      e.getAttribute('aria-labelledby')?e.getAttribute('aria-labelledby').split(/\s+/).map(id=>doc.getElementById(id)?.textContent||'').join(' '):'',
      /^(radio|checkbox|submit|button)$/.test(e.type)?e.value:null,
      e.tagName==='SELECT'?[...e.options].map(o=>[o.value,o.textContent,o.disabled,o.parentElement?.disabled||false]):null]);
    const formSig=f=>f?JSON.stringify([f.action,f.method,f.target,f.enctype,f.getAttribute('id'),f.noValidate]):null;
    const scopeSig=JSON.stringify([scope?.tagName,scope?.id,scope?.getAttribute('role')]);
    const values=nodes.map(e=>[e.value,e.checked,e.selectedIndex]);
    const signatures=nodes.map(signature), originalForm=formSig(form), originalAction=action?signature(action):null;
    const setters=new Map([[HTMLInputElement,Object.getOwnPropertyDescriptor(HTMLInputElement.prototype,'value').set],
      [HTMLTextAreaElement,Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype,'value').set],
      [HTMLSelectElement,Object.getOwnPropertyDescriptor(HTMLSelectElement.prototype,'value').set]]);
    const checkedSetter=Object.getOwnPropertyDescriptor(HTMLInputElement.prototype,'checked').set;
    const dispatch=EventTarget.prototype.dispatchEvent, nativeClick=HTMLElement.prototype.click;
    let dirty=false, internal=null, revoked=false, consumed=false;
NAVIGATION_WATCH
    const observer=new MutationObserver(()=>{if(!internal) dirty=true});
    observer.observe(scope,{subtree:true,attributes:true,characterData:true,childList:true});
    const event=e=>{if(!internal || e.target!==internal) dirty=true};
    doc.addEventListener('input',event,true); doc.addEventListener('change',event,true);
    const usable=e=>{if(!e||!e.isConnected||e.ownerDocument!==doc||!e.getClientRects().length||e.matches(':disabled')||e.readOnly)return false;
      for(let n=e;n;n=n.parentElement){const s=getComputedStyle(n);if(n.inert||n.hidden||n.getAttribute('aria-hidden')==='true'||s.display==='none'||s.visibility!=='visible'||Number(s.opacity)<=0||s.pointerEvents==='none')return false;}return true;};
    const alive=()=>{if(revoked||consumed||Date.now()>=deadline||document!==doc||location.origin!==origin||location.href!==url||navigation?.currentEntry!==initialEntry)throw Error('stale frame lease');};
    const compare=()=>nodes.forEach((e,i)=>{if(e.value!==values[i][0]||e.checked!==values[i][1]||e.selectedIndex!==values[i][2])throw Error('changed frame value')});
    const checkAction=()=>{if(!action)return;
      if(!action.isConnected||action.ownerDocument!==doc||!scope.contains(action)||signature(action)!==originalAction||!usable(action))throw Error('changed parent action');
      const route=action.formAction || (form?form.action:location.href);
      if(route!==submitAction)throw Error('changed parent routing');
    };
    const check=()=>{alive(); if(!scope||!scope.isConnected||scope.ownerDocument!==doc||JSON.stringify([scope.tagName,scope.id,scope.getAttribute('role')])!==scopeSig||formSig(form)!==originalForm)throw Error('changed parent scope');
      if(dirty)throw Error('changed parent epoch'); nodes.forEach((e,i)=>{if(!e||!e.isConnected||e.ownerDocument!==doc||signature(e)!==signatures[i]||!scope.contains(e)||!usable(e))throw Error('changed parent control')});
      compare(); checkAction(); return true;};
    const release=()=>{revoked=true;observer.disconnect();doc.removeEventListener('input',event,true);doc.removeEventListener('change',event,true);releaseNavigation()};
    const lease={nodes,revoked:false,consumed:false,deadline,check,release};
    Object.defineProperty(lease,'revoked',{get:()=>revoked,set:v=>{if(v)release()}});
    Object.defineProperty(lease,'consumed',{get:()=>consumed});
    lease.commit=({index,value,click,deadline:d,autoFinal})=>{
      deadline=Math.min(deadline,d||deadline); check();
      if(click){if(!allowClick||!action||index!==nodes.length)throw Error('unauthorized parent action');
        const r=action.getBoundingClientRect(),hit=doc.elementFromPoint(r.left+r.width/2,r.top+r.height/2);
        if(!hit||!(hit===action||action.contains(hit)))throw Error('covered parent action');
        check(); consumed=true; nativeClick.call(action); return true;}
      if(index<0||index>=nodes.length||typeof value!=='string')throw Error('invalid parent field');
      const e=nodes[index]; let setter;
      if(e.type==='checkbox'||e.type==='radio')setter=checkedSetter;
      else setter=setters.get(e instanceof HTMLInputElement?HTMLInputElement:e instanceof HTMLTextAreaElement?HTMLTextAreaElement:HTMLSelectElement);
      if(!setter)throw Error('unsupported parent native control');
      if(e.tagName==='SELECT'&&!([...e.options].some(o=>o.value===value&&!o.disabled&&!(o.parentElement&&o.parentElement.disabled))))throw Error('unknown parent option');
      alive(); internal=e; setter.call(e,e.type==='radio'?true:e.type==='checkbox'?value==='true':value);
      dispatch.call(e,new Event('input',{bubbles:true})); dispatch.call(e,new Event('change',{bubbles:true})); internal=null;
      values[index]=[e.value,e.checked,e.selectedIndex]; check(); return true;
    };
    check(); return lease;
}""".replace('NAVIGATION_WATCH', NAVIGATION_WATCH)


# Evaluated in the child frame that owns every node in `nodes`.
CHILD_GUARD = r"""({nodes,doc,origin,deadline}) => {
    const attrs=['id','name','type','autocomplete','inputmode','placeholder',
      'aria-label','aria-labelledby','aria-describedby','aria-required','role',
      'min','max','step','pattern','maxlength','minlength','required','multiple'];
    const clean=t=>String(t||'').replace(/\s+/g,' ').trim(); const url=location.href;
    const signature=e=>JSON.stringify([e.tagName,attrs.map(k=>e.getAttribute(k)),
      e.labels?[...e.labels].map(l=>clean(l.textContent)):[],
      e.getAttribute('aria-labelledby')?e.getAttribute('aria-labelledby').split(/\s+/).map(id=>doc.getElementById(id)?.textContent||'').join(' '):'',
      /^(radio|checkbox)$/.test(e.type)?e.value:null,
      e.tagName==='SELECT'?[...e.options].map(o=>[o.value,o.textContent,o.disabled,o.parentElement?.disabled||false]):null]);
    const signatures=nodes.map(signature), values=nodes.map(e=>[e.value,e.checked,e.selectedIndex]);
    const setters=new Map([[HTMLInputElement,Object.getOwnPropertyDescriptor(HTMLInputElement.prototype,'value').set],
      [HTMLTextAreaElement,Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype,'value').set],
      [HTMLSelectElement,Object.getOwnPropertyDescriptor(HTMLSelectElement.prototype,'value').set]]);
    const checkedSetter=Object.getOwnPropertyDescriptor(HTMLInputElement.prototype,'checked').set;
    const dispatch=EventTarget.prototype.dispatchEvent;
    let dirty=false,internal=null,revoked=false;
NAVIGATION_WATCH
    const observer=new MutationObserver(()=>{if(!internal)dirty=true});
    observer.observe(document.documentElement,{subtree:true,attributes:true,characterData:true,childList:true});
    const event=e=>{if(!internal||e.target!==internal)dirty=true};
    doc.addEventListener('input',event,true);doc.addEventListener('change',event,true);
    const usable=e=>{if(!e||!e.isConnected||e.ownerDocument!==doc||!e.getClientRects().length||e.matches(':disabled')||e.readOnly)return false;
      for(let n=e;n;n=n.parentElement){const s=getComputedStyle(n);if(n.inert||n.hidden||n.getAttribute('aria-hidden')==='true'||s.display==='none'||s.visibility!=='visible'||Number(s.opacity)<=0||s.pointerEvents==='none')return false;}return true;};
    const alive=()=>{if(revoked||Date.now()>=deadline||document!==doc||location.origin!==origin||location.href!==url||navigation?.currentEntry!==initialEntry)throw Error('stale child frame')};
    const compare=()=>nodes.forEach((e,i)=>{if(e.value!==values[i][0]||e.checked!==values[i][1]||e.selectedIndex!==values[i][2])throw Error('changed child value')});
    const check=()=>{alive();if(dirty)throw Error('changed child epoch');nodes.forEach((e,i)=>{if(!e||!e.isConnected||e.ownerDocument!==doc||signature(e)!==signatures[i]||!usable(e))throw Error('changed child control')});compare();return true};
    const release=()=>{revoked=true;observer.disconnect();doc.removeEventListener('input',event,true);doc.removeEventListener('change',event,true);releaseNavigation()};
    const lease={nodes,revoked:false,deadline,check,release};Object.defineProperty(lease,'revoked',{get:()=>revoked,set:v=>{if(v)release()}});
    lease.commit=({index,value,deadline:d,autoFinal})=>{deadline=Math.min(deadline,d||deadline);check();if(index<0||index>=nodes.length||typeof value!=='string')throw Error('invalid child field');const e=nodes[index];let setter;
      if(e.type==='checkbox'||e.type==='radio')setter=checkedSetter;else setter=setters.get(e instanceof HTMLInputElement?HTMLInputElement:e instanceof HTMLTextAreaElement?HTMLTextAreaElement:HTMLSelectElement);if(!setter)throw Error('unsupported child native control');
      if(e.tagName==='SELECT'&&!([...e.options].some(o=>o.value===value&&!o.disabled&&!(o.parentElement&&o.parentElement.disabled))))throw Error('unknown child option');
      alive();internal=e;setter.call(e,e.type==='radio'?true:e.type==='checkbox'?value==='true':value);dispatch.call(e,new Event('input',{bubbles:true}));dispatch.call(e,new Event('change',{bubbles:true}));internal=null;values[index]=[e.value,e.checked,e.selectedIndex];check();return true};
    check();return lease;
}""".replace('NAVIGATION_WATCH', NAVIGATION_WATCH)


# Evaluated in a child frame for an explicit auth submit control.  This is
# intentionally separate from CHILD_GUARD: fields remain fill-only there, and
# this action lease is created only after the auth binder has classified the
# stage and exact provider-owned action.
CHILD_ACTION_GUARD = r"""({action,doc,origin,deadline}) => {
    const attrs=['id','name','type','autocomplete','inputmode','placeholder',
      'aria-label','aria-labelledby','aria-describedby','aria-required','role',
      'formaction','formmethod','formtarget','formenctype'];
    const clean=t=>String(t||'').replace(/\s+/g,' ').trim();
    const signature=e=>JSON.stringify([e.tagName,attrs.map(k=>e.getAttribute(k)),
      clean(e.getAttribute('aria-label')||e.getAttribute('title')||e.innerText||e.value)]);
    const formSig=f=>f?JSON.stringify([f.action,f.method,f.target,f.enctype,f.getAttribute('id'),f.noValidate]):null;
    const original=signature(action), originalForm=action?.form||null,
      originalFormSig=formSig(originalForm), originalRoute=action?.formAction ||
      (originalForm?originalForm.action:location.href), url=location.href;
    let dirty=false,internal=null,revoked=false,consumed=false;
NAVIGATION_WATCH
    const observer=new MutationObserver(()=>{if(!internal)dirty=true});
    observer.observe(document.documentElement,{subtree:true,attributes:true,characterData:true,childList:true});
    const usable=e=>{if(!e||!e.isConnected||e.ownerDocument!==doc||!e.getClientRects().length||e.matches(':disabled')||e.readOnly)return false;
      for(let n=e;n;n=n.parentElement){const s=getComputedStyle(n);if(n.inert||n.hidden||n.getAttribute('aria-hidden')==='true'||s.display==='none'||s.visibility!=='visible'||s.pointerEvents==='none'||Number(s.opacity)<=0)return false;}return true;};
    const alive=()=>{if(revoked||consumed||Date.now()>=deadline||document!==doc||location.origin!==origin||location.href!==url||navigation?.currentEntry!==initialEntry)throw Error('stale child action lease')};
    const check=()=>{alive();if(dirty||!action||!action.isConnected||action.ownerDocument!==doc||signature(action)!==original||action.form!==originalForm||formSig(action.form)!==originalFormSig||
      (action.formAction || (action.form?action.form.action:location.href))!==originalRoute||!usable(action))throw Error('changed child action');return true;};
    const release=()=>{revoked=true;observer.disconnect();releaseNavigation()};
    const lease={revoked:false,consumed:false,deadline,check,release};
    Object.defineProperty(lease,'revoked',{get:()=>revoked,set:v=>{if(v)release()}});
    Object.defineProperty(lease,'consumed',{get:()=>consumed});
    lease.commit=({deadline:d,click})=>{deadline=Math.min(deadline,d||deadline);check();if(!click)throw Error('invalid child action');
      const r=action.getBoundingClientRect(),hit=doc.elementFromPoint(r.left+r.width/2,r.top+r.height/2);
      if(!hit||!(hit===action||action.contains(hit)))throw Error('covered child action');
      alive();consumed=true;HTMLElement.prototype.click.call(action);return true;};
    check();return lease;
}""".replace('NAVIGATION_WATCH', NAVIGATION_WATCH)


@dataclass
class FrameEntry:
    frame: Any
    document: Any
    origin: str
    host: Any
    ordinal: int
    guard: Any
    fields: list[tuple[int, Any]]


class _LeaseWitness:
    def __init__(self, lease: "CrossFrameLease") -> None:
        self.lease = lease

    async def evaluate(self, expression: str, arg: Any = None) -> Any:
        return await self.lease.evaluate(expression, arg)

    async def evaluate_handle(self, expression: str, arg: Any = None) -> Any:
        return await self.lease.evaluate_handle(expression, arg)

    async def dispose(self) -> None:
        return None


class CrossFrameLease:
    """Python coordinator over one parent guard and one guard per child frame."""

    def __init__(
        self,
        *,
        parent_guard: Any,
        parent_fields: dict[int, int],
        frames: list[FrameEntry],
        index_map: dict[int, tuple[Any, int]],
        validate_frame: Callable[[FrameEntry], Awaitable[None]],
        validate_topology: Callable[[], Awaitable[None]] | None,
        deadline: int,
        allow_click: bool = False,
        click_window_ms: int = 1500,
        summary: Any = None,
        child_action_guard: Any = None,
    ) -> None:
        self.parent_guard = parent_guard
        self.parent_fields = parent_fields
        self.frames = frames
        self.index_map = index_map
        self._validate_frame = validate_frame
        self._validate_topology = validate_topology
        self.deadline = deadline
        self.allow_click = allow_click
        self.click_window_ms = click_window_ms
        self.summary = summary
        self.child_action_guard = child_action_guard
        self.revoked = False
        self.consumed = False
        self._disposed = False
        self._click_attempted = False

    @property
    def click_attempted(self) -> bool:
        return self._click_attempted

    async def _check_deadline(self, *, click: bool = False) -> int:
        now = int(time.time() * 1000)
        if self.revoked or now >= self.deadline:
            raise FrameLeaseError("expired")
        if click:
            return min(self.deadline, now + self.click_window_ms)
        return self.deadline

    async def check_all(self, *, click: bool = False) -> bool:
        deadline = await self._check_deadline(click=click)
        self.deadline = min(self.deadline, deadline)
        # The parent guard owns only parent-document handles.  No child handle
        # can enter this call.
        try:
            if self._validate_topology is not None:
                await self._validate_topology()
            await self.parent_guard.evaluate("g => g.check()")
            await asyncio.gather(*(self._check_frame(entry) for entry in self.frames))
            if self.child_action_guard is not None:
                if await self.child_action_guard.evaluate("g => g.check()") is not True:
                    raise FrameLeaseError("frame_stale")
        except FrameLeaseError:
            raise
        except Exception:
            raise FrameLeaseError("frame_stale") from None
        return True

    async def _check_frame(self, entry: FrameEntry) -> None:
        try:
            await self._validate_frame(entry)
            if await entry.guard.evaluate("g => g.check()") is not True:
                raise FrameLeaseError("frame_stale")
        except FrameLeaseError:
            raise
        except Exception:
            raise FrameLeaseError("frame_stale") from None

    async def commit_field(self, global_index: int, value: str, *, auto_final: bool = False) -> bool:
        if self.consumed or self.revoked:
            raise FrameLeaseError("frame_stale")
        await self.check_all()
        target = self.index_map.get(global_index)
        if target is None:
            # A parent-only field is mapped to the parent guard with its local index.
            if global_index not in self.parent_fields:
                raise FrameLeaseError("frame_stale")
            guard, local_index = self.parent_guard, self.parent_fields[global_index]
        else:
            guard, local_index = target
        try:
            result = await guard.evaluate("(g,a) => g.commit(a)", {
                "index": local_index,
                "value": value,
                "deadline": self.deadline,
                "autoFinal": auto_final,
            })
        except Exception:
            raise FrameLeaseError("frame_stale") from None
        if result is not True:
            raise FrameLeaseError("frame_stale")
        await self.check_all()
        return True

    async def commit_click(self, deadline: int) -> bool:
        if not self.allow_click or self.consumed or self.revoked:
            raise FrameLeaseError("frame_stale")
        short_deadline = await self._check_deadline(click=True)
        self.deadline = min(self.deadline, deadline, short_deadline)
        # A final all-frame check is intentionally immediately before the only
        # parent evaluate that can consume/click.  This is conservative, but not
        # atomic across OOPIFs; see the protocol documentation.
        await self.check_all(click=True)
        self._click_attempted = True
        if self.child_action_guard is not None:
            try:
                result = await self.child_action_guard.evaluate("(g,a) => g.commit(a)", {
                    "deadline": self.deadline,
                    "click": True,
                })
            except Exception:
                raise
            if result is not True:
                raise FrameLeaseError("frame_stale")
            self.consumed = True
            return True
        try:
            parent_click_index = max(self.parent_fields.values(), default=-1) + 1
            result = await self.parent_guard.evaluate("(g,a) => g.commit(a)", {
                "deadline": self.deadline,
                "click": True,
                "index": parent_click_index,
            })
        except Exception:
            # The caller treats an unavailable acknowledgement conservatively.
            # It may query the parent guard's consumed bit, but never retries.
            raise
        if result is not True:
            raise FrameLeaseError("frame_stale")
        self.consumed = True
        return True

    async def evaluate(self, expression: str, arg: Any = None) -> Any:
        normalized = "".join(expression.split())
        if normalized in {"g=>g.check()", "g=>g.check(true)"}:
            return await self.check_all(click=False)
        if normalized == "g=>g.consumed":
            if self.consumed:
                return True
            try:
                return await self.parent_guard.evaluate("g => g.consumed")
            except Exception:
                if self._click_attempted:
                    raise
                return False
        if normalized == "g=>g.revoked":
            if self.revoked:
                return True
            try:
                return await self.parent_guard.evaluate("g => g.revoked")
            except Exception:
                return self.revoked
        if normalized == "g=>g.close()":
            await self.revoke()
            return None
        if normalized == "g=>{g.revoked=true;}":
            await self.revoke()
            return None
        if normalized.startswith("(g,d)=>g.commit") and "g.commit" in normalized:
            return await self.commit_click(int(arg))
        if "g.commit" in normalized and isinstance(arg, dict):
            if arg.get("click") is True:
                return await self.commit_click(int(arg.get("deadline", self.deadline)))
            return await self.commit_field(int(arg["index"]), arg.get("value", ""), auto_final=bool(arg.get("autoFinal")))
        if normalized == "g=>g.summary":
            return self.summary
        # A caller may inspect a lease's public-safe state only.  Unknown
        # expressions are not forwarded into an arbitrary frame.
        raise FrameLeaseError("frame_stale")

    async def evaluate_handle(self, expression: str, arg: Any = None) -> Any:
        if expression in {"g => g", "g=>g"}:
            return _LeaseWitness(self)
        if "g.nodes[i]" in expression or "g.nodes[i]" in expression.replace(" ", ""):
            index = int(arg)
            if index in self.parent_fields:
                # Parent guard handle is safe to retrieve from the parent guard.
                return await self.parent_guard.evaluate_handle("(g,i) => g.nodes[i]", self.parent_fields[index])
            if index in self.index_map:
                guard, local = self.index_map[index]
                return await guard.evaluate_handle("(g,i) => g.nodes[i]", local)
        raise FrameLeaseError("frame_stale")

    async def revoke(self) -> None:
        if self.revoked and self._disposed:
            return
        await self.dispose()

    async def _release_handle(self, handle: Any) -> None:
        try:
            await handle.evaluate("g => {g.revoked=true;}")
        except Exception:
            pass
        finally:
            try:
                await handle.dispose()
            except Exception:
                pass

    async def dispose(self) -> None:
        if self._disposed:
            return
        self.revoked = True
        self._disposed = True
        await self._release_handle(self.parent_guard)
        for entry in self.frames:
            await self._release_handle(entry.guard)
        if self.child_action_guard is not None:
            await self._release_handle(self.child_action_guard)


__all__ = ["CHILD_ACTION_GUARD", "CHILD_GUARD", "CrossFrameLease", "FrameEntry", "FrameLeaseError", "PARENT_GUARD"]
