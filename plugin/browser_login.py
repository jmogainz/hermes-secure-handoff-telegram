"""Bounded, owner-scoped Telegram browser login controller."""
from __future__ import annotations

import asyncio, base64, inspect, json, re, secrets, threading, time
from dataclasses import dataclass, field
from types import SimpleNamespace
from typing import Any
from urllib.parse import urlsplit

try:
    from .browser_adapters import adapter_for_origin, adapter_for_url
    from .config import DEFAULT_CDP_URL, validate_browser_cdp_url
    from .logincheck import load_runtime_config
except ImportError:  # Standalone Hermes plugin loader path.
    from browser_adapters import adapter_for_origin, adapter_for_url
    from config import DEFAULT_CDP_URL, validate_browser_cdp_url
    from logincheck import load_runtime_config

TTL = 600
IDLE_TTL = 1800
MAX_SESSIONS = 4
PLUGIN_HANDLER_GROUP = -100
FIELD_TYPES = {"text", "password", "otp"}
SAFE_LABELS = {"Username or email", "Password", "One-time code", "Code"}
SAFE_TOKEN_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
_REF_RE = re.compile(r"^r[0-9a-zA-Z_-]{1,32}$")

def _b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")

def _unb64(value: str) -> bytes:
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_-]+", value): raise ValueError
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))

def _origin(url: str) -> str:
    p = urlsplit(url)
    if p.scheme.lower() != "https" or not p.hostname or p.username or p.password: raise ValueError
    return f"https://{p.netloc}"

def make_request(origin: str, fields: list[dict], demo: bool = False, *, stage: str = "browser_auth", provider: str = "generic") -> tuple[dict, Any]:
    from cryptography.hazmat.primitives.asymmetric import rsa
    _origin(origin)
    if not SAFE_TOKEN_RE.fullmatch(stage) or not SAFE_TOKEN_RE.fullmatch(provider): raise ValueError("invalid stage")
    if not 1 <= len(fields) <= 4 or any(not isinstance(f, dict) or set(f) - {"id", "label", "type", "required"} or not re.fullmatch(r"f[0-3]", str(f.get("id", ""))) or f.get("label") not in SAFE_LABELS or f.get("type") not in FIELD_TYPES for f in fields): raise ValueError("invalid fields")
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048); n = key.public_key().public_numbers()
    request = {"v": 2, "id": "bl_" + secrets.token_urlsafe(16), "publicKey": {"kty": "RSA", "n": _b64(n.n.to_bytes((n.n.bit_length()+7)//8, "big")), "e": _b64(n.e.to_bytes((n.e.bit_length()+7)//8, "big"))}, "expiresAt": int(time.time()*1000)+TTL*1000, "origin": _origin(origin), "provider": provider, "stage": stage, "fields": fields, "demo": bool(demo)}
    return request, key

def decrypt_submission(raw: str, request: dict, key: Any) -> dict[str, str]:
    try:
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import padding
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        obj = json.loads(raw, object_pairs_hook=lambda pairs: {k:v for k,v in pairs})
        if not isinstance(obj, dict) or set(obj) != {"v","id","wrappedKey","iv","ciphertext"} or obj["v"] != 2 or obj["id"] != request["id"] or len(raw.encode()) > 4096: raise ValueError
        aes = key.decrypt(_unb64(obj["wrappedKey"]), padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)); iv = _unb64(obj["iv"]); ciphertext = _unb64(obj["ciphertext"])
        if len(aes) != 32 or len(iv) != 12: raise ValueError
        plain = AESGCM(aes).decrypt(iv, ciphertext, request["id"].encode())
        if len(plain) > 2048: raise ValueError
        body = json.loads(plain.decode()); values = body["values"]
        if set(body) != {"values"} or not isinstance(values, dict): raise ValueError
        result = {}
        expected_ids={f["id"] for f in request["fields"]}
        if set(values) != expected_ids: raise ValueError
        for f in request["fields"]:
            value = values.get(f["id"], "")
            if not isinstance(value, str) or len(value) > 512 or (f.get("required") and not value): raise ValueError
            result[f["id"]] = value
        return result
    except Exception:
        raise ValueError("invalid submission") from None

@dataclass
class Session:
    user: int; chat: int; thread: int|None; page: Any = field(default=None, repr=False); context: Any = field(default=None, repr=False); request: dict|None = None; key: Any = field(default=None, repr=False); site: Any = field(default=None, repr=False); refs: dict[str, Any] = field(default_factory=dict, repr=False); ref_meta: dict[str, dict] = field(default_factory=dict, repr=False); field_parts: dict[str, list[Any]] = field(default_factory=dict, repr=False); auto_submit: bool = False; status: str = "open"; used_ids: set[str] = field(default_factory=set, repr=False); wake: asyncio.Event|None = field(default=None, repr=False); lock: asyncio.Lock = field(default_factory=asyncio.Lock, repr=False); updated: float = field(default_factory=time.monotonic); document: Any = field(default=None, repr=False); form: Any = field(default=None, repr=False); scope: Any = field(default=None, repr=False); form_action: str = field(default="", repr=False); submit_action: str = field(default="", repr=False); provider: str = "generic"; stage: str = "browser_auth"

class BrowserController:
    def __init__(self, ctx: Any, *, browser=None, playwright=None, context=None, owns_browser=False):
        self.ctx=ctx; self.config=load_runtime_config(ctx); self.loop=None; self.bot=None; self.adapter=None; self._playwright=playwright; self._browser=browser; self._context=context; self._owns_browser=owns_browser; self._cdp_url=""; self.sessions={}; self._lock=threading.RLock()
    def _identity(self):
        try:
            from gateway.session_context import get_session_env
            v=[get_session_env(k,"") for k in ("HERMES_SESSION_PLATFORM","HERMES_SESSION_USER_ID","HERMES_SESSION_CHAT_ID","HERMES_SESSION_THREAD_ID")]
            if v[0] != "telegram" or not v[1] or not v[2]: return None
            return int(v[1]),int(v[2]),int(v[3]) if v[3] else None
        except Exception: return None
    def _owners(self):
        return set(self.config.allowed_user_ids) if self.config is not None else set()
    def _receipt(self,s,reason=None):
        """Best-effort status-only receipt; never serialize request payloads."""
        try:
            data_dir=getattr(self.ctx,"data_dir",None) or getattr(getattr(self.ctx,"state",None),"data_dir",None)
            if not data_dir or not s.request: return
            path=__import__("pathlib").Path(data_dir)/"browser_login_receipts.jsonl"
            path.parent.mkdir(parents=True,exist_ok=True)
            try: path.touch(mode=0o600,exist_ok=True); path.chmod(0o600)
            except OSError: pass
            with path.open("a",encoding="utf-8") as handle:
                row={"v":2,"id":s.request["id"],"status":s.status,"thread":s.thread,"time":int(time.time()*1000)}
                if reason in {"expiry","refresh_stage","preflight_before_decrypt","decrypt","preflight_after_decrypt","fill","refresh_before_click","preflight_after_fill","click","auto_submit","rebind"}: row["reason"]=reason
                handle.write(json.dumps(row,separators=(",",":"))+"\n")
        except Exception: pass
    def _submit(self,coro):
        if not self.loop or not self.loop.is_running(): return {"status":"unavailable"}
        future = asyncio.run_coroutine_threadsafe(coro,self.loop)
        try: return future.result(95)
        except TimeoutError:
            future.cancel()
            return {"status":"unavailable"}
        except Exception: return {"status":"unavailable"}
    def _configured_cdp_url(self):
        try: value=self.ctx.get_config("browser_cdp_url")
        except Exception: value=None
        validated=validate_browser_cdp_url(value or DEFAULT_CDP_URL)
        if validated is None: raise ValueError("browser_cdp_url must be a loopback HTTP endpoint")
        return validated
    async def _ensure_runtime(self):
        if self._browser: return
        from playwright.async_api import async_playwright
        self._cdp_url=self._configured_cdp_url(); self._playwright=await async_playwright().start()
        try: self._browser=await self._playwright.chromium.connect_over_cdp(self._cdp_url)
        except Exception:
            await self._playwright.stop(); self._playwright=None; self._cdp_url=""; raise
    async def _shared_context(self):
        await self._ensure_runtime()
        if self._context is not None: return self._context
        contexts=getattr(self._browser,"contexts",[])
        if not contexts: raise RuntimeError("Hermes Chrome has no persistent context")
        return contexts[0]
    async def _shared_page(self, context):
        pages=[p for p in getattr(context,"pages",[]) if not p.is_closed()]
        if pages: return pages[0]
        return await context.new_page()
    async def _existing_page(self, context, origin):
        pages=[]
        for page in getattr(context,"pages",[]):
            try:
                if page.is_closed() or _origin(page.url)!=origin: continue
                pages.append(page)
            except Exception: continue
        if len(pages)!=1: raise ValueError("ambiguous target")
        return pages[0]
    async def _attach_session(self,ident,origin):
        self._expire()
        if len(self.sessions)>=MAX_SESSIONS and ident not in self.sessions: raise RuntimeError
        context=await self._shared_context(); page=await self._existing_page(context,origin); adapter=adapter_for_origin(origin)
        old=self.sessions.pop(ident,None)
        if old: await self._dispose(old)
        s=Session(*ident,page=page,context=context,wake=asyncio.Event(),provider=adapter.name)
        self.sessions[ident]=s
        return s
    async def _usable_input(self,e):
        try:
            if not await e.is_visible() or not await e.is_enabled() or not await e.is_editable(): return False
            return await e.evaluate("""e => { const s=getComputedStyle(e); return !e.inert && e.getAttribute('aria-hidden') !== 'true' && !e.disabled && !e.readOnly && s.display !== 'none' && s.visibility !== 'hidden' && s.pointerEvents !== 'none' && Number(s.opacity) > 0 && e.getClientRects().length > 0; }""") is True
        except Exception: return False
    def _expire(self):
        for i,s in list(self.sessions.items()):
            if time.monotonic()-s.updated>IDLE_TTL:
                self.sessions.pop(i,None)
                if self.loop and self.loop.is_running(): asyncio.create_task(self._dispose(s))
    async def _dispose(self,s):
        if s.site:
            try: s.site.close()
            except Exception: pass
        if not self.sessions and self._playwright:
            # We only attach to Hermes Chrome. Stopping Playwright disconnects
            # this controller; it must never close the user's Chrome process.
            if self._owns_browser and self._browser:
                try: await self._browser.close()
                except Exception: pass
            try: await self._playwright.stop()
            except Exception: pass
            self._browser=self._playwright=self._context=None
            self._cdp_url=""
    async def _new_session(self,ident,url,demo=False):
        self._expire()
        if len(self.sessions)>=MAX_SESSIONS: raise RuntimeError
        context=await self._shared_context(); page=await self._shared_page(context)
        if demo:
            try:
                cdp=await context.new_cdp_session(page); await cdp.send("Security.setIgnoreCertificateErrors", {"ignore": True}); await cdp.detach()
            except Exception: pass
        await page.goto(url,wait_until="domcontentloaded",timeout=30000)
        origin=_origin(page.url); adapter=adapter_for_origin(origin)
        s=Session(*ident,page=page,context=context,wake=asyncio.Event(),provider=adapter.name); self.sessions[ident]=s; return s
    async def _bind_login(self, s):
        page=s.page; adapter=adapter_for_url(page.url); s.provider=adapter.name; candidates=[]
        for e in await page.locator("input").all():
            try:
                typ=(await e.get_attribute("type") or "text").lower(); name=(await e.get_attribute("name") or "").lower(); autocomplete=(await e.get_attribute("autocomplete") or "").lower(); aria=(await e.get_attribute("aria-label") or "").lower(); inputmode=(await e.get_attribute("inputmode") or "").lower(); maxlength=(await e.get_attribute("maxlength") or "").lower()
                if typ in {"hidden","submit","button","image","file","checkbox","radio"} or not await self._usable_input(e): continue
                metadata={"type":typ,"name":name,"autocomplete":autocomplete,"aria":aria,"inputmode":inputmode,"maxlength":maxlength}
                kind=adapter.classify_input(metadata)
                if kind is None: continue
                handle=await e.element_handle()
                if handle: candidates.append((kind,handle,metadata))
            except Exception: pass
        if not candidates: raise ValueError
        grouped=[]
        for kind, element, metadata in candidates:
            form_handle=await page.evaluate_handle("el => el.form",element)
            form=form_handle if await page.evaluate("form => !!form",form_handle) is True else None
            scope=form or await page.evaluate_handle("el => el.closest('dialog, [role=dialog], main') || document.body",element)
            group=None
            for existing in grouped:
                if await page.evaluate("a => a[0] === a[1]",[scope, existing[1]]) is True:
                    group=existing
                    break
            if group is None:
                grouped.append((form,scope,[]))
                group=grouped[-1]
            group[2].append((kind,element,metadata))
        eligible=[g for g in grouped if any(k in {"text","password","otp"} for k,_,_ in g[2])]
        secret=[g for g in eligible if any(k in {"password","otp"} for k,_,_ in g[2])]
        if len(secret)==1: eligible=secret
        if len(eligible)!=1: raise ValueError
        form,scope,candidates=eligible[0]
        split_otp=len(candidates)>1 and all(k=="otp" for k,_,_ in candidates)
        if form is None and not adapter.allow_formless: raise ValueError
        if (split_otp and not 2 <= len(candidates) <= 8) or (not split_otp and len(candidates)>4): raise ValueError
        if not split_otp and len({k for k,_,_ in candidates}) != len(candidates): raise ValueError
        submit=await self._find_submit(page,form,scope,adapter,allow_missing=split_otp)
        action=await page.evaluate("form => form.action",form) if form else page.url
        submit_action=action
        override=await page.evaluate("button => button.formAction || ''",submit) if submit else ""
        if override: submit_action=override
        if _origin(action)!=_origin(page.url) or _origin(submit_action)!=_origin(page.url): raise ValueError
        s.document=await page.evaluate_handle("() => document"); s.form=form; s.scope=scope; s.form_action=action; s.submit_action=submit_action
        logical=[("otp",candidates[0][1],[element for _,element,_ in candidates])] if split_otp else [(kind,element,[element]) for kind,element,_ in candidates]
        s.stage=adapter.stage_for(tuple(kind for kind,_,_ in logical)).id
        s.refs={}; s.ref_meta={}; s.field_parts={}; s.auto_submit=split_otp and submit is None
        for i,(kind,element,parts) in enumerate(logical):
            field_id=f"f{i}"; label={"text":"Username or email","password":"Password","otp":"One-time code"}[kind]
            s.refs[field_id]=element; s.field_parts[field_id]=parts; s.ref_meta[field_id]={"label":label,"type":kind,"required":True}
        if submit is not None: s.refs["submit"]=submit
    async def _related_submit(self,page,form,scope,handle):
        return await page.evaluate("""a => {
            const [btn, form, scope] = a;
            if (!btn || !btn.isConnected) return false;
            if (form) {
                if (btn.form === form || form.contains(btn)) return true;
                const dialogOf = el => el.closest('dialog, [role=dialog]');
                const d1 = dialogOf(btn), d2 = dialogOf(form);
                return !!(d1 && d1 === d2);
            }
            if (!scope || !scope.isConnected) return false;
            const scopeOf = el => el.closest('dialog, [role=dialog], main') || document.body;
            return scopeOf(btn) === scope;
        }""",[handle,form,scope]) is True
    async def _find_submit(self,page,form,scope,adapter,allow_missing=False):
        found=[]
        locators=await page.locator("form button[type=submit],form button:not([type]),form input[type=submit],button[type=submit]").all() if form else []
        for locator in locators:
            if not await locator.is_visible() or not await locator.is_enabled(): continue
            handle=await locator.element_handle()
            if handle and await self._related_submit(page,form,scope,handle):
                duplicate=False
                for existing in found:
                    if await page.evaluate("a => a[0]===a[1]",[handle,existing]) is True:
                        duplicate=True; break
                if not duplicate: found.append(handle)
        if len(found)==1: return found[0]
        if found: raise ValueError
        for label in adapter.submit_labels:
            locator=page.get_by_role("button", name=label, exact=True)
            if await locator.count()!=1: continue
            if not await locator.is_visible() or not await locator.is_enabled(): continue
            handle=await locator.element_handle()
            if handle and await self._related_submit(page,form,scope,handle): return handle
        for label in adapter.submit_labels:
            locator=page.get_by_text(label, exact=True)
            if await locator.count()!=1: continue
            handle=await locator.element_handle()
            if not handle or not await locator.is_visible() or not await locator.is_enabled(): continue
            if await self._related_submit(page,form,scope,handle): return handle
        if allow_missing: return None
        raise ValueError
    async def _close(self,ident):
        s=self.sessions.pop(ident,None)
        if not s: return {"status":"unavailable"}
        s.status="cancelled"; s.key=None
        if s.wake: s.wake.set()
        await self._dispose(s); return {"status":"closed"}
    async def _login_detected(self,s):
        try:
            adapter=adapter_for_url(str(getattr(s.page,"url","") or ""))
            for e in await s.page.locator("input").all():
                if not await self._usable_input(e): continue
                typ=(await e.get_attribute("type") or "text").lower(); name=(await e.get_attribute("name") or "").lower(); autocomplete=(await e.get_attribute("autocomplete") or "").lower(); aria=(await e.get_attribute("aria-label") or "").lower()
                if adapter.classify_input({"type":typ,"name":name,"autocomplete":autocomplete,"aria":aria}) is not None: return True
            return False
        except Exception: return True
    async def _safe_refs(self,s):
        refs={}; meta={}
        try:
            for i,e in enumerate((await s.page.locator("a,button,input:not([type=password]),textarea,select").all())[:64]):
                try:
                    if not await e.is_visible(): continue
                    typ=(await e.get_attribute("type") or "").lower()
                    if typ in {"hidden","password","email","tel","number"}: continue
                    ref=f"r{secrets.token_urlsafe(8)}"; handle=await e.element_handle()
                    if not handle: continue
                    tag=(await e.evaluate("e => e.tagName")).lower()
                    refs[ref]=handle; meta[ref]={"tag":tag,"text":"editable" if tag in {"input","textarea","select"} else (await e.inner_text())[:160]}
                except Exception: pass
        except Exception: pass
        s.refs,s.ref_meta=refs,meta; return refs,meta
    async def _ensure_prompt(self,s):
        if s.request and s.key and s.status == "waiting_for_login":
            try:
                await self._preflight(s)
                return {"status":"waiting_for_login","url":_origin(s.page.url)}
            except Exception:
                s.used_ids.add(s.request["id"])
                s.key = None
        try:
            await self._bind_login(s)
            return await self._present(s, SimpleNamespace(bot=self.bot), bool(s.site))
        except Exception:
            s.request = None
            s.key = None
            s.status = "unsupported_login"
            return {"status":"unsupported_login"}
    async def _snapshot(self,s):
        if await self._login_detected(s): return await self._ensure_prompt(s)
        await self._safe_refs(s)
        try:
            text=await s.page.evaluate("""() => { const b=document.body.cloneNode(true); b.querySelectorAll('form,input,textarea,select,script,style').forEach(e=>e.remove()); return b.innerText || ''; }""")
            return {"status":s.status,"url":_origin(s.page.url),"text":text[:4000],"refs":s.ref_meta}
        except Exception: return {"status":"unavailable"}
    async def _ordinary(self,s,action,args):
        if await self._login_detected(s): return await self._ensure_prompt(s)
        ref=args.get("ref",""); refs=s.refs
        if not isinstance(ref,str) or not _REF_RE.fullmatch(ref) or ref not in refs: return {"status":"stale_ref"}
        try:
            e=refs[ref]
            if await s.page.evaluate("a => a[0].ownerDocument !== document || !a[0].isConnected",[e]): return {"status":"stale_ref"}
            if not await e.is_visible() or not await e.is_enabled(): return {"status":"invalid"}
            if action=="click": await e.click(timeout=10000)
            else:
                text=args.get("text"); typ=(await e.get_attribute("type") or "").lower()
                if not isinstance(text,str) or len(text)>512: return {"status":"invalid"}
                if typ in {"password","email","tel","number"}: return {"status":"forbidden"}
                await e.fill(text,timeout=10000)
            s.updated=time.monotonic(); return await self._snapshot(s)
        except Exception: return {"status":"stale_ref"}
    async def _run(self,action,args,ident):
        self._expire()
        if action=="open":
            try: _origin(args.get("url"))
            except Exception: return {"status":"invalid_url"}
            old=self.sessions.pop(ident,None)
            if old: await self._dispose(old)
            try:
                s=await self._new_session(ident,args["url"],bool(args.get("demo")))
                return await self._snapshot(s)
            except Exception: return {"status":"unavailable"}
        if action=="attach":
            try: origin=_origin(args.get("origin"))
            except Exception: return {"status":"invalid_origin"}
            try:
                s=await self._attach_session(ident,origin)
                async with s.lock:
                    await self._bind_login(s)
                    return await self._present(s,SimpleNamespace(bot=self.bot),False)
            except Exception:
                s=self.sessions.get(ident)
                if s: s.status="unsupported_login"
                return {"status":"unsupported_login"}
        if action=="close": return await self._close(ident)
        s=self.sessions.get(ident)
        if not s: return {"status":"unavailable"}
        if action=="wait":
            async with s.lock: s.updated=time.monotonic(); wake=s.wake
            try: await asyncio.wait_for(wake.wait(),max(0,min(int(args.get("timeout",1)),90)))
            except asyncio.TimeoutError: pass
            async with s.lock:
                wake.clear(); return {"status":s.status}
        async with s.lock:
            s.updated=time.monotonic()
            if action=="read": return await self._snapshot(s)
            if action=="present":
                try:
                    await self._bind_login(s)
                    return await self._present(s,SimpleNamespace(bot=self.bot),False)
                except Exception:
                    s.status="unsupported_login"
                    return {"status":"unsupported_login"}
            if action in {"click","type"}: return await self._ordinary(s,action,args)
        return {"status":"invalid"}
    def tool(self,args=None,**kwargs):
        payload=dict(args) if isinstance(args,dict) else dict(kwargs); ident=self._identity()
        if ident is None or ident[0] not in self._owners(): result={"status":"rejected"}
        elif payload.get("action") in {"open","attach","present","read","click","type","wait","close"}: result=self._submit(self._run(payload.get("action"),payload,ident))
        else: result={"status":"invalid"}
        return json.dumps(result,separators=(",",":"))

    async def _send(self,context,chat,thread,text,markup=None):
        sender=getattr(getattr(context,"bot",None) or self.bot,"send_message",None)
        if not callable(sender): return False
        kw={"chat_id":chat,"text":text};
        if thread is not None: kw["message_thread_id"]=thread
        if markup is not None: kw["reply_markup"]=markup
        try:
            r=sender(**kw)
            if inspect.isawaitable(r): r=await r
            return r is not False
        except Exception: return False
    def _authorized(self,u):
        user,chat=getattr(u,"effective_user",None),getattr(u,"effective_chat",None); uid,cid=getattr(user,"id",None),getattr(chat,"id",None)
        if not isinstance(uid,int) or not isinstance(cid,int) or getattr(chat,"type",None)!="private" or uid not in self._owners(): return None
        t=getattr(getattr(u,"effective_message",None),"message_thread_id",None); return uid,cid,t if isinstance(t,int) else None
    async def _present(self,s,c,demo=False):
        try:
            fields=[{"id":k,"label":v["label"],"type":v["type"],"required":v["required"]} for k,v in s.ref_meta.items() if k.startswith("f")]
            adapter=adapter_for_url(s.page.url); descriptor=adapter.stage_for(tuple(field["type"] for field in fields)); s.stage=descriptor.id; s.provider=adapter.name
            s.request,s.key=make_request(_origin(s.page.url),fields,demo,stage=descriptor.id,provider=adapter.name)
            public=self.config.mini_app_url if self.config is not None else None
            if not isinstance(public,str): raise RuntimeError
            launch=public.rstrip("/")+"#request="+_b64(json.dumps(s.request,separators=(",",":")).encode())
            from telegram import KeyboardButton,ReplyKeyboardMarkup,WebAppInfo
            markup=ReplyKeyboardMarkup([[KeyboardButton("Open browser login",web_app=WebAppInfo(url=launch))]],resize_keyboard=True)
            if not await self._send(c,s.chat,s.thread,f"{descriptor.title} handoff is ready. Submit only to this browser.",markup): raise RuntimeError
            s.status="waiting_for_login"; return {"status":"waiting_for_login","url":_origin(s.page.url)}
        except Exception:
            s.status="publication_failed"; s.key=None; s.request=None
            return {"status":"publication_failed"}

    async def _preflight(self,s):
        if s.request["expiresAt"]<int(time.time()*1000) or _origin(s.page.url)!=s.request["origin"]: raise ValueError
        if await s.page.evaluate("d => d === document",s.document) is not True: raise ValueError
        if s.form:
            if await s.page.evaluate("f => f.ownerDocument === document",s.form) is not True: raise ValueError
            if _origin(s.form_action)!=s.request["origin"] or await s.page.evaluate("a => a[0].action === a[1]",[s.form,s.form_action]) is not True: raise ValueError
        else:
            if not s.scope or await s.page.evaluate("f => f.ownerDocument === document",s.scope) is not True: raise ValueError
            if _origin(s.form_action)!=s.request["origin"]: raise ValueError
        if _origin(s.submit_action)!=s.request["origin"]: raise ValueError
        for f in s.request["fields"]:
            primary=s.refs.get(f["id"]); parts=s.field_parts.get(f["id"]) or ([primary] if primary else [])
            if not parts: raise ValueError
            for e in parts:
                if not e or not await e.is_visible() or not await e.is_enabled() or not await e.is_editable(): raise ValueError
                if s.form:
                    connected=await s.page.evaluate("a => a[0].ownerDocument === document && a[0].form === a[1] && a[0].isConnected",[e,s.form])
                else:
                    connected=await s.page.evaluate("a => { const [el, scope] = a; const scopeOf = node => node.closest('dialog, [role=dialog], main') || document.body; return el.ownerDocument === document && el.isConnected && scopeOf(el) === scope; }",[e,s.scope])
                if connected is not True: raise ValueError
                typ=(await e.get_attribute("type") or "text").lower(); expected={"text":{"text","email"},"password":{"password"},"otp":{"one-time-code","text","tel"}}[f["type"]]
                if typ not in expected: raise ValueError
        e=s.refs.get("submit")
        if e is None and s.auto_submit: return
        if not e or not await e.is_visible() or not await e.is_enabled() or not await self._related_submit(s.page,s.form,s.scope,e): raise ValueError
        if await s.page.evaluate("a => !a[0].formAction || a[0].formAction === a[1]",[e,s.submit_action]) is not True: raise ValueError
    async def _refresh_same_stage(self,s):
        expected=[(f["label"],f["type"],bool(f["required"])) for f in s.request["fields"]]
        await self._bind_login(s)
        actual=[(s.ref_meta[k]["label"],s.ref_meta[k]["type"],bool(s.ref_meta[k]["required"])) for k in sorted(s.ref_meta) if k.startswith("f")]
        if actual!=expected: raise ValueError
    async def _wait_for_auto_submit(self,s,timeout=5.0):
        deadline=time.monotonic()+timeout
        while time.monotonic()<deadline:
            if not await self._login_detected(s): return
            await asyncio.sleep(0.1)
        raise ValueError
    async def _rebind_or_finish(self,s,c):
        try: await self._bind_login(s)
        except Exception:
            s.status="submitted"; s.key=None; return
        self._receipt(s); s.request=None; s.key=None; s.status="stage_submitted"
        await self._present(s,c,bool(s.site))
    async def _web_data(self,u,c):
        raw=getattr(getattr(getattr(u,"effective_message",None),"web_app_data",None),"data",None)
        try: rid=json.loads(raw).get("id") if isinstance(raw,str) else None
        except Exception: rid=None
        if not isinstance(rid,str) or not rid.startswith("bl_"):
            return
        s=next((x for x in self.sessions.values() if x.request and x.request.get("id")==rid),None)
        from telegram.ext import ApplicationHandlerStop
        if not s: raise ApplicationHandlerStop
        async with s.lock:
            identity=self._authorized(u)
            if not identity or identity!=(s.user,s.chat,s.thread) or rid in s.used_ids: raise ApplicationHandlerStop
            s.used_ids.add(rid)
            phase="expiry"
            try:
                if s.request["expiresAt"]<int(time.time()*1000): raise ValueError
                phase="refresh_stage"; await self._refresh_same_stage(s)
                phase="preflight_before_decrypt"; await self._preflight(s)
                phase="decrypt"; values=decrypt_submission(raw if isinstance(raw,str) else "",s.request,s.key)
                phase="preflight_after_decrypt"; await self._preflight(s)
                if s.request["expiresAt"]<int(time.time()*1000): raise ValueError
                phase="fill"
                for f in s.request["fields"]:
                    if s.request["expiresAt"]<int(time.time()*1000): raise ValueError
                    field_id=f["id"]; value=values[field_id]; parts=s.field_parts.get(field_id) or [s.refs[field_id]]
                    if f["type"]=="otp" and len(parts)>1:
                        if len(value)!=len(parts): raise ValueError
                        for index in range(len(parts)):
                            await self._refresh_same_stage(s)
                            await self._preflight(s)
                            current=s.field_parts.get(field_id) or []
                            if len(current)!=len(parts): raise ValueError
                            await current[index].fill(value[index],timeout=10000)
                    else:
                        await s.refs[field_id].fill(value,timeout=10000)
                if s.request["expiresAt"]<int(time.time()*1000): raise ValueError
                if s.auto_submit:
                    phase="auto_submit"; await self._wait_for_auto_submit(s)
                else:
                    phase="refresh_before_click"; await self._refresh_same_stage(s)
                    phase="preflight_after_fill"; await self._preflight(s)
                    phase="click"; await s.refs["submit"].click(timeout=10000)
                phase="rebind"
                await self._rebind_or_finish(s,c)
            except Exception: s.status="rejected"; s.key=None; self._receipt(s,phase)
            self._receipt(s)
            if s.wake: s.wake.set()
        if s.status=="submitted": await self._send(c,s.chat,s.thread,"Browser login submitted.")
        elif s.status=="rejected": await self._send(c,s.chat,s.thread,"Browser login rejected.")
        elif s.status=="publication_failed": await self._send(c,s.chat,s.thread,"Browser login unavailable.")
        self._schedule_wake(s)
        raise ApplicationHandlerStop
    def _safe_origin(self,s):
        try: return _origin(s.page.url)
        except Exception: return ""
    def _wake_text(self,status,origin):
        site=origin or "unknown"
        return (
            "[browser-login wakeup] Encrypted Mini App handoff finished. "
            f"Status: {status}. Site: {site}. Credentials are not included. "
            "Inspect the live browser and continue the current login task. "
            "If status is waiting_for_login, a new Mini App was published. "
            "If rejected, diagnose from receipts without reading field values. "
            "If submitted, verify whether the site is signed in."
        )
    def _schedule_wake(self,s):
        if self.adapter is None or not self.loop or not self.loop.is_running(): return
        status,user,chat,thread,origin=s.status,s.user,s.chat,s.thread,self._safe_origin(s)
        try: self.loop.create_task(self._wake_session(status,user,chat,thread,origin))
        except Exception: pass
    async def _wake_session(self,status,user,chat,thread,origin):
        adapter=self.adapter
        if adapter is None or status not in {"submitted","rejected","waiting_for_login","publication_failed","stage_submitted"}: return
        source=SimpleNamespace(chat_id=str(chat),user_id=str(user),thread_id=str(thread) if thread is not None else None)
        try: await self._deliver_wake(adapter,self._wake_text(status,origin),source)
        except Exception: pass
    async def _deliver_wake(self,adapter,text,source):
        from gateway.config import Platform
        from gateway.session import SessionSource
        from gateway.wake import deliver_wake
        real=SessionSource(platform=Platform.TELEGRAM,chat_id=str(source.chat_id),chat_type="dm",user_id=str(source.user_id) if source.user_id else None,thread_id=str(source.thread_id) if getattr(source,"thread_id",None) is not None else None)
        await deliver_wake(adapter,text=text,source=real)
    def _owns_request_id(self, request_id):
        if not isinstance(request_id,str) or not request_id.startswith("bl_"):
            return False
        with self._lock:
            return any(s.request and s.request.get("id")==request_id for s in self.sessions.values())
    def wire(self,application,adapter=None):
        self.adapter=adapter
        self.loop=asyncio.get_running_loop() if asyncio.get_event_loop().is_running() else self.loop; self.bot=getattr(application,"bot",None)
        from telegram.ext import MessageHandler,filters
        controller=self
        class Owned(filters.MessageFilter):
            def filter(_,m):
                raw=getattr(getattr(m,"web_app_data",None),"data","")
                try: value=json.loads(raw).get("id") if isinstance(raw,str) else None
                except Exception: value=None
                return controller._owns_request_id(value)
        application.add_handler(MessageHandler(filters.StatusUpdate.WEB_APP_DATA & Owned(),self._web_data,block=True),group=PLUGIN_HANDLER_GROUP)
    def close(self):
        i=self._identity(); return self._submit(self._close(i)) if i else {"status":"unavailable"}

SCHEMA={"name":"telegram_browser","description":"Use for Telegram browser work on Hermes's shared Chrome profile. Login-aware owner-scoped controls; never submit secrets.","parameters":{"type":"object","properties":{"action":{"type":"string","enum":["open","attach","present","read","click","type","wait","close"]},"url":{"type":"string"},"origin":{"type":"string"},"ref":{"type":"string"},"text":{"type":"string"},"timeout":{"type":"integer","maximum":90}},"required":["action"],"additionalProperties":False}}
def register(ctx):
    c=BrowserController(ctx)
    if c.config is not None and len(c.config.allowed_user_ids)!=1:
        return None
    try: c._configured_cdp_url()
    except ValueError: return None
    ctx.register_tool(name="telegram_browser",toolset="telegram_browser",schema=SCHEMA,handler=c.tool)
    ctx.register_telegram_handler(c.wire)
    return c
def wire(controller,application,adapter=None): controller.wire(application,adapter)
__all__=["BrowserController","SCHEMA","decrypt_submission","make_request","register","wire"]
