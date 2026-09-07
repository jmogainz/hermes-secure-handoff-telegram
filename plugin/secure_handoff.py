"""Bounded, owner-scoped Hermes Secure Handoff Telegram controller."""
from __future__ import annotations

import asyncio, base64, inspect, json, re, secrets, threading, time
from dataclasses import dataclass, field
from types import SimpleNamespace
from typing import Any
from urllib.parse import urlsplit

try:
    from .handoff_adapters import PAYMENT_KINDS, SUPPORTED_FIELD_TYPES, adapter_for_origin, adapter_for_url
    from .config import DEFAULT_CDP_URL, validate_browser_cdp_url
    from .connection_check import load_runtime_config
except ImportError:  # Standalone Hermes plugin loader path.
    from handoff_adapters import PAYMENT_KINDS, SUPPORTED_FIELD_TYPES, adapter_for_origin, adapter_for_url
    from config import DEFAULT_CDP_URL, validate_browser_cdp_url
    from connection_check import load_runtime_config

TTL = 600
IDLE_TTL = 1800
MAX_SESSIONS = 4
PLUGIN_HANDLER_GROUP = -100
MAX_FIELDS = 24
FIELD_TYPES = SUPPORTED_FIELD_TYPES
CHECKOUT_ACTIONS = {
    "buy",
    "pay",
    "purchase",
    "place order",
    "complete purchase",
    "continue to payment",
    "submit payment",
    "authorize purchase",
}
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

def _validate_v3_fields(fields: list[dict], mode: str) -> None:
    if not isinstance(fields, list):
        raise ValueError("invalid fields")
    if mode == "payment_confirmation":
        if fields:
            raise ValueError("confirmation requests cannot contain fields")
        return
    if not 1 <= len(fields) <= MAX_FIELDS:
        raise ValueError("invalid fields")
    id_pattern = re.compile(r"^f(?:[0-9]|1[0-9]|2[0-3])$")
    option_pattern = re.compile(r"^[^\x00-\x1f]{0,128}$")
    seen: set[str] = set()
    for field in fields:
        if not isinstance(field, dict):
            raise ValueError("invalid field")
        if set(field) - {"id", "label", "type", "required", "autocomplete", "inputMode", "options"}:
            raise ValueError("invalid field")
        field_id = field.get("id")
        label = field.get("label")
        kind = field.get("type")
        if not isinstance(field_id, str) or not id_pattern.fullmatch(field_id) or field_id in seen:
            raise ValueError("invalid field id")
        if not isinstance(label, str) or not label.strip() or len(label) > 80 or any(ord(c) < 32 for c in label):
            raise ValueError("invalid field label")
        if kind not in FIELD_TYPES or not isinstance(field.get("required"), bool):
            raise ValueError("invalid field type")
        autocomplete = field.get("autocomplete")
        if autocomplete is not None and (
            not isinstance(autocomplete, str)
            or len(autocomplete) > 64
            or not re.fullmatch(r"[A-Za-z0-9_-]+", autocomplete)
        ):
            raise ValueError("invalid autocomplete")
        input_mode = field.get("inputMode")
        if input_mode is not None and input_mode not in {"text", "numeric", "decimal", "tel", "email"}:
            raise ValueError("invalid input mode")
        options = field.get("options")
        if kind == "select":
            if not isinstance(options, list) or not 1 <= len(options) <= 64:
                raise ValueError("invalid select options")
            for option in options:
                if (
                    not isinstance(option, dict)
                    or set(option) != {"value", "label"}
                    or not isinstance(option["value"], str)
                    or not isinstance(option["label"], str)
                    or not option["label"].strip()
                    or not option_pattern.fullmatch(option["value"])
                    or not option_pattern.fullmatch(option["label"])
                ):
                    raise ValueError("invalid select option")
        elif options is not None:
            raise ValueError("options require select field")
        seen.add(field_id)


def _validate_action_label(action_label: str) -> str:
    if (
        not isinstance(action_label, str)
        or not action_label.strip()
        or len(action_label) > 80
        or any(ord(c) < 32 for c in action_label)
    ):
        raise ValueError("invalid action label")
    return action_label.strip()


def make_request(
    origin: str,
    fields: list[dict],
    demo: bool = False,
    *,
    stage: str = "browser_auth",
    provider: str = "generic",
    mode: str = "auth",
    action_label: str | None = None,
) -> tuple[dict, Any]:
    from cryptography.hazmat.primitives.asymmetric import rsa

    _origin(origin)
    if not SAFE_TOKEN_RE.fullmatch(stage) or not SAFE_TOKEN_RE.fullmatch(provider):
        raise ValueError("invalid stage")
    if mode not in {"auth", "checkout", "payment_confirmation"}:
        raise ValueError("invalid mode")
    _validate_v3_fields(fields, mode)
    if action_label is None:
        action_label = {
            "auth": "Submit to browser",
            "checkout": "Review purchase",
            "payment_confirmation": "Authorize purchase",
        }[mode]
    action_label = _validate_action_label(action_label)
    version = 3
    request_id = "sh_" + secrets.token_urlsafe(16)

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    n = key.public_key().public_numbers()
    request = {
        "v": version,
        "id": request_id,
        "publicKey": {
            "kty": "RSA",
            "n": _b64(n.n.to_bytes((n.n.bit_length() + 7) // 8, "big")),
            "e": _b64(n.e.to_bytes((n.e.bit_length() + 7) // 8, "big")),
        },
        "expiresAt": int(time.time() * 1000) + TTL * 1000,
        "origin": _origin(origin),
        "provider": provider,
        "stage": stage,
        "fields": fields,
        "demo": bool(demo),
    }
    if version == 3:
        request["mode"] = mode
        request["actionLabel"] = action_label
    return request, key

def decrypt_submission(raw: str, request: dict, key: Any) -> dict[str, Any]:
    try:
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import padding
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        obj = json.loads(raw, object_pairs_hook=lambda pairs: {k: v for k, v in pairs})
        version = request.get("v")
        if (
            not isinstance(obj, dict)
            or set(obj) != {"v", "id", "wrappedKey", "iv", "ciphertext"}
            or obj["v"] != version
            or version not in {2, 3}
            or obj["id"] != request["id"]
            or len(raw.encode()) > 4096
        ):
            raise ValueError
        aes = key.decrypt(
            _unb64(obj["wrappedKey"]),
            padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
        )
        iv = _unb64(obj["iv"])
        ciphertext = _unb64(obj["ciphertext"])
        if len(aes) != 32 or len(iv) != 12:
            raise ValueError
        plain = AESGCM(aes).decrypt(iv, ciphertext, request["id"].encode())
        if len(plain) > 2048:
            raise ValueError
        body = json.loads(plain.decode())
        if not isinstance(body, dict):
            raise ValueError

        if version == 3 and request.get("mode") == "payment_confirmation":
            if set(body) != {"confirm"} or body["confirm"] is not True:
                raise ValueError
            return {"confirm": True}

        if set(body) != {"values"} or not isinstance(body["values"], dict):
            raise ValueError
        values = body["values"]
        expected_ids = {f["id"] for f in request["fields"]}
        if set(values) != expected_ids:
            raise ValueError
        result: dict[str, str] = {}
        for field in request["fields"]:
            value = values.get(field["id"], "")
            if not isinstance(value, str) or len(value) > 512 or (field.get("required") and not value):
                raise ValueError
            result[field["id"]] = value
        return result
    except Exception:
        raise ValueError("invalid submission") from None

@dataclass
class Session:
    user: int; chat: int; thread: int|None; page: Any = field(default=None, repr=False); context: Any = field(default=None, repr=False); request: dict|None = None; key: Any = field(default=None, repr=False); site: Any = field(default=None, repr=False); refs: dict[str, Any] = field(default_factory=dict, repr=False); ref_meta: dict[str, dict] = field(default_factory=dict, repr=False); field_parts: dict[str, list[Any]] = field(default_factory=dict, repr=False); field_frames: dict[str, Any] = field(default_factory=dict, repr=False); field_origins: dict[str, str] = field(default_factory=dict, repr=False); field_documents: dict[str, Any] = field(default_factory=dict, repr=False); auto_submit: bool = False; status: str = "open"; mode: str = "auth"; checkout_filled: bool = False; used_ids: set[str] = field(default_factory=set, repr=False); wake: asyncio.Event|None = field(default=None, repr=False); lock: asyncio.Lock = field(default_factory=asyncio.Lock, repr=False); updated: float = field(default_factory=time.monotonic); document: Any = field(default=None, repr=False); form: Any = field(default=None, repr=False); scope: Any = field(default=None, repr=False); form_action: str = field(default="", repr=False); submit_action: str = field(default="", repr=False); provider: str = "generic"; stage: str = "browser_auth"

class SecureHandoffController:
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
            path=__import__("pathlib").Path(data_dir)/"secure_handoff_receipts.jsonl"
            path.parent.mkdir(parents=True,exist_ok=True)
            try: path.touch(mode=0o600,exist_ok=True); path.chmod(0o600)
            except OSError: pass
            with path.open("a",encoding="utf-8") as handle:
                row={"v":3,"id":s.request["id"],"status":s.status,"thread":s.thread,"time":int(time.time()*1000)}
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
    async def _bind_auth_stage(self, s):
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
        eligible=[g for g in grouped if any(k in {"text","email","tel","number","password","otp"} for k,_,_ in g[2])]
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
        s.mode="auth"; s.refs={}; s.ref_meta={}; s.field_parts={}; s.field_frames={}; s.field_origins={}; s.field_documents={}; s.auto_submit=split_otp and submit is None
        labels={"text":"Username or email","email":"Email","tel":"Phone","number":"Number","password":"Password","otp":"One-time code"}
        for i,(kind,element,parts) in enumerate(logical):
            field_id=f"f{i}"; s.refs[field_id]=element; s.field_parts[field_id]=parts; s.field_frames[field_id]=page.main_frame; s.field_origins[field_id]=_origin(page.url); s.field_documents[field_id]=s.document; s.ref_meta[field_id]={"label":labels[kind],"type":kind,"required":True}
        if submit is not None: s.refs["submit"]=submit
    def _reset_binding(self, s):
        s.refs = {}
        s.ref_meta = {}
        s.field_parts = {}
        s.field_frames = {}
        s.field_origins = {}
        s.field_documents = {}
        s.form = None
        s.scope = None
        s.form_action = ""
        s.submit_action = ""
        s.auto_submit = False

    async def _control_metadata(self, element, frame, adapter):
        tag = (await element.evaluate("e => e.tagName")).lower()
        typ = (await element.get_attribute("type") or ("select" if tag == "select" else "text")).lower()
        metadata = {
            "tag": tag,
            "type": typ,
            "name": (await element.get_attribute("name") or "").lower(),
            "autocomplete": (await element.get_attribute("autocomplete") or "").lower(),
            "aria": (await element.get_attribute("aria-label") or "").lower(),
            "placeholder": (await element.get_attribute("placeholder") or "").lower(),
            "inputmode": (await element.get_attribute("inputmode") or "").lower(),
            "maxlength": (await element.get_attribute("maxlength") or "").lower(),
            "id": (await element.get_attribute("id") or "").lower(),
        }
        kind = adapter.classify_input(metadata)
        if kind is None:
            return None
        label = await element.evaluate("""e => {
            const text = e.labels && [...e.labels].map(label => label.innerText || '').join(' ');
            return (text || e.getAttribute('aria-label') || e.getAttribute('placeholder') || e.getAttribute('name') || '').replace(/\\s+/g, ' ').trim().slice(0, 80);
        }""")
        if not isinstance(label, str) or not label:
            label = {
                "card_number": "Card number",
                "card_expiry": "Expiration date",
                "cvc": "Security code",
                "email": "Email",
                "tel": "Phone",
                "select": "Selection",
            }.get(kind, kind.replace("_", " ").title())
        options = None
        if tag == "select":
            options = await element.evaluate("e => [...e.options].slice(0, 64).map(o => ({value: String(o.value), label: String(o.textContent || '').trim()}))")
        return {
            "kind": kind,
            "label": label,
            "required": (await element.get_attribute("required")) is not None or (await element.get_attribute("aria-required")) == "true",
            "autocomplete": metadata["autocomplete"] or None,
            "inputMode": metadata["inputmode"] or None,
            "options": options,
            "metadata": metadata,
            "frame": frame,
        }

    async def _find_checkout_action(self, page, adapter):
        found = []
        labels = {label.casefold() for label in CHECKOUT_ACTIONS}
        for locator in await page.locator("button, input[type=submit], [role=button]").all():
            try:
                if not await locator.is_visible() or not await locator.is_enabled():
                    continue
                text = (await locator.inner_text()).strip() if (await locator.get_attribute("type") or "").lower() != "submit" else (await locator.get_attribute("value") or await locator.inner_text()).strip()
                if " ".join(text.split()).casefold() not in labels:
                    continue
                handle = await locator.element_handle()
                duplicate = False
                if handle:
                    for existing in found:
                        if await page.evaluate("a => a[0] === a[1]", [handle, existing]):
                            duplicate = True
                            break
                if handle and not duplicate:
                    found.append(handle)
            except Exception:
                continue
        if len(found) != 1:
            raise ValueError("checkout action is ambiguous")
        action = found[0]
        form_handle = await page.evaluate_handle("el => el.form", action)
        form = form_handle if await page.evaluate("form => !!form", form_handle) is True else None
        scope = await page.evaluate_handle("el => el.closest('form, dialog, [role=dialog], main') || document.body", action)
        action_url = await page.evaluate("form => form.action", form) if form else page.url
        submit_action = await page.evaluate("button => button.formAction || ''", action) or action_url
        if _origin(action_url) != _origin(page.url) or _origin(submit_action) != _origin(page.url):
            raise ValueError("checkout action origin mismatch")
        return action, form, scope, action_url, submit_action

    async def _bind_checkout(self, s):
        page = s.page
        was_filled = bool(getattr(s, "checkout_filled", False))
        adapter = adapter_for_url(page.url)
        action, form, scope, action_url, submit_action = await self._find_checkout_action(page, adapter)
        page_origin = _origin(page.url)
        candidates = []
        for frame in page.frames:
            try:
                frame_origin = page_origin if frame == page.main_frame else _origin(frame.url)
            except Exception:
                continue
            if frame != page.main_frame and not frame_origin.startswith("https://"):
                continue
            for element in await frame.locator("input, textarea, select").all():
                try:
                    if not await self._usable_input(element):
                        continue
                    candidate = await self._control_metadata(element, frame, adapter)
                    if candidate is None:
                        continue
                    if frame != page.main_frame and candidate["kind"] not in PAYMENT_KINDS:
                        continue
                    handle = await element.element_handle()
                    if not handle:
                        continue
                    host = None if frame == page.main_frame else await frame.frame_element()
                    if host is not None and not await page.evaluate("a => a[1].contains(a[0])", [host, scope]):
                        continue
                    candidate.update({
                        "handle": handle,
                        "origin": frame_origin,
                        "document": await frame.evaluate_handle("() => document"),
                        "host": host,
                    })
                    candidates.append(candidate)
                except Exception:
                    continue
        if not candidates or len(candidates) > MAX_FIELDS:
            raise ValueError("checkout fields unavailable")
        semantic = " ".join(
            f"{candidate['label']} {candidate['metadata']['name']} {candidate['metadata']['aria']} {candidate['metadata']['placeholder']}"
            for candidate in candidates
        ).casefold()
        checkout_signal = (
            any(candidate["kind"] in PAYMENT_KINDS for candidate in candidates)
            or any(token in semantic for token in ("billing", "checkout", "address", "payment", "order", "purchase", "card"))
            or len(candidates) >= 2
        )
        if not checkout_signal:
            raise ValueError("not a checkout form")

        self._reset_binding(s)
        s.document = await page.evaluate_handle("() => document")
        s.form = form
        s.scope = scope
        s.form_action = action_url
        s.submit_action = submit_action
        s.mode = "checkout"
        s.stage = "checkout_details"
        s.checkout_filled = was_filled
        s.refs["submit"] = action
        for index, candidate in enumerate(candidates):
            field_id = f"f{index}"
            metadata = {
                "label": candidate["label"],
                "type": candidate["kind"],
                "required": bool(candidate["required"]),
            }
            if candidate["autocomplete"]:
                metadata["autocomplete"] = candidate["autocomplete"]
            if candidate["inputMode"]:
                metadata["inputMode"] = candidate["inputMode"]
            if candidate["options"] is not None:
                metadata["options"] = candidate["options"]
            s.refs[field_id] = candidate["handle"]
            s.ref_meta[field_id] = metadata
            s.field_parts[field_id] = [candidate["handle"]]
            s.field_frames[field_id] = candidate["frame"]
            s.field_origins[field_id] = candidate["origin"]
            s.field_documents[field_id] = candidate["document"]

    async def _bind_stage(self, s):
        try:
            await self._bind_checkout(s)
        except Exception:
            self._reset_binding(s)
            await self._bind_auth_stage(s)
            s.mode = "auth"

    async def _related_submit(self, page, form, scope, handle):
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
    async def _auth_stage_detected(self,s):
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
    async def _stage_detected(self, s):
        safe_refs, safe_meta = s.refs, s.ref_meta
        try:
            await self._bind_stage(s)
            return True
        except Exception:
            self._reset_binding(s)
            s.refs, s.ref_meta = safe_refs, safe_meta
            return False

    async def _ensure_prompt(self,s):
        if s.request and s.key and s.status in {"waiting_for_handoff", "waiting_for_confirmation"}:
            try:
                await self._preflight(s)
                return {"status":s.status,"url":_origin(s.page.url)}
            except Exception:
                s.used_ids.add(s.request["id"])
                s.key = None
        try:
            await self._bind_stage(s)
            return await self._present(s, SimpleNamespace(bot=self.bot), bool(s.site))
        except Exception:
            s.request = None
            s.key = None
            s.status = "unsupported_stage"
            return {"status":"unsupported_stage"}
    async def _snapshot(self,s):
        if await self._stage_detected(s): return await self._ensure_prompt(s)
        await self._safe_refs(s)
        try:
            text=await s.page.evaluate("""() => { const b=document.body.cloneNode(true); b.querySelectorAll('form,input,textarea,select,script,style').forEach(e=>e.remove()); return b.innerText || ''; }""")
            return {"status":s.status,"url":_origin(s.page.url),"text":text[:4000],"refs":s.ref_meta}
        except Exception: return {"status":"unavailable"}
    async def _ordinary(self,s,action,args):
        if await self._stage_detected(s): return await self._ensure_prompt(s)
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
                    await self._bind_stage(s)
                    return await self._present(s,SimpleNamespace(bot=self.bot),False)
            except Exception:
                s=self.sessions.get(ident)
                if s: s.status="unsupported_stage"
                return {"status":"unsupported_stage"}
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
                    await self._bind_stage(s)
                    return await self._present(s,SimpleNamespace(bot=self.bot),False)
                except Exception:
                    s.status="unsupported_stage"
                    return {"status":"unsupported_stage"}
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
    async def _present_confirmation(self,s,c,demo=False):
        try:
            s.mode = "payment_confirmation"
            s.stage = "payment_confirmation"
            s.request,s.key=make_request(_origin(s.page.url),[],demo,stage=s.stage,provider=s.provider,mode="payment_confirmation",action_label="Authorize purchase")
            public=self.config.mini_app_url if self.config is not None else None
            if not isinstance(public,str): raise RuntimeError
            launch=public.rstrip("/")+"#request="+_b64(json.dumps(s.request,separators=(",",":")).encode())
            from telegram import KeyboardButton,ReplyKeyboardMarkup,WebAppInfo
            markup=ReplyKeyboardMarkup([[KeyboardButton("Authorize purchase",web_app=WebAppInfo(url=launch))]],resize_keyboard=True)
            if not await self._send(c,s.chat,s.thread,"Review the browser checkout, then authorize the purchase.",markup): raise RuntimeError
            s.status="waiting_for_confirmation"
            return {"status":"waiting_for_confirmation","url":_origin(s.page.url)}
        except Exception:
            s.status="publication_failed"; s.key=None; s.request=None
            return {"status":"publication_failed"}

    async def _present(self,s,c,demo=False):
        try:
            fields=[{"id":k, **dict(v)} for k,v in s.ref_meta.items() if k.startswith("f")]
            adapter=adapter_for_url(s.page.url); descriptor=adapter.stage_for(tuple(field["type"] for field in fields), checkout=s.mode=="checkout"); s.stage=descriptor.id; s.provider=adapter.name
            if s.mode == "checkout":
                s.request,s.key=make_request(_origin(s.page.url),fields,demo,stage=descriptor.id,provider=adapter.name,mode="checkout",action_label="Review purchase")
            else:
                s.request,s.key=make_request(_origin(s.page.url),fields,demo,stage=descriptor.id,provider=adapter.name)
            public=self.config.mini_app_url if self.config is not None else None
            if not isinstance(public,str): raise RuntimeError
            launch=public.rstrip("/")+"#request="+_b64(json.dumps(s.request,separators=(",",":")).encode())
            from telegram import KeyboardButton,ReplyKeyboardMarkup,WebAppInfo
            markup=ReplyKeyboardMarkup([[KeyboardButton("Open secure handoff",web_app=WebAppInfo(url=launch))]],resize_keyboard=True)
            if not await self._send(c,s.chat,s.thread,f"{descriptor.title} handoff is ready. Submit only to this browser.",markup): raise RuntimeError
            s.status="waiting_for_handoff"; return {"status":"waiting_for_handoff","url":_origin(s.page.url)}
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
        expected_types = {
            "text": {"text", "email"},
            "email": {"email", "text"},
            "tel": {"tel", "text", "number"},
            "number": {"number", "text"},
            "password": {"password"},
            "otp": {"one-time-code", "text", "tel"},
            "card_number": {"text", "tel", "number", "password"},
            "card_expiry": {"text", "tel", "number"},
            "cvc": {"text", "tel", "number", "password"},
            "select": {"select"},
        }
        field_specs = s.request["fields"]
        if s.mode == "payment_confirmation":
            field_specs = [{"id":key,"type":meta["type"]} for key,meta in s.ref_meta.items() if key.startswith("f")]
        for f in field_specs:
            field_id=f["id"]; primary=s.refs.get(field_id); parts=s.field_parts.get(field_id) or ([primary] if primary else [])
            if not parts: raise ValueError
            for e in parts:
                if not e or not await e.is_visible() or not await e.is_enabled() or not await e.is_editable(): raise ValueError
                if s.mode in {"checkout", "payment_confirmation"}:
                    frame=s.field_frames.get(field_id); expected_origin=s.field_origins.get(field_id); document=s.field_documents.get(field_id)
                    if frame is None or frame.is_detached() or not expected_origin or _origin(frame.url)!=expected_origin: raise ValueError
                    if await frame.evaluate("d => d === document",document) is not True: raise ValueError
                    host=e if frame == s.page.main_frame else await frame.frame_element()
                    if not await s.page.evaluate("a => a[0].ownerDocument === document && a[0].isConnected && a[1].contains(a[0])",[host,s.scope]): raise ValueError
                elif s.form:
                    connected=await s.page.evaluate("a => a[0].ownerDocument === document && a[0].form === a[1] && a[0].isConnected",[e,s.form])
                    if connected is not True: raise ValueError
                else:
                    connected=await s.page.evaluate("a => { const [el, scope] = a; const scopeOf = node => node.closest('dialog, [role=dialog], main') || document.body; return el.ownerDocument === document && el.isConnected && scopeOf(el) === scope; }",[e,s.scope])
                    if connected is not True: raise ValueError
                tag=(await e.evaluate("el => el.tagName")).lower(); typ="select" if tag == "select" else (await e.get_attribute("type") or "text").lower()
                if typ not in expected_types.get(f["type"],set()): raise ValueError
        e=s.refs.get("submit")
        if e is None and s.auto_submit: return
        if not e or not await e.is_visible() or not await e.is_enabled() or not await self._related_submit(s.page,s.form,s.scope,e): raise ValueError
        if await s.page.evaluate("a => !a[0].formAction || a[0].formAction === a[1]",[e,s.submit_action]) is not True: raise ValueError
    async def _refresh_same_stage(self,s):
        if s.mode == "payment_confirmation":
            expected=[(k,v["label"],v["type"],bool(v["required"])) for k,v in s.ref_meta.items() if k.startswith("f")]
            s.mode = "checkout"
            try:
                await self._bind_checkout(s)
                actual=[(k,s.ref_meta[k]["label"],s.ref_meta[k]["type"],bool(s.ref_meta[k]["required"])) for k in sorted(s.ref_meta) if k.startswith("f")]
            finally:
                s.mode = "payment_confirmation"
                s.stage = "payment_confirmation"
            if actual != expected: raise ValueError
            return
        expected=[(f["label"],f["type"],bool(f["required"])) for f in s.request["fields"]]
        if s.mode == "checkout":
            await self._bind_checkout(s)
        else:
            await self._bind_auth_stage(s)
        actual=[(s.ref_meta[k]["label"],s.ref_meta[k]["type"],bool(s.ref_meta[k]["required"])) for k in sorted(s.ref_meta) if k.startswith("f")]
        if actual!=expected: raise ValueError
    async def _wait_for_auto_submit(self,s,timeout=5.0):
        deadline=time.monotonic()+timeout
        while time.monotonic()<deadline:
            if not await self._auth_stage_detected(s): return
            await asyncio.sleep(0.1)
        raise ValueError
    async def _rebind_or_finish(self,s,c):
        try: await self._bind_stage(s)
        except Exception:
            s.status="submitted"; s.key=None; return
        self._receipt(s); s.request=None; s.key=None; s.status="stage_submitted"
        await self._present(s,c,bool(s.site))
    async def _fill_bound_field(self,s,field,value):
        field_id=field["id"]; parts=s.field_parts.get(field_id) or [s.refs[field_id]]
        if field["type"]=="otp" and len(parts)>1:
            if len(value)!=len(parts): raise ValueError
            for index in range(len(parts)):
                await self._refresh_same_stage(s)
                await self._preflight(s)
                current=s.field_parts.get(field_id) or []
                if len(current)!=len(parts): raise ValueError
                await current[index].fill(value[index],timeout=10000)
            return
        element=s.refs[field_id]
        tag=(await element.evaluate("el => el.tagName")).lower()
        if tag == "select":
            await element.select_option(value=value,timeout=10000)
        else:
            await element.fill(value,timeout=10000)

    async def _web_data(self,u,c):
        raw=getattr(getattr(getattr(u,"effective_message",None),"web_app_data",None),"data",None)
        try: rid=json.loads(raw).get("id") if isinstance(raw,str) else None
        except Exception: rid=None
        if not isinstance(rid,str) or not rid.startswith("sh_"):
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
                phase="decrypt"; payload=decrypt_submission(raw if isinstance(raw,str) else "",s.request,s.key)
                phase="preflight_after_decrypt"; await self._preflight(s)
                if s.request["expiresAt"]<int(time.time()*1000): raise ValueError
                if s.mode == "payment_confirmation":
                    if payload.get("confirm") is not True or set(payload) != {"confirm"}: raise ValueError
                    phase="confirm_click"; await s.refs["submit"].click(timeout=10000)
                    phase="rebind"; await self._rebind_or_finish(s,c)
                else:
                    phase="fill"
                    for field in s.request["fields"]:
                        if s.request["expiresAt"]<int(time.time()*1000): raise ValueError
                        await self._fill_bound_field(s,field,payload[field["id"]])
                    if s.request["expiresAt"]<int(time.time()*1000): raise ValueError
                    if s.mode == "checkout":
                        s.checkout_filled=True
                        phase="refresh_before_confirmation"; await self._refresh_same_stage(s)
                        phase="preflight_after_fill"; await self._preflight(s)
                        phase="confirmation"; await self._present_confirmation(s,c,bool(s.site))
                    elif s.auto_submit:
                        phase="auto_submit"; await self._wait_for_auto_submit(s)
                        phase="rebind"; await self._rebind_or_finish(s,c)
                    else:
                        phase="refresh_before_click"; await self._refresh_same_stage(s)
                        phase="preflight_after_fill"; await self._preflight(s)
                        phase="click"; await s.refs["submit"].click(timeout=10000)
                        phase="rebind"; await self._rebind_or_finish(s,c)
            except Exception: s.status="rejected"; s.key=None; self._receipt(s,phase)
            self._receipt(s)
            if s.wake: s.wake.set()
        if s.status in {"submitted","stage_submitted"}: await self._send(c,s.chat,s.thread,"Secure handoff action submitted.")
        elif s.status=="waiting_for_confirmation": await self._send(c,s.chat,s.thread,"Checkout details are ready. Review the browser page, then authorize the purchase.")
        elif s.status=="rejected": await self._send(c,s.chat,s.thread,"Secure handoff rejected.")
        elif s.status=="publication_failed": await self._send(c,s.chat,s.thread,"Secure handoff unavailable.")
        self._schedule_wake(s)
        raise ApplicationHandlerStop
    def _safe_origin(self,s):
        try: return _origin(s.page.url)
        except Exception: return ""
    def _wake_text(self,status,origin):
        site=origin or "unknown"
        return (
            "[secure-handoff wakeup] Encrypted Mini App handoff finished. "
            f"Status: {status}. Site: {site}. Credentials are not included. "
            "Inspect the live browser and continue the current handoff task. "
            "If status is waiting_for_handoff, a new Mini App was published. "
            "If rejected, diagnose from receipts without reading field values. "
            "If submitted, verify the provider's resulting state."
        )
    def _schedule_wake(self,s):
        if self.adapter is None or not self.loop or not self.loop.is_running(): return
        status,user,chat,thread,origin=s.status,s.user,s.chat,s.thread,self._safe_origin(s)
        try: self.loop.create_task(self._wake_session(status,user,chat,thread,origin))
        except Exception: pass
    async def _wake_session(self,status,user,chat,thread,origin):
        adapter=self.adapter
        if adapter is None or status not in {"submitted","rejected","waiting_for_handoff","publication_failed","stage_submitted"}: return
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
        if not isinstance(request_id,str) or not request_id.startswith("sh_"):
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

SCHEMA={"name":"telegram_secure_handoff","description":"Use for owner-scoped secure handoff work in Hermes's dedicated Chrome profile. Supports generic auth and checkout stages; never submit secrets outside the encrypted Mini App.","parameters":{"type":"object","properties":{"action":{"type":"string","enum":["open","attach","present","read","click","type","wait","close"]},"url":{"type":"string"},"origin":{"type":"string"},"ref":{"type":"string"},"text":{"type":"string"},"timeout":{"type":"integer","maximum":90}},"required":["action"],"additionalProperties":False}}
def register(ctx):
    c=SecureHandoffController(ctx)
    if c.config is not None and len(c.config.allowed_user_ids)!=1:
        return None
    try: c._configured_cdp_url()
    except ValueError: return None
    ctx.register_tool(name="telegram_secure_handoff",toolset="telegram_secure_handoff",schema=SCHEMA,handler=c.tool)
    ctx.register_telegram_handler(c.wire)
    return c
def wire(controller,application,adapter=None): controller.wire(application,adapter)
__all__=["SecureHandoffController","SCHEMA","decrypt_submission","make_request","register","wire"]
