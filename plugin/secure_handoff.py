"""Bounded, owner-scoped Hermes Secure Handoff Telegram controller."""
from __future__ import annotations

import asyncio, base64, inspect, json, re, secrets, threading, time, unicodedata
from dataclasses import dataclass, field
from types import SimpleNamespace
from typing import Any
from urllib.parse import urlsplit

try:
    from . import composition
    from .handoff_adapters import PAYMENT_KINDS, SUPPORTED_FIELD_TYPES, adapter_for_origin, adapter_for_url
    from .config import DEFAULT_CDP_URL, validate_browser_cdp_url
    from .connection_check import load_runtime_config
    from .frame_lease import CHILD_GUARD, PARENT_GUARD, CrossFrameLease, FrameEntry, FrameLeaseError
except ImportError:  # Standalone Hermes plugin loader path.
    import composition
    from handoff_adapters import PAYMENT_KINDS, SUPPORTED_FIELD_TYPES, adapter_for_origin, adapter_for_url
    from config import DEFAULT_CDP_URL, validate_browser_cdp_url
    from connection_check import load_runtime_config
    from frame_lease import CHILD_GUARD, PARENT_GUARD, CrossFrameLease, FrameEntry, FrameLeaseError
TTL = 600
IDLE_TTL = 1800
MAX_SESSIONS = 4
PLUGIN_HANDLER_GROUP = -100
MAX_FIELDS = 24
MAX_SELECT_OPTIONS = 512
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
_TARGET_ID_RE = re.compile(r"^[0-9A-Fa-f]{32}$")
_SAFE_OPTION_RE = re.compile(r"^[^\x00-\x1f\x7f]{0,128}$")

class _FrameBindingError(ValueError):
    """Internal frame rejection with a fixed public-safe reason."""

    def __init__(self, reason="frame_unsupported"):
        self.reason = reason if reason in {"frame_unsupported", "frame_stale"} else "frame_unsupported"
        super().__init__(self.reason)


class _AmbiguousTarget(ValueError):
    """Opaque target lookup failed; never serialize provider exception text."""


def _b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")

def _unb64(value: str) -> bytes:
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_-]+", value): raise ValueError
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))

def _origin(url: str) -> str:
    if not isinstance(url, str) or not url or len(url) > 8192 or "\\" in url:
        raise ValueError("invalid URL")
    if any(c.isspace() or ord(c) < 32 or ord(c) == 127 for c in url):
        raise ValueError("invalid URL")
    p = urlsplit(url)
    port = p.port
    if (p.scheme.lower() != "https" or not p.hostname or p.username is not None
        or p.password is not None or port == 0 or p.netloc.endswith(":")):
        raise ValueError("invalid origin")
    host = p.hostname.encode("idna").decode("ascii")
    if "%" in host: raise ValueError("invalid host")
    if ":" in host: host = f"[{host}]"
    return f"https://{host}" + (f":{port}" if port is not None and port != 443 else "")


def _normalise_option_label(value: str) -> str:
    return " ".join(unicodedata.normalize("NFKC", value).split()).casefold()


def _validate_private_select_options(options: list[dict]) -> None:
    if not isinstance(options, list) or not 1 <= len(options) <= MAX_SELECT_OPTIONS:
        raise ValueError("invalid select options")
    seen_values: set[str] = set()
    seen_labels: set[str] = set()
    for option in options:
        if (
            not isinstance(option, dict)
            or set(option) != {"value", "label"}
            or not isinstance(option["value"], str)
            or not isinstance(option["label"], str)
            or not _SAFE_OPTION_RE.fullmatch(option["value"])
            or not _SAFE_OPTION_RE.fullmatch(option["label"])
            or not option["label"].strip()
            or option["value"] in seen_values
        ):
            raise ValueError("invalid select option")
        normalised = _normalise_option_label(option["label"])
        if not normalised or normalised in seen_labels:
            raise ValueError("ambiguous select option labels")
        seen_values.add(option["value"])
        seen_labels.add(normalised)

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
        if set(field) - {"id", "label", "type", "required", "autocomplete", "inputMode", "options", "selectionMode", "frameOrdinal"}:
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
        frame_ordinal = field.get("frameOrdinal")
        if frame_ordinal is not None and (type(frame_ordinal) is not int or not 0 <= frame_ordinal <= 63):
            raise ValueError("invalid frame ordinal")
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
        selection_mode = field.get("selectionMode")
        if selection_mode is not None and selection_mode != "search":
            raise ValueError("invalid selection mode")
        options = field.get("options")
        if kind == "select":
            if selection_mode == "search":
                if options is not None:
                    raise ValueError("search select cannot publish options")
            else:
                if not isinstance(options, list) or not 1 <= len(options) <= 64:
                    raise ValueError("invalid select options")
                option_ids = set()
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
                    if option["value"] in option_ids: raise ValueError("duplicate select option")
                    option_ids.add(option["value"])
        elif options is not None or selection_mode is not None:
            raise ValueError("selection metadata requires select field")
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
    if mode not in {"auth", "form", "checkout", "payment_confirmation"}:
        raise ValueError("invalid mode")
    _validate_v3_fields(fields, mode)
    if action_label is None:
        action_label = {
            "auth": "Submit to browser",
            "form": "Fill fields",
            "checkout": "Review purchase",
            "payment_confirmation": "Authorize purchase",
        }[mode]
    action_label = _validate_action_label(action_label)
    if mode == "form" and action_label != "Fill fields":
        raise ValueError("invalid form action")
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

def _strict_json(raw):
    def object_pairs(pairs):
        result = {}
        for key, value in pairs:
            if key in result: raise ValueError("duplicate key")
            result[key] = value
        return result
    def invalid_constant(_value):
        raise ValueError("invalid constant")
    return json.loads(raw, object_pairs_hook=object_pairs, parse_constant=invalid_constant)


def decrypt_submission(raw: str, request: dict, key: Any) -> dict[str, Any]:
    try:
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import padding
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        if not isinstance(raw, str) or len(raw.encode()) > 4096: raise ValueError
        obj = _strict_json(raw)
        version = request.get("v")
        if (
            not isinstance(obj, dict)
            or set(obj) != {"v", "id", "wrappedKey", "iv", "ciphertext"}
            or type(obj["v"]) is not int
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
        body = _strict_json(plain.decode())
        if not isinstance(body, dict):
            raise ValueError

        if version == 3 and request.get("mode") == "source_approval":
            if set(body) not in ({"grant"}, {"deny"}): raise ValueError
            decision=next(iter(body))
            if type(body[decision]) is not str or body[decision] != request["source"]["nonce"]:
                raise ValueError
            return body

        if version == 3 and request.get("mode") == "purchase_approval":
            if set(body) != {"approve"} or body["approve"] != request["transaction"]["id"]:
                raise ValueError
            return {"approve": body["approve"]}

        if version == 3 and request.get("mode") == "payment_confirmation":
            raise ValueError

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
            if field["type"] == "checkbox" and (value not in {"true", "false"} or (field.get("required") and value != "true")):
                raise ValueError
            if field["type"] == "select":
                if field.get("selectionMode") != "search" and value not in {option["value"] for option in field.get("options", [])}:
                    raise ValueError
            result[field["id"]] = value
        return result
    except Exception:
        raise ValueError("invalid submission") from None

@dataclass
class Session:
    user: int; chat: int; thread: int|None; page: Any = field(default=None, repr=False); context: Any = field(default=None, repr=False); request: dict|None = None; key: Any = field(default=None, repr=False); site: Any = field(default=None, repr=False); refs: dict[str, Any] = field(default_factory=dict, repr=False); ref_meta: dict[str, dict] = field(default_factory=dict, repr=False); field_parts: dict[str, list[Any]] = field(default_factory=dict, repr=False); field_frames: dict[str, Any] = field(default_factory=dict, repr=False); field_origins: dict[str, str] = field(default_factory=dict, repr=False); field_documents: dict[str, Any] = field(default_factory=dict, repr=False)
    field_hosts: dict[str, Any] = field(default_factory=dict, repr=False)
    field_frame_ordinals: dict[str, int] = field(default_factory=dict, repr=False)
    field_source_labels: dict[str, str] = field(default_factory=dict, repr=False)
    cross_frame: bool = False
    auto_submit: bool = False; status: str = "open"; mode: str = "auth"; checkout_filled: bool = False; used_ids: set[str] = field(default_factory=set, repr=False); wake: asyncio.Event|None = field(default=None, repr=False); lock: asyncio.Lock = field(default_factory=asyncio.Lock, repr=False); updated: float = field(default_factory=time.monotonic); document: Any = field(default=None, repr=False); form: Any = field(default=None, repr=False); scope: Any = field(default=None, repr=False); form_action: str = field(default="", repr=False); submit_action: str = field(default="", repr=False); provider: str = "generic"; stage: str = "browser_auth"

    # Generic forms retain their exact native nodes; no same-looking rebind.
    form_controls: list[dict] = field(default_factory=list, repr=False)
    select_options: dict[str, list[dict]] = field(default_factory=dict, repr=False)
    requested_mode: str | None = None
    deadline: Any = field(default=None, repr=False)
    auth_container: Any = field(default=None, repr=False)
    commit_guard: Any = field(default=None, repr=False)
    commit_slots: dict = field(default_factory=dict, repr=False)
    generation: int = 0
    session_ref: str | None = None
    composition_snapshot: str | None = None
    component_ref: str | None = None
    composition_refs: dict = field(default_factory=dict, repr=False)
    composition_options: dict = field(default_factory=dict, repr=False)
    composition_fields: list = field(default_factory=list, repr=False)
    purchase_blocker: str | None = None
    purchase_factory: Any = field(default=None, repr=False)
    purchase_registry: Any = field(default=None, repr=False)
    purchase_selection: Any = field(default=None, repr=False)
    purchase_fill_completed: float = 0
    purchase_wire: str | None = field(default=None, repr=False)
    purchase_sources: Any = field(default=None, repr=False)
    catalog_grants: list = field(default_factory=list, repr=False)
    catalog_candidates: dict = field(default_factory=dict, repr=False)
    source_pending: Any = field(default=None, repr=False)
    source_entry: Any = field(default=None, repr=False)

try:
    from .observed_purchase import ObservedPurchaseMixin
    from . import observed_purchase
    from .purchase_sources import PurchaseAcquisitionMixin
    from . import purchase_sources
except ImportError:  # Standalone directory loader.
    from observed_purchase import ObservedPurchaseMixin
    import observed_purchase
    from purchase_sources import PurchaseAcquisitionMixin
    import purchase_sources

class SecureHandoffController(PurchaseAcquisitionMixin, ObservedPurchaseMixin):
    def __init__(self, ctx: Any, *, browser=None, playwright=None, context=None, owns_browser=False):
        self.ctx=ctx; self.config=load_runtime_config(ctx); self.loop=None; self.bot=None; self.adapter=None; self._playwright=playwright; self._browser=browser; self._context=context; self._owns_browser=owns_browser; self._cdp_url=""; self.sessions={}; self._lock=threading.RLock(); self._acquisitions={}
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
    async def _page_target_id(self, page):
        cdp = await page.context.new_cdp_session(page)
        try:
            info = await cdp.send("Target.getTargetInfo")
            return info.get("targetInfo", {}).get("targetId")
        finally:
            await cdp.detach()
    async def _existing_page(self, context, origin, target_id=None):
        pages=[]
        for page in getattr(context,"pages",[]):
            try:
                if page.is_closed() or _origin(page.url)!=origin: continue
                if target_id is not None and await self._page_target_id(page) != target_id: continue
                pages.append(page)
            except Exception: continue
        if len(pages)!=1: raise _AmbiguousTarget
        return pages[0]
    def _acquisition_current(self, ident, lease):
        if lease is not None and self._acquisitions.get(ident) is not lease:
            raise ValueError("cancelled acquisition")

    async def _attach_session(self,ident,origin,target_id=None,lease=None):
        self._expire()
        if len(self.sessions)>=MAX_SESSIONS and ident not in self.sessions: raise RuntimeError
        context=await self._shared_context()
        self._acquisition_current(ident, lease)
        page=await self._existing_page(context,origin,target_id); adapter=adapter_for_origin(origin)
        self._acquisition_current(ident, lease)
        if any(other.page is page for key, other in self.sessions.items() if key != ident): raise ValueError("page already leased")
        old=self.sessions.get(ident)
        if old: await self._retire_session(old)
        self._acquisition_current(ident, lease)
        s=Session(*ident,page=page,context=context,wake=asyncio.Event(),provider=adapter.name)
        self.sessions[ident]=s
        return s
    async def _usable_input(self,e):
        try:
            if not await e.is_visible() or not await e.is_enabled() or not await e.is_editable(): return False
            return await e.evaluate("""e => {
                if (!e.isConnected || e.disabled || e.readOnly || !e.getClientRects().length) return false;
                for (let node=e; node; node=node.parentElement) {
                    const s=getComputedStyle(node);
                    if (node.inert || node.getAttribute('aria-hidden') === 'true' || s.display === 'none' || s.visibility === 'hidden' || s.pointerEvents === 'none' || Number(s.opacity) <= 0) return false;
                }
                return true;
            }""") is True
        except Exception: return False
    def _scrub_binding(self, s):
        self._scrub_purchase_sources(s)
        s.purchase_factory = None
        s.purchase_selection = None
        s.purchase_wire = None
        if s.purchase_registry is not None:
            registry, s.purchase_registry = s.purchase_registry, None
            asyncio.get_running_loop().create_task(registry.close())
        if s.deadline:
            s.deadline.cancel()
            s.deadline = None
        s.key = None
        s.request = None
        self._reset_binding(s)
        s.form_controls = []
        s.document = None
        s.composition_refs.clear()
        s.composition_options.clear()
        s.composition_fields.clear()

    async def _retire_session(self, s):
        self._invalidate(s, "cancelled")
        async with s.lock:
            self._scrub_binding(s)
            identity = (s.user, s.chat, s.thread)
            if self.sessions.get(identity) is s:
                self.sessions.pop(identity, None)
            if s.wake: s.wake.set()

    def _expire(self):
        for i,s in list(self.sessions.items()):
            if s.request and s.request["expiresAt"] <= int(time.time()*1000):
                self._invalidate(s, "expired")
                if not s.lock.locked(): self._scrub_binding(s)
                if s.wake: s.wake.set()
            if time.monotonic()-s.updated>IDLE_TTL:
                self._invalidate(s, "expired")
                if not s.lock.locked(): self._scrub_binding(s)
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
    async def _new_session(self,ident,url,demo=False,lease=None):
        if demo and not (self._owns_browser and self._context is not None):
            raise ValueError("demo requires an owned synthetic context")
        self._expire()
        if len(self.sessions)>=MAX_SESSIONS: raise RuntimeError
        context=await self._shared_context()
        self._acquisition_current(ident, lease)
        page=await self._shared_page(context)
        self._acquisition_current(ident, lease)
        if any(other.page is page for other in self.sessions.values()): raise ValueError("page already leased")
        await page.goto(url,wait_until="domcontentloaded",timeout=30000)
        self._acquisition_current(ident, lease)
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
        if submit is not None:
            action_text = await submit.evaluate("e => (e.innerText || e.getAttribute('value') || e.getAttribute('aria-label') || '').trim().toLowerCase()")
            if action_text not in {"continue", "next", "sign in", "log in", "login", "verify", "verify code", "submit"}:
                raise ValueError("not an auth action")
            # Autofill hints identify data, not the operation. Account deletion
            # and profile edits also use current-password/username. Ambiguous
            # actions always remain fill-only, even with those hints.
            explicit = any(m["autocomplete"] in {"username", "current-password", "one-time-code"} for _, _, m in candidates)
            if action_text in {"continue", "next", "submit"}:
                raise ValueError("ambiguous action is fill-only")
            if any(m["autocomplete"] == "new-password" for _, _, m in candidates):
                raise ValueError("registration is fill-only")
            if not explicit and not any(k in {"password", "otp"} for k, _, _ in candidates):
                raise ValueError("not an auth stage")
        action=await page.evaluate("form => form.action",form) if form else page.url
        submit_action=action
        override=await page.evaluate("button => button.formAction || ''",submit) if submit else ""
        if override: submit_action=override
        if _origin(action)!=_origin(page.url) or _origin(submit_action)!=_origin(page.url): raise ValueError
        s.document=await page.evaluate_handle("() => document"); s.form=form; s.scope=scope; s.form_action=action; s.submit_action=submit_action
        s.auth_container=await page.evaluate_handle("e => e.closest('dialog, [role=dialog], main') || document.body", candidates[0][1])
        logical=[("otp",candidates[0][1],[element for _,element,_ in candidates])] if split_otp else [(kind,element,[element]) for kind,element,_ in candidates]
        s.stage=adapter.stage_for(tuple(kind for kind,_,_ in logical)).id
        s.mode="auth"; s.refs={}; s.ref_meta={}; s.field_parts={}; s.field_frames={}; s.field_origins={}; s.field_documents={}; s.auto_submit=split_otp and submit is None
        labels={"text":"Username or email","email":"Email","tel":"Phone","number":"Number","password":"Password","otp":"One-time code"}
        for i,(kind,element,parts) in enumerate(logical):
            field_id=f"f{i}"; s.refs[field_id]=element; s.field_parts[field_id]=parts; s.field_frames[field_id]=page.main_frame; s.field_origins[field_id]=_origin(page.url); s.field_documents[field_id]=s.document; s.ref_meta[field_id]={"label":labels[kind],"type":kind,"required":True}
        if submit is not None: s.refs["submit"]=submit
    async def _release_guard(self, guard):
        try: await guard.evaluate("g => {g.revoked=true;}")
        except Exception: pass
        finally:
            try: await guard.dispose()
            except Exception: pass

    def _invalidate(self, s, status):
        s.generation += 1
        s.status = status
        s.key = None
        if s.commit_guard is not None:
            guard, s.commit_guard = s.commit_guard, None
            asyncio.get_running_loop().create_task(self._release_guard(guard))

    def _current(self, s, generation=None):
        return (self.sessions.get((s.user,s.chat,s.thread)) is s
                and s.status not in {"cancelled", "expired"}
                and (generation is None or generation == s.generation))

    def _reset_binding(self, s):
        if s.commit_guard is not None:
            guard, s.commit_guard = s.commit_guard, None
            asyncio.get_running_loop().create_task(self._release_guard(guard))
        s.commit_slots = {}
        s.form_controls = []
        s.select_options = {}
        s.auth_container = None
        s.document = None
        s.refs = {}
        s.ref_meta = {}
        s.field_parts = {}
        s.field_frames = {}
        s.field_origins = {}
        s.field_documents = {}
        s.field_hosts = {}
        s.field_frame_ordinals = {}
        s.field_source_labels = {}
        s.cross_frame = False
        s.form = None
        s.scope = None
        s.form_action = ""
        s.submit_action = ""
        s.checkout_action = None
        s.auto_submit = False

    async def _select_option_metadata(self, element):
        return await element.evaluate(
            """(e, limit) => {
                let count = 0;
                const options = [];
                for (const option of e.options) {
                    if (option.disabled || (option.parentElement && option.parentElement.disabled)) continue;
                    count += 1;
                    if (options.length < limit) {
                        options.push({value: String(option.value), label: String(option.textContent || '').trim()});
                    }
                }
                return {count, options};
            }""",
            MAX_SELECT_OPTIONS + 1,
        )

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
        options = all_options = None
        option_count = None
        if tag == "select":
            option_data = await self._select_option_metadata(element)
            option_count = option_data.get("count") if isinstance(option_data, dict) else None
            all_options = option_data.get("options") if isinstance(option_data, dict) else None
            if not isinstance(option_count, int) or not isinstance(all_options, list) or option_count != len(all_options) or option_count > MAX_SELECT_OPTIONS:
                raise ValueError("invalid select options")
            options = all_options[:64]
            if option_count > 64:
                _validate_private_select_options(all_options)
        return {
            "kind": kind,
            "label": label,
            "required": (await element.get_attribute("required")) is not None or (await element.get_attribute("aria-required")) == "true",
            "autocomplete": metadata["autocomplete"] or None,
            "inputMode": metadata["inputmode"] or None,
            "options": options,
            "all_options": all_options,
            "option_count": option_count,
            "metadata": metadata,
            "frame": frame,
        }

    async def _find_checkout_action(self, page, adapter):
        # Billing/checkout flows commonly render an active modal over a page
        # that still contains an underlying action with the same label. Scope
        # discovery to the sole visible dialog instead of guessing globally.
        roots = [page]
        visible_dialogs = []
        for dialog in await page.locator("dialog,[role=dialog]").all():
            try:
                if await dialog.is_visible():
                    visible_dialogs.append(dialog)
            except Exception:
                continue
        if len(visible_dialogs) == 1:
            roots = visible_dialogs
        found = []
        labels = {label.casefold() for label in CHECKOUT_ACTIONS}
        for root in roots:
            for locator in await root.locator("button, input[type=submit], [role=button]").all():
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

    async def _frame_host_in_scope(self, page, frame, scope, expected_host=None):
        """Validate an iframe host chain without ever crossing a child handle."""
        if frame == page.main_frame:
            return True
        parent = frame.parent_frame
        if parent is None:
            raise _FrameBindingError("frame_stale")
        try:
            host = await frame.frame_element()
            if host is None:
                raise _FrameBindingError("frame_stale")
            if expected_host is not None:
                same = await parent.evaluate("a => a[0] === a[1]", [host, expected_host])
                if same is not True:
                    raise _FrameBindingError("frame_stale")
            while parent != page.main_frame:
                valid = await parent.evaluate("""host => {
                    if (!host || !host.isConnected || host.ownerDocument !== document || !host.getClientRects().length) return false;
                    for (let n=host; n; n=n.parentElement) {
                        const s=getComputedStyle(n);
                        if (n.inert || n.hidden || n.getAttribute('aria-hidden')==='true' || s.display==='none' ||
                            s.visibility !== 'visible' || Number(s.opacity) <= 0 || s.pointerEvents === 'none') return false;
                    }
                    return true;
                }""", host)
                if valid is not True:
                    return False
                host = await parent.frame_element()
                if host is None:
                    raise _FrameBindingError("frame_stale")
                parent = parent.parent_frame
                if parent is None:
                    raise _FrameBindingError("frame_stale")
            return await page.evaluate("""a => {
                const [host, scope] = a;
                if (!host || !scope || !host.isConnected || !scope.isConnected ||
                    host.ownerDocument !== document || scope.ownerDocument !== document || !scope.contains(host) ||
                    !host.getClientRects().length) return false;
                for (let n=host; n; n=n.parentElement) {
                    const s=getComputedStyle(n);
                    if (n.inert || n.hidden || n.getAttribute('aria-hidden')==='true' || s.display==='none' ||
                        s.visibility !== 'visible' || Number(s.opacity) <= 0 || s.pointerEvents === 'none') return false;
                }
                return true;
            }""", [host, scope]) is True
        except _FrameBindingError:
            raise
        except Exception:
            raise _FrameBindingError("frame_stale") from None

    async def _frame_host_contained(self, page, frame, scope):
        """Check frame-host containment without treating hidden hosts as active."""
        if frame == page.main_frame:
            return True
        parent = frame.parent_frame
        if parent is None:
            raise _FrameBindingError("frame_stale")
        try:
            host = await frame.frame_element()
            if host is None:
                raise _FrameBindingError("frame_stale")
            while parent != page.main_frame:
                if await parent.evaluate(
                    "host => !!host && host.isConnected && host.ownerDocument === document", host
                ) is not True:
                    return False
                host = await parent.frame_element()
                if host is None:
                    raise _FrameBindingError("frame_stale")
                parent = parent.parent_frame
                if parent is None:
                    raise _FrameBindingError("frame_stale")
            return await page.evaluate(
                "a => !!a[0] && !!a[1] && a[0].isConnected && a[1].isConnected && "
                "a[0].ownerDocument === document && a[1].ownerDocument === document && a[1].contains(a[0])",
                [host, scope],
            ) is True
        except _FrameBindingError:
            raise
        except Exception:
            raise _FrameBindingError("frame_stale") from None

    async def _frame_has_visible_controls(self, frame):
        controls = []
        for locator in await frame.locator(
            'input,textarea,select,button,[contenteditable],[role="textbox"],[role="combobox"],[role="checkbox"],[role="radio"],[role="slider"],[role="button"],[onclick],[tabindex]'
        ).all():
            try:
                if await locator.is_visible():
                    controls.append(locator)
            except Exception:
                continue
        return controls

    async def _validate_scope_iframes(self, scope):
        """Validate active iframe hosts; non-rendered helper frames are inert."""
        scope_element = scope.as_element() if hasattr(scope, "as_element") else scope
        if scope_element is None:
            raise _FrameBindingError("frame_stale")
        for iframe in await scope_element.query_selector_all("iframe"):
            try:
                if not await iframe.evaluate("""e => {
                    if (!e.isConnected || !e.getClientRects().length) return false;
                    for (let n=e; n; n=n.parentElement) {
                        const s=getComputedStyle(n);
                        if (n.inert || n.hidden || n.getAttribute('aria-hidden') === 'true' ||
                            s.display === 'none' || s.visibility !== 'visible' || Number(s.opacity) <= 0 ||
                            s.pointerEvents === 'none') return false;
                    }
                    return true;
                }"""):
                    continue
            except _FrameBindingError:
                raise
            except Exception:
                raise _FrameBindingError("frame_stale") from None
            finally:
                try: await iframe.dispose()
                except Exception: pass

    async def _bind_checkout(self, s):
        page = s.page
        was_filled = bool(getattr(s, "checkout_filled", False))
        adapter = adapter_for_url(page.url)
        action, form, scope, action_url, submit_action = await self._find_checkout_action(page, adapter)
        page_origin = _origin(page.url)
        await self._validate_scope_iframes(scope)
        candidates = []
        for frame_ordinal, frame in enumerate(page.frames):
            if frame_ordinal > 63:
                raise _FrameBindingError("frame_unsupported")
            if frame == page.main_frame:
                frame_origin = page_origin
                frame_doc = await page.evaluate_handle("() => document")
                frame_host = None
                visible_controls = await self._frame_has_visible_controls(frame)
            else:
                try:
                    frame_host = await frame.frame_element()
                    if frame_host is None:
                        raise _FrameBindingError("frame_stale")
                    if not await self._frame_host_contained(page, frame, scope):
                        continue
                    if not await self._frame_host_in_scope(page, frame, scope, frame_host):
                        continue
                    frame_origin = _origin(frame.url)
                except _FrameBindingError:
                    raise
                except Exception:
                    raise _FrameBindingError("frame_unsupported") from None
                visible_controls = await self._frame_has_visible_controls(frame)
                if not visible_controls:
                    raise _FrameBindingError("frame_unsupported")
                frame_doc = await frame.evaluate_handle("() => document")
                custom_controls = [
                    await control.evaluate(
                        "e => !['INPUT','TEXTAREA','SELECT'].includes(e.tagName)"
                    )
                    for control in visible_controls
                ]
                if any(custom_controls):
                    raise _FrameBindingError("frame_unsupported")
            for element in visible_controls:
                try:
                    handle = await element.element_handle()
                    if frame == page.main_frame and handle and await page.evaluate(
                        "a => a[0] === a[1]", [handle, action]
                    ) is True:
                        continue
                    if frame == page.main_frame and not await element.evaluate(
                        "e => ['INPUT','TEXTAREA','SELECT'].includes(e.tagName)"
                    ):
                        if handle and await page.evaluate(
                            "a => a[1].contains(a[0])", [handle, scope]
                        ) is True:
                            raise _FrameBindingError("frame_unsupported")
                        continue
                    if not await self._usable_input(element):
                        if frame != page.main_frame:
                            raise _FrameBindingError("frame_unsupported")
                        continue
                    candidate = await self._control_metadata(element, frame, adapter)
                    if candidate is None:
                        if frame != page.main_frame:
                            raise _FrameBindingError("frame_unsupported")
                        continue
                    handle = await element.element_handle()
                    if not handle:
                        raise _FrameBindingError("frame_stale")
                    if frame == page.main_frame:
                        in_scope = await page.evaluate(
                            """a => {
                                const [element, form, scope] = a;
                                if (!element || !element.isConnected) return false;
                                if (form) return element.form === form || form.contains(element);
                                return !!scope && scope.contains(element);
                            }""",
                            [handle, form, scope],
                        )
                        if in_scope is not True:
                            continue
                    candidate.update({
                        "handle": handle,
                        "origin": frame_origin,
                        "document": frame_doc,
                        "host": frame_host,
                        "frameOrdinal": frame_ordinal,
                    })
                    candidates.append(candidate)
                except _FrameBindingError:
                    raise
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
        s.checkout_action = action
        s.mode = "checkout"
        s.stage = "checkout_details"
        s.checkout_filled = was_filled
        s.refs["submit"] = action
        s.cross_frame = any(candidate["frame"] != page.main_frame for candidate in candidates)
        for index, candidate in enumerate(candidates):
            field_id = f"f{index}"
            public_label = candidate["label"]
            if s.cross_frame:
                public_label = candidate["kind"].replace("_", " ").replace("-", " ").title() + f" {index + 1}"
            metadata = {
                "label": public_label,
                "type": candidate["kind"],
                "required": bool(candidate["required"]),
            }
            if s.cross_frame:
                metadata["frameOrdinal"] = candidate["frameOrdinal"]
            if not s.cross_frame and candidate["autocomplete"] and re.fullmatch(r"[A-Za-z0-9_-]{1,64}", candidate["autocomplete"]):
                metadata["autocomplete"] = candidate["autocomplete"]
            if not s.cross_frame and candidate["inputMode"] in {"text", "numeric", "decimal", "tel", "email"}:
                metadata["inputMode"] = candidate["inputMode"]
            if candidate["kind"] == "select":
                if candidate["option_count"] > 64:
                    metadata["selectionMode"] = "search"
                else:
                    metadata["options"] = [
                        {"value": f"o{i}", "label": f"Option {i + 1}"}
                        for i, _option in enumerate(candidate["options"])
                    ]
            s.refs[field_id] = candidate["handle"]
            s.ref_meta[field_id] = metadata
            if candidate["kind"] == "select":
                s.select_options[field_id] = list(candidate["all_options"])
                if s.cross_frame and candidate["option_count"] <= 64:
                    s.composition_options[field_id] = {
                        f"o{i}": option["value"]
                        for i, option in enumerate(candidate["all_options"])
                    }
            s.field_parts[field_id] = [candidate["handle"]]
            s.field_frames[field_id] = candidate["frame"]
            s.field_origins[field_id] = candidate["origin"]
            s.field_documents[field_id] = candidate["document"]
            s.field_hosts[field_id] = candidate["host"]
            s.field_frame_ordinals[field_id] = candidate["frameOrdinal"]
            s.field_source_labels[field_id] = candidate["label"]
            s.form_controls.append({"handle": candidate["handle"], "metadata": candidate["metadata"],
                                    "field": metadata, "select_options": candidate["all_options"],
                                    "frame": candidate["frame"], "origin": candidate["origin"],
                                    "document": candidate["document"], "host": candidate["host"],
                                    "frameOrdinal": candidate["frameOrdinal"]})
    async def _collect_form_controls(self, page):
        """Read bounded native metadata only, never current values/checked state."""
        adapter = adapter_for_url(page.url)
        controls = []
        scope = form = None
        # Unsupported visible widgets must not silently disappear from a form.
        selector = 'input, textarea, select, [contenteditable], [role=textbox], [role=combobox], [role=checkbox], [role=radio], [role=slider], [role=button], [onclick], [tabindex], iframe'
        for locator in await page.locator(selector).all():
            if not await locator.is_visible():
                continue
            tag = (await locator.evaluate("e => e.tagName")).lower()
            typ = (await locator.get_attribute("type") or "text").lower()
            if tag == "input" and typ in {"hidden", "button", "submit", "reset", "image"}:
                continue
            if tag == "button":
                continue
            if not await self._usable_input(locator):
                # Disabled/inert native controls are not user-editable; custom widgets fail closed.
                if tag in {"input", "textarea", "select"} and typ != "file":
                    continue
                raise ValueError("unsupported control")
            metadata = {name: await locator.get_attribute(name) or "" for name in
                        ("name", "autocomplete", "inputmode", "min", "max", "step", "pattern", "maxlength", "multiple", "role")}
            metadata.update(tag=tag, type=typ)
            if typ == "range" and any(metadata[k] not in {"", default} for k, default in (("min","0"),("max","100"),("step","1"))):
                raise ValueError("range domain unsupported")
            kind = adapter.classify_form_control(metadata)
            if kind is None or (tag == "select" and await locator.get_attribute("multiple") is not None):
                raise ValueError("unsupported control")
            handle = await locator.element_handle()
            if handle is None:
                raise ValueError("missing control")
            current_form = await page.evaluate_handle("e => e.form", handle)
            has_form = await page.evaluate("f => !!f", current_form)
            current_scope = current_form if has_form else await page.evaluate_handle("e => e.closest('dialog, [role=dialog], main') || document.body", handle)
            if scope is None:
                scope, form = current_scope, current_form if has_form else None
            elif not await page.evaluate("a => a[0] === a[1]", [scope, current_scope]):
                raise ValueError("ambiguous form")
            label = await handle.evaluate("""e => ((e.labels && [...e.labels].map(l => l.textContent || '').join(' ')) || e.getAttribute('aria-label') || e.getAttribute('name') || '').replace(/\\s+/g,' ').trim().slice(0,80)""")
            field_meta = {"label": label or kind.replace("-", " ").title(), "type": kind,
                          "required": await locator.get_attribute("required") is not None or await locator.get_attribute("aria-required") == "true"}
            # Only syntactically bounded metadata is projected; full raw constraints stay private.
            autocomplete = metadata["autocomplete"]
            if re.fullmatch(r"[A-Za-z0-9_-]{1,64}", autocomplete):
                field_meta["autocomplete"] = autocomplete
            if metadata["inputmode"] in {"text", "numeric", "decimal", "tel", "email"}:
                field_meta["inputMode"] = metadata["inputmode"]
            select_options = None
            if tag == "select":
                option_data = await self._select_option_metadata(handle)
                if not isinstance(option_data, dict) or option_data.get("count") != len(option_data.get("options", [])):
                    raise ValueError("invalid select options")
                select_options = list(option_data["options"])
                if len(select_options) > 64:
                    _validate_private_select_options(select_options)
                    field_meta["selectionMode"] = "search"
                else:
                    field_meta["options"] = select_options
            controls.append({"handle": handle, "metadata": metadata, "field": field_meta, "select_options": select_options})
            if len(controls) > MAX_FIELDS * 8:
                raise ValueError("too many controls")
        if not controls:
            raise ValueError("no form controls")
        return controls, form, scope

    async def _bind_form(self, s):
        page = s.page
        origin = _origin(page.url)
        controls, form, scope = await self._collect_form_controls(page)
        await self._validate_scope_iframes(scope)
        action = await page.evaluate("f => f.action", form) if form else page.url
        if _origin(action) != origin:
            raise ValueError("form action origin mismatch")
        self._reset_binding(s)
        s.form_controls = controls
        s.document = await page.evaluate_handle("() => document")
        s.form, s.scope, s.form_action = form, scope, action
        s.mode, s.stage = "form", "general_form"
        radio_groups = {}
        for control in controls:
            metadata, field_meta = control["metadata"], dict(control["field"])
            if metadata["type"] == "radio":
                name = metadata["name"]
                if not name:
                    raise ValueError("unnamed radio group")
                if name in radio_groups:
                    field_id = radio_groups[name]
                    s.field_parts[field_id].append(control["handle"])
                    s.ref_meta[field_id]["required"] |= field_meta["required"]
                    s.ref_meta[field_id]["options"].append({"value": f"o{len(s.field_parts[field_id])-1}", "label": field_meta["label"]})
                    continue
                field_id = f"f{len(s.ref_meta)}"
                radio_groups[name] = field_id
                field_meta["options"] = [{"value": "o0", "label": field_meta["label"]}]
                field_meta["label"] = "Radio selection"
            else:
                field_id = f"f{len(s.ref_meta)}"
            s.refs[field_id] = control["handle"]
            s.ref_meta[field_id] = field_meta
            if control.get("select_options") is not None:
                s.select_options[field_id] = list(control["select_options"])
            s.field_parts[field_id] = [control["handle"]]
            s.field_frames[field_id] = page.main_frame
            s.field_origins[field_id] = origin
            s.field_documents[field_id] = s.document
        for field_id in radio_groups.values():
            if not 2 <= len(s.field_parts[field_id]) <= 64:
                raise ValueError("ambiguous radio group")
        _validate_v3_fields([{"id": key, **meta} for key, meta in s.ref_meta.items()], "form")

    async def _bind_composed_entry(self, s):
        """Bind a composed fill-only scope that includes vetted child frames."""
        await self._bind_checkout(s)
        if not s.cross_frame:
            raise ValueError("not a frame-aware composition")
        # The checkout action remains privately pinned as checkout_action, but it
        # is never a model-facing component or a fill slot in compose mode.
        s.refs.pop("submit", None)
        s.mode = "form"
        s.stage = "general_form"
        _validate_v3_fields([{"id": key, **meta} for key, meta in s.ref_meta.items()], "form")

    async def _validate_frame_lease_entry(self, s, entry):
        """Revalidate one private frame/document/host identity."""
        self._assert_active(s)
        frame = entry.frame
        if frame == s.page.main_frame:
            return
        try:
            if frame.is_detached() or s.page.frames[entry.ordinal] is not frame:
                raise _FrameBindingError("frame_stale")
            if _origin(frame.url) != entry.origin:
                raise _FrameBindingError("frame_stale")
            if await frame.evaluate("d => d === document", entry.document) is not True:
                raise _FrameBindingError("frame_stale")
            if await self._frame_host_in_scope(s.page, frame, s.scope, entry.host) is not True:
                raise _FrameBindingError("frame_stale")
        except _FrameBindingError:
            raise
        except Exception:
            raise _FrameBindingError("frame_stale") from None

    async def _pin_cross_frame_guard(self, s, *, parent_guard=None, allow_click=False, summary=None, deadline=None):
        """Create a composite lease with frame-local native mutation guards."""
        if deadline is None:
            deadline = s.request["expiresAt"]
        fields = [field_id for field_id in s.ref_meta if field_id.startswith("f")]
        parent_nodes = []
        parent_fields = {}
        grouped = {}
        index_map = {}
        s.commit_slots = {}
        global_index = 0
        for field_id in fields:
            parts = s.field_parts.get(field_id) or [s.refs[field_id]]
            slots = []
            for handle in parts:
                frame = s.field_frames.get(field_id)
                if frame is None:
                    raise _FrameBindingError("frame_stale")
                slots.append(global_index)
                if frame == s.page.main_frame:
                    parent_fields[global_index] = len(parent_nodes)
                    parent_nodes.append(handle)
                else:
                    grouped.setdefault(frame, []).append((global_index, handle))
                global_index += 1
            s.commit_slots[field_id] = slots
        if parent_guard is None:
            action = getattr(s, "checkout_action", None) or s.refs.get("submit")
            parent_guard = await s.page.evaluate_handle(PARENT_GUARD, {
                "nodes": parent_nodes,
                "form": s.form,
                "scope": s.scope,
                "doc": s.document,
                "action": action,
                "deadline": deadline,
                "submitAction": s.submit_action,
                "allowClick": allow_click,
            })
        entries = []
        guards = []
        try:
            for frame, frame_fields in grouped.items():
                if frame.is_detached() or frame not in s.page.frames:
                    raise _FrameBindingError("frame_stale")
                first_field = next(field_id for field_id in fields if s.field_frames.get(field_id) is frame)
                document = s.field_documents[first_field]
                origin = s.field_origins[first_field]
                host = s.field_hosts[first_field]
                local_nodes = [handle for _, handle in frame_fields]
                guard = await frame.evaluate_handle(CHILD_GUARD, {
                    "nodes": local_nodes,
                    "doc": document,
                    "origin": origin,
                    "deadline": deadline,
                })
                guards.append(guard)
                entry = FrameEntry(frame, document, origin, host, s.field_frame_ordinals[first_field], guard, frame_fields)
                entries.append(entry)
                for local_index, (index, _handle) in enumerate(frame_fields):
                    index_map[index] = (guard, local_index)
            async def validate_topology():
                known = {entry.frame for entry in entries}
                for frame in s.page.frames:
                    if frame == s.page.main_frame or frame in known:
                        continue
                    try:
                        host = await frame.frame_element()
                        if host is None:
                            continue
                        if await self._frame_host_in_scope(s.page, frame, s.scope, host) is True:
                            raise _FrameBindingError("frame_stale")
                    except _FrameBindingError:
                        raise
                    except Exception:
                        # A frame that cannot be classified is not safe to
                        # ignore if it appeared under the bound checkout.
                        raise FrameLeaseError("frame_stale") from None
            lease = CrossFrameLease(
                parent_guard=parent_guard,
                parent_fields=parent_fields,
                frames=entries,
                index_map=index_map,
                validate_frame=lambda entry: self._validate_frame_lease_entry(s, entry),
                validate_topology=validate_topology,
                deadline=deadline,
                allow_click=allow_click,
                summary=summary,
            )
            await lease.check_all()
            return lease
        except BaseException:
            for guard in guards:
                try:
                    await guard.evaluate("g => {g.revoked=true;}")
                except Exception:
                    pass
                finally:
                    try:
                        await guard.dispose()
                    except Exception:
                        pass
            if parent_guard is not None and parent_guard is not getattr(s, "commit_guard", None):
                try:
                    await parent_guard.evaluate("g => {g.revoked=true;}")
                except Exception:
                    pass
                finally:
                    try:
                        await parent_guard.dispose()
                    except Exception:
                        pass
            raise
    async def _preflight_frame_form(self, s):
        """Private preflight for a top checkout scope with child native controls."""
        if s.mode != "form" or not s.request or s.request.get("mode") != "form" or "submit" in s.refs:
            raise ValueError("invalid frame form mode")
        if s.request["expiresAt"] < int(time.time() * 1000) or _origin(s.page.url) != s.request["origin"]:
            raise _FrameBindingError("frame_stale")
        if await s.page.evaluate("d => d === document", s.document) is not True:
            raise _FrameBindingError("frame_stale")
        if not s.form or not s.scope:
            raise _FrameBindingError("frame_stale")
        if await s.page.evaluate("f => f.ownerDocument === document && f.isConnected", s.form) is not True:
            raise _FrameBindingError("frame_stale")
        if await s.page.evaluate("e => e.ownerDocument === document && e.isConnected", s.scope) is not True:
            raise _FrameBindingError("frame_stale")
        action = await s.page.evaluate("f => f.action", s.form)
        if action != s.form_action or _origin(action) != s.request["origin"]:
            raise _FrameBindingError("frame_stale")
        expected = s.composition_fields if s.requested_mode == "compose" else [{"id": key, **meta} for key, meta in s.ref_meta.items()]
        if s.request["fields"] != expected:
            raise _FrameBindingError("frame_stale")
        checked_frames = set()
        adapter = adapter_for_url(s.page.url)
        for control in s.form_controls:
            frame = control["frame"]
            if frame != s.page.main_frame:
                marker = id(frame)
                if marker not in checked_frames:
                    await self._validate_frame_lease_entry(s, SimpleNamespace(
                        frame=frame, ordinal=control["frameOrdinal"], origin=control["origin"],
                        document=control["document"], host=control["host"],
                    ))
                    checked_frames.add(marker)
                if await frame.evaluate(
                    "a => a[0].isConnected && a[0].ownerDocument === a[1]",
                    [control["handle"], control["document"]],
                ) is not True:
                    raise _FrameBindingError("frame_stale")
            else:
                if await s.page.evaluate(
                    "a => a[0].isConnected && a[0].ownerDocument === a[1] && a[2].contains(a[0])",
                    [control["handle"], s.document, s.scope],
                ) is not True:
                    raise _FrameBindingError("frame_stale")
            live = await self._control_metadata(control["handle"], frame, adapter)
            if live is None or live["metadata"] != control["metadata"] or live["kind"] != control["field"]["type"]:
                raise _FrameBindingError("frame_stale")
            if bool(live["required"]) != bool(control["field"]["required"]):
                raise _FrameBindingError("frame_stale")
            if control.get("select_options") != live.get("all_options"):
                raise _FrameBindingError("frame_stale")
        if s.commit_guard is not None:
            await s.commit_guard.evaluate("g => g.check()")

    async def _preflight_form(self, s):
        if getattr(s, "cross_frame", False):
            return await self._preflight_frame_form(s)
        if s.mode != "form" or s.request.get("mode") != "form" or "submit" in s.refs:
            raise ValueError("invalid form mode")
        if s.request["expiresAt"] < int(time.time()*1000) or _origin(s.page.url) != s.request["origin"]:
            raise ValueError("stale form")
        if await s.page.evaluate("d => d === document", s.document) is not True:
            raise ValueError("stale document")
        controls, form, scope = await self._collect_form_controls(s.page)
        if len(controls) != len(s.form_controls) or not await s.page.evaluate("a => a[0] === a[1]", [scope, s.scope]):
            raise ValueError("changed form")
        action = await s.page.evaluate("f => f.action", form) if form else s.page.url
        if action != s.form_action or _origin(action) != s.request["origin"]:
            raise ValueError("changed form action")
        expected = s.composition_fields if s.requested_mode == "compose" else [{"id": key, **meta} for key, meta in s.ref_meta.items()]
        if s.request["fields"] != expected:
            raise ValueError("changed field metadata")
        for old, live in zip(s.form_controls, controls):
            if old["metadata"] != live["metadata"] or old["field"] != live["field"]:
                raise ValueError("changed control metadata")
            if old.get("select_options") != live.get("select_options"):
                raise ValueError("changed select options")
            if not await s.page.evaluate("a => a[0] === a[1] && a[0].isConnected && a[0].ownerDocument === document", [old["handle"], live["handle"]]):
                raise ValueError("changed control")

    async def _bind_stage(self, s):
        if s.requested_mode == "form":
            await self._bind_form(s)
            return
        try:
            await self._bind_checkout(s)
        except Exception:
            self._reset_binding(s)
            try:
                await self._bind_auth_stage(s)
                s.mode = "auth"
            except Exception:
                self._reset_binding(s)
                await self._bind_form(s)

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
    async def _deadline_expired(self, s, request_id):
        if not s.request or s.request["id"] != request_id: return
        self._invalidate(s, "expired")
        async with s.lock:
            if s.request and s.request["id"] == request_id:
                self._scrub_binding(s)
                if s.wake: s.wake.set()

    def _arm_deadline(self, s):
        if s.deadline: s.deadline.cancel()
        loop = asyncio.get_running_loop()
        request_id = s.request["id"]
        delay = max(0, (s.request["expiresAt"] - int(time.time()*1000)) / 1000)
        s.deadline = loop.call_later(delay, lambda: loop.create_task(self._deadline_expired(s, request_id)))

    async def cancel_from_update(self, update):
        identity = self._authorized(update)
        self._acquisitions.pop(identity, None)
        s = self.sessions.get(identity) if identity else None
        if s is None:
            return False
        self._invalidate(s, "cancelled")
        async with s.lock:
            if self.sessions.get(identity) is not s:
                return False
            if s.request:
                s.used_ids.add(s.request["id"])
            s.key = None
            s.request = None
            s.status = "cancelled"
            self._scrub_binding(s)
            self.sessions.pop(identity, None)
            if s.wake:
                s.wake.set()
        # Cancellation releases capabilities, not browser tabs or their state.
        return True

    async def _close(self,ident):
        self._acquisitions.pop(ident, None)
        s=self.sessions.get(ident)
        if not s: return {"status":"unavailable", "reason":"session_missing"}
        # Signal cancellation before waiting for any active encrypted apply.
        self._invalidate(s, "cancelled")
        async with s.lock:
            if self.sessions.get(ident) is s: self.sessions.pop(ident,None)
            self._scrub_binding(s)
            if s.wake: s.wake.set()
        await self._dispose(s)
        return {"status":"closed"}
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
        # Never expose ordinary DOM text or editable refs through this tool.
        s.refs, s.ref_meta = {}, {}
        return {}, {}
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
            if s.status not in {"cancelled","expired"}: s.status = "unsupported_stage"
            return {"status":s.status}
    async def _snapshot(self,s):
        if s.status == "purchase_review_ready":
            return {"status":s.status,"session_ref":s.session_ref}
        if s.status == "human_action_required" and s.purchase_blocker in {"public_fact_source_unavailable", "purchase_binding_unsupported"}:
            return {"status":s.status, "url":self._safe_origin(s), "reason":s.purchase_blocker}
        if s.status in {"filled", "human_action_required", "purchase_submitted", "outcome_unknown", "rejected", "cancelled", "expired"}:
            return {"status": s.status, "url": self._safe_origin(s)}
        if s.request and s.key and s.status in {"waiting_for_handoff", "waiting_for_confirmation"}:
            return {"status": s.status, "url": self._safe_origin(s)}
        if await self._stage_detected(s): return await self._ensure_prompt(s)
        return {"status": s.status, "url": self._safe_origin(s)}

    async def _ordinary(self,s,action,args):
        # No model-authored values or action bypasses in the handoff tool.
        ref = args.get("ref", "")
        if isinstance(ref, str) and ref in s.refs:
            try:
                if await s.page.evaluate("a => a[0].ownerDocument !== document || !a[0].isConnected", [s.refs[ref]]):
                    return {"status":"stale_ref"}
            except Exception:
                return {"status":"stale_ref"}
        return {"status":"forbidden"}

    async def _composition(self, action, args, ident):
        if not composition.valid_payload(action,args): return {"status":"invalid"}
        denied = {"status":"rejected"}
        s = self.sessions.get(ident)
        if not s or s.requested_mode != "compose": return denied
        if (action == 'cancel_composition' and args['component_ref'] == s.component_ref
                and s.component_ref and s.status == 'waiting_for_handoff'):
            self._invalidate(s,'cancelled')
        async with s.lock:
            if self.sessions.get(ident) is not s: return denied
            if action in {"composition_status", "cancel_composition"}:
                if args['component_ref'] != s.component_ref or not s.component_ref: return denied
                if action == 'cancel_composition' and s.status == 'cancelled':
                    self._scrub_binding(s)
                    if s.wake: s.wake.set()
                return {"status":s.status, "component_ref":s.component_ref}
            if not self._current(s): return denied
            if action == 'discover_components':
                if args['session_ref'] != s.session_ref or not s.session_ref: return denied
                if s.status == 'waiting_for_handoff': return denied
                self._scrub_binding(s)
                s.component_ref = None
                s.composition_snapshot = None
                try:
                    try:
                        await self._bind_form(s)
                    except Exception:
                        # A composed checkout may have native controls in vetted
                        # HTTPS child frames.  Keep the ordinary top-document
                        # binder unchanged and use the frame path only here.
                        self._reset_binding(s)
                        await self._bind_composed_entry(s)
                    fields, refs, bindings, options = composition.project(s.ref_meta)
                    if s.cross_frame:
                        for field_id, private_options in s.select_options.items():
                            if field_id in options:
                                options[field_id] = {
                                    f"o{i}": option["value"]
                                    for i, option in enumerate(private_options)
                                }
                    s.composition_fields = fields
                    s.composition_refs = bindings
                    s.composition_options = options
                    s.request,s.key = make_request(_origin(s.page.url),fields,mode='form',stage='general_form')
                    s.request['expiresAt'] = int(time.time()*1000) + 120000
                    s.status = 'composition_available'
                    await self._pin_commit_guard(s)
                    await self._preflight_form(s)
                    self._assert_active(s)
                    s.composition_snapshot = composition.mint('sn_')
                    self._arm_deadline(s)
                    return {"status":"composition_available", "snapshot_ref":s.composition_snapshot,
                            "expires_at_ms":s.request['expiresAt'], "phase":"entry", "refs":refs}
                except (Exception, asyncio.CancelledError) as error:
                    s.status = 'rejected'
                    self._scrub_binding(s)
                    if isinstance(error,asyncio.CancelledError): raise
                    return denied
            if args['snapshot_ref'] != s.composition_snapshot or not s.composition_snapshot or s.status != 'composition_available':
                return denied
            try:
                chosen, visual = composition.select_groups(args,s.composition_refs,s.ref_meta)
            except Exception:
                return denied
            try:
                await self._preflight_form(s)
                await s.commit_guard.evaluate('g => g.check()')
                self._assert_active(s)
                # Keep the original native order, irrespective of visual groups.
                s.composition_fields = [f for f in s.composition_fields if f['id'] in chosen]
                s.request['fields'] = s.composition_fields
                s.request['composition'] = visual
                encoded = json.dumps(s.request,separators=(',',':')).encode('utf-8')
                if len(encoded)>4096: raise ValueError('manifest too large')
                s.component_ref = composition.mint('cp_')
                # Consume snapshot before any external await. Failed/ambiguous
                # publication is terminal; never retry a possibly delivered key.
                s.composition_snapshot = None
                s.composition_refs.clear()
                from telegram import KeyboardButton,ReplyKeyboardMarkup,WebAppInfo
                launch = self.config.mini_app_url.rstrip('/') + '#request=' + _b64(encoded)
                markup=ReplyKeyboardMarkup([[KeyboardButton('Open secure handoff',web_app=WebAppInfo(url=launch))]],resize_keyboard=True)
                if not await self._send(SimpleNamespace(bot=self.bot),s.chat,s.thread,'Encrypted field entry is ready. No purchase action is authorized.',markup):
                    raise ValueError('publication failed')
                self._assert_active(s)
                await self._preflight_form(s)
                await s.commit_guard.evaluate('g => g.check()')
                self._assert_active(s)
                s.status='waiting_for_handoff'
                self._arm_deadline(s)
                return {'status':s.status,'component_ref':s.component_ref}
            except (Exception,asyncio.CancelledError) as error:
                if s.status not in {'cancelled','expired'}: s.status='publication_failed'
                self._scrub_binding(s)
                if isinstance(error,asyncio.CancelledError): raise
                return {'status':s.status}

    async def _run(self,action,args,ident):
        if args.get("mode") not in {None, "form", "compose"}: return {"status":"invalid"}
        if args.get('mode') == 'compose' and action != 'attach': return {"status":"invalid"}
        self._expire()
        if action in purchase_sources.ACTIONS:
            return await self._purchase_sources(action,args,ident)
        if action in observed_purchase.ACTIONS:
            return await getattr(self, action)(args,ident)
        if action in composition.ACTIONS:
            return await self._composition(action,args,ident)
        if action=="open":
            if args.get("mode") == "compose": return {"status":"invalid"}
            lease = object(); self._acquisitions[ident] = lease
            try: _origin(args.get("url"))
            except Exception: return {"status":"invalid_url"}
            old=self.sessions.get(ident)
            if old: await self._retire_session(old)
            try:
                s=await self._new_session(ident,args["url"],lease=lease)
                s.requested_mode = args.get("mode")
                return await self._snapshot(s)
            except Exception: return {"status":"unavailable"}
        if action=="attach":
            lease = object(); self._acquisitions[ident] = lease
            try: origin=_origin(args.get("origin"))
            except Exception: return {"status":"invalid_origin"}
            target_id=args.get("ref")
            if target_id is not None and (not isinstance(target_id,str) or not _TARGET_ID_RE.fullmatch(target_id)): return {"status":"invalid_ref"}
            try:
                s=await self._attach_session(ident,origin,target_id,lease=lease)
                s.requested_mode = args.get("mode")
                async with s.lock:
                    if s.requested_mode == "compose":
                        s.session_ref = composition.mint("ss_")
                        return {"status":"attached", "session_ref":s.session_ref}
                    await self._bind_stage(s)
                    return await self._present(s,SimpleNamespace(bot=self.bot),False)
            except _AmbiguousTarget:
                return {"status":"unsupported_stage", "reason":"ambiguous_target"}
            except Exception:
                s=self.sessions.get(ident)
                if s and self._current(s): s.status="unsupported_stage"; self._scrub_binding(s)
                return {"status":"unsupported_stage", "reason":"binding_rejected"}
        if action=="close": return await self._close(ident)
        s=self.sessions.get(ident)
        if not s: return {"status":"unavailable", "reason":"session_missing"}
        if s.requested_mode == "compose":
            return {"status":s.status} if action in {"read","wait"} else {"status":"forbidden"}
        generation = s.generation
        if action=="wait":
            async with s.lock:
                if not self._current(s, generation): return {"status":"unavailable", "reason":"session_missing"}
                s.updated=time.monotonic(); wake=s.wake
            try: await asyncio.wait_for(wake.wait(),max(0,min(int(args.get("timeout",1)),90)))
            except asyncio.TimeoutError: pass
            async with s.lock:
                if not self._current(s, generation): return {"status":s.status}
                wake.clear(); return {"status":s.status}
        async with s.lock:
            if not self._current(s, generation): return {"status":"unavailable", "reason":"session_missing"}
            s.updated=time.monotonic()
            if action=="read": return await self._snapshot(s)
            if action=="present":
                if s.status == "purchase_review_ready": return await self._snapshot(s)
                if s.mode == "purchase_approval": return await self._present(s,SimpleNamespace(bot=self.bot),False)
                s.requested_mode = args.get("mode", s.requested_mode)
                try:
                    await self._bind_stage(s)
                    return await self._present(s,SimpleNamespace(bot=self.bot),False)
                except Exception:
                    if s.status not in {"cancelled","expired"}: s.status="unsupported_stage"
                    self._scrub_binding(s)
                    return {"status":s.status, "reason":"binding_rejected"}
            if action in {"click","type"}: return await self._ordinary(s,action,args)
        return {"status":"invalid"}
    def tool(self,args=None,**kwargs):
        if args is not None and not isinstance(args, dict): return '{"status":"invalid"}'
        payload=dict(args) if isinstance(args,dict) else dict(kwargs); ident=self._identity()
        if not isinstance(payload.get("action"),str): return '{"status":"invalid"}'
        if payload.get("action") in purchase_sources.ACTIONS:
            if not purchase_sources.valid_payload(payload["action"],payload): return '{"status":"invalid"}'
        elif payload.get("action") in observed_purchase.ACTIONS:
            if not observed_purchase.valid_payload(payload["action"],payload): return '{"status":"invalid"}'
        elif payload.get("action") in composition.ACTIONS:
            if not composition.valid_payload(payload["action"],payload): return '{"status":"invalid"}'
        elif (set(payload) - {"action","url","origin","mode","ref","text","timeout"}
            or any(not isinstance(payload[k], str) for k in ("action","url","origin","mode","ref","text") if k in payload)
            or ("timeout" in payload and (type(payload["timeout"]) is not int or not 0 <= payload["timeout"] <= 90))):
            return '{"status":"invalid"}'
        if (ident is None or len(ident) != 3 or type(ident[0]) is not int or type(ident[1]) is not int
            or ident[0] <= 0 or ident[1] != ident[0] or (ident[2] is not None and (type(ident[2]) is not int or ident[2] <= 0))
            or ident[0] not in self._owners()): result={"status":"rejected"}
        elif payload.get("action") in {"open","attach","present","read","click","type","wait","close"} | composition.ACTIONS | observed_purchase.ACTIONS | purchase_sources.ACTIONS: result=self._submit(self._run(payload.get("action"),payload,ident))
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
            from .purchase_approval import pin_purchase, approval_request, PublicFactSourceUnavailable
        except ImportError:
            from purchase_approval import pin_purchase, approval_request, PublicFactSourceUnavailable
        s.purchase_blocker = None
        if s.purchase_factory is not None:
            return await self._post_fill_purchase(s)
        try:
            self._assert_active(s)
            guard = await pin_purchase(s)
        except Exception as error:
            s.status = "human_action_required"
            s.key = None
            s.purchase_blocker = ("public_fact_source_unavailable" if isinstance(error, PublicFactSourceUnavailable)
                                  else "purchase_binding_unsupported")
            return await self._snapshot(s)
        old_guard = s.commit_guard
        # Take ownership before the first await so cancellation cannot orphan
        # the newly created lease between extraction and publication.
        s.commit_guard = guard
        try:
            summary = await guard.evaluate("g => g.summary")
            self._assert_active(s)
            s.request, s.key = approval_request(make_request, _origin(s.page.url), summary,
                                               s.request["expiresAt"], demo)
            s.mode = "purchase_approval"
            s.generation += 1
            self._arm_deadline(s)
            return await self._publish_purchase(s,c)
        except Exception:
            s.status = "publication_failed"
            self._scrub_binding(s)
            return {"status":s.status}
        finally:
            # The new lease privately retains the old guard for structural checks.
            # Dispose only the Python handle; do not revoke that underlying guard.
            await old_guard.dispose()

    async def _publish_purchase(self,s,c):
        try:
            self._check_observed_request(s)
            self._assert_active(s)
            await s.commit_guard.evaluate("g => g.check()")
            encoded=json.dumps(s.request,separators=(",",":"),ensure_ascii=False).encode("utf-8")
            if len(encoded)>4096: raise ValueError("manifest too large")
            from telegram import KeyboardButton,ReplyKeyboardMarkup,WebAppInfo
            launch=self.config.mini_app_url.rstrip("/")+"#request="+_b64(encoded)
            markup=ReplyKeyboardMarkup([[KeyboardButton("Review purchase",web_app=WebAppInfo(url=launch))]],resize_keyboard=True)
            if not await self._send(c,s.chat,s.thread,"Review the selected checkout facts in the Mini App. Field entry did not authorize payment.",markup): raise ValueError("publication failed")
            self._assert_active(s)
            await s.commit_guard.evaluate("g => g.check()")
            s.status="waiting_for_confirmation"
            return {"status":s.status,"url":self._safe_origin(s)}
        except (Exception, asyncio.CancelledError) as error:
            if s.status not in {"cancelled","expired"}: s.status="publication_failed"
            self._scrub_binding(s)
            if isinstance(error, asyncio.CancelledError): raise
            return {"status":s.status}

    async def _present(self,s,c,demo=False):
        if not self._current(s): return {"status":s.status}
        generation = s.generation
        if s.mode == "purchase_approval":
            if s.status != "waiting_for_confirmation": return {"status":s.status}
            return await self._publish_purchase(s,c)
        if s.status == "human_action_required":
            return {"status": s.status, "url": self._safe_origin(s)}
        try:
            if demo and not (self._owns_browser and self._context is not None): raise ValueError("unowned demo")
            if s.request and s.request["expiresAt"] <= int(time.time()*1000):
                self._invalidate(s, "expired")
                raise ValueError("expired publication")
            fields=[{"id":k, **dict(v)} for k,v in s.ref_meta.items() if k.startswith("f")]
            adapter=adapter_for_url(s.page.url); descriptor=adapter.stage_for(tuple(field["type"] for field in fields), checkout=s.mode=="checkout", form=s.mode=="form"); s.stage=descriptor.id; s.provider=adapter.name
            if s.mode == "form":
                s.request,s.key=make_request(_origin(s.page.url),fields,demo,stage=descriptor.id,provider=adapter.name,mode="form")
            elif s.mode == "checkout":
                s.request,s.key=make_request(_origin(s.page.url),fields,demo,stage=descriptor.id,provider=adapter.name,mode="checkout",action_label="Review purchase")
            else:
                s.request,s.key=make_request(_origin(s.page.url),fields,demo,stage=descriptor.id,provider=adapter.name)
            self._arm_deadline(s)
            await self._pin_commit_guard(s)
            if not self._current(s, generation): raise ValueError("stale publication")
            self._assert_active(s)
            public=self.config.mini_app_url if self.config is not None else None
            if not isinstance(public,str): raise RuntimeError
            encoded=json.dumps(s.request,separators=(",",":"),ensure_ascii=False).encode("utf-8")
            if len(encoded) > 4096: raise ValueError("manifest too large")
            fragment="#request="+_b64(encoded)
            if len(fragment.encode("utf-8")) > 8192: raise ValueError("fragment too large")
            launch=public.rstrip("/")+fragment
            from telegram import KeyboardButton,ReplyKeyboardMarkup,WebAppInfo
            markup=ReplyKeyboardMarkup([[KeyboardButton("Open secure handoff",web_app=WebAppInfo(url=launch))]],resize_keyboard=True)
            if not self._current(s, generation): raise ValueError("stale publication")
            self._assert_active(s)
            if not await self._send(c,s.chat,s.thread,f"{descriptor.title} handoff is ready. Submit only to this browser.",markup): raise RuntimeError
            if not self._current(s, generation): raise ValueError("stale publication")
            self._assert_active(s)
            s.generation += 1
            s.used_ids.clear()
            s.status="waiting_for_handoff"; self._arm_deadline(s); return {"status":"waiting_for_handoff","url":_origin(s.page.url)}
        except (Exception, asyncio.CancelledError) as error:
            if s.status not in {"cancelled","expired"}: s.status="publication_failed"
            self._scrub_binding(s)
            if isinstance(error, asyncio.CancelledError): raise
            return {"status":s.status}

    async def _preflight(self,s):
        self._check_observed_request(s)
        if s.mode == "form":
            return await self._preflight_form(s)
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
                if not await self._usable_input(e): raise ValueError
                if s.mode == "checkout":
                    live = await self._control_metadata(e, frame, adapter_for_url(s.page.url))
                    expected_label = s.field_source_labels.get(field_id, f["label"])
                    if live is None or live["kind"] != f["type"] or live["label"] != expected_label or bool(live["required"]) != f["required"]:
                        raise ValueError("changed checkout metadata")
                    if f.get("selectionMode") == "search":
                        pinned = s.select_options.get(field_id)
                        if live["option_count"] is None or live["option_count"] <= 64 or pinned is None or live["all_options"] != pinned:
                            raise ValueError("changed checkout options")
                    elif f["type"] == "select":
                        expected_options = s.select_options.get(field_id) if s.cross_frame else f.get("options", [])
                        if live["option_count"] != len(expected_options or []) or live["options"] != expected_options:
                            raise ValueError("changed checkout options")
        e=s.refs.get("submit")
        if e is None and s.auto_submit: return
        if not e or not await e.is_visible() or not await e.is_enabled() or not await self._related_submit(s.page,s.form,s.scope,e): raise ValueError
        if await s.page.evaluate("a => !a[0].formAction || a[0].formAction === a[1]",[e,s.submit_action]) is not True: raise ValueError
    async def _pin_commit_guard(self, s):
        """One private browser lease; never expose its nodes or option mappings."""
        if any(frame != s.page.main_frame for frame in s.field_frames.values()):
            s.cross_frame = True
            s.commit_guard = await self._pin_cross_frame_guard(s)
            return
        nodes, slots = [], {}
        for field_id in s.ref_meta:
            if not field_id.startswith("f"): continue
            parts = s.field_parts.get(field_id) or [s.refs[field_id]]
            slots[field_id] = list(range(len(nodes), len(nodes) + len(parts)))
            nodes.extend(parts)
        submit_index = len(nodes) if s.refs.get("submit") else -1
        if submit_index >= 0: nodes.append(s.refs["submit"])
        s.commit_slots = slots
        s.commit_guard = await s.page.evaluate_handle(r"""a => {
            const {nodes, form, scope, doc, deadline, auth, submitIndex} = a;
            const origin = location.origin, url = location.href;
            const attrs = ['id','name','type','autocomplete','inputmode','placeholder',
                'aria-label','aria-labelledby','aria-describedby','aria-required','role',
                'min','max','step','pattern','maxlength','minlength','required','multiple',
                'form','formaction','formmethod','formtarget','formenctype'];
            const clean = t => String(t || '').replace(/\s+/g,' ').trim();
            const signature = e => JSON.stringify([e.tagName,
                attrs.map(k => e.getAttribute(k)),
                e.labels ? [...e.labels].map(l => clean(l.textContent)) : [],
                clean(e.getAttribute('aria-labelledby') ? e.getAttribute('aria-labelledby').split(/\s+/).map(id => doc.getElementById(id)?.textContent || '').join(' ') : ''),
                /^(radio|checkbox|submit|button)$/.test(e.type) ? e.value : null,
                e.tagName === 'SELECT' ? [...e.options].map(o => [o.value, o.textContent, o.disabled, o.parentElement.disabled || false]) : null,
                e === nodes[submitIndex] ? clean(e.innerText || e.getAttribute('value') || e.getAttribute('aria-label')) : null]);
            const scopeOf = e => e.form || e.closest('dialog, [role=dialog], main') || doc.body;
            const inventory = () => [...doc.querySelectorAll('input,textarea,select,button,[role=button],[contenteditable]')].filter(e => scopeOf(e) === scope || scope.contains(e));
            let members = inventory();
            const signatures = nodes.map(signature), positions = nodes.map(e => members.indexOf(e));
            const forms = nodes.map(e => e.form || null);
            const formSignature = f => f ? JSON.stringify([f.action,f.method,f.target,f.enctype,f.getAttribute('id'),f.noValidate]) : null;
            const originalForm = formSignature(form);
            const scopeSignature = JSON.stringify([scope.tagName,scope.id,scope.getAttribute('role')]);
            const submitAction = submitIndex < 0 ? null : nodes[submitIndex].formAction || '';
            const usable = e => {
                if (!e.isConnected || e.ownerDocument !== doc || !e.getClientRects().length || e.matches(':disabled') || e.readOnly) return false;
                for (let n=e; n; n=n.parentElement) {
                    const style=getComputedStyle(n);
                    if (n.inert || n.getAttribute('aria-hidden') === 'true' || style.display === 'none' || style.visibility !== 'visible' || style.pointerEvents === 'none' || Number(style.opacity) <= 0) return false;
                }
                return true;
            };
            const setters = new Map([HTMLInputElement, HTMLTextAreaElement, HTMLSelectElement].map(C => [C, Object.getOwnPropertyDescriptor(C.prototype,'value').set]));
            const checkedSetter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype,'checked').set;
            const dispatch = EventTarget.prototype.dispatchEvent, nativeClick = HTMLElement.prototype.click;
            const lease = {nodes, revoked:false, deadline, submitIndex};
            const alive = () => {if (lease.revoked || Date.now() >= lease.deadline || doc !== document || location.origin !== origin || location.href !== url) throw Error('stale lease');};
            lease.check = (refresh=false) => {
                alive();
                if (!scope.isConnected || scope.ownerDocument !== doc || JSON.stringify([scope.tagName,scope.id,scope.getAttribute('role')]) !== scopeSignature ||
                    (form && (!form.isConnected || form.ownerDocument !== doc)) || formSignature(form) !== originalForm) throw Error('changed scope');
                const live = inventory(), replacements = new Map();
                if (live.length !== members.length) throw Error('changed membership');
                for (let i=0; i<live.length; i++) {
                    if (live[i] === members[i]) continue;
                    const n=positions.indexOf(i);
                    if (!refresh || !auth || !form || n < 0 || n === submitIndex || nodes[n].isConnected || live[i].form !== form || signature(live[i]) !== signatures[n]) throw Error('changed node');
                    replacements.set(n, live[i]);
                }
                const proposed=nodes.map((e,i) => replacements.get(i) || e);
                for (let i=0; i<proposed.length; i++) {
                    const e=proposed[i];
                    if (!e.isConnected || e.ownerDocument !== doc || (e.form || null) !== forms[i] || signature(e) !== signatures[i] ||
                        !(scopeOf(e) === scope || scope.contains(e)) || (i !== submitIndex && !usable(e))) throw Error('changed semantics');
                }
                if (submitIndex >= 0 && (proposed[submitIndex].formAction || '') !== submitAction) throw Error('changed action');
                for (const [i,e] of replacements) nodes[i]=e;
                members=live;
                alive();
                return true;
            };
            lease.commit = ({index,value,click,deadline,autoFinal}) => {
                lease.deadline=Math.min(lease.deadline,deadline);
                lease.check(true);
                const e=nodes[index];
                if (!e) throw Error('unknown node');
                if (click) {
                    if (index !== submitIndex || !auth || !usable(e)) throw Error('unauthorized action');
                    const r=e.getBoundingClientRect(), hit=doc.elementFromPoint(r.left+r.width/2,r.top+r.height/2);
                    if (!hit || !(e === hit || e.contains(hit))) throw Error('covered action');
                    alive();
                    nativeClick.call(e);
                    return true;
                }
                if (index === submitIndex || typeof value !== 'string') throw Error('invalid field');
                let setter;
                if (e.type === 'checkbox' || e.type === 'radio') setter=checkedSetter;
                else setter=setters.get(e instanceof HTMLInputElement ? HTMLInputElement : e instanceof HTMLTextAreaElement ? HTMLTextAreaElement : HTMLSelectElement);
                if (!setter) throw Error('unsupported native control');
                if (e.tagName === 'SELECT' && ![...e.options].some(o => o.value === value && !o.disabled && !o.parentElement.disabled)) throw Error('unknown option');
                if (['week','color','range'].includes(e.type)) {
                    const probe=e.cloneNode(false); setter.call(probe,value);
                    if (probe.value !== value || !probe.checkValidity()) throw Error('invalid native value');
                }
                alive();
                setter.call(e, e.type === 'radio' ? true : e.type === 'checkbox' ? value === 'true' : value);
                dispatch.call(e,new Event('input',{bubbles:true}));
                // Destination handlers can restage or invalidate the lease synchronously.
                // Never send a second event or mutate a later node without revalidation.
                if (autoFinal && !e.isConnected) {alive(); return true;}
                lease.check(true);
                dispatch.call(e,new Event('change',{bubbles:true}));
                if (autoFinal && !e.isConnected) {alive(); return true;}
                lease.check(true);
                return true;
            };
            lease.check();
            return lease;
        }""", {"nodes":nodes, "form":s.form, "scope":s.scope, "doc":s.document,
                 "deadline":s.request["expiresAt"], "auth":s.mode == "auth", "submitIndex":submit_index})

    async def _guarded_commit(self, s, index, value="", *, click=False, auto_final=False):
        self._assert_active(s)
        if s.commit_guard is None: raise ValueError("missing commit lease")
        if await s.commit_guard.evaluate("(g,a) => g.commit(a)", {
            "index":index, "value":value, "click":click,
            "deadline":s.request["expiresAt"], "autoFinal":auto_final}) is not True:
            raise ValueError("commit rejected")
        self._assert_active(s)

    async def _refresh_same_stage(self, s):
        self._assert_active(s)
        if s.commit_guard is None: raise ValueError("missing commit lease")
        await s.commit_guard.evaluate("g => g.check(true)")
        self._assert_active(s)
        if s.mode == "auth":
            # Only the guard may adopt same-form/same-signature replacement inputs.
            # Original document, form, scope and action node never change.
            for field_id, slots in s.commit_slots.items():
                parts = [await s.commit_guard.evaluate_handle("(g,i) => g.nodes[i]", i) for i in slots]
                s.field_parts[field_id] = parts
                s.refs[field_id] = parts[0]

    async def _wait_for_auto_submit(self,s,timeout=5.0):
        deadline=time.monotonic()+timeout
        while time.monotonic()<deadline:
            self._assert_active(s)
            if not await self._auth_stage_detected(s):
                self._assert_active(s)
                return
            await asyncio.sleep(0.1)
        raise ValueError
    async def _rebind_or_finish(self,s,c):
        self._assert_active(s)
        generation = s.generation
        try: await self._bind_stage(s)
        except Exception:
            self._assert_active(s)
            if not self._current(s, generation): raise ValueError("stale continuation")
            s.status="submitted"; s.key=None; return
        self._assert_active(s)
        if not self._current(s, generation): raise ValueError("stale continuation")
        self._receipt(s); s.status="stage_submitted"
        await self._present(s,c,bool(s.site))
    def _assert_active(self, s):
        if not self._current(s):
            raise ValueError("inactive session")
        if not s.request or s.request["expiresAt"] <= int(time.time()*1000):
            raise ValueError("expired request")

    async def _fill_bound_field(self, s, field, value):
        self._assert_active(s)
        slots = s.commit_slots[field["id"]]
        if field["type"] == "otp" and len(slots) > 1:
            if len(value) != len(slots): raise ValueError("invalid split code")
            for i, index in enumerate(slots):
                await self._guarded_commit(s, index, value[i], auto_final=s.auto_submit and i == len(slots)-1)
        elif field["type"] == "select" and len(slots) > 1:
            await self._guarded_commit(s, slots[int(value[1:])], value)
        else:
            await self._guarded_commit(s, slots[0], value)

    def _resolve_search_select_value(self, s, field, value):
        if not isinstance(value, str) or field.get("selectionMode") != "search":
            return value
        options = s.select_options.get(field["id"])
        if not isinstance(options, list):
            raise ValueError("missing select options")
        if not value.strip():
            if field.get("required"):
                raise ValueError("required select")
            matches = [option for option in options if option["value"] == ""]
        else:
            wanted = _normalise_option_label(value)
            matches = [option for option in options if _normalise_option_label(option["label"]) == wanted]
        if len(matches) != 1:
            raise ValueError("select label not found")
        return matches[0]["value"]

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
            if not self._current(s) or not s.request or s.request["id"] != rid or not identity or identity!=(s.user,s.chat,s.thread) or rid in s.used_ids: raise ApplicationHandlerStop
            s.used_ids.add(rid)
            if s.request.get("mode") == "source_approval":
                await self._accept_source_approval(s, raw, c)
                raise ApplicationHandlerStop
            phase="expiry"
            purchase_attempted=False
            try:
                if s.request["expiresAt"]<int(time.time()*1000): raise ValueError
                phase="refresh_stage"; await self._refresh_same_stage(s)
                phase="preflight_before_decrypt"; await self._preflight(s)
                phase="decrypt"; payload=decrypt_submission(raw if isinstance(raw,str) else "",s.request,s.key)
                phase="preflight_after_decrypt"; await self._preflight(s)
                if s.request["expiresAt"]<int(time.time()*1000): raise ValueError
                if s.mode == "purchase_approval":
                    phase="click"
                    self._assert_active(s)
                    purchase_attempted=True
                    await s.commit_guard.evaluate("(g,d) => g.commit({deadline:d})", s.request["expiresAt"])
                    s.status="purchase_submitted"; s.key=None
                elif s.mode == "payment_confirmation":
                    if payload.get("confirm") is not True or set(payload) != {"confirm"}: raise ValueError
                    # No final purchase execution without a bound, user-visible transaction summary.
                    s.status="human_action_required"; s.key=None
                else:
                    phase="fill"
                    for field in s.request["fields"]:
                        if s.request["expiresAt"]<int(time.time()*1000): raise ValueError
                        if s.mode == "form": await self._preflight_form(s)
                        value = self._resolve_search_select_value(s, field, payload[field["id"]])
                        if field["type"] == "select" and s.cross_frame and field.get("selectionMode") != "search":
                            mapping = s.composition_options.get(field["id"])
                            if not isinstance(mapping, dict) or value not in mapping:
                                raise ValueError("unknown select option")
                            value = mapping[value]
                        elif s.requested_mode == "compose" and field["type"] == "select":
                            value = s.composition_options[field["id"]][value]
                        await self._fill_bound_field(s,field,value)
                    if s.request["expiresAt"]<int(time.time()*1000): raise ValueError
                    if s.mode == "form":
                        await self._preflight_form(s)
                        self._assert_active(s)
                        if s.requested_mode == "compose" and s.purchase_factory is not None:
                            s.checkout_filled=True
                            await self._post_fill_purchase(s)
                        else:
                            s.status="filled"; s.key=None
                    elif s.mode == "checkout":
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
                        phase="click"; await self._guarded_commit(s, sum(len(v) for v in s.commit_slots.values()), click=True)
                        phase="rebind"; await self._rebind_or_finish(s,c)
            except asyncio.CancelledError:
                # Once dispatch starts, cancellation cannot establish whether the
                # browser committed. Never query/retry the click to recover an ack.
                if purchase_attempted:
                    s.status="outcome_unknown"
                elif s.status not in {"cancelled", "expired", "publication_failed"}:
                    s.status="cancelled"
                self._receipt(s,phase)
                self._scrub_binding(s)
                if s.wake: s.wake.set()
                self._schedule_wake(s)
                raise
            except Exception:
                if s.status not in {"cancelled", "expired"}: s.status="rejected"
                if purchase_attempted:
                    try: consumed=await s.commit_guard.evaluate("g => g.consumed")
                    except asyncio.CancelledError:
                        s.status="outcome_unknown"
                        self._receipt(s,phase)
                        self._scrub_binding(s)
                        if s.wake: s.wake.set()
                        self._schedule_wake(s)
                        raise
                    except Exception: consumed=True
                    if consumed: s.status="outcome_unknown"
                s.key=None; self._receipt(s,phase)
            self._receipt(s)
            if s.status in {"filled", "human_action_required", "submitted", "purchase_submitted", "outcome_unknown", "rejected", "cancelled", "expired", "publication_failed"}:
                self._scrub_binding(s)
            if s.wake: s.wake.set()
        if s.status in {"submitted","stage_submitted"}: await self._send(c,s.chat,s.thread,"Secure handoff action submitted.")
        elif s.status=="outcome_unknown": await self._send(c,s.chat,s.thread,"Purchase outcome unknown. Do not retry; verify the provider result first.")
        elif s.status=="purchase_submitted": await self._send(c,s.chat,s.thread,"Approved purchase action submitted; not proof of payment or ownership. Outcome unknown until provider verification.")
        elif s.status=="human_action_required": await self._send(c,s.chat,s.thread,"Checkout fields filled. Complete the final purchase directly in the provider page; no purchase action was clicked.")
        elif s.status=="purchase_review_ready": await self._send(c,s.chat,s.thread,"Checkout facts are ready for review composition. No purchase action was clicked.")
        elif s.status=="filled": await self._send(c,s.chat,s.thread,"Secure handoff fields filled. No submit action was clicked.")
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
            "If submitted, verify the provider's resulting state. "
            "If purchase_submitted or outcome_unknown, this is not proof of payment or ownership. "
            "Do not retry the purchase; verify the provider result first."
        )
    def _schedule_wake(self,s):
        if self.adapter is None or not self.loop or not self.loop.is_running(): return
        status,user,chat,thread,origin=s.status,s.user,s.chat,s.thread,self._safe_origin(s)
        try: self.loop.create_task(self._wake_session(status,user,chat,thread,origin))
        except Exception: pass
    async def _wake_session(self,status,user,chat,thread,origin):
        adapter=self.adapter
        if adapter is None or status not in {"submitted","filled","human_action_required","purchase_submitted","outcome_unknown","rejected","purchase_review_ready","waiting_for_handoff","waiting_for_confirmation","publication_failed","stage_submitted","composition_available"}: return
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
        # Reserve this protocol namespace even after expiry/close/replacement.
        # Late ciphertext is consumed status-only, never offered to another handler.
        return bool(re.fullmatch(r"sh_[A-Za-z0-9_-]{1,64}", request_id))
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

SCHEMA={"name":"telegram_secure_handoff","description":"Use for owner-scoped secure handoff work in Hermes's dedicated Chrome profile. Supports generic auth and checkout stages; never submit secrets outside the encrypted Mini App.","parameters":{"type":"object","properties":{"action":{"type":"string","enum":["open","attach","present","read","click","type","wait","close"]},"url":{"type":"string"},"origin":{"type":"string"},"mode":{"type":"string","enum":["form"],"description":"Explicit fill-only generic form; never clicks submit."},"ref":{"type":"string","description":"Opaque Chrome target ID for attach; ordinary actions use the handoff ref returned by the tool"},"text":{"type":"string"},"timeout":{"type":"integer","maximum":90}},"required":["action"],"additionalProperties":False}}
# Exact disjoint model payloads; identity and document authority never come from arguments.
SCHEMA['description'] += ' For agent-shaped encrypted ENTRY, attach mode compose, discover_components, then present_composition. Choose optional fields and bounded group headings/order; required fields cannot be omitted. No purchase authority.'
_props = SCHEMA['parameters']['properties']
_legacy = dict(_props)
_props['action'] = {'type':'string','enum':_props['action']['enum'] + sorted(composition.ACTIONS)}
_props['mode'] = {'type':'string','enum':['form','compose'], 'description':'compose attaches without navigation or publication; then discover and compose encrypted fill-only ENTRY.'}
for _key,_prefix in [('session_ref','ss_'),('snapshot_ref','sn_'),('component_ref','cp_')]:
    _props[_key] = {'type':'string','pattern':'^'+_prefix+'[A-Za-z0-9_-]{32}$'}
_props['layout'] = {'type':'string','enum':['stack','sections']}
_props['groups'] = {'type':'array','minItems':1,'maxItems':8,'items':{'type':'object','additionalProperties':False,
    'required':['title','refs'],'properties':{'title':{'type':'string','enum':sorted(composition.TITLES)},
    'refs':{'type':'array','minItems':1,'maxItems':24,'uniqueItems':True,'items':{'type':'string','pattern':'^fr_[A-Za-z0-9_-]{32}$'}}}}}
SCHEMA['parameters']['oneOf'] = [
    {'properties':{'action':{'enum':_legacy['action']['enum']}},
     'not':{'anyOf':[{'required':[k]} for k in ['session_ref','snapshot_ref','component_ref','layout','groups']]}}
]
for _action,_keys in [('discover_components',['session_ref']),('present_composition',['snapshot_ref','layout','groups']),
                      ('composition_status',['component_ref']),('cancel_composition',['component_ref'])]:
    SCHEMA['parameters']['oneOf'].append({'type':'object','additionalProperties':False,
        'required':['action']+_keys, 'properties':{'action':{'const':_action},**{k:_props[k] for k in _keys}}})
_props['action']['enum'] += sorted(observed_purchase.ACTIONS)
for _key,_prefix in [('revision','pr_'),('action_ref','pa_')]:
    _props[_key] = {'type':'string','pattern':'^'+_prefix+'[A-Za-z0-9_-]{32}$'}
_props['fact_refs'] = {'type':'array','minItems':2,'maxItems':24,'uniqueItems':True,
                       'items':{'type':'string','pattern':'^pf_[A-Za-z0-9_-]{32}$'}}
SCHEMA['parameters']['oneOf'][0]['not']['anyOf'] += [{'required':[k]} for k in ['revision','fact_refs','action_ref']]
for _action,_keys in [('inspect_purchase',['session_ref']),('compose_purchase',['session_ref','revision','fact_refs','action_ref'])]:
    SCHEMA['parameters']['oneOf'].append({'type':'object','additionalProperties':False,
        'required':['action']+_keys,'properties':{'action':{'const':_action},**{k:_props[k] for k in _keys}}})
SCHEMA['description'] += ' inspect_purchase/compose_purchase select runtime-issued public fact refs only. Requires trusted post-fill public-source acquisition; unavailable without it. Separate user Complete purchase tap authorizes one bound action, not a guaranteed charge.'
_props['action']['enum'] += sorted(purchase_sources.ACTIONS)
_props['catalog_ref'] = {'type':'string','pattern':'^cs_[A-Za-z0-9_-]{32}$'}
_props['source_revision'] = {'type':'string','pattern':'^ps_[A-Za-z0-9_-]{32}$'}
_props['source_refs'] = {'type':'array','minItems':4,'maxItems':24,'uniqueItems':True,
    'items':{'type':'string','pattern':'^sr_[A-Za-z0-9_-]{32}$'}}
SCHEMA['parameters']['oneOf'][0]['not']['anyOf'] += [{'required':[k]} for k in ['source_revision','source_refs','catalog_ref']]
for _action,_keys in [('discover_catalog_sources',['session_ref']),('request_source_approval',['session_ref','catalog_ref']),('discover_purchase_sources',['session_ref']),('select_purchase_sources',['session_ref','source_revision','source_refs'])]:
    SCHEMA['parameters']['oneOf'].append({'type':'object','additionalProperties':False,
        'required':['action']+_keys,'properties':{'action':{'const':_action},**{k:_props[k] for k in _keys}}})
SCHEMA['description'] += ' After discover_components, discover_purchase_sources and select_purchase_sources explicitly arm composed checkout using only issued refs. First discover_catalog_sources and request_source_approval for an exact issued catalog_ref; wait for the owner encrypted Mini App grant. The owner must identify and review the original public nonpersonal product page. Source selection is not privacy certification or purchase authority; unsupported sources fail closed.'
del _props, _legacy, _key, _prefix, _action, _keys

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
