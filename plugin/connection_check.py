"""Native Telegram transport spike for the Hermes plugin system.

This module deliberately owns only a connection round-trip test.  It does not
create a Telegram client, start polling, call a model/tool, or handle a real
login.  The Telegram adapter supplies the already-running PTB Application to
``wire`` at connect time.
"""

from __future__ import annotations

import base64
import binascii
import hmac
import inspect
import json
import logging
import os
import re
import secrets
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Optional
from urllib.parse import urlsplit


logger = logging.getLogger(__name__)

REQUEST_VERSION = 1
FIXED_MARKER = "telegram-roundtrip-ok"
FIXED_MARKER_BYTES = FIXED_MARKER.encode("ascii")
TTL_SECONDS = 10 * 60
MAX_PENDING = 32
MAX_WIRE_BYTES = 4096
RSA_KEY_SIZE = 2048
RSA_CIPHERTEXT_BYTES = RSA_KEY_SIZE // 8
MAX_HISTORY = 64
HISTORY_TTL_SECONDS = TTL_SECONDS
PLUGIN_HANDLER_GROUP = -100

_MAX_LAUNCH_URL_CHARS = 4096
_MAX_PARSE_BYTES = 64 * 1024
_BASE64URL_RE = re.compile(r"^[A-Za-z0-9_-]+$")
_RECEIPT_FILENAME = "connection_check_receipts.jsonl"


@dataclass(frozen=True)
class RuntimeConfig:
    """Validated plugin settings loaded through ``ctx.get_config``."""

    mini_app_url: str
    allowed_user_ids: frozenset[int]


@dataclass
class PendingRequest:
    """In-memory request state; the private key never leaves this object."""

    request_id: str
    sender_id: int
    chat_id: int
    origin_thread: Optional[int]
    created_at_ms: int
    expires_at_ms: int
    launch_url: str = field(repr=False)
    private_key: Any = field(default=None, repr=False)
    status: str = "pending"
    updated_at_ms: int = 0


@dataclass(frozen=True)
class IssueResult:
    status: str
    request: Optional[PendingRequest] = None


@dataclass(frozen=True)
class HandlerOutcome:
    """A status-only result for one owned update."""

    owned: bool
    status: str = ""
    text: Optional[str] = None
    chat_id: Optional[int] = None
    thread_id: Optional[int] = None
    remove_keyboard: bool = False


def _b64url_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _b64url_uint(value: int) -> str:
    width = max(1, (value.bit_length() + 7) // 8)
    return _b64url_encode(value.to_bytes(width, "big"))


def _public_jwk(private_key: Any) -> dict[str, str]:
    numbers = private_key.public_key().public_numbers()
    return {
        "kty": "RSA",
        "n": _b64url_uint(numbers.n),
        "e": _b64url_uint(numbers.e),
    }


def _json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """Reject duplicate JSON keys instead of accepting an ambiguous payload."""

    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _load_json_object(raw: str, *, parse_limit: int = _MAX_PARSE_BYTES) -> Optional[dict[str, Any]]:
    if not isinstance(raw, str):
        return None
    try:
        if len(raw.encode("utf-8")) > parse_limit:
            return None
        value = json.loads(raw, object_pairs_hook=_json_object)
    except (UnicodeEncodeError, UnicodeDecodeError, TypeError, ValueError, json.JSONDecodeError):
        return None
    return value if isinstance(value, dict) else None


def _extract_request_id(raw: Any) -> Optional[str]:
    """Extract only an opaque id for native handler scoping.

    Unknown or syntactically unparseable data is intentionally not claimed by
    the plugin, allowing another WEB_APP_DATA consumer to receive it.
    """

    if not isinstance(raw, str):
        return None
    obj = _load_json_object(raw)
    request_id = obj.get("id") if obj is not None else None
    if not isinstance(request_id, str) or not request_id:
        return None
    return request_id


def _parse_ciphertext(raw: Any, expected_id: str) -> Optional[bytes]:
    if not isinstance(raw, str):
        return None
    if len(raw.encode("utf-8")) > MAX_WIRE_BYTES:
        return None
    obj = _load_json_object(raw, parse_limit=MAX_WIRE_BYTES)
    if obj is None or set(obj) != {"v", "id", "ciphertext"}:
        return None
    if obj.get("v") != REQUEST_VERSION or obj.get("id") != expected_id:
        return None

    encoded = obj.get("ciphertext")
    if not isinstance(encoded, str) or not _BASE64URL_RE.fullmatch(encoded):
        return None
    # An RSA-2048 ciphertext is exactly 256 bytes and its unpadded base64url
    # representation is at most 342 characters.  Both checks keep malformed
    # inputs out of the decrypt call.
    if len(encoded) > 342:
        return None
    padding = "=" * (-len(encoded) % 4)
    try:
        ciphertext = base64.urlsafe_b64decode((encoded + padding).encode("ascii"))
    except (ValueError, UnicodeEncodeError, binascii.Error):
        return None
    if len(ciphertext) != RSA_CIPHERTEXT_BYTES:
        return None
    return ciphertext


def _validate_mini_app_url(raw: Any) -> Optional[str]:
    if not isinstance(raw, str) or not raw or len(raw) > _MAX_LAUNCH_URL_CHARS:
        return None
    if any(character.isspace() for character in raw):
        return None
    try:
        parsed = urlsplit(raw)
        hostname = parsed.hostname
        _ = parsed.port
    except ValueError:
        return None
    if (
        parsed.scheme.lower() != "https"
        or not parsed.netloc
        or not hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or parsed.netloc.endswith(":")
    ):
        return None
    return raw


def _validate_allowed_user_ids(raw: Any) -> Optional[frozenset[int]]:
    if not isinstance(raw, (list, tuple)) or not raw:
        return None
    values: list[int] = []
    for value in raw:
        if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
            return None
        values.append(value)
    return frozenset(values)


def load_runtime_config(ctx: Any) -> Optional[RuntimeConfig]:
    """Read and validate only the two documented, plugin-scoped settings."""

    try:
        mini_app_url = ctx.get_config("mini_app_url")
        allowed_user_ids = ctx.get_config("allowed_user_ids")
    except Exception:
        return None
    validated_url = _validate_mini_app_url(mini_app_url)
    validated_users = _validate_allowed_user_ids(allowed_user_ids)
    if validated_url is None or validated_users is None:
        return None
    return RuntimeConfig(validated_url, validated_users)


def _safe_int(value: Any) -> Optional[int]:
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value


def _identity_from_update(update: Any) -> Optional[tuple[int, int]]:
    user = getattr(update, "effective_user", None)
    chat = getattr(update, "effective_chat", None)
    user_id = _safe_int(getattr(user, "id", None))
    chat_id = _safe_int(getattr(chat, "id", None))
    if user_id is None or chat_id is None:
        return None
    return user_id, chat_id


def _thread_from_message(message: Any) -> Optional[int]:
    thread_id = _safe_int(getattr(message, "message_thread_id", None))
    return thread_id


def _web_app_data_from_update(update: Any) -> Any:
    message = getattr(update, "effective_message", None)
    web_app_data = getattr(message, "web_app_data", None)
    return getattr(web_app_data, "data", None)


class ReceiptStore:
    """Write bounded, nonsecret verification receipts under plugin data."""

    def __init__(self, ctx: Any):
        self._ctx = ctx
        self._lock = threading.RLock()

    @property
    def path(self) -> Optional[Path]:
        candidate = None
        try:
            candidate = getattr(self._ctx, "data_dir", None)
        except Exception:
            candidate = None
        if not isinstance(candidate, (str, os.PathLike)):
            try:
                state = getattr(self._ctx, "state", None)
                candidate = getattr(state, "data_dir", None)
            except Exception:
                candidate = None
        if not isinstance(candidate, (str, os.PathLike)):
            return None
        try:
            return Path(candidate) / _RECEIPT_FILENAME
        except (TypeError, ValueError):
            return None

    def append(self, request: PendingRequest, status: str, timestamp_ms: int) -> None:
        path = self.path
        if path is None:
            return
        record = {
            "id": request.request_id,
            "status": status,
            "created_at": request.created_at_ms,
            "expires_at": request.expires_at_ms,
            "updated_at": timestamp_ms,
            "thread": request.origin_thread,
        }
        try:
            encoded = json.dumps(
                record,
                ensure_ascii=True,
                separators=(",", ":"),
                sort_keys=True,
            ) + "\n"
            with self._lock:
                path.parent.mkdir(parents=True, exist_ok=True)
                with path.open("a", encoding="utf-8") as handle:
                    handle.write(encoded)
                    handle.flush()
                try:
                    os.chmod(path, 0o600)
                except OSError:
                    pass
        except (OSError, TypeError, ValueError):
            # Receipts are for parent verification and never affect the
            # transport result.  Keep this path silent rather than exposing
            # any update content through logs.
            return


class OwnedWebAppDataFilter:
    """Matcher used to build a PTB MessageFilter at connect time."""

    def __init__(self, owner: "TelegramSecureHandoffPlugin"):
        self._owner = owner

    def filter(self, message: Any) -> bool:
        raw = getattr(getattr(message, "web_app_data", None), "data", None)
        request_id = _extract_request_id(raw)
        return request_id is not None and self._owner.owns_request_id(request_id)


def _make_ptb_owned_filter(owner: "TelegramSecureHandoffPlugin", filters_module: Any) -> Any:
    """Create a real PTB MessageFilter without importing PTB at discovery."""

    matcher = OwnedWebAppDataFilter(owner)

    class _PTBOwnedWebAppDataFilter(filters_module.MessageFilter):
        def __init__(self) -> None:
            super().__init__(name="telegram-secure-handoff-owned-web-app-data")

        def filter(self, message: Any) -> bool:
            return matcher.filter(message)

    return _PTBOwnedWebAppDataFilter()


class TelegramSecureHandoffPlugin:
    """The stateful connection-test implementation."""

    def __init__(
        self,
        config: RuntimeConfig,
        ctx: Any,
        *,
        clock: Optional[Callable[[], float]] = None,
    ):
        self.config = config
        self._ctx = ctx
        self._clock = clock or (lambda: time.time())
        self._lock = threading.RLock()
        self._pending: dict[str, PendingRequest] = {}
        self._active_by_user: dict[int, str] = {}
        self._history: dict[str, PendingRequest] = {}
        self.receipts = ReceiptStore(ctx)

    def _now_ms(self) -> int:
        return int(self._clock() * 1000)

    def owns_request_id(self, request_id: str) -> bool:
        with self._lock:
            return request_id in self._pending or request_id in self._history

    @property
    def pending_count(self) -> int:
        with self._lock:
            return len(self._pending)

    def _record(self, request: PendingRequest, status: str, timestamp_ms: int) -> None:
        self.receipts.append(request, status, timestamp_ms)

    def _prune_history_locked(self, now_ms: int) -> None:
        cutoff = now_ms - HISTORY_TTL_SECONDS * 1000
        stale = [
            request_id
            for request_id, request in self._history.items()
            if request.updated_at_ms < cutoff
        ]
        for request_id in stale:
            self._history.pop(request_id, None)
        if len(self._history) > MAX_HISTORY:
            oldest = sorted(
                self._history.values(), key=lambda request: request.updated_at_ms
            )[: len(self._history) - MAX_HISTORY]
            for request in oldest:
                self._history.pop(request.request_id, None)

    def _move_to_history_locked(
        self,
        request: PendingRequest,
        status: str,
        timestamp_ms: int,
    ) -> None:
        self._pending.pop(request.request_id, None)
        if self._active_by_user.get(request.sender_id) == request.request_id:
            self._active_by_user.pop(request.sender_id, None)
        request.status = status
        request.updated_at_ms = timestamp_ms
        # Do not retain the private key after a terminal transition.  The
        # history entry only needs identity/routing metadata for replay checks.
        request.private_key = None
        self._history[request.request_id] = request
        self._record(request, status, timestamp_ms)

    def _expire_pending_locked(self, now_ms: int) -> None:
        expired = [
            request
            for request in self._pending.values()
            if request.expires_at_ms <= now_ms
        ]
        for request in expired:
            self._move_to_history_locked(request, "expired", now_ms)

    def _authorized_command_identity(self, update: Any) -> Optional[tuple[int, int]]:
        identity = _identity_from_update(update)
        if identity is None:
            return None
        user_id, chat_id = identity
        chat = getattr(update, "effective_chat", None)
        if getattr(chat, "type", None) != "private":
            return None
        if user_id not in self.config.allowed_user_ids:
            return None
        return identity

    def _make_request_locked(
        self,
        sender_id: int,
        chat_id: int,
        origin_thread: Optional[int],
        now_ms: int,
    ) -> Optional[PendingRequest]:
        try:
            from cryptography.hazmat.primitives.asymmetric import rsa

            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=RSA_KEY_SIZE,
            )
        except Exception:
            return None

        for _ in range(4):
            request_id = secrets.token_urlsafe(18)
            if request_id not in self._pending and request_id not in self._history:
                break
        else:
            return None

        expires_at_ms = now_ms + TTL_SECONDS * 1000
        request_payload = {
            "v": REQUEST_VERSION,
            "id": request_id,
            "publicKey": _public_jwk(private_key),
            "expiresAt": expires_at_ms,
        }
        request_json = json.dumps(
            request_payload,
            ensure_ascii=True,
            separators=(",", ":"),
        ).encode("utf-8")
        launch_url = (
            f"{self.config.mini_app_url}#request={_b64url_encode(request_json)}"
        )
        if len(launch_url) > _MAX_LAUNCH_URL_CHARS:
            return None
        request = PendingRequest(
            request_id=request_id,
            sender_id=sender_id,
            chat_id=chat_id,
            origin_thread=origin_thread,
            created_at_ms=now_ms,
            expires_at_ms=expires_at_ms,
            launch_url=launch_url,
            private_key=private_key,
            updated_at_ms=now_ms,
        )
        self._pending[request_id] = request
        self._active_by_user[sender_id] = request_id
        self._record(request, "pending", now_ms)
        return request

    def issue(self, sender_id: int, chat_id: int, origin_thread: Optional[int]) -> IssueResult:
        with self._lock:
            now_ms = self._now_ms()
            self._expire_pending_locked(now_ms)
            self._prune_history_locked(now_ms)
            existing_id = self._active_by_user.get(sender_id)
            if existing_id is not None:
                return IssueResult("existing", self._pending.get(existing_id))
            if len(self._pending) >= MAX_PENDING:
                return IssueResult("cap")
            request = self._make_request_locked(
                sender_id,
                chat_id,
                origin_thread,
                now_ms,
            )
            return IssueResult("created", request) if request is not None else IssueResult("unavailable")

    def _is_matching_origin(self, request: PendingRequest, update: Any) -> bool:
        identity = _identity_from_update(update)
        return identity == (request.sender_id, request.chat_id)

    def _status_text(self, status: str) -> str:
        return {
            "success": "Connection test succeeded.",
            "expired": "Connection test expired. Start a new test with /handoffcheck.",
            "replay": "Connection test already used.",
            "invalid": "Connection test rejected.",
            "rejected": "Connection test rejected.",
            "cancelled": "Connection test cancelled.",
        }.get(status, "Connection test rejected.")

    def _outcome_for_request(
        self,
        request: PendingRequest,
        status: str,
        *,
        remove_keyboard: bool = False,
    ) -> HandlerOutcome:
        return HandlerOutcome(
            owned=True,
            status=status,
            text=self._status_text(status),
            chat_id=request.chat_id,
            thread_id=request.origin_thread,
            remove_keyboard=remove_keyboard,
        )

    def _claim_submission(self, update: Any, request_id: str, raw: Any) -> tuple[HandlerOutcome, Any, Optional[PendingRequest]]:
        """Claim before decrypting/awaiting; return exactly one private key."""

        with self._lock:
            request = self._pending.get(request_id) or self._history.get(request_id)
            if request is None:
                return HandlerOutcome(False), None, None

            if not self._is_matching_origin(request, update):
                now_ms = self._now_ms()
                self._record(request, "rejected", now_ms)
                identity = _identity_from_update(update)
                if identity is None:
                    return self._outcome_for_request(request, "rejected"), None, None
                return (
                    HandlerOutcome(
                        owned=True,
                        status="rejected",
                        text=self._status_text("rejected"),
                        chat_id=identity[1],
                        thread_id=_thread_from_message(getattr(update, "effective_message", None)),
                    ),
                    None,
                    None,
                )

            now_ms = self._now_ms()
            if request.request_id in self._history:
                status = "expired" if request.status == "expired" else (
                    "cancelled" if request.status == "cancelled" else "replay"
                )
                self._record(request, status, now_ms)
                return self._outcome_for_request(request, status), None, None

            if request.expires_at_ms <= now_ms:
                self._move_to_history_locked(request, "expired", now_ms)
                return self._outcome_for_request(
                    request,
                    "expired",
                    remove_keyboard=True,
                ), None, None

            # Moving the entry before parsing/decryption closes the concurrent
            # duplicate race. A second update sees a terminal/processing id
            # and never receives the private key.
            self._pending.pop(request.request_id, None)
            if self._active_by_user.get(request.sender_id) == request.request_id:
                self._active_by_user.pop(request.sender_id, None)
            request.status = "processing"
            request.updated_at_ms = now_ms
            self._history[request.request_id] = request
            private_key = request.private_key
            self._record(request, "processing", now_ms)
            return HandlerOutcome(True, "processing"), private_key, request

    def _finish_submission(
        self,
        request: PendingRequest,
        status: str,
    ) -> HandlerOutcome:
        with self._lock:
            now_ms = self._now_ms()
            request.status = status
            request.updated_at_ms = now_ms
            request.private_key = None
            self._history[request.request_id] = request
            self._record(request, status, now_ms)
            return self._outcome_for_request(
                request,
                status,
                remove_keyboard=status == "success",
            )

    def process_submission(self, update: Any, raw: Any) -> HandlerOutcome:
        request_id = _extract_request_id(raw)
        if request_id is None:
            return HandlerOutcome(False)
        claim, private_key, request = self._claim_submission(update, request_id, raw)
        if not claim.owned:
            return claim
        if request is None or private_key is None:
            return claim
        ciphertext = _parse_ciphertext(raw, request.request_id)
        if ciphertext is None:
            return self._finish_submission(request, "invalid")
        try:
            from cryptography.hazmat.primitives import hashes
            from cryptography.hazmat.primitives.asymmetric import padding

            plaintext = private_key.decrypt(
                ciphertext,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None,
                ),
            )
            valid = hmac.compare_digest(plaintext, FIXED_MARKER_BYTES)
        except Exception:
            valid = False
        return self._finish_submission(request, "success" if valid else "invalid")

    def cancel(self, sender_id: int) -> Optional[PendingRequest]:
        with self._lock:
            now_ms = self._now_ms()
            self._expire_pending_locked(now_ms)
            request_id = self._active_by_user.get(sender_id)
            request = self._pending.get(request_id) if request_id else None
            if request is None:
                return None
            self._move_to_history_locked(request, "cancelled", now_ms)
            return request

    @staticmethod
    async def _send(
        context: Any,
        *,
        chat_id: int,
        thread_id: Optional[int],
        text: str,
        reply_markup: Any = None,
    ) -> None:
        bot = getattr(context, "bot", None)
        send_message = getattr(bot, "send_message", None)
        if not callable(send_message):
            return
        kwargs: dict[str, Any] = {"chat_id": chat_id, "text": text}
        if thread_id is not None:
            kwargs["message_thread_id"] = thread_id
        if reply_markup is not None:
            kwargs["reply_markup"] = reply_markup
        try:
            result = send_message(**kwargs)
            if inspect.isawaitable(result):
                await result
        except Exception:
            # The owned update is still stopped below; a Telegram send error
            # must not fall through to model/generic handlers.
            return

    @staticmethod
    def _raise_stop() -> None:
        from telegram.ext import ApplicationHandlerStop

        raise ApplicationHandlerStop

    @staticmethod
    def _keyboard(url: str) -> Any:
        from telegram import KeyboardButton, ReplyKeyboardMarkup, WebAppInfo

        button = KeyboardButton(
            text="Open connection test",
            web_app=WebAppInfo(url=url),
        )
        return ReplyKeyboardMarkup(
            [[button]],
            resize_keyboard=True,
            one_time_keyboard=False,
            input_field_placeholder="No passwords",
        )

    @staticmethod
    def _remove_keyboard() -> Any:
        from telegram import ReplyKeyboardRemove

        return ReplyKeyboardRemove()

    async def handle_handoffcheck(self, update: Any, context: Any) -> None:
        identity = self._authorized_command_identity(update)
        if identity is None:
            return
        sender_id, chat_id = identity
        message = getattr(update, "effective_message", None)
        thread_id = _thread_from_message(message)
        result = self.issue(sender_id, chat_id, thread_id)
        if result.status == "created" and result.request is not None:
            text = (
                "Connection test — no passwords. Open the button below, "
                "then tap Send test. Cancel with /handoffcancel."
            )
            markup = self._keyboard(result.request.launch_url)
        elif result.status == "existing" and result.request is not None:
            text = (
                "A connection test is already pending. Use the existing "
                "button, or cancel with /handoffcancel."
            )
            markup = self._keyboard(result.request.launch_url)
        elif result.status == "cap":
            text = "Connection test unavailable right now; try again later."
            markup = None
        else:
            text = "Connection test unavailable."
            markup = None
        await self._send(
            context,
            chat_id=chat_id,
            thread_id=thread_id,
            text=text,
            reply_markup=markup,
        )
        self._raise_stop()

    async def handle_handoffcancel(self, update: Any, context: Any) -> None:
        identity = self._authorized_command_identity(update)
        if identity is None:
            return
        sender_id, chat_id = identity
        message = getattr(update, "effective_message", None)
        current_thread = _thread_from_message(message)
        request = self.cancel(sender_id)
        target_thread = request.origin_thread if request is not None and request.chat_id == chat_id else current_thread
        await self._send(
            context,
            chat_id=chat_id,
            thread_id=target_thread,
            text="Connection test cancelled." if request is not None else "No connection test is pending.",
            reply_markup=self._remove_keyboard(),
        )
        self._raise_stop()

    async def handle_web_app_data(self, update: Any, context: Any) -> None:
        raw = _web_app_data_from_update(update)
        outcome = self.process_submission(update, raw)
        if not outcome.owned:
            return
        if outcome.text is not None and outcome.chat_id is not None:
            await self._send(
                context,
                chat_id=outcome.chat_id,
                thread_id=outcome.thread_id,
                text=outcome.text,
                reply_markup=self._remove_keyboard() if outcome.remove_keyboard else None,
            )
        self._raise_stop()

    def wire(self, application: Any, adapter: Any) -> None:
        """Add scoped handlers to Hermes' already-built PTB Application."""

        del adapter  # The native Application/context bot is the only handle needed.
        if application is None or not callable(getattr(application, "add_handler", None)):
            return
        from telegram.ext import CommandHandler, MessageHandler, filters

        owner_scope = filters.ChatType.PRIVATE & filters.User(
            user_id=self.config.allowed_user_ids,
        )
        application.add_handler(
            CommandHandler(
                "handoffcheck",
                self.handle_handoffcheck,
                filters=owner_scope,
                block=True,
            ),
            group=PLUGIN_HANDLER_GROUP,
        )
        application.add_handler(
            CommandHandler(
                "handoffcancel",
                self.handle_handoffcancel,
                filters=owner_scope,
                block=True,
            ),
            group=PLUGIN_HANDLER_GROUP,
        )
        web_app_scope = filters.StatusUpdate.WEB_APP_DATA & _make_ptb_owned_filter(
            self,
            filters,
        )
        application.add_handler(
            MessageHandler(
                web_app_scope,
                self.handle_web_app_data,
                block=True,
            ),
            group=PLUGIN_HANDLER_GROUP,
        )


def register(ctx: Any) -> None:
    """Hermes directory-plugin entry point; invalid config disables wiring."""

    config = load_runtime_config(ctx)
    if config is None:
        logger.warning(
            "Hermes Secure Handoff Telegram connection test disabled: missing or invalid mini_app_url/allowed_user_ids"
        )
        return
    ctx.register_telegram_handler(TelegramSecureHandoffPlugin(config, ctx).wire)


__all__ = [
    "FIXED_MARKER",
    "FIXED_MARKER_BYTES",
    "MAX_PENDING",
    "MAX_WIRE_BYTES",
    "PLUGIN_HANDLER_GROUP",
    "REQUEST_VERSION",
    "RSA_KEY_SIZE",
    "RuntimeConfig",
    "TelegramSecureHandoffPlugin",
    "load_runtime_config",
    "register",
]
