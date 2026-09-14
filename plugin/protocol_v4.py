"""Version 4 encrypted transport for generic browser operations.

The wire protocol carries only an agent-authored entry manifest or one explicit
action approval.  Browser selectors, current values, and provider semantics are
not protocol data.
"""
from __future__ import annotations

import base64
import binascii
import json
import re
import secrets
import time
import unicodedata
from typing import Any
from urllib.parse import urlsplit

REQUEST_VERSION = 4
TTL_SECONDS = 10 * 60
MAX_ENVELOPE_BYTES = 4096
MAX_PLAINTEXT_BYTES = 2048
MAX_FIELDS = 24
MAX_VALUE_CHARS = 512
MAX_LABEL_CHARS = 80
MAX_SUMMARY_CHARS = 160
MAX_VIEW_NODES = 64
MAX_VIEW_DEPTH = 6
MAX_VIEW_CHILDREN = 24
MAX_VIEW_TEXT_CHARS = 240

_B64_RE = re.compile(r"^[A-Za-z0-9_-]+$")
_REQUEST_ID_RE = re.compile(r"^sh_[A-Za-z0-9_-]{32}$")
_FIELD_ID_RE = re.compile(r"^f(?:[0-9]|1[0-9]|2[0-3])$")
_SAFE_TYPES = frozenset({
    "text", "password", "email", "tel", "url", "number", "search",
    "textarea", "select", "checkbox", "radio", "date", "time",
    "datetime-local", "month", "week", "color", "range",
})
_SAFE_STRATEGIES = frozenset({"keyboard", "fill", "select", "check"})
_COMPONENT_KEYS = frozenset({"kind", "length", "alphabet"})
_SEGMENTED_ALPHABETS = frozenset({"digits", "alphanumeric"})
_UI_SCHEMA = "secure-handoff.ui/1"
_URI_TEXT_RE = re.compile(r"(?i)(?://|(?:https?|tg|javascript|data|file|mailto|tel):)")
_BIDI_CONTROLS = frozenset({
    "\u061c", "\u200e", "\u200f", "\u202a", "\u202b", "\u202c", "\u202d", "\u202e",
    "\u2066", "\u2067", "\u2068", "\u2069",
})


def _json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate key")
        result[key] = value
    return result


def strict_json(raw: str, *, limit: int) -> Any:
    if not isinstance(raw, str) or len(raw.encode("utf-8")) > limit:
        raise ValueError("invalid json")

    def invalid_constant(_value: str) -> None:
        raise ValueError("invalid constant")

    try:
        return json.loads(
            raw,
            object_pairs_hook=_json_object,
            parse_constant=invalid_constant,
        )
    except (UnicodeError, TypeError, ValueError, RecursionError) as error:
        raise ValueError("invalid json") from None


def b64url_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def b64url_decode(value: Any, *, maximum: int) -> bytes:
    if not isinstance(value, str) or not value or len(value) > maximum or not _B64_RE.fullmatch(value):
        raise ValueError("invalid base64url")
    try:
        return base64.urlsafe_b64decode((value + "=" * (-len(value) % 4)).encode("ascii"))
    except (UnicodeError, ValueError, binascii.Error):
        raise ValueError("invalid base64url") from None


def normalize_origin(raw: Any) -> str:
    if not isinstance(raw, str) or not raw or len(raw) > 4096 or "\\" in raw:
        raise ValueError("invalid origin")
    if any(character.isspace() or ord(character) < 32 or ord(character) == 127 for character in raw):
        raise ValueError("invalid origin")
    try:
        parsed = urlsplit(raw)
        port = parsed.port
    except (TypeError, ValueError):
        raise ValueError("invalid origin") from None
    if (
        parsed.scheme.lower() != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or parsed.path not in ("", "/")
        or parsed.netloc.endswith(":")
        or port == 0
    ):
        raise ValueError("invalid origin")
    host = parsed.hostname.encode("idna").decode("ascii").lower()
    if "%" in host:
        raise ValueError("invalid origin")
    if ":" in host:
        host = f"[{host}]"
    return f"https://{host}" + (f":{port}" if port is not None and port != 443 else "")


def origin_from_url(raw: Any) -> str:
    if not isinstance(raw, str):
        raise ValueError("invalid url")
    try:
        parsed = urlsplit(raw)
        return normalize_origin(f"{parsed.scheme}://{parsed.netloc}")
    except (TypeError, ValueError):
        raise ValueError("invalid url") from None


def _unsafe_visible_character(character: str) -> bool:
    codepoint = ord(character)
    return (
        unicodedata.category(character) in {"Cc", "Cf", "Cs"}
        or codepoint in {0x034F, 0x115F, 0x1160, 0x17B4, 0x17B5, 0x3164, 0xFFA0}
        or 0xFE00 <= codepoint <= 0xFE0F
        or 0xE0100 <= codepoint <= 0xE01EF
        or character in _BIDI_CONTROLS
    )


def _safe_text(value: Any, maximum: int) -> str:
    if (
        not isinstance(value, str)
        or not value.strip()
        or len(value) > maximum
        or any(_unsafe_visible_character(character) for character in value)
        or _URI_TEXT_RE.search(value) is not None
    ):
        raise ValueError("invalid text")
    return value.strip()


def _validate_component(
    value: Any,
    *,
    field_type: str,
    strategy: str,
    required: bool,
) -> dict[str, Any] | None:
    if value is None:
        return None
    if not isinstance(value, dict) or set(value) != _COMPONENT_KEYS:
        raise ValueError("invalid component")
    if value.get("kind") != "segmented_code":
        raise ValueError("invalid component")
    length = value.get("length")
    alphabet = value.get("alphabet")
    if (
        type(length) is not int
        or not 4 <= length <= 12
        or not isinstance(alphabet, str)
        or alphabet not in _SEGMENTED_ALPHABETS
        or required is not True
    ):
        raise ValueError("invalid component")
    expected_type = "tel" if alphabet == "digits" else "text"
    if strategy != "keyboard" or field_type != expected_type:
        raise ValueError("invalid component binding")
    return {"kind": "segmented_code", "length": length, "alphabet": alphabet}


def _component_accepts_value(component: dict[str, Any], value: str) -> bool:
    length = component["length"]
    if len(value) != length:
        return False
    if component["alphabet"] == "digits":
        return re.fullmatch(r"[0-9]+", value) is not None
    return re.fullmatch(r"[0-9A-Za-z]+", value) is not None


def _validate_binding(value: Any, component: dict[str, Any] | None) -> list[str]:
    if value is None:
        return []
    if component is None or component.get("kind") != "segmented_code":
        raise ValueError("invalid binding")
    if not isinstance(value, dict) or set(value) != {"mode", "refs"} or value.get("mode") != "split_chars":
        raise ValueError("invalid binding")
    refs = value.get("refs")
    if not isinstance(refs, list) or not 1 <= len(refs) <= 11 or len(refs) + 1 != component["length"]:
        raise ValueError("invalid binding")
    if any(not isinstance(ref, str) or re.fullmatch(r"fr_[A-Za-z0-9_-]{32}", ref) is None for ref in refs):
        raise ValueError("invalid binding")
    if len(refs) != len(set(refs)):
        raise ValueError("invalid binding")
    return list(refs)


def _normalize_view(value: Any, identifiers: dict[str, str], *, source_key: str) -> dict[str, Any]:
    if (
        not isinstance(value, dict)
        or set(value) != {"schema", "kind", "children"}
        or value.get("schema") != _UI_SCHEMA
        or value.get("kind") != "stack"
    ):
        raise ValueError("invalid view")
    seen: set[str] = set()
    count = 0

    def walk(node: Any, depth: int) -> dict[str, Any]:
        nonlocal count
        count += 1
        if count > MAX_VIEW_NODES or depth > MAX_VIEW_DEPTH or not isinstance(node, dict):
            raise ValueError("invalid view")
        kind = node.get("kind")
        if not isinstance(kind, str):
            raise ValueError("invalid view")
        if kind == "field":
            if set(node) != {"kind", source_key}:
                raise ValueError("invalid view")
            identifier = node[source_key]
            if not isinstance(identifier, str) or identifier not in identifiers or identifier in seen:
                raise ValueError("invalid view")
            seen.add(identifier)
            return {"kind": "field", "field": identifiers[identifier]}
        if kind == "text":
            tone = node.get("tone")
            if set(node) != {"kind", "text", "tone"} or not isinstance(tone, str) or tone not in {"normal", "muted"}:
                raise ValueError("invalid view")
            return {"kind": "text", "text": _safe_text(node.get("text"), MAX_VIEW_TEXT_CHARS), "tone": node["tone"]}
        if kind == "divider":
            if set(node) != {"kind"}:
                raise ValueError("invalid view")
            return {"kind": "divider"}
        if kind not in {"stack", "row", "section"}:
            raise ValueError("invalid view")
        required = {"kind", "children"} | ({"title"} if kind == "section" else set())
        if set(node) != required:
            raise ValueError("invalid view")
        children = node.get("children")
        if not isinstance(children, list) or not 1 <= len(children) <= MAX_VIEW_CHILDREN:
            raise ValueError("invalid view")
        normalized: dict[str, Any] = {"kind": kind}
        if kind == "section":
            normalized["title"] = _safe_text(node.get("title"), MAX_LABEL_CHARS)
        normalized["children"] = [walk(child, depth + 1) for child in children]
        return normalized

    normalized = walk({"kind": value["kind"], "children": value["children"]}, 1)
    if seen != set(identifiers):
        raise ValueError("invalid view")
    return {"schema": _UI_SCHEMA, **normalized}


def validate_entry_fields(fields: Any) -> list[dict[str, Any]]:
    if not isinstance(fields, list) or not 1 <= len(fields) <= MAX_FIELDS:
        raise ValueError("invalid fields")
    result: list[dict[str, Any]] = []
    seen_refs: set[str] = set()
    for ordinal, field in enumerate(fields):
        base_keys = {"ref", "label", "type", "required", "strategy"}
        allowed = {
            frozenset(base_keys),
            frozenset(base_keys | {"component"}),
            frozenset(base_keys | {"component", "binding"}),
        }
        if not isinstance(field, dict) or set(field) not in allowed:
            raise ValueError("invalid field")
        ref = field["ref"]
        kind = field["type"]
        strategy = field["strategy"]
        if not isinstance(ref, str) or not re.fullmatch(r"fr_[A-Za-z0-9_-]{32}", ref):
            raise ValueError("invalid field ref")
        if (
            not isinstance(kind, str)
            or kind not in _SAFE_TYPES
            or not isinstance(strategy, str)
            or strategy not in _SAFE_STRATEGIES
            or type(field["required"]) is not bool
        ):
            raise ValueError("invalid field")
        if kind == "select" and strategy != "select":
            raise ValueError("invalid strategy")
        if kind in {"checkbox", "radio"} and strategy != "check":
            raise ValueError("invalid strategy")
        if kind not in {"select", "checkbox", "radio"} and strategy not in {"keyboard", "fill"}:
            raise ValueError("invalid strategy")
        component = _validate_component(
            field.get("component"), field_type=kind, strategy=strategy, required=field["required"]
        )
        extra_refs = _validate_binding(field.get("binding"), component)
        bound_refs = [ref, *extra_refs]
        if len(bound_refs) != len(set(bound_refs)) or any(item in seen_refs for item in bound_refs):
            raise ValueError("invalid field ref")
        normalized = {
            "id": f"f{ordinal}",
            "label": _safe_text(field["label"], MAX_LABEL_CHARS),
            "type": kind,
            "required": field["required"],
            "strategy": strategy,
        }
        if component is not None:
            normalized["component"] = component
        result.append(normalized)
        seen_refs.update(bound_refs)
    return result


def _new_request_base(origin: str) -> tuple[dict[str, Any], Any]:
    from cryptography.hazmat.primitives.asymmetric import rsa

    normalized = normalize_origin(origin)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    numbers = key.public_key().public_numbers()
    request = {
        "v": REQUEST_VERSION,
        "id": "sh_" + secrets.token_urlsafe(24),
        "origin": normalized,
        "expiresAt": int(time.time() * 1000) + TTL_SECONDS * 1000,
        "publicKey": {
            "kty": "RSA",
            "n": b64url_encode(numbers.n.to_bytes((numbers.n.bit_length() + 7) // 8, "big")),
            "e": b64url_encode(numbers.e.to_bytes((numbers.e.bit_length() + 7) // 8, "big")),
        },
    }
    return request, key


def make_entry_request(origin: str, fields: Any, view: Any = None) -> tuple[dict[str, Any], Any]:
    request, key = _new_request_base(origin)
    request["kind"] = "entry"
    normalized_fields = validate_entry_fields(fields)
    request["fields"] = normalized_fields
    if view is not None:
        identifiers = {raw["ref"]: field["id"] for raw, field in zip(fields, normalized_fields)}
        request["view"] = _normalize_view(view, identifiers, source_key="ref")
    return request, key


def make_action_request(origin: str, summary: Any) -> tuple[dict[str, Any], Any]:
    request, key = _new_request_base(origin)
    request.update({
        "kind": "action_approval",
        "approvalNonce": "approve_" + secrets.token_urlsafe(18),
        "summary": _safe_text(summary, MAX_SUMMARY_CHARS),
    })
    return request, key


def make_request(origin: str, fields: Any = None, *, kind: str = "entry", summary: Any = None, view: Any = None, **_ignored: Any):
    """Compatibility entry point, now limited to the v4 transport-only shapes."""
    if kind == "entry":
        return make_entry_request(origin, fields, view)
    if kind == "action_approval":
        return make_action_request(origin, summary)
    raise ValueError("invalid request kind")


def _validate_request(request: Any) -> None:
    if not isinstance(request, dict) or request.get("v") != REQUEST_VERSION:
        raise ValueError("invalid request")
    if not isinstance(request.get("id"), str) or not _REQUEST_ID_RE.fullmatch(request["id"]):
        raise ValueError("invalid request")
    if type(request.get("expiresAt")) is not int:
        raise ValueError("invalid request")
    normalize_origin(request.get("origin"))
    if request.get("kind") == "entry":
        base_keys = {"v", "id", "origin", "expiresAt", "publicKey", "kind", "fields"}
        if set(request) not in {frozenset(base_keys), frozenset(base_keys | {"view"})}:
            raise ValueError("invalid request")
        fields = request.get("fields")
        if not isinstance(fields, list) or not 1 <= len(fields) <= MAX_FIELDS:
            raise ValueError("invalid request")
        seen: set[str] = set()
        for field in fields:
            base_keys = {"id", "label", "type", "required", "strategy"}
            if not isinstance(field, dict) or set(field) not in {frozenset(base_keys), frozenset(base_keys | {"component"})}:
                raise ValueError("invalid request")
            field_id = field["id"]
            if not isinstance(field_id, str) or not _FIELD_ID_RE.fullmatch(field_id) or field_id in seen:
                raise ValueError("invalid request")
            _safe_text(field["label"], MAX_LABEL_CHARS)
            if (
                not isinstance(field["type"], str)
                or field["type"] not in _SAFE_TYPES
                or not isinstance(field["strategy"], str)
                or field["strategy"] not in _SAFE_STRATEGIES
                or type(field["required"]) is not bool
            ):
                raise ValueError("invalid request")
            _validate_component(
                field.get("component"),
                field_type=field["type"],
                strategy=field["strategy"],
                required=field["required"],
            )
            seen.add(field_id)
        if "view" in request:
            _normalize_view(request["view"], {field_id: field_id for field_id in seen}, source_key="field")
    elif request.get("kind") == "action_approval":
        if set(request) != {"v", "id", "origin", "expiresAt", "publicKey", "kind", "approvalNonce", "summary"}:
            raise ValueError("invalid request")
        if not isinstance(request.get("approvalNonce"), str) or not re.fullmatch(r"approve_[A-Za-z0-9_-]{24}", request["approvalNonce"]):
            raise ValueError("invalid request")
        _safe_text(request.get("summary"), MAX_SUMMARY_CHARS)
    else:
        raise ValueError("invalid request")


def decrypt_submission(raw: str, request: dict[str, Any], private_key: Any) -> dict[str, Any]:
    """Decrypt and validate one exact v4 submission.

    The return value is intentionally short-lived controller input.  Callers
    must clear it immediately after dispatching the requested browser calls.
    """
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    try:
        _validate_request(request)
        if private_key is None:
            raise ValueError("missing key")
        obj = strict_json(raw, limit=MAX_ENVELOPE_BYTES)
        if (
            not isinstance(obj, dict)
            or set(obj) != {"v", "id", "wrappedKey", "iv", "ciphertext"}
            or type(obj["v"]) is not int
            or obj["v"] != REQUEST_VERSION
            or obj["id"] != request["id"]
        ):
            raise ValueError("invalid envelope")
        wrapped = b64url_decode(obj["wrappedKey"], maximum=342)
        iv = b64url_decode(obj["iv"], maximum=16)
        ciphertext = b64url_decode(obj["ciphertext"], maximum=3072)
        if len(wrapped) != 256 or len(iv) != 12 or not 16 <= len(ciphertext) <= MAX_PLAINTEXT_BYTES + 16:
            raise ValueError("invalid envelope")
        aes = private_key.decrypt(
            wrapped,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        if len(aes) != 32:
            raise ValueError("invalid key")
        plaintext = AESGCM(aes).decrypt(iv, ciphertext, request["id"].encode("ascii"))
        if len(plaintext) > MAX_PLAINTEXT_BYTES:
            raise ValueError("invalid plaintext")
        body = strict_json(plaintext.decode("utf-8"), limit=MAX_PLAINTEXT_BYTES)
        if not isinstance(body, dict):
            raise ValueError("invalid body")

        if request["kind"] == "action_approval":
            if set(body) != {"approve"} or body["approve"] != request["approvalNonce"]:
                raise ValueError("invalid approval")
            return {"approve": body["approve"]}

        if set(body) != {"values"} or not isinstance(body["values"], dict):
            raise ValueError("invalid values")
        expected = {field["id"] for field in request["fields"]}
        if set(body["values"]) != expected:
            raise ValueError("invalid values")
        values: dict[str, str] = {}
        for field in request["fields"]:
            value = body["values"][field["id"]]
            if (
                not isinstance(value, str)
                or len(value) > MAX_VALUE_CHARS
                or (field["required"] and not value)
                or (field["strategy"] == "check" and value not in {"true", "false"})
                or (field["required"] and field["strategy"] == "check" and value != "true")
                or (field.get("component") is not None and value != "" and not _component_accepts_value(field["component"], value))
            ):
                raise ValueError("invalid value")
            values[field["id"]] = value
        return values
    except Exception:
        raise ValueError("invalid submission") from None


__all__ = [
    "REQUEST_VERSION", "TTL_SECONDS", "MAX_FIELDS", "MAX_VALUE_CHARS", "MAX_VIEW_NODES",
    "normalize_origin", "origin_from_url", "validate_entry_fields",
    "make_entry_request", "make_action_request", "make_request",
    "decrypt_submission", "b64url_encode", "strict_json",
]
