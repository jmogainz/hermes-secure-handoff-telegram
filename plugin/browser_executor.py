"""Generic Playwright executor for transport-only secure handoff.

Inventory exposes structural capabilities only.  Element handles, selectors,
labels, current values, and page text remain private to this module/controller.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

try:
    from .protocol_v4 import origin_from_url
except ImportError:  # Standalone Hermes directory loader.
    from protocol_v4 import origin_from_url

_CONTROL_SELECTOR = (
    'input:not([type="hidden"]):not([type="file"]),textarea,select,button,a[href],'
    '[contenteditable]:not([contenteditable="false"]),[role="button"],'
    '[role="textbox"],[role="searchbox"],[role="combobox"]'
)
_ACTION_INPUT_TYPES = frozenset({"button", "submit", "reset", "image"})
_CHECK_INPUT_TYPES = frozenset({"checkbox", "radio"})


@dataclass
class BrowserControl:
    """Private exact handle plus the finite operations it supports."""

    handle: Any = field(repr=False)
    frame: Any = field(repr=False)
    category: str
    capabilities: tuple[str, ...]

    async def apply(self, strategy: str, value: Any = None) -> None:
        if strategy not in self.capabilities:
            raise ValueError("unsupported operation")
        if strategy == "keyboard":
            if not isinstance(value, str):
                raise ValueError("invalid value")
            await self.handle.focus()
            await self.handle.press("ControlOrMeta+A")
            await self.handle.press("Backspace")
            await self.handle.type(value)
            return
        if strategy == "fill":
            if not isinstance(value, str):
                raise ValueError("invalid value")
            await self.handle.fill(value)
            return
        if strategy == "select":
            if not isinstance(value, str):
                raise ValueError("invalid value")
            await self.handle.select_option(label=value)
            return
        if strategy == "check":
            if value not in {"true", "false"}:
                raise ValueError("invalid value")
            await self.handle.set_checked(value == "true")
            return
        if strategy == "click":
            if value is not None:
                raise ValueError("invalid click")
            await self.handle.click()
            return
        raise ValueError("unsupported operation")


class GenericBrowserExecutor:
    """Enumerate native/generic controls in the top page and child frames."""

    @staticmethod
    async def _shape(handle: Any) -> tuple[str, tuple[str, ...]] | None:
        structural = await handle.evaluate(
            """element => ({
                tag: String(element.tagName || '').toLowerCase(),
                type: String(element.getAttribute('type') || '').toLowerCase(),
                role: String(element.getAttribute('role') || '').toLowerCase(),
                editable: element.isContentEditable === true
            })"""
        )
        if not isinstance(structural, dict):
            return None
        tag = structural.get("tag")
        input_type = structural.get("type") or "text"
        role = structural.get("role")
        if tag in {"button", "a"} or role == "button" or (tag == "input" and input_type in _ACTION_INPUT_TYPES):
            return "action", ("click",)
        if tag == "input" and input_type in _CHECK_INPUT_TYPES:
            return "checkable", ("check",)
        if tag == "select":
            return "select", ("select",)
        if tag in {"input", "textarea"} or structural.get("editable") is True:
            return "editable", ("keyboard", "fill")
        if role in {"textbox", "searchbox", "combobox"}:
            return "editable", ("keyboard",)
        return None

    @staticmethod
    async def _flag(handle: Any, method: str, default: bool = False) -> bool:
        try:
            return bool(await getattr(handle, method)())
        except Exception:
            return default

    async def inventory(self, page: Any) -> list[dict[str, Any]]:
        records: list[dict[str, Any]] = []
        frames = list(getattr(page, "frames", []) or [])
        if not frames:
            main = getattr(page, "main_frame", None)
            if main is not None:
                frames = [main]
        for frame_ordinal, frame in enumerate(frames):
            try:
                frame_origin = origin_from_url(getattr(frame, "url", ""))
            except ValueError:
                try:
                    frame_origin = origin_from_url(await frame.evaluate("location.origin"))
                except Exception:
                    frame_origin = ""
            try:
                handles = await frame.locator(_CONTROL_SELECTOR).element_handles()
            except Exception:
                continue
            control_ordinal = 0
            for handle in handles:
                try:
                    shape = await self._shape(handle)
                except Exception:
                    continue
                if shape is None:
                    continue
                control_ordinal += 1
                category, capabilities = shape
                visible = await self._flag(handle, "is_visible")
                enabled = await self._flag(handle, "is_enabled")
                editable = await self._flag(handle, "is_editable") if category == "editable" else False
                target = BrowserControl(handle, frame, category, capabilities)
                records.append({
                    "target": target,
                    "category": category,
                    "capabilities": list(capabilities),
                    "frame_origin": frame_origin,
                    "frame_ordinal": frame_ordinal,
                    "ordinal": control_ordinal,
                    "visible": visible,
                    "enabled": enabled,
                    "editable": editable,
                })
        return records


BrowserExecutor = GenericBrowserExecutor

__all__ = ["BrowserControl", "GenericBrowserExecutor", "BrowserExecutor"]
