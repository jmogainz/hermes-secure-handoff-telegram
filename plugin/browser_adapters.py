"""Target-neutral browser login adapters.

The controller owns page/session safety. Adapters only describe semantic control
hints for a provider's login surface; they never receive credential values.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import urlsplit

_OTP_ORDINAL_RE = re.compile(r"\b(?:digit|character|number)\s+\d+\s+of\s+\d+\b")


@dataclass(frozen=True)
class StageDescriptor:
    id: str
    title: str
    message: str


@dataclass(frozen=True)
class BrowserAdapter:
    name: str
    origins: tuple[str, ...]
    submit_labels: tuple[str, ...]
    allow_formless: bool = False

    def classify_input(self, metadata: dict[str, str]) -> str | None:
        typ = (metadata.get("type") or "").lower()
        name = (metadata.get("name") or "").lower()
        autocomplete = (metadata.get("autocomplete") or "").lower()
        aria = (metadata.get("aria") or "").lower()
        inputmode = (metadata.get("inputmode") or "").lower()
        maxlength = (metadata.get("maxlength") or "").lower()
        tokens = set(autocomplete.split())

        if typ == "password" or "current-password" in tokens:
            return "password"
        if (
            typ == "one-time-code"
            or "one-time-code" in tokens
            or "otp" in name
            or "code" in name
            or bool(_OTP_ORDINAL_RE.search(aria))
            or (inputmode == "numeric" and maxlength == "1" and "digit" in aria)
        ):
            return "otp"
        if typ in {"text", "email"} or tokens & {"username", "email"} or any(
            token in name for token in ("user", "email", "login")
        ):
            return "text"

        # Google account-recovery code controls are intentionally isolated to
        # this adapter: the live control is type=tel, name=Pin, aria-label=Enter
        # code, and is not associated with an HTML form.
        if self.name == "google" and typ in {"tel", "text"} and (
            name in {"pin", "code"} or "enter code" in aria or "verification code" in aria
        ):
            return "otp"
        return None

    def stage_for(self, field_types: tuple[str, ...]) -> StageDescriptor:
        if self.name == "google" and field_types == ("otp",):
            return StageDescriptor(
                "google_verification_code",
                "Enter Google verification code",
                "Enter the code Google sent for this browser. It is encrypted before Telegram receives it.",
            )
        if field_types == ("text",):
            return StageDescriptor(
                "identifier",
                "Enter account identifier",
                "Enter the username or email for this browser.",
            )
        if field_types == ("password",):
            return StageDescriptor(
                "password",
                "Enter password",
                "Enter the password for this browser.",
            )
        if field_types == ("otp",):
            return StageDescriptor(
                "one_time_code",
                "Enter one-time code",
                "Enter the one-time code for this browser.",
            )
        return StageDescriptor(
            "browser_auth",
            "Enter details for this browser",
            "Your entries are encrypted before Telegram receives them.",
        )


GENERIC_ADAPTER = BrowserAdapter(
    name="generic",
    origins=(),
    submit_labels=("Continue", "Next", "Sign in", "Log in", "Submit"),
)

GOOGLE_ADAPTER = BrowserAdapter(
    name="google",
    origins=("https://accounts.google.com",),
    submit_labels=("Next",),
    allow_formless=True,
)

_ADAPTERS = (GOOGLE_ADAPTER, GENERIC_ADAPTER)


def adapter_for_origin(origin: str) -> BrowserAdapter:
    for adapter in _ADAPTERS:
        if origin in adapter.origins:
            return adapter
    return GENERIC_ADAPTER


def adapter_for_url(url: str) -> BrowserAdapter:
    parsed = urlsplit(url)
    origin = f"{parsed.scheme}://{parsed.netloc}" if parsed.scheme and parsed.netloc else ""
    return adapter_for_origin(origin)


__all__ = [
    "BrowserAdapter",
    "StageDescriptor",
    "adapter_for_origin",
    "adapter_for_url",
]
