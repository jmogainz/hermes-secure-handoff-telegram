"""Provider-neutral semantic descriptors for secure browser handoffs."""
from __future__ import annotations

import re
from dataclasses import dataclass

_OTP_ORDINAL_RE = re.compile(r"\b(?:digit|character|number)\s+\d+\s+of\s+\d+\b")

CHECKOUT_KINDS = frozenset({"email", "tel", "number", "card_number", "card_expiry", "cvc", "select"})
PAYMENT_KINDS = frozenset({"card_number", "card_expiry", "cvc"})
SUPPORTED_FIELD_TYPES = frozenset({
    "text",
    "email",
    "tel",
    "number",
    "password",
    "otp",
    "card_number",
    "card_expiry",
    "cvc",
    "select",
    "textarea", "checkbox", "date", "time", "datetime-local", "month", "week",
    "url", "search", "color", "range",
})


@dataclass(frozen=True)
class StageDescriptor:
    id: str
    title: str
    message: str
    mode: str = "auth"


@dataclass(frozen=True)
class BrowserAdapter:
    """Semantic hints only; never receives field values or browser state."""

    name: str
    origins: tuple[str, ...]
    submit_labels: tuple[str, ...]
    allow_formless: bool = False

    def classify_input(self, metadata: dict[str, str]) -> str | None:
        typ = (metadata.get("type") or "").lower()
        tag = (metadata.get("tag") or "").lower()
        name = (metadata.get("name") or "").lower()
        autocomplete = (metadata.get("autocomplete") or "").lower()
        aria = (metadata.get("aria") or "").lower()
        placeholder = (metadata.get("placeholder") or "").lower()
        inputmode = (metadata.get("inputmode") or "").lower()
        maxlength = (metadata.get("maxlength") or "").lower()
        tokens = set(autocomplete.split())
        semantic = " ".join((name, autocomplete, aria, placeholder, metadata.get("id", "").lower()))

        if tokens & {"cc-number"} or any(token in semantic for token in ("cardnumber", "card number", "creditcard", "credit card")):
            return "card_number"
        if tokens & {"cc-exp", "cc-exp-month", "cc-exp-year"} or any(
            token in semantic for token in ("cardexpiry", "card expiry", "expiration date", "expiry date", "exp month", "exp year")
        ):
            return "card_expiry"
        if tokens & {"cc-csc"} or any(token in semantic for token in ("cvc", "cvv", "security code", "card security")):
            return "cvc"

        if typ == "password" or "current-password" in tokens:
            return "password"
        if (
            typ == "one-time-code"
            or "one-time-code" in tokens
            or "otp" in name
            or "code" in name
            or "code" in aria
            or bool(_OTP_ORDINAL_RE.search(aria))
            or (inputmode == "numeric" and maxlength == "1" and "digit" in aria)
        ):
            return "otp"

        # Preserve the native email keyboard/validation contract even when this
        # control is the login username stage. Authority is checked separately.
        if tokens & {"username"} or any(token in name for token in ("user", "login", "username")):
            return "email" if typ == "email" else "text"
        if typ == "email" or "email" in tokens or "email" in name:
            return "email"
        if typ == "tel" or "tel" in tokens or any(token in semantic for token in ("phone", "telephone", "mobile")):
            return "tel"
        if typ == "number" or inputmode == "decimal":
            return "number"
        if tag == "select":
            return "select"
        if tag == "textarea" or typ in {"text", "search"}:
            return "text"
        return None

    def classify_form_control(self, metadata: dict[str, str]) -> str | None:
        """Native shape first; never turn a postal code into an auth stage."""
        tag, typ = metadata.get("tag"), metadata.get("type")
        if tag in {"textarea", "select"}:
            return tag
        if tag != "input":
            return None
        if typ == "radio":
            return "select"
        if typ in {"text", "tel", "number", "one-time-code"} and (
            "one-time-code" in metadata.get("autocomplete", "").split() or typ == "one-time-code"
        ):
            return "otp"
        if typ in SUPPORTED_FIELD_TYPES - PAYMENT_KINDS - {"select", "textarea", "otp"}:
            return typ
        return None

    def stage_for(
        self,
        field_types: tuple[str, ...],
        *,
        checkout: bool = False,
        form: bool = False,
        confirmation: bool = False,
    ) -> StageDescriptor:
        if form:
            return StageDescriptor("general_form", "Fill fields", "Encrypted entries fill the bound controls without clicking submit.", "form")
        if confirmation:
            return StageDescriptor(
                "payment_confirmation",
                "Authorize purchase",
                "Review the browser page, then confirm the purchase.",
                "payment_confirmation",
            )
        if checkout:
            return StageDescriptor(
                "checkout_details",
                "Enter checkout details",
                "Entries are encrypted locally before transmission.",
                "checkout",
            )
        if field_types == ("text",) or field_types == ("email",):
            return StageDescriptor(
                "identifier",
                "Enter account identifier",
                "Enter the username or email for this browser.",
                "auth",
            )
        if field_types == ("password",):
            return StageDescriptor(
                "password",
                "Enter password",
                "Enter the password for this browser.",
                "auth",
            )
        if field_types == ("otp",):
            return StageDescriptor(
                "one_time_code",
                "Enter one-time code",
                "Enter the one-time code for this browser.",
                "auth",
            )
        return StageDescriptor(
            "browser_auth",
            "Enter secure details",
            "Entries are encrypted locally before transmission.",
            "auth",
        )


GENERIC_ADAPTER = BrowserAdapter(
    name="generic",
    origins=(),
    submit_labels=(
        "Continue",
        "Next",
        "Sign in",
        "Log in",
        "Submit",
    ),
)


def adapter_for_origin(_origin: str) -> BrowserAdapter:
    return GENERIC_ADAPTER


def adapter_for_url(_url: str) -> BrowserAdapter:
    return GENERIC_ADAPTER


__all__ = [
    "BrowserAdapter",
    "CHECKOUT_KINDS",
    "GENERIC_ADAPTER",
    "PAYMENT_KINDS",
    "SUPPORTED_FIELD_TYPES",
    "StageDescriptor",
    "adapter_for_origin",
    "adapter_for_url",
]
