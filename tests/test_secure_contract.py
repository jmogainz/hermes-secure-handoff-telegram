import base64
import json

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from plugin.secure_handoff import decrypt_submission, make_request


def _envelope(request, key, body):
    aes = b"a" * 32
    iv = b"b" * 12
    plaintext = json.dumps(body, separators=(",", ":")).encode()
    wrapped = key.public_key().encrypt(
        aes,
        padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
    )
    return json.dumps({
        "v": request["v"],
        "id": request["id"],
        "wrappedKey": base64.urlsafe_b64encode(wrapped).decode().rstrip("="),
        "iv": base64.urlsafe_b64encode(iv).decode().rstrip("="),
        "ciphertext": base64.urlsafe_b64encode(
            AESGCM(aes).encrypt(iv, plaintext, request["id"].encode())
        ).decode().rstrip("="),
    })


def test_v3_secure_handoff_supports_checkout_and_field_free_confirmation():
    fields = [
        {"id": "f0", "label": "Billing name", "type": "text", "required": True},
        {"id": "f1", "label": "Billing email", "type": "email", "required": True},
        {"id": "f2", "label": "Card number", "type": "card_number", "required": True},
        {"id": "f3", "label": "Expiration date", "type": "card_expiry", "required": True},
        {"id": "f4", "label": "Security code", "type": "cvc", "required": True},
    ]
    request, key = make_request(
        "https://checkout.example",
        fields,
        mode="checkout",
        stage="checkout_details",
        action_label="Review purchase",
    )

    assert request["v"] == 3
    assert request["id"].startswith("sh_")
    assert request["mode"] == "checkout"
    assert request["actionLabel"] == "Review purchase"
    assert request["fields"] == fields
    assert key is not None

    confirmation, confirmation_key = make_request(
        "https://checkout.example",
        [],
        mode="payment_confirmation",
        stage="payment_confirmation",
        action_label="Authorize purchase",
    )
    assert confirmation["fields"] == []
    assert confirmation["mode"] == "payment_confirmation"
    assert confirmation["actionLabel"] == "Authorize purchase"
    assert confirmation_key is not None


def test_v3_decrypts_checkout_values_and_requires_field_free_confirmation():
    request, key = make_request(
        "https://checkout.example",
        [{"id": "f0", "label": "Card number", "type": "card_number", "required": True}],
        mode="checkout",
        stage="checkout_details",
        action_label="Review purchase",
    )
    raw = _envelope(request, key, {"values": {"f0": "synthetic-card-number"}})
    assert decrypt_submission(raw, request, key) == {"f0": "synthetic-card-number"}

    confirmation, confirmation_key = make_request(
        "https://checkout.example",
        [],
        mode="payment_confirmation",
        stage="payment_confirmation",
        action_label="Authorize purchase",
    )
    confirm_raw = _envelope(confirmation, confirmation_key, {"confirm": True})
    assert decrypt_submission(confirm_raw, confirmation, confirmation_key) == {"confirm": True}

    values_in_confirmation = _envelope(confirmation, confirmation_key, {"values": {}})
    with pytest.raises(ValueError):
        decrypt_submission(values_in_confirmation, confirmation, confirmation_key)


def test_v3_checkout_accepts_a_safe_empty_select_placeholder():
    request, _ = make_request(
        "https://checkout.example",
        [{
            "id": "f0",
            "label": "Country",
            "type": "select",
            "required": True,
            "options": [
                {"value": "", "label": "Choose a country"},
                {"value": "US", "label": "United States"},
            ],
        }],
        mode="checkout",
        stage="checkout_details",
        action_label="Review purchase",
    )
    assert request["fields"][0]["options"][0]["value"] == ""
