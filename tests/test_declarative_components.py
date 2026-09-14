"""Protocol-v4 tests for agent-composed, data-only Mini App components."""
from __future__ import annotations

import base64
import json
import time

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from plugin.protocol_v4 import decrypt_submission, make_entry_request, validate_entry_fields
from plugin.secure_handoff import SCHEMA


ORIGIN = "https://fixture.example"
FIELD_REF = "fr_" + "F" * 32
SEGMENTED = {"kind": "segmented_code", "length": 6, "alphabet": "digits"}


def b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode().rstrip("=")


def envelope(request, key, values):
    aes, iv = b"a" * 32, b"b" * 12
    wrapped = key.public_key().encrypt(
        aes,
        padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
    )
    plaintext = json.dumps({"values": values}, separators=(",", ":")).encode()
    ciphertext = AESGCM(aes).encrypt(iv, plaintext, request["id"].encode())
    return json.dumps({
        "v": 4,
        "id": request["id"],
        "wrappedKey": b64(wrapped),
        "iv": b64(iv),
        "ciphertext": b64(ciphertext),
    }, separators=(",", ":"))


def segmented_field(**overrides):
    field = {
        "ref": FIELD_REF,
        "label": "Verification code",
        "type": "tel",
        "required": True,
        "strategy": "keyboard",
        "component": dict(SEGMENTED),
    }
    field.update(overrides)
    return field


def two_fields():
    first = segmented_field()
    second = {
        "ref": "fr_" + "B" * 32,
        "label": "Account name",
        "type": "text",
        "required": True,
        "strategy": "keyboard",
    }
    return [first, second]


def composed_view():
    return {
        "schema": "secure-handoff.ui/1",
        "kind": "stack",
        "children": [
            {"kind": "text", "text": "Enter the values shown in your browser.", "tone": "muted"},
            {
                "kind": "section",
                "title": "Verification",
                "children": [
                    {
                        "kind": "row",
                        "children": [
                            {"kind": "field", "ref": FIELD_REF},
                            {"kind": "field", "ref": "fr_" + "B" * 32},
                        ],
                    }
                ],
            },
            {"kind": "divider"},
        ],
    }


def test_segmented_code_component_is_preserved_as_public_ui_metadata():
    normalized = validate_entry_fields([segmented_field()])
    assert normalized == [{
        "id": "f0",
        "label": "Verification code",
        "type": "tel",
        "required": True,
        "strategy": "keyboard",
        "component": SEGMENTED,
    }]
    request, _ = make_entry_request(ORIGIN, [segmented_field()])
    assert request["fields"][0]["component"] == SEGMENTED
    assert FIELD_REF not in json.dumps(request)


def test_public_tool_schema_exposes_bounded_data_only_component_descriptor():
    field_schema = SCHEMA["parameters"]["properties"]["fields"]["items"]
    component_variants = [variant["properties"]["component"] for variant in field_schema["oneOf"][1:]]
    assert len(component_variants) == 2
    assert all(component["type"] == "object" for component in component_variants)
    assert all(component["additionalProperties"] is False for component in component_variants)
    assert all(component["properties"]["kind"]["enum"] == ["segmented_code"] for component in component_variants)
    assert all(component["properties"]["length"]["minimum"] == 4 for component in component_variants)
    assert all(component["properties"]["length"]["maximum"] == 12 for component in component_variants)
    assert {component["properties"]["alphabet"]["enum"][0] for component in component_variants} == {
        "digits", "alphanumeric",
    }


def test_view_ast_is_agent_composed_but_wire_contains_only_field_ids():
    request, _ = make_entry_request(ORIGIN, two_fields(), composed_view())
    assert request["view"] == {
        "schema": "secure-handoff.ui/1",
        "kind": "stack",
        "children": [
            {"kind": "text", "text": "Enter the values shown in your browser.", "tone": "muted"},
            {
                "kind": "section",
                "title": "Verification",
                "children": [
                    {
                        "kind": "row",
                        "children": [
                            {"kind": "field", "field": "f0"},
                            {"kind": "field", "field": "f1"},
                        ],
                    }
                ],
            },
            {"kind": "divider"},
        ],
    }
    encoded = json.dumps(request)
    assert FIELD_REF not in encoded
    assert ("fr_" + "B" * 32) not in encoded


@pytest.mark.parametrize(
    "view",
    [
        {"kind": "stack", "children": [{"kind": "field", "ref": FIELD_REF}]},
        {
            "schema": "secure-handoff.ui/2",
            "kind": "stack",
            "children": [
                {"kind": "field", "ref": FIELD_REF},
                {"kind": "field", "ref": "fr_" + "B" * 32},
            ],
        },
        {
            "schema": "secure-handoff.ui/1",
            "kind": "stack",
            "children": [
                {"kind": "field", "ref": FIELD_REF},
                {"kind": "field", "ref": FIELD_REF},
                {"kind": "field", "ref": "fr_" + "B" * 32},
            ],
        },
        {
            "schema": "secure-handoff.ui/1",
            "kind": "stack",
            "children": [
                {"kind": "field", "ref": FIELD_REF},
                {"kind": "field", "ref": "fr_" + "C" * 32},
            ],
        },
        {
            "schema": "secure-handoff.ui/1",
            "kind": "stack",
            "children": [
                {"kind": "html", "html": "<input>"},
                {"kind": "field", "ref": FIELD_REF},
                {"kind": "field", "ref": "fr_" + "B" * 32},
            ],
        },
        {
            "schema": "secure-handoff.ui/1",
            "kind": "stack",
            "children": [
                {"kind": "text", "text": "Copy here", "tone": "muted", "href": "https://example.test"},
                {"kind": "field", "ref": FIELD_REF},
                {"kind": "field", "ref": "fr_" + "B" * 32},
            ],
        },
    ],
)
def test_view_ast_rejects_missing_duplicate_unknown_or_executable_nodes(view):
    with pytest.raises(ValueError):
        make_entry_request(ORIGIN, two_fields(), view)


def test_visible_text_length_counts_unicode_code_points():
    label = "🔐" * 80
    request, _ = make_entry_request(ORIGIN, [segmented_field(label=label)])
    assert request["fields"][0]["label"] == label

    with pytest.raises(ValueError):
        make_entry_request(ORIGIN, [segmented_field(label="🔐" * 81)])


def test_view_ast_rejects_excessive_depth():
    node = {"kind": "field", "ref": FIELD_REF}
    for _ in range(7):
        node = {"kind": "stack", "children": [node]}
    node["schema"] = "secure-handoff.ui/1"
    with pytest.raises(ValueError):
        make_entry_request(ORIGIN, [segmented_field()], node)


def test_tool_schema_exposes_data_only_view_ast():
    view = SCHEMA["parameters"]["properties"]["view"]
    assert view["type"] == "object"
    assert "data-only" in view["description"]


def test_segmented_code_can_declare_bounded_character_fanout_without_wire_refs():
    extra = ["fr_" + character * 32 for character in "ABCDE"]
    raw = segmented_field(binding={"mode": "split_chars", "refs": extra})
    request, _ = make_entry_request(ORIGIN, [raw])
    assert request["fields"] == [{
        "id": "f0",
        "label": "Verification code",
        "type": "tel",
        "required": True,
        "strategy": "keyboard",
        "component": SEGMENTED,
    }]
    assert all(ref not in json.dumps(request) for ref in [FIELD_REF, *extra])


@pytest.mark.parametrize("binding", [
    {"mode": "split_chars", "refs": []},
    {"mode": "split_chars", "refs": ["fr_" + "A" * 32]},
    {"mode": "split_chars", "refs": ["fr_" + character * 32 for character in "ABCDEZ"]},
    {"mode": "split_chars", "refs": ["fr_" + "A" * 32] * 5},
    {"mode": "slices", "refs": ["fr_" + character * 32 for character in "ABCDE"]},
    {"mode": "split_chars", "refs": ["fr_" + character * 32 for character in "ABCDE"], "script": "alert(1)"},
])
def test_segmented_character_fanout_rejects_wrong_shape_count_duplicates_or_code(binding):
    with pytest.raises(ValueError):
        validate_entry_fields([segmented_field(binding=binding)])


@pytest.mark.parametrize("component", [
    {"kind": "segmented_code", "length": 0, "alphabet": "digits"},
    {"kind": "segmented_code", "length": 3, "alphabet": "digits"},
    {"kind": "segmented_code", "length": 13, "alphabet": "digits"},
    {"kind": "segmented_code", "length": 6, "alphabet": "unicode"},
    {"kind": "segmented_code", "length": 6, "alphabet": "digits", "html": "<b>x</b>"},
    {"kind": "script", "length": 6, "alphabet": "digits"},
])
def test_segmented_code_component_rejects_unbounded_or_executable_metadata(component):
    with pytest.raises(ValueError):
        validate_entry_fields([segmented_field(component=component)])


@pytest.mark.parametrize("field", [
    segmented_field(type=[]),
    segmented_field(strategy={}),
    segmented_field(component={"kind": "segmented_code", "length": 6, "alphabet": []}),
])
def test_malformed_nested_json_types_reject_as_protocol_errors(field):
    with pytest.raises(ValueError):
        validate_entry_fields([field])


@pytest.mark.parametrize("node", [
    {"kind": [], "children": [{"kind": "field", "ref": FIELD_REF}]},
    {"kind": "text", "text": "Safe text", "tone": []},
])
def test_malformed_view_node_types_reject_as_protocol_errors(node):
    view = {"schema": "secure-handoff.ui/1", "kind": "stack", "children": [node]}
    with pytest.raises(ValueError):
        make_entry_request(ORIGIN, [segmented_field()], view)


@pytest.mark.parametrize("overrides", [
    {"strategy": "fill"},
    {"required": False},
    {"type": "password"},
    {"type": "text", "component": {"kind": "segmented_code", "length": 6, "alphabet": "digits"}},
    {"type": "tel", "component": {"kind": "segmented_code", "length": 6, "alphabet": "alphanumeric"}},
])
def test_segmented_code_component_rejects_incoherent_binding_metadata(overrides):
    with pytest.raises(ValueError):
        validate_entry_fields([segmented_field(**overrides)])


@pytest.mark.parametrize("value", ["", "12345", "1234567", "12a456", "１２３４５６"])
def test_decrypt_rejects_invalid_segmented_digit_values(value):
    request, key = make_entry_request(ORIGIN, [segmented_field()])
    with pytest.raises(ValueError):
        decrypt_submission(envelope(request, key, {"f0": value}), request, key)


def test_decrypt_accepts_exact_segmented_value_and_returns_no_component_metadata():
    request, key = make_entry_request(ORIGIN, [segmented_field()])
    assert decrypt_submission(envelope(request, key, {"f0": "123456"}), request, key) == {"f0": "123456"}


@pytest.mark.parametrize("text", [
    "Paypa\u200bl security check",
    "Control\u0085separator",
    "Paypa\u3164l security check",
    "Filler\u115ftext",
    "Broken\ud800label",
    "Open https://example.test",
    "Continue at //evil.invalid",
    "Use tg://resolve?domain=example",
    "javascript:alert(1)",
])
def test_agent_authored_visible_text_rejects_invisible_or_uri_scheme_spoofing(text):
    with pytest.raises(ValueError):
        make_entry_request(ORIGIN, [segmented_field(label=text)])

    view = {
        "schema": "secure-handoff.ui/1",
        "kind": "stack",
        "children": [
            {"kind": "text", "text": text, "tone": "muted"},
            {"kind": "field", "ref": FIELD_REF},
        ],
    }
    with pytest.raises(ValueError):
        make_entry_request(ORIGIN, [segmented_field()], view)
