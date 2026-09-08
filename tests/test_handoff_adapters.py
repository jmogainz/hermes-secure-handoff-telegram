from plugin.handoff_adapters import adapter_for_origin


def test_standard_adapter_classifies_common_login_controls():
    adapter = adapter_for_origin("https://example.test")

    assert adapter.name == "generic"
    assert adapter.classify_input({"type": "text", "name": "username", "autocomplete": "username", "aria": ""}) == "text"
    assert adapter.classify_input({"type": "email", "name": "email", "autocomplete": "username"}) == "email"
    assert adapter.classify_input({"type": "password", "name": "", "autocomplete": "current-password", "aria": ""}) == "password"
    assert adapter.classify_input({"type": "text", "name": "code", "autocomplete": "one-time-code", "aria": ""}) == "otp"
    assert adapter.classify_input({"type": "text", "name": "", "autocomplete": "", "aria": "digit 1 of 6"}) == "otp"
    assert adapter.classify_input({"type": "text", "name": "", "autocomplete": "", "aria": "digit 6 of 6", "inputmode": "numeric", "maxlength": "1"}) == "otp"


def test_generic_adapter_describes_formless_code_controls():
    adapter = adapter_for_origin("https://checkout.example")

    assert adapter.name == "generic"
    assert adapter.allow_formless is False
    assert adapter.classify_input({"type": "tel", "name": "pin", "autocomplete": "off", "aria": "Enter code"}) == "otp"
    assert "Next" in adapter.submit_labels
    assert adapter.stage_for(("otp",)).id == "one_time_code"


def test_generic_adapter_classifies_checkout_fields_without_site_specific_rules():
    adapter = adapter_for_origin("https://checkout.example")

    assert adapter.classify_input({"type": "text", "name": "cardNumber", "autocomplete": "cc-number", "aria": ""}) == "card_number"
    assert adapter.classify_input({"type": "text", "name": "expiry", "autocomplete": "cc-exp", "aria": ""}) == "card_expiry"
    assert adapter.classify_input({"type": "text", "name": "cvc", "autocomplete": "cc-csc", "aria": ""}) == "cvc"
    assert adapter.classify_input({"type": "email", "name": "billingEmail", "autocomplete": "email", "aria": ""}) == "email"
    assert adapter.classify_input({"type": "tel", "name": "phone", "autocomplete": "tel", "aria": ""}) == "tel"
    assert adapter.classify_input({"type": "text", "name": "firstName", "autocomplete": "given-name", "aria": ""}) == "text"
    assert adapter.stage_for(("text", "card_number", "card_expiry", "cvc"), checkout=True).id == "checkout_details"
