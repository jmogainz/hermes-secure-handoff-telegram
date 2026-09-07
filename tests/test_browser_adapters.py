from plugin.browser_adapters import adapter_for_origin


def test_standard_adapter_classifies_common_login_controls():
    adapter = adapter_for_origin("https://example.test")

    assert adapter.name == "generic"
    assert adapter.classify_input({"type": "text", "name": "username", "autocomplete": "username", "aria": ""}) == "text"
    assert adapter.classify_input({"type": "password", "name": "", "autocomplete": "current-password", "aria": ""}) == "password"
    assert adapter.classify_input({"type": "text", "name": "code", "autocomplete": "one-time-code", "aria": ""}) == "otp"
    assert adapter.classify_input({"type": "text", "name": "", "autocomplete": "", "aria": "digit 1 of 6"}) == "otp"
    assert adapter.classify_input({"type": "text", "name": "", "autocomplete": "", "aria": "digit 6 of 6", "inputmode": "numeric", "maxlength": "1"}) == "otp"


def test_google_adapter_isolatedly_describes_formless_code_controls():
    adapter = adapter_for_origin("https://accounts.google.com")

    assert adapter.name == "google"
    assert adapter.allow_formless is True
    assert adapter.classify_input({"type": "tel", "name": "Pin", "autocomplete": "off", "aria": "Enter code"}) == "otp"
    assert adapter.submit_labels == ("Next",)
    assert adapter.stage_for(("otp",)).id == "google_verification_code"
