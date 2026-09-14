"""Secret-free static hosting and release metadata regressions."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_transport_only_release_versions_are_coherent():
    import tomllib
    import yaml
    from plugin import __version__
    from scripts.release_check import VERSION
    expected = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]["version"]
    assert isinstance(expected, str) and expected.strip()
    assert __version__ == expected
    assert VERSION == expected
    assert json.loads((ROOT / "package.json").read_text())["version"] == expected
    lock = json.loads((ROOT / "package-lock.json").read_text())
    assert lock["version"] == lock["packages"][""]["version"] == expected
    for path in ("plugin.yaml", "plugin/plugin.yaml"):
        assert yaml.safe_load((ROOT / path).read_text())["version"] == expected


def test_sensitive_entry_host_has_defense_in_depth_headers():
    config = json.loads((ROOT / "web/vercel.json").read_text())
    headers = {h["key"].lower(): h["value"] for entry in config["headers"]
               if entry["source"] == "/(.*)" for h in entry["headers"]}
    assert headers.get("referrer-policy") == "no-referrer"
    assert headers.get("x-content-type-options") == "nosniff"
    assert headers.get("cache-control") == "no-store"
    assert headers.get("x-frame-options") == "DENY"
    assert "max-age=31536000" in headers.get("strict-transport-security", "")
    assert headers.get("permissions-policy") == "camera=(), microphone=(), geolocation=(), payment=(), usb=()"
    csp = headers["content-security-policy"]
    for directive in ("connect-src 'none'", "form-action 'none'", "object-src 'none'", "base-uri 'none'", "frame-ancestors 'none'"):
        assert directive in csp


def test_compact_frontend_and_real_sdk_checks_run_in_ci():
    package = json.loads((ROOT / "package.json").read_text())
    assert package["scripts"]["test"] == "npm run test:frontend"
    assert package["scripts"]["test:frontend"] == "node tests/frontend.test.mjs"
    workflow = (ROOT / ".github/workflows/ci.yml").read_text()
    assert "npm run test:qa-real-sdk" in workflow
