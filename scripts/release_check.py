#!/usr/bin/env python3
"""Fail-closed checks for source and built release artifacts."""

from __future__ import annotations

import json
import sys
import tarfile
import tomllib
import zipfile
from pathlib import Path
from typing import NoReturn

ROOT = Path(__file__).resolve().parents[1]
DIST = ROOT / "dist"
VERSION = "1.1.0"
REQUIRED_SDIST = {
    "plugin.yaml",
    "LICENSE",
    "README.md",
    "SECURITY.md",
    "web/index.html",
    "web/app.js",
    "web/styles.css",
    "web/vercel.json",
    "SECURE_HANDOFF_CONTRACT.md",
    "SECURE_HANDOFF_PROTOCOL.md",
}
FORBIDDEN_MARKERS = (".vercel/", ".env", "secure_handoff_receipts", "CURRENT.md", "_REPORT.md")
FORBIDDEN_FRONTEND_MARKERS = (
    "fetch(",
    "XMLHttpRequest",
    "localStorage",
    "sessionStorage",
    "document.cookie",
    "sendBeacon",
    "stripe",
    "vercel",
    "slack",
)


def fail(message: str) -> NoReturn:
    raise SystemExit(f"release check failed: {message}")


def archive_names(path: Path) -> set[str]:
    if path.suffix == ".whl":
        with zipfile.ZipFile(path) as archive:
            return set(archive.namelist())
    if path.name.endswith(".tar.gz"):
        with tarfile.open(path, "r:gz") as archive:
            prefix = f"{path.name[:-7]}/"
            return {name[len(prefix):] for name in archive.getnames() if name.startswith(prefix)}
    fail(f"unsupported artifact {path.name}")


def main() -> int:
    metadata = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    project = metadata["project"]
    if project["version"] != VERSION:
        fail("pyproject version drift")
    if project["name"] != "hermes-telegram-secure-handoff":
        fail("package identity drift")
    if json.loads((ROOT / "package.json").read_text(encoding="utf-8"))["version"] != VERSION:
        fail("package.json version drift")
    if f'"version": "{VERSION}"' not in (ROOT / "package-lock.json").read_text(encoding="utf-8"):
        fail("package-lock version drift")
    if (ROOT / "plugin.yaml").read_text(encoding="utf-8") != (ROOT / "plugin" / "plugin.yaml").read_text(encoding="utf-8"):
        fail("directory and package manifests differ")
    manifest = (ROOT / "plugin.yaml").read_text(encoding="utf-8")
    if "manifest_version: 1" not in manifest or "name: telegram-secure-handoff" not in manifest:
        fail("manifest identity/compatibility drift")
    frontend = (ROOT / "web" / "app.js").read_text(encoding="utf-8").lower()
    for marker in FORBIDDEN_FRONTEND_MARKERS:
        if marker.lower() in frontend:
            fail(f"forbidden frontend marker: {marker}")
    wheels = sorted(DIST.glob("*.whl"))
    sdists = sorted(DIST.glob("*.tar.gz"))
    if len(wheels) != 1 or len(sdists) != 1:
        fail("build exactly one wheel and one sdist before checking")
    wheel_names = archive_names(wheels[0])
    if "hermes_telegram_secure_handoff/plugin.yaml" not in wheel_names:
        fail("wheel is missing packaged plugin manifest")
    entry_points = next((name for name in wheel_names if name.endswith(".dist-info/entry_points.txt")), None)
    if entry_points is None:
        fail("wheel is missing entry-point metadata")
    assert entry_points is not None
    with zipfile.ZipFile(wheels[0]) as archive:
        entry_text = archive.read(entry_points).decode("utf-8")
    if "hermes_agent.plugins" not in entry_text or "telegram-secure-handoff = hermes_telegram_secure_handoff:register" not in entry_text:
        fail("wheel entry point drift")
    sdist_names = archive_names(sdists[0])
    if not REQUIRED_SDIST <= sdist_names:
        fail(f"sdist missing {sorted(REQUIRED_SDIST - sdist_names)}")
    all_names = wheel_names | sdist_names
    bad = sorted(name for name in all_names if any(marker in name for marker in FORBIDDEN_MARKERS))
    if bad:
        fail(f"forbidden local artifacts in release: {bad}")
    print(f"release artifacts: PASS ({wheels[0].name}, {sdists[0].name})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
