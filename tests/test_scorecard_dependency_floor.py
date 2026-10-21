"""Keep patched dependency floors aligned across source and generated locks.

These floors correspond to published advisories in the October 2026
OpenSSF Scorecard report. When dependencies are upgraded, lockfiles
must be updated together rather than only changing the manifest.
"""

from __future__ import annotations

import json
import re
import sys
from collections import defaultdict
from pathlib import Path

from packaging.version import Version

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib


ROOT = Path(__file__).resolve().parents[1]


def _toml(path: str) -> dict:
    return tomllib.loads((ROOT / path).read_text(encoding="utf-8"))


def _locked_versions(path: str) -> dict[str, list[str]]:
    """Collect every locked version, because a lock may carry more than one."""
    versions: dict[str, list[str]] = defaultdict(list)
    for package in _toml(path)["package"]:
        versions[package["name"]].append(package["version"])
    return versions


def test_python_vulnerability_floors_are_locked() -> None:
    project = _toml("pyproject.toml")
    assert any(dep.startswith("mcp>=1.30.0,<2;") for dep in project["project"]["dependencies"])
    overrides = project["tool"]["uv"]["override-dependencies"]
    assert "pyjwt==2.15.0" in overrides
    assert "multidict>=6.9.1" in overrides
    locked = _locked_versions("uv.lock")
    docker = (ROOT / "docker-requirements.txt").read_text(encoding="utf-8")
    for name, floor in (("mcp", "1.30.0"), ("pyjwt", "2.15.0"), ("multidict", "6.9.1")):
        assert locked[name], name
        assert all(Version(version) >= Version(floor) for version in locked[name]), name
        # The container installs these exact pins with --no-deps, so the
        # manifest floor alone does not keep the published image patched.
        pinned = re.findall(rf"^{re.escape(name)}==(\S+?) ", docker, flags=re.MULTILINE)
        assert pinned, name
        assert all(Version(version) >= Version(floor) for version in pinned), name


def test_rust_vulnerability_floors_are_locked() -> None:
    workspace = _toml("rust/Cargo.toml")
    assert workspace["workspace"]["dependencies"]["ruzstd"]["version"] == "=0.9.1"
    locked = _locked_versions("rust/Cargo.lock")
    for name, floor in (("rustls", "0.23.46"), ("ruzstd", "0.9.1"), ("webpki-roots", "1.0.10")):
        assert locked[name], name
        assert all(Version(version) >= Version(floor) for version in locked[name]), name


def test_dashboard_vite_fix_is_consistent_across_locks() -> None:
    package = json.loads((ROOT / "dashboard/package.json").read_text(encoding="utf-8"))
    lock = json.loads((ROOT / "dashboard/package-lock.json").read_text(encoding="utf-8"))
    assert package["devDependencies"]["vite"] == "^7.3.7"
    assert lock["packages"][""]["devDependencies"]["vite"] == "^7.3.7"
    assert Version(lock["packages"]["node_modules/vite"]["version"]) >= Version("7.3.7")
    for lock_path in ("dashboard/pnpm-lock.yaml", "dashboard/bun.lock"):
        text = (ROOT / lock_path).read_text(encoding="utf-8")
        # Anchor on the bare package so scoped names such as
        # "@tailwindcss/vite" never stand in for the Vite pin itself.
        resolved = set(re.findall(r"(?<![\w/@.-])vite@(\d+\.\d+\.\d+)", text))
        assert resolved, lock_path
        assert all(Version(version) >= Version("7.3.7") for version in resolved), lock_path
