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
    assert "setuptools>=84.1.0" in overrides
    # filelock 4.2.1 is the first patched release and requires Python 3.11.
    # 3.20.3 is the last release before the vulnerable range that still
    # installs on Python 3.10, which this project still supports.
    assert "filelock==3.20.3; python_version < '3.11'" in overrides
    assert "filelock>=4.2.1; python_version >= '3.11'" in overrides
    locked = _locked_versions("uv.lock")
    docker = (ROOT / "docker-requirements.txt").read_text(encoding="utf-8")
    for name, floor in (
        ("mcp", "1.30.0"),
        ("pyjwt", "2.15.0"),
        ("multidict", "6.9.1"),
        ("setuptools", "84.1.0"),
    ):
        assert locked[name], name
        assert all(Version(version) >= Version(floor) for version in locked[name]), name
        if name == "setuptools":
            continue
        # The container installs these exact pins with --no-deps, so the
        # manifest floor alone does not keep the published image patched.
        pinned = _requirement_pins(docker, name)
        assert pinned, name
        assert all(Version(version) >= Version(floor) for version in pinned), name
    _assert_filelock_split(locked)


def test_rust_vulnerability_floors_are_locked() -> None:
    workspace = _toml("rust/Cargo.toml")
    assert workspace["workspace"]["dependencies"]["ruzstd"]["version"] == "=0.9.1"
    locked = _locked_versions("rust/Cargo.lock")
    for name, floor in (
        ("rustls", "0.23.46"),
        ("rustls-webpki", "0.103.16"),
        ("ruzstd", "0.9.1"),
        ("webpki-roots", "1.0.10"),
    ):
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


def test_action_runtime_pins_match_python_floors() -> None:
    floors = {
        "action/scanner-runtime-requirements.txt": {"mcp": "1.30.0", "pyjwt": "2.15.0"},
        "action/scanner-cisco-runtime-requirements.txt": {
            "filelock": "4.2.1",
            "mcp": "1.30.0",
            "multidict": "6.9.1",
            "pyjwt": "2.15.0",
        },
        "action/pypi-attestations-requirements.txt": {"pyjwt": "2.15.0"},
        "docker-requirements.txt": {"filelock": "4.2.1"},
    }
    for path, packages in floors.items():
        text = (ROOT / path).read_text(encoding="utf-8")
        for name, floor in packages.items():
            pinned = _requirement_pins(text, name)
            assert pinned, f"{path} {name}"
            assert all(Version(version) >= Version(floor) for version in pinned), f"{path} {name}"


def test_node_vulnerability_floors_are_locked() -> None:
    containment = json.loads(
        (ROOT / ".github/tools/containment-ci/package.json").read_text(encoding="utf-8")
    )
    assert containment["devDependencies"]["vitest"] == "4.1.12"
    assert containment["overrides"] == {
        "@vitest/mocker": "4.1.12",
        "source-map-js": "1.2.2",
        "vite": "8.3.3",
    }
    for name, floor in (
        ("@vitest/mocker", "4.1.12"),
        ("source-map-js", "1.2.2"),
        ("vite", "8.3.3"),
        ("vitest", "4.1.12"),
    ):
        versions = _npm_versions(".github/tools/containment-ci/package-lock.json", name)
        assert versions, name
        assert all(Version(version) >= Version(floor) for version in versions), name

    pi = json.loads((ROOT / "ci/pi-exact-continuation/package.json").read_text(encoding="utf-8"))
    assert pi["overrides"]["undici"] == "8.12.3"
    undici = _npm_versions("ci/pi-exact-continuation/package-lock.json", "undici")
    assert undici, "undici"
    assert all(Version(version) >= Version("8.12.3") for version in undici)
    assert pi["overrides"]["zod"] == "4.6.6"
    zod = _npm_versions("ci/pi-exact-continuation/package-lock.json", "zod")
    assert zod, "zod"
    assert all(Version(version) >= Version("4.6.6") for version in zod)


def _requirement_pins(text: str, name: str) -> list[str]:
    return re.findall(rf"^{re.escape(name)}==(\S+?)(?:\s|;|$)", text, flags=re.MULTILINE)


def _assert_filelock_split(locked: dict[str, list[str]]) -> None:
    packages = [package for package in _toml("uv.lock")["package"] if package["name"] == "filelock"]
    assert {package["version"] for package in packages} == set(locked["filelock"])
    saw_legacy = False
    saw_patched = False
    for package in packages:
        version = Version(package["version"])
        markers = package.get("resolution-markers") or []
        assert markers, package["version"]
        if version < Version("4.2.1"):
            assert version == Version("3.20.3")
            assert all(marker.startswith("python_full_version < '3.11'") for marker in markers)
            saw_legacy = True
        else:
            assert all(not marker.startswith("python_full_version < '3.11'") for marker in markers)
            saw_patched = True
    assert saw_legacy and saw_patched


def _npm_versions(path: str, name: str) -> list[str]:
    lock = json.loads((ROOT / path).read_text(encoding="utf-8"))
    suffix = f"node_modules/{name}"
    return [
        meta["version"]
        for key, meta in lock["packages"].items()
        if key == suffix or key.endswith(f"/{suffix}")
    ]
