"""The pinned public-suffix snapshot and its refresh script stay consistent."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/refresh_public_suffix_snapshot.py"


def _module():
    spec = importlib.util.spec_from_file_location("refresh_public_suffix_snapshot", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_the_checked_in_snapshot_matches_its_pin() -> None:
    module = _module()
    assert module.check() == 0
    manifest = json.loads(module.MANIFEST.read_text(encoding="utf-8"))
    assert manifest["license"] == "MPL-2.0"
    assert manifest["source"] == "https://publicsuffix.org/list/public_suffix_list.dat"


def _list(body: str) -> bytes:
    return (
        "// This Source Code Form is subject to the terms of the Mozilla Public\n"
        "// VERSION: 2026-01-01_00-00-00_UTC\n"
        f"// COMMIT: {'a' * 40}\n"
        "// ===BEGIN ICANN DOMAINS===\n"
        f"{body}\n"
        "// ===END ICANN DOMAINS===\n"
        "// ===BEGIN PRIVATE DOMAINS===\n"
        "example-host.test\n"
        "// ===END PRIVATE DOMAINS===\n"
    ).encode()


def test_a_valid_list_is_described() -> None:
    manifest = _module().manifest_for(_list("test"))
    assert manifest["version"] == "2026-01-01_00-00-00_UTC"
    assert manifest["commit"] == "a" * 40
    assert len(manifest["sha256"]) == 64


@pytest.mark.parametrize(
    "data",
    [
        pytest.param(b"test\n", id="no-license-header"),
        pytest.param(_list("test").replace(b"// ===END PRIVATE DOMAINS===\n", b""), id="no-end-marker"),
        pytest.param(
            _list("test").replace(b"// ===BEGIN PRIVATE DOMAINS===\n", b""),
            id="no-private-section",
        ),
        pytest.param(
            _list("test")
            .replace(b"// ===END ICANN DOMAINS===\n", b"// ===SWAP===\n")
            .replace(b"// ===BEGIN PRIVATE DOMAINS===\n", b"// ===END ICANN DOMAINS===\n")
            .replace(b"// ===SWAP===\n", b"// ===BEGIN PRIVATE DOMAINS===\n"),
            id="markers-out-of-order",
        ),
        pytest.param(_list("test").replace(b"// COMMIT: " + b"a" * 40, b""), id="no-commit"),
        pytest.param(_list("test") + b"x" * (4 * 1024 * 1024), id="too-large"),
    ],
)
def test_anything_else_is_refused(data: bytes) -> None:
    with pytest.raises(ValueError):
        _module().manifest_for(data)


def test_a_changed_list_fails_the_check(tmp_path, monkeypatch) -> None:
    module = _module()
    (tmp_path / module.LIST_NAME).write_bytes(_list("test"))
    (tmp_path / "snapshot.v1.json").write_text(module.MANIFEST.read_text(encoding="utf-8"))
    monkeypatch.setattr(module, "SNAPSHOT_DIR", tmp_path)
    monkeypatch.setattr(module, "MANIFEST", tmp_path / "snapshot.v1.json")
    assert module.check() == 1
