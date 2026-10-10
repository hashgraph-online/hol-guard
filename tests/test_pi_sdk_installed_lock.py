from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest


def _verifier():
    path = Path(__file__).resolve().parents[1] / "scripts" / "ci" / "verify_pi_exact_continuation.py"
    spec = importlib.util.spec_from_file_location("pi_sdk_lock_verifier", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize("locked", ["5.0.9", "5.0.10", "5.0.11"])
def test_installed_shrinkwrap_must_match_reviewed_lock(tmp_path: Path, locked: str) -> None:
    name = "node_modules/@earendil-works/pi-coding-agent/node_modules/brace-expansion"
    root = tmp_path / name
    root.mkdir(parents=True)
    (root / "package.json").write_text(json.dumps({"version": "5.0.9"}), encoding="utf-8")
    lock = tmp_path / "package-lock.json"
    lock.write_text(json.dumps({"packages": {name: {"version": locked}}}), encoding="utf-8")
    verifier = _verifier()
    if locked == "5.0.9":
        verifier.verify_installed_lock(tmp_path, lock)
    else:
        with pytest.raises(SystemExit, match="installed dependency differs"):
            verifier.verify_installed_lock(tmp_path, lock)


def test_installed_lock_rejects_paths_outside_fixture(tmp_path: Path) -> None:
    lock = tmp_path / "package-lock.json"
    lock.write_text(json.dumps({"packages": {"../outside": {"version": "1"}}}), encoding="utf-8")
    with pytest.raises(SystemExit, match="invalid installed package path"):
        _verifier().verify_installed_lock(tmp_path, lock)
