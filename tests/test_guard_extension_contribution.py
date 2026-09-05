"""Contribution schema validation for external Guard extensions."""

from __future__ import annotations

import json
import shutil
import sys
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.runtime import extension_contribution as contribution_module
from codex_plugin_scanner.guard.runtime.extension_contribution import (
    contribution_ids,
    load_contribution_payloads,
    validate_contribution,
)
from codex_plugin_scanner.guard.runtime.extension_trust import ids_for_class
from codex_plugin_scanner.guard.runtime.mcp_server_contribution import mcp_catalog_ids

_NOODLE = Path(__file__).resolve().parents[1] / "contributions/extensions/command.noodle.json"


def _noodle_payload() -> dict[str, object]:
    payload = json.loads(_NOODLE.read_text(encoding="utf-8"))
    assert isinstance(payload, dict)
    return payload


def test_in_tree_contributions_match_external_trust_class() -> None:
    payloads = load_contribution_payloads()
    ids = {str(item["id"]) for item in payloads}
    assert ids == contribution_ids()
    assert contribution_ids() | mcp_catalog_ids() == ids_for_class("external")
    for payload in payloads:
        validate_contribution(payload, filename=str(payload["id"]))


def test_contribution_cannot_self_declare_trusted_library() -> None:
    payload = _noodle_payload()
    payload["trustClass"] = "trusted-library"
    with pytest.raises(ValueError, match="schema"):
        validate_contribution(payload, filename="evil.json")


def test_contribution_schema_rejects_missing_required_fields() -> None:
    payload = _noodle_payload()
    del payload["description"]
    with pytest.raises(ValueError, match="schema"):
        validate_contribution(payload, filename="missing.json")


def test_contribution_rejects_unknown_icon_and_unbound_detector() -> None:
    payload = _noodle_payload()
    payload["icon"] = {"kind": "react-icon", "name": "NotAnAllowlistedIcon"}
    with pytest.raises(ValueError, match="allowlisted"):
        validate_contribution(payload, filename="icon.json")
    payload = _noodle_payload()
    payload["detector"] = {"kind": "python-module", "module": "os.path"}
    with pytest.raises(ValueError, match="schema"):
        validate_contribution(payload, filename="module.json")
    payload = _noodle_payload()
    payload["detector"] = {
        "kind": "python-module",
        "module": "codex_plugin_scanner.guard.runtime.command_git_extensions",
    }
    with pytest.raises(ValueError, match="not bound"):
        validate_contribution(payload, filename="bind.json")


def test_frozen_packaged_payloads_load_from_meipass(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    repo = Path(__file__).resolve().parents[1]
    dest = tmp_path / "codex_plugin_scanner" / "guard" / "contracts" / "data" / "extensions"
    contributions = dest / "contributions"
    contributions.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(
        repo / "contributions" / "extensions" / "command.noodle.json", contributions / "command.noodle.json"
    )
    shutil.copyfile(
        repo / "contracts" / "extensions" / "contribution.v1.schema.json",
        dest / "contribution.v1.schema.json",
    )
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(sys, "_MEIPASS", str(tmp_path), raising=False)

    def missing_package(_name: str) -> object:
        raise ModuleNotFoundError("missing packaged extensions")

    monkeypatch.setattr(contribution_module.resources, "files", missing_package)
    contribution_module.reset_contribution_cache()
    try:
        payloads = contribution_module._load_packaged_payloads()
        assert any(item.get("id") == "command.noodle" for item in payloads)
    finally:
        contribution_module.reset_contribution_cache()


def test_frozen_packaged_payloads_fail_closed_without_package_data(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(sys, "_MEIPASS", str(tmp_path), raising=False)

    def missing_package(_name: str) -> object:
        raise ModuleNotFoundError("missing packaged extensions")

    monkeypatch.setattr(contribution_module.resources, "files", missing_package)
    with pytest.raises(FileNotFoundError, match="contributions"):
        contribution_module._load_packaged_payloads()


def test_frozen_bind_detector_accepts_importable_module_without_source(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(
        contribution_module,
        "_detector_source_path",
        lambda _leaf: tmp_path / "missing.py",
    )
    contribution_module._bind_detector(
        "command.noodle",
        "codex_plugin_scanner.guard.runtime.command_noodle_extensions",
        "command.noodle.json",
    )


def test_frozen_bind_detector_fails_when_module_is_missing(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(
        contribution_module,
        "_detector_source_path",
        lambda _leaf: tmp_path / "missing.py",
    )
    monkeypatch.setattr(contribution_module.importlib.util, "find_spec", lambda _name: None)
    with pytest.raises(ValueError, match="missing"):
        contribution_module._bind_detector(
            "command.noodle",
            "codex_plugin_scanner.guard.runtime.command_noodle_extensions",
            "command.noodle.json",
        )
