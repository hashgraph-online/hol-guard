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


def test_in_tree_contributions_match_reviewed_trust_classes() -> None:
    payloads = load_contribution_payloads()
    ids = {str(item["id"]) for item in payloads}
    assert ids == contribution_ids()
    expected = ids_for_class("external") | ids_for_class("first-party") | ids_for_class("trusted-library")
    assert contribution_ids() | mcp_catalog_ids() == expected
    for payload in payloads:
        validate_contribution(payload, filename=str(payload["id"]))


def test_contribution_cannot_self_declare_trusted_library() -> None:
    payload = _noodle_payload()
    payload["trustClass"] = "trusted-library"
    with pytest.raises(ValueError, match="trust class"):
        validate_contribution(payload, filename="evil.json")


def test_contribution_schema_rejects_missing_required_fields() -> None:
    payload = _noodle_payload()
    del payload["description"]
    with pytest.raises(ValueError, match="schema"):
        validate_contribution(payload, filename="missing.json")


def test_contribution_rejects_unknown_icon_and_unbound_native_source() -> None:
    payload = _noodle_payload()
    payload["icon"] = {"kind": "react-icon", "name": "NotAnAllowlistedIcon", "background": "#000000"}
    with pytest.raises(ValueError, match="allowlisted"):
        validate_contribution(payload, filename="icon.json")
    payload = _noodle_payload()
    payload["nativeSource"] = dict(payload["nativeSource"], path="contributions/command-sources/command.git.json")
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
        repo / "contracts" / "extensions" / "contribution.v2.schema.json",
        dest / "contribution.v2.schema.json",
    )
    shutil.copyfile(
        repo / "contracts" / "extensions" / "trust-class-map.v1.json",
        dest / "trust-class-map.v1.json",
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


def test_legacy_detector_descriptor_requires_explicit_conversion() -> None:
    payload = _noodle_payload()
    payload["schemaVersion"] = "guard.extension-contribution.v1"
    with pytest.raises(ValueError, match="convert it to a command source"):
        validate_contribution(payload, filename="legacy.json")
