"""Contribution schema validation for external Guard extensions."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.runtime.extension_contribution import (
    contribution_ids,
    load_contribution_payloads,
    validate_contribution,
)
from codex_plugin_scanner.guard.runtime.extension_trust import ids_for_class


def test_in_tree_contributions_match_external_trust_class() -> None:
    payloads = load_contribution_payloads()
    ids = {str(item["id"]) for item in payloads}
    assert ids == ids_for_class("external")
    assert contribution_ids() == ids_for_class("external")
    for payload in payloads:
        validate_contribution(payload, filename=str(payload["id"]))


def test_contribution_cannot_self_declare_trusted_library() -> None:
    payload = {
        "schemaVersion": "guard.extension-contribution.v1",
        "id": "command.noodle",
        "trustClass": "trusted-library",
        "activation": "opt-in",
        "icon": {"kind": "none"},
        "detector": {
            "kind": "python-module",
            "module": "codex_plugin_scanner.guard.runtime.command_noodle_extensions",
        },
    }
    with pytest.raises(ValueError, match="non-external"):
        validate_contribution(payload, filename="evil.json")


def test_contribution_rejects_unknown_icon_and_foreign_module(tmp_path: Path) -> None:
    payload = json.loads(
        (Path(__file__).resolve().parents[1] / "contributions/extensions/command.noodle.json").read_text(
            encoding="utf-8"
        )
    )
    payload["icon"] = {"kind": "react-icon", "name": "NotAnAllowlistedIcon"}
    with pytest.raises(ValueError, match="allowlisted"):
        validate_contribution(payload, filename="icon.json")
    payload["icon"] = {"kind": "none"}
    payload["detector"] = {"kind": "python-module", "module": "os.path"}
    with pytest.raises(ValueError, match="outside the runtime package"):
        validate_contribution(payload, filename="module.json")
