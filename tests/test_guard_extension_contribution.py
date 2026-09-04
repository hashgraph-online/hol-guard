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

_NOODLE = Path(__file__).resolve().parents[1] / "contributions/extensions/command.noodle.json"


def _noodle_payload() -> dict[str, object]:
    payload = json.loads(_NOODLE.read_text(encoding="utf-8"))
    assert isinstance(payload, dict)
    return payload


def test_in_tree_contributions_match_external_trust_class() -> None:
    payloads = load_contribution_payloads()
    ids = {str(item["id"]) for item in payloads}
    assert ids == ids_for_class("external")
    assert contribution_ids() == ids_for_class("external")
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
