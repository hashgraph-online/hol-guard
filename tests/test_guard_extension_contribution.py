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
_MASTER_OF = Path(__file__).resolve().parents[1] / "contributions/command-sources/command.master-of.json"


def _noodle_payload() -> dict[str, object]:
    payload = json.loads(_NOODLE.read_text(encoding="utf-8"))
    assert isinstance(payload, dict)
    return payload


def _master_of_source() -> dict[str, object]:
    payload = json.loads(_MASTER_OF.read_text(encoding="utf-8"))
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


def _rule_by_id(rules: list[dict[str, object]], rule_id: str) -> dict[str, object]:
    for entry in rules:
        if entry["rule_id"] == rule_id:
            return entry
    raise AssertionError(f"missing rule {rule_id}")


def _matcher_subcommand_paths(matcher: dict[str, object]) -> set[tuple[str, ...]]:
    """Flatten an executable.v1/any.v1 matcher tree into its subcommand tuples."""

    paths: set[tuple[str, ...]] = set()
    op = matcher.get("op")
    if op == "executable.v1":
        config = matcher["config"]
        assert isinstance(config, dict)
        subcommands = config.get("subcommands", [])
        assert isinstance(subcommands, list)
        paths.add(tuple(subcommands))
    elif op == "any.v1":
        matchers = matcher.get("matchers", [])
        assert isinstance(matchers, list)
        for child in matchers:
            paths |= _matcher_subcommand_paths(child)
    else:
        raise AssertionError(f"unexpected matcher op {op!r}")
    return paths


def test_master_of_bulk_mutations_default_to_review() -> None:
    """park --all, classify --all, agy-setup, and cowork on/off default to review."""

    source = _master_of_source()["extension"]
    assert isinstance(source, dict)
    rules = source["rules"]
    permissions = source["permissions"]
    assert isinstance(rules, list)
    assert isinstance(permissions, list)

    destructive = {
        "command.master-of.bulk-park": {("park",)},
        "command.master-of.bulk-classify": {("classify",)},
        "command.master-of.agy-setup": {("agy-setup",)},
        "command.master-of.cowork-toggle": {("cowork", "on"), ("cowork", "off")},
    }
    for rule_id, expected_paths in destructive.items():
        rule = _rule_by_id(rules, rule_id)
        assert rule["default_mode"] == "review"
        assert rule["severity"] == "high"
        matcher = rule["matcher"]
        assert isinstance(matcher, dict)
        assert _matcher_subcommand_paths(matcher) == expected_paths

        permission_id = rule["permission_id"]
        permission = next(p for p in permissions if p["permission_id"] == permission_id)
        assert permission["baseline_floor"] == "review"
        assert permission["default_enabled"] is True


def test_master_of_inspection_commands_are_never_matched() -> None:
    """doctor and the status/check/full/search family stay unmatched by every rule."""

    source = _master_of_source()["extension"]
    assert isinstance(source, dict)
    rules = source["rules"]
    assert isinstance(rules, list)

    safe_first_tokens = {"doctor", "status", "check", "full", "search", "gate", "unclassified", "unparked"}
    matched_first_tokens: set[str] = set()
    for rule in rules:
        matcher = rule["matcher"]
        assert isinstance(matcher, dict)
        for path in _matcher_subcommand_paths(matcher):
            if path:
                matched_first_tokens.add(path[0])
        for variant in rule["safe_variants"]:
            for path in _matcher_subcommand_paths(variant["matcher"]):
                if path:
                    matched_first_tokens.add(path[0])

    assert matched_first_tokens.isdisjoint(safe_first_tokens)


def test_master_of_bulk_park_ignores_scoped_single_skill_invocation() -> None:
    """`mo park <name>` without --all does not satisfy the bulk-park matcher."""

    source = _master_of_source()["extension"]
    assert isinstance(source, dict)
    rule = _rule_by_id(source["rules"], "command.master-of.bulk-park")
    matcher = rule["matcher"]
    assert isinstance(matcher, dict)
    config = matcher["config"]
    assert isinstance(config, dict)
    assert config["required_flags"] == ["--all"]
    assert config["subcommands"] == ["park"]
