from __future__ import annotations

import json
from dataclasses import FrozenInstanceError
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.runtime.generated_command_catalog_loader import (
    GeneratedCommandCatalogError,
    load_generated_command_catalog_bytes,
)

ROOT = Path(__file__).resolve().parents[1]
CATALOG = ROOT / "contracts/extensions/command-catalog.v1.json"
PROGRAM = ROOT / "contracts/extensions/native-command-program.v1.json"


def _load():
    return load_generated_command_catalog_bytes(CATALOG.read_bytes(), PROGRAM.read_bytes())


def test_generated_catalog_is_immutable_metadata_bound_to_native_program() -> None:
    catalog = _load()

    assert len(catalog.extensions) == 73
    assert len(catalog.permissions) == 254
    assert catalog.get("command.api-gateway").name == "API gateway command protection"
    rule = catalog.get_rule("command.api-gateway.delete")
    assert rule is not None
    assert not hasattr(rule, "matcher")
    assert catalog.permission_for_rule_id(rule.rule_id).extension_id == "command.api-gateway"
    assert catalog.get("command.mcp-filesystem").surface == "mcp"
    with pytest.raises(FrozenInstanceError):
        rule.title = "changed"  # type: ignore[misc]


def test_generated_catalog_rejects_unbound_provenance() -> None:
    envelope = json.loads(CATALOG.read_bytes())
    envelope["source_digest"] = "0" * 64

    with pytest.raises(GeneratedCommandCatalogError, match="provenance_mismatch"):
        load_generated_command_catalog_bytes(
            json.dumps(envelope, sort_keys=True, separators=(",", ":")).encode(),
            PROGRAM.read_bytes(),
        )


def test_generated_catalog_retains_native_executable_ownership() -> None:
    catalog = _load()

    assert {"git", "gh", "docker", "kubectl", "npm"} <= catalog.owned_executables
    assert "cwv.py" not in catalog.owned_executables
    assert isinstance(catalog.owned_executables, frozenset)


def test_generated_catalog_rejects_catalog_or_program_substitution() -> None:
    envelope = json.loads(CATALOG.read_bytes())
    envelope["catalog"][0]["name"] = "substituted"
    changed_catalog = json.dumps(envelope, sort_keys=True, separators=(",", ":")).encode()
    with pytest.raises(GeneratedCommandCatalogError, match="digest_mismatch"):
        load_generated_command_catalog_bytes(changed_catalog, PROGRAM.read_bytes())

    envelope = json.loads(CATALOG.read_bytes())
    envelope["program_digest"] = "0" * 64
    changed_binding = json.dumps(envelope, sort_keys=True, separators=(",", ":")).encode()
    with pytest.raises(GeneratedCommandCatalogError, match="program_mismatch"):
        load_generated_command_catalog_bytes(changed_binding, PROGRAM.read_bytes())
