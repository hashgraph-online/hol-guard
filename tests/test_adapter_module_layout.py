"""Keep adapter helpers discoverable to Python, static analysis, and freezers."""

from __future__ import annotations

from fnmatch import fnmatchcase
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import native_harness_ops as harness_ops
from codex_plugin_scanner.guard.setup_contract_registry import harness_contracts
from scripts.ci.hook_data_plane_ownership_contract import load_manifest

ROOT = Path(__file__).resolve().parents[1]
GUARD = ROOT / "src/codex_plugin_scanner/guard"
HARNESS_MODULES = (
    "native_harness_client.py",
    "native_harness_ops.py",
    "native_codex_ops.py",
    "native_harness_install_ops.py",
    "harness_context.py",
    "bounded_cli_hook_bridge.py",
    "bounded_cli_hook_native.py",
)


def test_harness_ops_lists_every_contract_harness_and_alias() -> None:
    assert set(harness_ops.list_harnesses()) == {contract.harness for contract in harness_contracts()}
    for harness in harness_ops.list_harnesses():
        assert harness_ops.canonical_harness(harness) == harness
        for alias in harness_ops.aliases_of(harness):
            assert harness_ops.canonical_harness(alias) == harness


def test_adapter_sources_remain_in_native_ownership_contract(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(ROOT)
    manifest = load_manifest(ROOT / "docs/guard/contracts/hook-data-plane-ownership.v2.json")
    owner_globs = [pattern for node in manifest["nodes"] for pattern in node.get("paths", [])]
    protected_globs = manifest["protected_change_globs"]
    for module_name in HARNESS_MODULES:
        relative = (GUARD / module_name).relative_to(ROOT).as_posix()
        assert any(fnmatchcase(relative, pattern) for pattern in owner_globs), relative
        assert any(fnmatchcase(relative, pattern) for pattern in protected_globs), relative


def test_native_harness_registry_matches_the_runtime_description() -> None:
    from codex_plugin_scanner.guard.native_harness_client import NATIVE_HARNESSES, describe

    described = {entry["harness"]: entry for entry in describe()["adapters"]}
    assert list(described) == [harness for harness, _aliases, _launcher in NATIVE_HARNESSES]
    for harness, aliases, launcher_name in NATIVE_HARNESSES:
        entry = described[harness]
        assert tuple(entry["aliases"]) == aliases
        assert entry["launcher_name"] == launcher_name
        assert entry["executable"] == (launcher_name or harness)
