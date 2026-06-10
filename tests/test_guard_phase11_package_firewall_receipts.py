"""Phase 11 package firewall receipt proofs (SCSR181-183)."""

from __future__ import annotations

import os
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from codex_plugin_scanner.guard.local_supply_chain import audit_receipt_metadata
from codex_plugin_scanner.guard.package_firewall_receipts import package_firewall_receipt_metadata
from codex_plugin_scanner.guard.shims import install_package_shims, probe_package_shim_intercepts
from codex_plugin_scanner.guard.shim_probe import protect_evaluator_evidence
from codex_plugin_scanner.guard.stable_digest import stable_digest_hex
from tests.shim_execution_helpers import write_fake_manager_script


def _harness_context(tmp_path: Path) -> MagicMock:
    home_dir = tmp_path / "home"
    home_dir.mkdir(parents=True, exist_ok=True)
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir(parents=True, exist_ok=True)
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir(parents=True, exist_ok=True)
    context = MagicMock()
    context.home_dir = home_dir
    context.workspace_dir = workspace_dir
    context.guard_home = guard_home
    return context


def test_protect_evaluator_evidence_includes_evaluator_source() -> None:
    evidence = protect_evaluator_evidence(
        {
            "supply_chain_evaluation": {"source": "guard-cloud", "evidence_ids": ["ev-1"]},
            "verdict": {"action": "allow"},
        },
    )
    assert evidence["evaluator_source"] == "guard-cloud"


def test_package_firewall_receipt_metadata_records_manager_subset_for_test() -> None:
    metadata = package_firewall_receipt_metadata(
        operation="test",
        managers=("npm", "pnpm"),
        result={
            "tested_managers": ["npm", "pnpm"],
            "intercept_proved": True,
            "manager_results": [
                {
                    "manager": "npm",
                    "command_hash": "abc123",
                    "evaluator_source": "guard-cloud",
                    "evaluator_invoked": True,
                },
            ],
        },
    )
    evidence = metadata["scanner_evidence"]
    assert isinstance(evidence, dict)
    assert evidence["operation"] == "test"
    assert evidence["manager_subset"] == ["npm", "pnpm"]
    intercept_proofs = evidence["intercept_proofs"]
    assert isinstance(intercept_proofs, list)
    assert intercept_proofs[0]["command_hash"] == "abc123"
    assert intercept_proofs[0]["evaluator_source"] == "guard-cloud"


def test_audit_receipt_metadata_includes_manifest_and_lockfile_hashes(tmp_path: Path) -> None:
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir()
    manifest_path = workspace_dir / "package.json"
    lockfile_path = workspace_dir / "package-lock.json"
    manifest_path.write_text('{"name":"demo"}', encoding="utf-8")
    lockfile_path.write_text('{"lockfileVersion":1}', encoding="utf-8")
    manifest_hash = stable_digest_hex(manifest_path.read_bytes())
    lockfile_hash = stable_digest_hex(lockfile_path.read_bytes())

    metadata = audit_receipt_metadata(
        {
            "manifest_paths": ["package.json"],
            "lockfile_paths": ["package-lock.json"],
            "inventory": {"total_packages": 1},
            "evaluation": {"decision": "monitor", "packages": []},
        },
        workspace_dir=workspace_dir,
    )
    evidence = metadata["scanner_evidence"]
    assert isinstance(evidence, dict)
    assert evidence["manifest_hashes"] == [manifest_hash]
    assert evidence["lockfile_hashes"] == [lockfile_hash]


def test_probe_package_shim_intercepts_records_command_hash_and_evaluator_source(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    context = _harness_context(tmp_path)
    install_package_shims(context, managers=("npm",))
    shim_dir = context.guard_home / "package-shims" / "bin"
    fake_bin = tmp_path / "fake-bin"
    fake_bin.mkdir(parents=True)
    write_fake_manager_script(
        fake_bin=fake_bin,
        manager="npm",
        marker_path=tmp_path / "npm-probe-marker.json",
        exit_code=0,
    )
    monkeypatch.setenv("PATH", os.pathsep.join([str(shim_dir), str(fake_bin)]))

    result = probe_package_shim_intercepts(context, managers=("npm",), workspace_dir=context.workspace_dir)
    manager_results = result["manager_results"]
    assert isinstance(manager_results, list)
    assert manager_results
    npm_result = manager_results[0]
    assert isinstance(npm_result.get("command_hash"), str)
    assert npm_result["command_hash"]
    assert isinstance(npm_result.get("evaluator_source"), str)
