from __future__ import annotations

import os
from dataclasses import replace
from pathlib import Path

import pytest

import codex_plugin_scanner.guard.local_supply_chain as local_supply_chain_module
from codex_plugin_scanner.guard.local_supply_chain import (
    recompute_package_protect_artifact_hash,
)
from codex_plugin_scanner.guard.models import (
    PolicyDecision,
)
from codex_plugin_scanner.guard.store import GuardStore
from tests.manifest_install_fixtures import (
    _build_review_package_payload,
    _fake_policy_integrity_keyring,  # noqa: F401 -- registers the module autouse fixture
    _native_package_intent,  # noqa: F401 -- registers the module autouse fixture
    _package_policy_config,
    _review_package_evaluation,
    _seed_exact_package_review_allow,
)


def test_build_package_protect_payload_reuses_unchanged_exact_review_approval(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        local_supply_chain_module,
        "evaluate_package_request_artifact",
        lambda **_kwargs: _review_package_evaluation(),
    )
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir()
    store = GuardStore(tmp_path / "guard-home")
    config = _package_policy_config(
        guard_home=store.guard_home,
        workspace_dir=workspace_dir,
    )
    _seed_exact_package_review_allow(store=store, workspace_dir=workspace_dir, config=config)

    retry_payload, retry_rc = _build_review_package_payload(
        store=store,
        workspace_dir=workspace_dir,
        config=config,
        now="2026-07-17T00:01:00Z",
    )

    assert retry_rc == 0
    assert retry_payload["verdict"]["action"] == "allow"
    assert retry_payload["executed"] is False
    assert retry_payload["supply_chain_evaluation"]["reasons"][0]["code"] == "saved_package_approval"


def test_saved_package_approval_survives_guard_shim_repair(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        local_supply_chain_module,
        "evaluate_package_request_artifact",
        lambda **_kwargs: _review_package_evaluation(),
    )
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir()
    store = GuardStore(tmp_path / "guard-home")
    shim_dir = store.guard_home / "package-shims" / "bin"
    manager_dir = tmp_path / "manager-bin"
    shim_dir.mkdir(parents=True)
    manager_dir.mkdir()
    shim = shim_dir / "npm"
    manager = manager_dir / "npm"
    shim.write_text("#!/bin/sh\n# generated wrapper v1\n", encoding="utf-8")
    manager.write_text("#!/bin/sh\n# real manager\n", encoding="utf-8")
    shim.chmod(0o755)
    manager.chmod(0o755)
    relative_shim_dir = os.path.relpath(shim_dir, workspace_dir)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("PATH", f"{relative_shim_dir}{os.pathsep}{manager_dir}")
    config = _package_policy_config(guard_home=store.guard_home, workspace_dir=workspace_dir)
    _seed_exact_package_review_allow(store=store, workspace_dir=workspace_dir, config=config)

    replacement_shim = shim.with_suffix(".new")
    replacement_shim.write_text("#!/bin/sh\n# regenerated wrapper with different bytes\n", encoding="utf-8")
    replacement_shim.chmod(0o755)
    replacement_shim.replace(shim)
    retry_payload, retry_rc = _build_review_package_payload(
        store=store,
        workspace_dir=workspace_dir,
        config=config,
        now="2026-07-17T00:01:00Z",
    )

    assert retry_rc == 0
    assert retry_payload["verdict"]["action"] == "allow"
    assert retry_payload["supply_chain_evaluation"]["reasons"][0]["code"] == "saved_package_approval"

    manager.write_text("#!/bin/sh\n# changed real manager\n", encoding="utf-8")
    manager.chmod(0o755)
    changed_payload, changed_rc = _build_review_package_payload(
        store=store,
        workspace_dir=workspace_dir,
        config=config,
        now="2026-07-17T00:02:00Z",
    )

    assert changed_rc == 2
    assert changed_payload["verdict"]["action"] == "review"

    with pytest.raises(ValueError, match="PATH could not be verified"):
        local_supply_chain_module._package_manager_launch_environment(
            {"PATH": "invalid\0path"},
            guard_home=store.guard_home,
            launch_cwd=workspace_dir,
        )


def test_saved_npx_approval_survives_guard_shim_replacement(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        local_supply_chain_module,
        "evaluate_package_request_artifact",
        lambda **_kwargs: _review_package_evaluation(),
    )
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir()
    home_dir = tmp_path / "home"
    guard_home = home_dir / ".hol-guard"
    store = GuardStore(guard_home)
    shim_dir = guard_home / "package-shims" / "bin"
    manager_dir = tmp_path / "manager-bin"
    shim_dir.mkdir(parents=True)
    manager_dir.mkdir()
    shim = shim_dir / "npx"
    manager = manager_dir / "npx"
    shim.write_text("#!/bin/sh\n# generated wrapper v1\n", encoding="utf-8")
    manager.write_text("#!/bin/sh\n# real manager\n", encoding="utf-8")
    shim.chmod(0o755)
    manager.chmod(0o755)
    monkeypatch.setenv("HOME", str(home_dir))
    monkeypatch.setenv("PATH", f"{shim_dir}{os.pathsep}{manager_dir}")
    config = _package_policy_config(guard_home=guard_home, workspace_dir=workspace_dir)
    command = ["npx", "-y", "@modelcontextprotocol/server-memory@latest"]
    baseline_payload, baseline_rc = _build_review_package_payload(
        store=store,
        workspace_dir=workspace_dir,
        config=config,
        now="2026-07-17T00:00:00Z",
        command=command,
    )
    assert baseline_rc == 2
    receipt = baseline_payload["receipt"]
    assert isinstance(receipt, dict)
    store.ensure_policy_integrity_ready_for_write(now="2026-07-17T00:00:00Z")
    store.upsert_policy(
        PolicyDecision(
            harness="guard-cli",
            scope="artifact",
            action="allow",
            artifact_id=str(receipt["artifact_id"]),
            artifact_hash=str(receipt["artifact_hash"]),
            source="approval-gate",
        ),
        "2026-07-17T00:00:00Z",
    )

    replacement_shim = shim.with_suffix(".new")
    replacement_shim.write_text("#!/bin/sh\n# regenerated wrapper with different bytes\n", encoding="utf-8")
    replacement_shim.chmod(0o755)
    replacement_shim.replace(shim)
    retry_payload, retry_rc = _build_review_package_payload(
        store=store,
        workspace_dir=workspace_dir,
        config=config,
        now="2026-07-17T00:01:00Z",
        command=command,
    )

    assert retry_rc == 0
    assert retry_payload["verdict"]["action"] == "allow"
    assert retry_payload["supply_chain_evaluation"]["reasons"][0]["code"] == "saved_package_approval"

    manager.write_text("#!/bin/sh\n# changed real manager\n", encoding="utf-8")
    manager.chmod(0o755)
    changed_payload, changed_rc = _build_review_package_payload(
        store=store,
        workspace_dir=workspace_dir,
        config=config,
        now="2026-07-17T00:02:00Z",
        command=command,
    )

    assert changed_rc == 2
    assert changed_payload["verdict"]["action"] == "review"


def test_durable_exact_npx_approval_survives_reapproval_and_repeated_retries(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    reapproval_evaluation = replace(
        _review_package_evaluation(),
        policy_action="require-reapproval",
    )
    monkeypatch.setattr(
        local_supply_chain_module,
        "evaluate_package_request_artifact",
        lambda **_kwargs: reapproval_evaluation,
    )
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir()
    home_dir = tmp_path / "home"
    guard_home = home_dir / ".hol-guard"
    store = GuardStore(guard_home)
    shim_dir = guard_home / "package-shims" / "bin"
    manager_dir = tmp_path / "manager-bin"
    shim_dir.mkdir(parents=True)
    manager_dir.mkdir()
    for directory in (shim_dir, manager_dir):
        executable = directory / "npx"
        executable.write_text("#!/bin/sh\n# test npx\n", encoding="utf-8")
        executable.chmod(0o755)
    monkeypatch.setenv("HOME", str(home_dir))
    monkeypatch.setenv("PATH", f"{shim_dir}{os.pathsep}{manager_dir}")
    config = _package_policy_config(guard_home=guard_home, workspace_dir=workspace_dir)
    command = ["npx", "-y", "@modelcontextprotocol/server-memory@latest"]

    baseline_payload, baseline_rc = _build_review_package_payload(
        store=store,
        workspace_dir=workspace_dir,
        config=config,
        now="2026-07-17T00:00:00Z",
        command=command,
    )
    assert baseline_rc == 2
    receipt = baseline_payload["receipt"]
    assert isinstance(receipt, dict)
    store.ensure_policy_integrity_ready_for_write(now="2026-07-17T00:00:30Z")
    store.upsert_policy(
        PolicyDecision(
            harness="guard-cli",
            scope="artifact",
            action="allow",
            artifact_id=str(receipt["artifact_id"]),
            artifact_hash=str(receipt["artifact_hash"]),
            source="approval-gate",
        ),
        "2026-07-17T00:00:30Z",
    )

    for minute in (1, 30):
        retry_payload, retry_rc = _build_review_package_payload(
            store=store,
            workspace_dir=workspace_dir,
            config=config,
            now=f"2026-07-17T00:{minute:02d}:00Z",
            command=command,
        )
        assert retry_rc == 0
        assert retry_payload["verdict"]["action"] == "allow"
        assert retry_payload["supply_chain_evaluation"]["reasons"][0]["code"] == "saved_package_approval"

    changed_payload, changed_rc = _build_review_package_payload(
        store=store,
        workspace_dir=workspace_dir,
        config=config,
        now="2026-07-17T00:31:00Z",
        command=["npx", "-y", "@modelcontextprotocol/server-filesystem@latest"],
    )
    assert changed_rc == 2
    assert changed_payload["verdict"]["action"] == "require-reapproval"


def test_recomputed_package_protect_hash_includes_the_same_final_launch_identity(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        local_supply_chain_module,
        "evaluate_package_request_artifact",
        lambda **_kwargs: _review_package_evaluation(),
    )
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir()
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    npm = fake_bin / "npm"
    npm.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    npm.chmod(0o755)
    monkeypatch.setenv("PATH", str(fake_bin))
    store = GuardStore(tmp_path / "guard-home")
    config = _package_policy_config(guard_home=store.guard_home, workspace_dir=workspace_dir)
    payload, returncode = _build_review_package_payload(
        store=store,
        workspace_dir=workspace_dir,
        config=config,
        now="2026-07-17T00:00:00Z",
    )
    receipt = payload["receipt"]
    assert isinstance(receipt, dict)

    recomputed = recompute_package_protect_artifact_hash(
        ["npm", "install", "guard-proof"],
        store=store,
        workspace_dir=workspace_dir,
        now="2026-07-17T00:00:00Z",
        config=config,
    )

    assert returncode == 2
    assert recomputed == receipt["artifact_hash"]
