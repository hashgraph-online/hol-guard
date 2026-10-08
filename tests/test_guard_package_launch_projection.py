from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path

import pytest

import codex_plugin_scanner.guard.local_supply_chain as local_supply_chain_module
from codex_plugin_scanner.guard.local_supply_chain import (
    build_package_protect_payload,
)
from codex_plugin_scanner.guard.models import (
    GuardAction,
    PolicyDecision,
)
from codex_plugin_scanner.guard.store import GuardStore
from tests.manifest_install_fixtures import (
    _allow_package_evaluation,
    _fake_policy_integrity_keyring,  # noqa: F401 -- registers the module autouse fixture
    _native_package_intent,  # noqa: F401 -- registers the module autouse fixture
    _package_policy_config,
)


@pytest.mark.parametrize("final_action", ("allow", "warn"))
def test_package_protect_rebuilds_every_permitted_final_projection_before_launch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    final_action: str,
) -> None:
    monkeypatch.setattr(
        local_supply_chain_module,
        "evaluate_package_request_artifact",
        lambda **_kwargs: _allow_package_evaluation(),
    )
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir()
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    marker = tmp_path / f"final-{final_action}-launch.txt"
    npm = fake_bin / "npm"
    npm.write_text(f"#!/bin/sh\nprintf 'launch\\n' >> '{marker}'\n", encoding="utf-8")
    npm.chmod(0o755)
    monkeypatch.setenv("PATH", str(fake_bin))
    store = GuardStore(tmp_path / "guard-home")
    initial_authority = local_supply_chain_module._build_package_protect_authority(
        command=["npm", "install", "guard-proof"],
        store=store,
        workspace_dir=workspace_dir,
        now="2026-07-17T00:01:00Z",
        config=None,
        additional_current_action=None,
        additional_policy_context=None,
    )
    assert initial_authority is not None

    def insert_final_policy() -> tuple[object | None, dict[str, object] | None]:
        if final_action == "warn":
            store.upsert_policy(
                PolicyDecision(
                    harness=initial_authority.artifact.harness,
                    scope="artifact",
                    action="warn",
                    artifact_id=initial_authority.artifact.artifact_id,
                    artifact_hash=initial_authority.artifact_hash,
                    reason="warn inserted at the final authority boundary",
                    source="manual",
                ),
                "2026-07-17T00:01:00Z",
            )
        return None, None

    result = build_package_protect_payload(
        command=["npm", "install", "guard-proof"],
        store=store,
        workspace_dir=workspace_dir,
        dry_run=False,
        now="2026-07-17T00:01:00Z",
        config=None,
        unsafe_raw_output=False,
        timeout_seconds=30,
        additional_authority_provider=insert_final_policy,
    )
    assert result is not None
    payload, returncode = result

    assert returncode == 0
    assert payload["executed"] is True
    assert marker.read_text(encoding="utf-8").splitlines() == ["launch"]
    evaluation = payload["supply_chain_evaluation"]
    assert isinstance(evaluation, dict)
    assert evaluation["policy_action"] == final_action
    assert evaluation["decision"] == final_action
    user_copy = evaluation["user_copy"]
    assert isinstance(user_copy, dict)
    assert payload["verdict"] == {
        "action": final_action,
        "reason": user_copy["summary"],
        "risk_signals": [reason["message"] for reason in evaluation["reasons"]],
        "matched_advisories": [],
        "blocking": False,
    }
    receipt = payload["receipt"]
    assert isinstance(receipt, dict)
    assert receipt["policy_decision"] == final_action
    assert receipt["capabilities_summary"] == user_copy["summary"]
    assert receipt["provenance_summary"] == user_copy["harness_message"]
    action_envelope = receipt["action_envelope_json"]
    assert isinstance(action_envelope, dict)
    assert action_envelope["policy_action"] == final_action

    stored_receipt = store.get_receipt(receipt["receipt_id"])
    assert stored_receipt is not None
    assert stored_receipt["policy_decision"] == final_action
    assert stored_receipt["capabilities_summary"] == user_copy["summary"]
    assert stored_receipt["provenance_summary"] == user_copy["harness_message"]
    assert stored_receipt["action_envelope_json"]["policy_action"] == final_action
    final_events = store.list_events(event_name=f"install_time_{final_action}")
    assert len(final_events) == 1
    assert final_events[0]["payload"]["action"] == final_action
    other_action = "warn" if final_action == "allow" else "allow"
    assert store.list_events(event_name=f"install_time_{other_action}") == []


def test_package_protect_current_warn_rewrites_every_final_package_projection(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    feed_evaluation = replace(
        _allow_package_evaluation(),
        packages=(
            {
                "name": "guard-proof",
                "version": "1.0.0",
                "decision": "allow",
                "related_advisory_ids": ["adv-feed-allow-current-warn"],
            },
        ),
    )
    monkeypatch.setattr(
        local_supply_chain_module,
        "evaluate_package_request_artifact",
        lambda **_kwargs: feed_evaluation,
    )
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir()
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    marker = tmp_path / "current-warn-launches.txt"
    npm = fake_bin / "npm"
    npm.write_text(f"#!/bin/sh\nprintf 'launch\\n' >> '{marker}'\n", encoding="utf-8")
    npm.chmod(0o755)
    monkeypatch.setenv("PATH", str(fake_bin))
    store = GuardStore(tmp_path / "guard-home")
    config = _package_policy_config(
        guard_home=store.guard_home,
        workspace_dir=workspace_dir,
        package_action="warn",
    )

    result = build_package_protect_payload(
        command=["npm", "install", "guard-proof"],
        store=store,
        workspace_dir=workspace_dir,
        dry_run=False,
        now="2026-07-17T00:01:00Z",
        config=config,
        unsafe_raw_output=False,
        timeout_seconds=30,
    )
    assert result is not None
    payload, returncode = result

    assert returncode == 0
    assert payload["executed"] is True
    assert marker.read_text(encoding="utf-8").splitlines() == ["launch"]
    evaluation = payload["supply_chain_evaluation"]
    assert isinstance(evaluation, dict)
    assert evaluation["decision"] == "warn"
    assert evaluation["policy_action"] == "warn"
    packages = evaluation["packages"]
    assert isinstance(packages, list)
    assert packages
    assert all(package["decision"] == "warn" for package in packages)
    matched_advisories = payload["matched_advisories"]
    assert matched_advisories == [
        {
            "advisory_id": "adv-feed-allow-current-warn",
            "package_name": "guard-proof",
            "version": "1.0.0",
            "decision": "warn",
        }
    ]
    assert payload["verdict"]["action"] == "warn"
    assert payload["verdict"]["matched_advisories"] == matched_advisories
    receipt = payload["receipt"]
    assert isinstance(receipt, dict)
    assert receipt["policy_decision"] == "warn"
    assert receipt["action_envelope_json"]["policy_action"] == "warn"
    stored_receipt = store.get_receipt(receipt["receipt_id"])
    assert stored_receipt is not None
    assert stored_receipt["policy_decision"] == "warn"
    assert stored_receipt["action_envelope_json"]["policy_action"] == "warn"
    events = store.list_events(event_name="install_time_warn")
    assert len(events) == 1
    assert events[0]["payload"]["action"] == "warn"


@pytest.mark.parametrize(
    ("current_action", "expected_package_decision"),
    (("warn", "warn"), ("block", "block"), ("require-reapproval", "ask")),
)
def test_current_package_policy_rewrites_every_package_decision(
    current_action: GuardAction,
    expected_package_decision: str,
) -> None:
    evaluation = replace(
        _allow_package_evaluation(),
        packages=(
            {"name": "first", "decision": "allow"},
            {"name": "second", "decision": "allow"},
        ),
    )

    rewritten = local_supply_chain_module._package_evaluation_with_current_policy_action(
        evaluation,
        current_action=current_action,
    )

    assert rewritten.policy_action == current_action
    assert all(package["decision"] == expected_package_decision for package in rewritten.packages)


def test_package_protect_launch_uses_final_canonical_workspace_after_symlink_retarget(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        local_supply_chain_module,
        "evaluate_package_request_artifact",
        lambda **_kwargs: _allow_package_evaluation(),
    )
    approved_workspace = tmp_path / "approved-workspace"
    approved_workspace.mkdir()
    attacker_workspace = tmp_path / "attacker-workspace"
    attacker_workspace.mkdir()
    workspace_alias = tmp_path / "workspace"
    workspace_alias.symlink_to(approved_workspace, target_is_directory=True)
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    marker = tmp_path / "launch-workspace.txt"
    npm = fake_bin / "npm"
    npm.write_text(f"#!/bin/sh\n/bin/pwd -P > '{marker}'\n", encoding="utf-8")
    npm.chmod(0o755)
    monkeypatch.setenv("PATH", str(fake_bin))
    store = GuardStore(tmp_path / "guard-home")
    original_resolved_argv = local_supply_chain_module.resolved_runtime_launch_argv

    def retarget_workspace_after_final_identity(
        identity: dict[str, object],
        *,
        args: tuple[str, ...],
    ) -> tuple[str, ...] | None:
        launch_command = original_resolved_argv(identity, args=args)
        workspace_alias.unlink()
        workspace_alias.symlink_to(attacker_workspace, target_is_directory=True)
        return launch_command

    monkeypatch.setattr(
        local_supply_chain_module,
        "resolved_runtime_launch_argv",
        retarget_workspace_after_final_identity,
    )

    result = build_package_protect_payload(
        command=["npm", "install", "guard-proof"],
        store=store,
        workspace_dir=workspace_alias,
        dry_run=False,
        now="2026-07-17T00:01:00Z",
        config=None,
        unsafe_raw_output=False,
        timeout_seconds=30,
    )
    assert result is not None
    payload, returncode = result

    assert returncode == 0
    assert payload["executed"] is True
    assert marker.read_text(encoding="utf-8").strip() == str(approved_workspace.resolve(strict=True))
    assert workspace_alias.resolve(strict=True) == attacker_workspace.resolve(strict=True)


def test_package_protect_launch_uses_final_environment_snapshot(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        local_supply_chain_module,
        "evaluate_package_request_artifact",
        lambda **_kwargs: _allow_package_evaluation(),
    )
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir()
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    marker = tmp_path / "launch-registry.txt"
    npm = fake_bin / "npm"
    npm.write_text(f"#!/bin/sh\nprintf '%s\\n' \"$NPM_CONFIG_REGISTRY\" > '{marker}'\n", encoding="utf-8")
    npm.chmod(0o755)
    monkeypatch.setenv("PATH", str(fake_bin))
    monkeypatch.setenv("NPM_CONFIG_REGISTRY", "https://approved.example.test/npm")
    package_secret = "package-secret-must-not-appear"
    monkeypatch.setenv("NPM_TOKEN", package_secret)
    store = GuardStore(tmp_path / "guard-home")
    original_resolved_argv = local_supply_chain_module.resolved_runtime_launch_argv

    def mutate_environment_after_final_identity(
        identity: dict[str, object],
        *,
        args: tuple[str, ...],
    ) -> tuple[str, ...] | None:
        launch_command = original_resolved_argv(identity, args=args)
        monkeypatch.setenv("NPM_CONFIG_REGISTRY", "https://attacker.example.test/npm")
        monkeypatch.setenv("NPM_TOKEN", "attacker-secret")
        return launch_command

    monkeypatch.setattr(
        local_supply_chain_module,
        "resolved_runtime_launch_argv",
        mutate_environment_after_final_identity,
    )

    result = build_package_protect_payload(
        command=["npm", "install", "guard-proof"],
        store=store,
        workspace_dir=workspace_dir,
        dry_run=False,
        now="2026-07-17T00:01:00Z",
        config=None,
        unsafe_raw_output=False,
        timeout_seconds=30,
    )
    assert result is not None
    payload, returncode = result

    assert returncode == 0
    assert payload["executed"] is True
    assert marker.read_text(encoding="utf-8").strip() == "https://approved.example.test/npm"
    assert package_secret not in json.dumps(payload)
    assert package_secret not in json.dumps(store.list_receipts(limit=10))


def test_package_protect_normal_launch_uses_captured_authority_inputs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        local_supply_chain_module,
        "evaluate_package_request_artifact",
        lambda **_kwargs: _allow_package_evaluation(),
    )
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir()
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    marker = tmp_path / "normal-authority-launch.txt"
    npm = fake_bin / "npm"
    npm.write_text(f"#!/bin/sh\nprintf 'launch\\n' > '{marker}'\n", encoding="utf-8")
    npm.chmod(0o755)
    monkeypatch.setenv("PATH", str(fake_bin))
    store = GuardStore(tmp_path / "guard-home")

    result = build_package_protect_payload(
        command=["npm", "install", "guard-proof"],
        store=store,
        workspace_dir=workspace_dir,
        dry_run=False,
        now="2026-07-17T00:01:00Z",
        config=None,
        unsafe_raw_output=False,
        timeout_seconds=30,
    )
    assert result is not None
    payload, returncode = result

    assert returncode == 0
    assert payload["verdict"]["action"] == "allow"
    assert payload["executed"] is True
    assert marker.read_text(encoding="utf-8").splitlines() == ["launch"]
