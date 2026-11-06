from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

import codex_plugin_scanner.guard.local_supply_chain as local_supply_chain_module
from codex_plugin_scanner.guard.config import GuardConfig
from codex_plugin_scanner.guard.local_supply_chain import (
    build_package_protect_payload,
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


def test_package_protect_dry_run_previews_one_shot_allow_then_launch_claims_it_once(
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
    marker = tmp_path / "npm-launches.txt"
    npm = fake_bin / "npm"
    npm.write_text(f"#!/bin/sh\nprintf 'launch\\n' >> '{marker}'\n", encoding="utf-8")
    npm.chmod(0o755)
    monkeypatch.setenv("PATH", str(fake_bin))
    store = GuardStore(tmp_path / "guard-home")
    config = _package_policy_config(
        guard_home=store.guard_home,
        workspace_dir=workspace_dir,
    )
    baseline_payload, baseline_rc = _build_review_package_payload(
        store=store,
        workspace_dir=workspace_dir,
        config=config,
        now="2026-07-17T00:00:00Z",
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
            expires_at="2026-07-18T00:00:00Z",
        ),
        "2026-07-17T00:00:30Z",
    )

    preview_payload, preview_rc = _build_review_package_payload(
        store=store,
        workspace_dir=workspace_dir,
        config=config,
        now="2026-07-17T00:01:00Z",
    )

    assert preview_rc == 0
    assert preview_payload["verdict"]["action"] == "allow"
    assert preview_payload["executed"] is False
    preview_lookup = store.resolve_policy_decision_lookup(
        "guard-cli",
        str(receipt["artifact_id"]),
        str(receipt["artifact_hash"]),
        None,
        None,
        "2026-07-17T00:01:00Z",
        consume_one_shot=False,
    )
    assert preview_lookup["decision"] is not None
    assert store.approval_reuse_claim_disposition(preview_lookup["decision"]) == "consumed"
    assert marker.exists() is False

    launch_result = build_package_protect_payload(
        command=["npm", "install", "guard-proof"],
        store=store,
        workspace_dir=workspace_dir,
        dry_run=False,
        now="2026-07-17T00:02:00Z",
        config=config,
        unsafe_raw_output=False,
        timeout_seconds=30,
    )
    assert launch_result is not None
    launch_payload, launch_rc = launch_result

    assert launch_rc == 0
    assert launch_payload["verdict"]["action"] == "allow"
    assert launch_payload["executed"] is True
    assert marker.read_text(encoding="utf-8").splitlines() == ["launch"]
    claimed_lookup = store.resolve_policy_decision_lookup(
        "guard-cli",
        str(receipt["artifact_id"]),
        str(receipt["artifact_hash"]),
        None,
        None,
        "2026-07-17T00:02:00Z",
        consume_one_shot=False,
    )
    assert claimed_lookup["decision"] is None

    denied_result = build_package_protect_payload(
        command=["npm", "install", "guard-proof"],
        store=store,
        workspace_dir=workspace_dir,
        dry_run=False,
        now="2026-07-17T00:03:00Z",
        config=config,
        unsafe_raw_output=False,
        timeout_seconds=30,
    )
    assert denied_result is not None
    denied_payload, denied_rc = denied_result

    assert denied_rc == 2
    assert denied_payload["verdict"]["action"] == "review"
    assert denied_payload["executed"] is False
    assert marker.read_text(encoding="utf-8").splitlines() == ["launch"]


def test_package_protect_claim_failure_blocks_launch(
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
    marker = tmp_path / "unexpected-npm-launch.txt"
    npm = fake_bin / "npm"
    npm.write_text(f"#!/bin/sh\nprintf 'launch\\n' >> '{marker}'\n", encoding="utf-8")
    npm.chmod(0o755)
    monkeypatch.setenv("PATH", str(fake_bin))
    store = GuardStore(tmp_path / "guard-home")
    config = _package_policy_config(
        guard_home=store.guard_home,
        workspace_dir=workspace_dir,
    )
    _seed_exact_package_review_allow(store=store, workspace_dir=workspace_dir, config=config)
    monkeypatch.setattr(store, "claim_approval_reuse_decision", lambda *_args, **_kwargs: False)

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

    assert returncode == 2
    assert payload["verdict"]["action"] == "review"
    assert payload["executed"] is False
    assert payload["supply_chain_evaluation"]["reasons"][0]["code"] == "approval_reuse_claim_failed"
    assert marker.exists() is False


def test_package_protect_retained_local_once_deletion_after_claim_blocks_launch(
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
    marker = tmp_path / "unexpected-retained-local-once-launch.txt"
    npm = fake_bin / "npm"
    npm.write_text(f"#!/bin/sh\nprintf 'launch\\n' >> '{marker}'\n", encoding="utf-8")
    npm.chmod(0o755)
    monkeypatch.setenv("PATH", str(fake_bin))
    store = GuardStore(tmp_path / "guard-home")
    config = _package_policy_config(guard_home=store.guard_home, workspace_dir=workspace_dir)
    baseline_payload, baseline_rc = _build_review_package_payload(
        store=store,
        workspace_dir=workspace_dir,
        config=config,
        now="2026-07-17T00:00:00Z",
    )
    assert baseline_rc == 2
    receipt = baseline_payload["receipt"]
    assert isinstance(receipt, dict)
    approval_id = store.record_local_once_approval(
        request_id="package-retained-local-once",
        harness="guard-cli",
        artifact_id=str(receipt["artifact_id"]),
        artifact_hash=str(receipt["artifact_hash"]),
        workspace=None,
        publisher=None,
        action="allow",
        created_at="2026-07-17T00:00:30Z",
        expires_at="2026-07-18T00:00:00Z",
    )
    assert approval_id is not None
    selected = store.resolve_policy_decision(
        "guard-cli",
        str(receipt["artifact_id"]),
        str(receipt["artifact_hash"]),
        now="2026-07-17T00:00:45Z",
        consume_one_shot=False,
    )
    assert selected is not None
    assert store.approval_reuse_claim_disposition(selected) == "retained"
    original_claim = store.claim_approval_reuse_decision

    def claim_then_delete(decision: dict[str, object], *, now: str) -> bool:
        assert decision["approval_id"] == approval_id
        assert store.approval_reuse_claim_disposition(decision) == "retained"
        claimed = original_claim(decision, now=now)
        assert claimed is True
        with sqlite3.connect(store.path) as connection:
            cursor = connection.execute(
                "delete from guard_local_once_approvals where approval_id = ?",
                (approval_id,),
            )
        assert cursor.rowcount == 1
        return True

    monkeypatch.setattr(store, "claim_approval_reuse_decision", claim_then_delete)

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

    assert returncode == 2
    assert payload["verdict"]["action"] == "review"
    assert payload["executed"] is False
    assert payload["supply_chain_evaluation"]["reasons"][0]["code"] == ("approval_reuse_context_changed_after_claim")
    assert marker.exists() is False


def test_package_protect_retained_persistent_policy_deletion_after_claim_blocks_launch(
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
    marker = tmp_path / "unexpected-retained-policy-launch.txt"
    npm = fake_bin / "npm"
    npm.write_text(f"#!/bin/sh\nprintf 'launch\\n' >> '{marker}'\n", encoding="utf-8")
    npm.chmod(0o755)
    monkeypatch.setenv("PATH", str(fake_bin))
    store = GuardStore(tmp_path / "guard-home")
    config = _package_policy_config(guard_home=store.guard_home, workspace_dir=workspace_dir)
    receipt = _seed_exact_package_review_allow(store=store, workspace_dir=workspace_dir, config=config)
    selected = store.resolve_policy_decision(
        "guard-cli",
        str(receipt["artifact_id"]),
        str(receipt["artifact_hash"]),
        now="2026-07-17T00:00:45Z",
        consume_one_shot=False,
    )
    assert selected is not None
    assert store.approval_reuse_claim_disposition(selected) == "retained"
    original_claim = store.claim_approval_reuse_decision

    def claim_then_delete(decision: dict[str, object], *, now: str) -> bool:
        assert store.approval_reuse_claim_disposition(decision) == "retained"
        claimed = original_claim(decision, now=now)
        assert claimed is True
        decision_id = decision["decision_id"]
        assert isinstance(decision_id, int)
        with sqlite3.connect(store.path) as connection:
            cursor = connection.execute(
                "delete from policy_decisions where decision_id = ?",
                (decision_id,),
            )
        assert cursor.rowcount == 1
        return True

    monkeypatch.setattr(store, "claim_approval_reuse_decision", claim_then_delete)

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

    assert returncode == 2
    assert payload["verdict"]["action"] == "review"
    assert payload["executed"] is False
    assert payload["supply_chain_evaluation"]["reasons"][0]["code"] == ("approval_reuse_context_changed_after_claim")
    assert marker.exists() is False


def test_package_protect_reloads_saved_policy_after_claim_before_launch(
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
    marker = tmp_path / "unexpected-post-claim-policy-launch.txt"
    npm = fake_bin / "npm"
    npm.write_text(f"#!/bin/sh\nprintf 'launch\\n' >> '{marker}'\n", encoding="utf-8")
    npm.chmod(0o755)
    monkeypatch.setenv("PATH", str(fake_bin))
    store = GuardStore(tmp_path / "guard-home")
    config = _package_policy_config(guard_home=store.guard_home, workspace_dir=workspace_dir)
    _seed_exact_package_review_allow(store=store, workspace_dir=workspace_dir, config=config)
    original_claim = store.claim_approval_reuse_decision

    def claim_then_block(decision: dict[str, object], *, now: str) -> bool:
        claimed = original_claim(decision, now=now)
        assert claimed is True
        store.upsert_policy(
            PolicyDecision(
                harness=str(decision["harness"]),
                scope="artifact",
                action="block",
                artifact_id=str(decision["artifact_id"]),
                artifact_hash=str(decision["artifact_hash"]),
                reason="policy changed to block during saved approval claim",
                source="manual",
            ),
            now,
        )
        return True

    monkeypatch.setattr(store, "claim_approval_reuse_decision", claim_then_block)

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

    assert returncode == 2
    assert payload["verdict"]["action"] == "block"
    assert payload["executed"] is False
    assert payload["supply_chain_evaluation"]["reasons"][0]["code"] == "saved_package_block"
    assert marker.exists() is False


@pytest.mark.parametrize(
    ("refresh_mode", "expected_returncode", "expected_action", "expected_launch"),
    (
        ("unchanged", 0, "allow", True),
        ("block", 2, "block", False),
        ("failure", 2, "block", False),
    ),
)
def test_package_protect_refreshes_current_config_after_saved_claim(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    refresh_mode: str,
    expected_returncode: int,
    expected_action: str,
    expected_launch: bool,
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
    marker = tmp_path / f"config-refresh-{refresh_mode}-launch.txt"
    npm = fake_bin / "npm"
    npm.write_text(f"#!/bin/sh\nprintf 'launch\\n' >> '{marker}'\n", encoding="utf-8")
    npm.chmod(0o755)
    monkeypatch.setenv("PATH", str(fake_bin))
    store = GuardStore(tmp_path / "guard-home")
    config = _package_policy_config(guard_home=store.guard_home, workspace_dir=workspace_dir)
    _seed_exact_package_review_allow(store=store, workspace_dir=workspace_dir, config=config)

    def current_config() -> GuardConfig:
        if refresh_mode == "failure":
            raise RuntimeError("sensitive config provider failure")
        return _package_policy_config(
            guard_home=store.guard_home,
            workspace_dir=workspace_dir,
            package_action="block" if refresh_mode == "block" else "review",
        )

    result = build_package_protect_payload(
        command=["npm", "install", "guard-proof"],
        store=store,
        workspace_dir=workspace_dir,
        dry_run=False,
        now="2026-07-17T00:01:00Z",
        config=config,
        current_config_provider=current_config,
        unsafe_raw_output=False,
        timeout_seconds=30,
    )
    assert result is not None
    payload, returncode = result

    assert returncode == expected_returncode
    assert payload["verdict"]["action"] == expected_action
    assert payload["executed"] is expected_launch
    assert marker.exists() is expected_launch
    if refresh_mode == "failure":
        first_reason = payload["supply_chain_evaluation"]["reasons"][0]
        assert first_reason["code"] == "approval_reuse_policy_changed"
        assert "sensitive" not in json.dumps(payload)
