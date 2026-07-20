"""Regression tests for Bun install approval replay."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.approvals import apply_approval_resolution
from codex_plugin_scanner.guard.local_supply_chain import build_package_protect_payload
from codex_plugin_scanner.guard.models import GuardApprovalRequest
from codex_plugin_scanner.guard.store import GuardStore
from tests.test_guard_js_supply_chain_phase11 import WORKSPACE_ID, _bundle_response, _package


@pytest.fixture(autouse=True)
def _fake_policy_integrity_keyring(install_fake_system_keyring) -> None:
    install_fake_system_keyring()


def _write_bun_workspace(workspace_dir: Path) -> None:
    (workspace_dir / "package.json").write_text(
        json.dumps({"name": "demo", "dependencies": {"minimist": "^1.2.0"}}, indent=2),
        encoding="utf-8",
    )
    (workspace_dir / "bun.lock").write_text(
        '{"lockfileVersion":1,"packages":{"minimist":["minimist@1.2.8","",{}]}}\n',
        encoding="utf-8",
    )


def test_bun_install_approval_never_lowers_current_block_when_integrity_is_degraded(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir()
    _write_bun_workspace(workspace_dir)
    store.get_cloud_workspace_id = lambda: WORKSPACE_ID  # type: ignore[method-assign]
    store.cache_supply_chain_bundle(
        WORKSPACE_ID,
        _bundle_response(packages=[_package(name="minimist", version="1.2.8", default_action="block")]),
        "2026-06-14T00:00:00Z",
    )
    command = ["bun", "install", "--frozen-lockfile"]

    baseline_payload, baseline_rc = build_package_protect_payload(
        command=command,
        store=store,
        workspace_dir=workspace_dir,
        dry_run=True,
        now="2026-06-14T00:00:00Z",
        config=None,
        unsafe_raw_output=False,
        timeout_seconds=30,
    )
    assert baseline_rc == 2
    assert baseline_payload["verdict"]["action"] == "block"
    receipt = baseline_payload["receipt"]
    assert isinstance(receipt, dict)
    store.add_approval_request(
        GuardApprovalRequest(
            request_id="req-bun-install",
            harness="guard-cli",
            artifact_id=str(receipt["artifact_id"]),
            artifact_name=str(receipt["artifact_name"]),
            artifact_type="package_request",
            artifact_hash=str(receipt["artifact_hash"]),
            policy_action="block",
            recommended_scope="artifact",
            changed_fields=("package_request",),
            source_scope="project",
            config_path=str(workspace_dir / "hol-guard.toml"),
            workspace=str(workspace_dir),
            launch_target="bun install --frozen-lockfile",
            review_command="hol-guard approvals approve req-bun-install",
            approval_url="http://127.0.0.1:4455/approvals/req-bun-install",
        ),
        "2026-06-14T00:00:30Z",
    )
    with pytest.raises(ValueError, match="terminal_policy_action_not_resolvable"):
        apply_approval_resolution(
            store=store,
            request_id="req-bun-install",
            action="allow",
            scope="artifact",
            workspace=None,
            reason="same bun install",
            now="2026-06-14T00:01:00Z",
        )
    pending_request = store.get_approval_request("req-bun-install")
    assert pending_request is not None
    assert pending_request["status"] == "pending"
    assert store.list_policy_decisions() == []
    store._policy_integrity_secret_store = None

    first_retry_payload, first_retry_rc = build_package_protect_payload(
        command=command,
        store=store,
        workspace_dir=workspace_dir,
        dry_run=True,
        now="2026-06-14T00:02:00Z",
        config=None,
        unsafe_raw_output=False,
        timeout_seconds=30,
    )
    second_retry_payload, second_retry_rc = build_package_protect_payload(
        command=command,
        store=store,
        workspace_dir=workspace_dir,
        dry_run=True,
        now="2026-06-14T00:03:00Z",
        config=None,
        unsafe_raw_output=False,
        timeout_seconds=30,
    )

    assert first_retry_rc == 2
    assert second_retry_rc == 2
    for retry_payload in (first_retry_payload, second_retry_payload):
        assert retry_payload["verdict"]["action"] == "block"
        retry_receipt = retry_payload["receipt"]
        assert isinstance(retry_receipt, dict)
        assert retry_receipt["artifact_hash"] == receipt["artifact_hash"]
        assert retry_receipt["policy_decision"] == "block"
        evaluation = retry_payload["supply_chain_evaluation"]
        assert isinstance(evaluation, dict)
        assert not any(
            isinstance(reason, dict) and reason.get("code") == "saved_package_approval"
            for reason in evaluation.get("reasons", [])
        )
