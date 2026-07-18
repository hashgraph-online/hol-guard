"""Trust-boundary regressions for Copilot generic hook policy hints."""

from __future__ import annotations

import argparse
import io
import json
from pathlib import Path
from typing import cast

import pytest

from codex_plugin_scanner.guard.cli.commands_hook_generic import _run_hook_generic_payload
from codex_plugin_scanner.guard.config import GuardConfig
from codex_plugin_scanner.guard.models import GuardAction, PolicyDecision
from codex_plugin_scanner.guard.store import GuardStore

_IGNORED_BENIGN_HINT_REASON = "untrusted_hook_payload_hint_ignored_guard_verified_benign"
_BENIGN_COMMAND = (
    "cd /tmp/hol-guard-fixtures/hashgraph-online && python - <<'PY'\n"
    "from pathlib import Path\n"
    "text = Path('bounty_submissions.txt').read_text()\n"
    "print('bytes', len(text))\n"
    "print('rows', text.count('data-testid=\"portal-grid-row\"'))\n"
    "PY"
)


def _copilot_payload(
    *,
    command: str = _BENIGN_COMMAND,
    policy_action: GuardAction = "block",
) -> dict[str, object]:
    return {
        "hook_name": "preToolUse",
        "tool_name": "bash",
        "tool_input": {"command": command},
        "policy_action": policy_action,
        "source_scope": "project",
    }


def _run_copilot_generic_hook(
    *,
    config: GuardConfig,
    payload: dict[str, object],
    store: GuardStore,
    workspace: Path,
    cli_action: GuardAction | None = None,
) -> tuple[int, dict[str, object], dict[str, object]]:
    output = io.StringIO()
    rc = _run_hook_generic_payload(
        argparse.Namespace(
            artifact_id=None,
            artifact_name=None,
            harness="copilot",
            json=False,
            policy_action=cli_action,
        ),
        action_envelope=None,
        config=config,
        home_dir=workspace.parent / "home",
        output_stream=output,
        payload=payload,
        runtime_workspace=workspace,
        store=store,
    )
    response_value = json.loads(output.getvalue())
    assert isinstance(response_value, dict)
    response = cast(dict[str, object], response_value)
    receipt = store.list_receipts(limit=1)[0]
    return rc, response, receipt


def _receipt_evidence(receipt: dict[str, object], source: str) -> dict[str, object]:
    evidence = receipt["scanner_evidence"]
    assert isinstance(evidence, list)
    for raw_item in cast(list[object], evidence):
        if not isinstance(raw_item, dict):
            continue
        item = cast(dict[str, object], raw_item)
        if item.get("source") == source:
            return item
    raise AssertionError(f"missing {source!r} scanner evidence")


def _guard_config(
    tmp_path: Path,
    workspace: Path,
    *,
    default_action: GuardAction = "warn",
) -> GuardConfig:
    return GuardConfig(
        guard_home=tmp_path / "guard-home",
        workspace=workspace,
        default_action=default_action,
    )


def test_verified_benign_copilot_legacy_block_hint_stays_prompt_free_with_evidence(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    store = GuardStore(tmp_path / "guard-home")

    rc, response, receipt = _run_copilot_generic_hook(
        config=_guard_config(tmp_path, workspace),
        payload=_copilot_payload(),
        store=store,
        workspace=workspace,
    )

    assert rc == 0
    assert response == {"permissionDecision": "allow"}
    assert receipt["policy_decision"] == "warn"
    assert store.list_approval_requests() == []
    composition = _receipt_evidence(receipt, "policy_composition")
    assert composition["current_config_action"] == "warn"
    assert composition["untrusted_hook_payload_hint"] == "block"
    assert composition["untrusted_hook_payload_hint_disposition"] == "ignored"
    assert composition["untrusted_hook_payload_hint_reason_code"] == _IGNORED_BENIGN_HINT_REASON
    assert composition["current_composed_action"] == "warn"
    assert composition["authoritative_action"] == "warn"
    trust_evidence = _receipt_evidence(receipt, "hook_payload_trust")
    assert trust_evidence == {
        "source": "hook_payload_trust",
        "input_source": "untrusted_hook_payload_hint",
        "status": "ignored",
        "reason_code": _IGNORED_BENIGN_HINT_REASON,
        "classifier": "is_explicitly_benign_tool_action_request",
    }


def test_verified_benign_copilot_hint_cannot_lower_configured_block(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    store = GuardStore(tmp_path / "guard-home")

    rc, response, receipt = _run_copilot_generic_hook(
        config=_guard_config(tmp_path, workspace, default_action="block"),
        payload=_copilot_payload(),
        store=store,
        workspace=workspace,
    )

    assert rc == 0
    assert response["permissionDecision"] == "deny"
    assert receipt["policy_decision"] == "block"
    composition = _receipt_evidence(receipt, "policy_composition")
    assert composition["untrusted_hook_payload_hint_disposition"] == "ignored"
    assert composition["current_config_action"] == "block"
    assert composition["current_composed_action"] == "block"
    assert composition["authoritative_action"] == "block"


def test_verified_benign_copilot_hint_cannot_lower_trusted_cli_block(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    store = GuardStore(tmp_path / "guard-home")

    rc, response, receipt = _run_copilot_generic_hook(
        config=_guard_config(tmp_path, workspace),
        payload=_copilot_payload(),
        store=store,
        workspace=workspace,
        cli_action="block",
    )

    assert rc == 0
    assert response["permissionDecision"] == "deny"
    composition = _receipt_evidence(receipt, "policy_composition")
    assert composition["trusted_cli_override"] == "block"
    assert composition["untrusted_hook_payload_hint_disposition"] == "ignored"
    assert composition["current_composed_action"] == "block"
    assert composition["authoritative_action"] == "block"


def test_verified_benign_copilot_exact_stored_block_remains_terminal(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    store = GuardStore(tmp_path / "guard-home")
    config = _guard_config(tmp_path, workspace)
    payload = _copilot_payload()
    _, first_response, first_receipt = _run_copilot_generic_hook(
        config=config,
        payload=payload,
        store=store,
        workspace=workspace,
    )
    assert first_response == {"permissionDecision": "allow"}
    store.upsert_policy(
        PolicyDecision(
            harness="copilot",
            scope="artifact",
            action="block",
            artifact_id=str(first_receipt["artifact_id"]),
            artifact_hash=str(first_receipt["artifact_hash"]),
            source="local",
        ),
        "2026-07-17T00:00:00+00:00",
    )

    rc, response, receipt = _run_copilot_generic_hook(
        config=config,
        payload=payload,
        store=store,
        workspace=workspace,
    )

    assert rc == 0
    assert response["permissionDecision"] == "deny"
    assert receipt["policy_decision"] == "block"
    composition = _receipt_evidence(receipt, "policy_composition")
    assert composition["current_composed_action"] == "warn"
    assert composition["saved_policy_action"] == "block"
    assert composition["authoritative_action"] == "block"
    reuse = _receipt_evidence(receipt, "approval_reuse")
    assert reuse["status"] == "accepted"
    assert reuse["reason_code"] == "approval_reuse_saved_block"


def test_unmodeled_copilot_payload_block_remains_conservative_deny(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    store = GuardStore(tmp_path / "guard-home")

    rc, response, receipt = _run_copilot_generic_hook(
        config=_guard_config(tmp_path, workspace),
        payload=_copilot_payload(command="custom-dangerous-tool --write /tmp/file"),
        store=store,
        workspace=workspace,
    )

    assert rc == 0
    assert response["permissionDecision"] == "deny"
    assert receipt["policy_decision"] == "block"
    composition = _receipt_evidence(receipt, "policy_composition")
    assert composition["untrusted_hook_payload_hint"] == "block"
    assert composition["untrusted_hook_payload_hint_disposition"] == "applied"
    assert composition["untrusted_hook_payload_hint_reason_code"] is None
    assert composition["current_composed_action"] == "block"
    evidence = cast(list[object], receipt["scanner_evidence"])
    evidence_dicts = [cast(dict[str, object], item) for item in evidence if isinstance(item, dict)]
    assert not any(item.get("source") == "hook_payload_trust" for item in evidence_dicts)


def test_copilot_payload_allow_cannot_lower_stronger_current_policy(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    store = GuardStore(tmp_path / "guard-home")

    rc, response, receipt = _run_copilot_generic_hook(
        config=_guard_config(tmp_path, workspace, default_action="sandbox-required"),
        payload=_copilot_payload(policy_action="allow"),
        store=store,
        workspace=workspace,
    )

    assert rc == 0
    assert response["permissionDecision"] == "deny"
    assert receipt["policy_decision"] == "sandbox-required"
    composition = _receipt_evidence(receipt, "policy_composition")
    assert composition["current_config_action"] == "sandbox-required"
    assert composition["untrusted_hook_payload_hint"] == "allow"
    assert composition["untrusted_hook_payload_hint_disposition"] == "ignored"
    assert composition["current_composed_action"] == "sandbox-required"
    assert composition["authoritative_action"] == "sandbox-required"


@pytest.mark.parametrize(
    ("current_action", "expected_permission"),
    (("review", "deny"), ("block", "deny")),
)
def test_untrusted_permissive_daemon_hint_never_lowers_current_policy(
    tmp_path: Path,
    current_action: GuardAction,
    expected_permission: str,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    store = GuardStore(tmp_path / "guard-home")
    payload = {
        **_copilot_payload(policy_action="allow"),
        "daemon_status": "unreachable",
        "fail_mode": "permissive",
    }

    rc, response, receipt = _run_copilot_generic_hook(
        config=_guard_config(tmp_path, workspace, default_action=current_action),
        payload=payload,
        store=store,
        workspace=workspace,
    )

    assert rc == 0
    assert response["permissionDecision"] == expected_permission
    assert receipt["policy_decision"] == current_action
    composition = _receipt_evidence(receipt, "policy_composition")
    assert composition["daemon_hint_trust"] == "untrusted_hook_payload"
    assert composition["daemon_hint_disposition"] == "preserved_current_action"
    assert composition["daemon_hint_reason_code"] == ("untrusted_daemon_permissive_hint_preserved_current_action")
    assert composition["current_composed_action"] == current_action
    assert composition["authoritative_action"] == current_action
    daemon_evidence = _receipt_evidence(receipt, "daemon_hint_trust")
    assert daemon_evidence == {
        "source": "daemon_hint_trust",
        "input_source": "untrusted_hook_payload",
        "status": "monotonic-only",
        "disposition": "preserved_current_action",
        "reason_code": "untrusted_daemon_permissive_hint_preserved_current_action",
    }


def test_verified_benign_copilot_hint_cannot_bypass_strict_daemon_failure(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    store = GuardStore(tmp_path / "guard-home")
    payload = {
        **_copilot_payload(),
        "daemon_status": "unreachable",
        "fail_mode": "strict",
    }

    rc, response, receipt = _run_copilot_generic_hook(
        config=_guard_config(tmp_path, workspace),
        payload=payload,
        store=store,
        workspace=workspace,
    )

    assert rc == 0
    assert response["permissionDecision"] == "deny"
    assert receipt["policy_decision"] == "block"
    composition = _receipt_evidence(receipt, "policy_composition")
    assert composition["untrusted_hook_payload_hint_disposition"] == "ignored"
    assert composition["daemon_status"] == "unreachable"
    assert composition["fail_mode"] == "strict"
    assert composition["daemon_hint_trust"] == "untrusted_hook_payload"
    assert composition["daemon_hint_disposition"] == "tightened_to_block"
    assert composition["daemon_hint_reason_code"] == "untrusted_daemon_strict_hint_tightened_to_block"
    assert composition["current_composed_action"] == "block"
    assert composition["authoritative_action"] == "block"
    daemon_evidence = _receipt_evidence(receipt, "daemon_hint_trust")
    assert daemon_evidence["status"] == "monotonic-only"
    assert daemon_evidence["disposition"] == "tightened_to_block"
