from __future__ import annotations

import json
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import local_supply_chain
from codex_plugin_scanner.guard.cli import render
from codex_plugin_scanner.guard.cli.commands_support_runtime_policy import _localize_pending_approval_copy
from codex_plugin_scanner.guard.cli.protect_approvals import _queue_local_protect_approvals
from codex_plugin_scanner.guard.local_supply_chain import build_package_protect_payload
from codex_plugin_scanner.guard.runtime.supply_chain_package_eval import (
    PackageRequestEvaluation,
    SupplyChainUserCopy,
)
from codex_plugin_scanner.guard.store import GuardStore


@pytest.mark.parametrize("rich_available", [True, False])
@pytest.mark.parametrize("action", ["review", "require-reapproval"])
@pytest.mark.parametrize("harness_message", ["This install needs approval.", ""])
@pytest.mark.parametrize("url_source", ["copy", "canonical"])
def test_protect_output_preserves_approval_guidance(
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
    rich_available: bool,
    action: str,
    harness_message: str,
    url_source: str,
) -> None:
    approval_url = "http://127.0.0.1:5474/requests/package-review"
    next_step = "Approve in Guard, then retry."
    payload = {
        "executed": False,
        "primary_approval_url": approval_url if url_source == "canonical" else None,
        "request": {"command": ["npx", "example-package"], "install_kind": "execute"},
        "verdict": {"action": action, "reason": "Current package policy requires approval."},
        "supply_chain_evaluation": {
            "decision": "ask",
            "user_copy": {
                "harness_message": harness_message,
                "next_step": next_step,
                "dashboard_url": approval_url if url_source == "copy" else None,
            },
        },
    }
    monkeypatch.setattr(render, "_RICH_AVAILABLE", rich_available)

    render.emit_guard_payload("protect", payload, False)

    output = " ".join(capsys.readouterr().out.split())
    assert approval_url in output
    assert output.count(approval_url) == 1
    assert next_step in output
    assert payload["executed"] is False
    assert payload["verdict"]["action"] == action


@pytest.mark.parametrize("rich_available", [True, False])
def test_protect_guidance_prefers_the_current_queued_request(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch, rich_available: bool
) -> None:
    payload = _pending_package_payload()
    approval_url = "http://127.0.0.1:5474/requests/current-package"
    stale_url = "http://127.0.0.1:5474/requests/old-package"
    payload["primary_approval_url"] = approval_url
    payload["supply_chain_evaluation"]["user_copy"]["dashboard_url"] = stale_url
    monkeypatch.setattr(render, "_RICH_AVAILABLE", rich_available)

    render.emit_guard_payload("protect", payload, False)

    output = " ".join(capsys.readouterr().out.split())
    assert approval_url in output
    assert stale_url not in output
    assert payload["executed"] is False


@pytest.mark.parametrize("rich_available", [True, False])
def test_protect_guidance_deduplicates_approval_url_in_next_step(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch, rich_available: bool
) -> None:
    payload = _pending_package_payload()
    approval_url = "http://127.0.0.1:5474/requests/package-review"
    payload["primary_approval_url"] = approval_url
    payload["supply_chain_evaluation"]["user_copy"].update(next_step=f"Open {approval_url}", dashboard_url=approval_url)
    monkeypatch.setattr(render, "_RICH_AVAILABLE", rich_available)

    render.emit_guard_payload("protect", payload, False)

    assert capsys.readouterr().out.count(approval_url) == 1


def _pending_package_payload() -> dict[str, object]:
    return {
        "executed": False,
        "request": {
            "command": ["npx", "example-package@1.0.0"],
            "install_kind": "execute",
            "package_manager": "npx",
            "harness": "guard-cli",
            "targets": [],
        },
        "receipt": {
            "artifact_id": "package-example",
            "artifact_name": "example-package",
            "artifact_hash": "a" * 64,
            "policy_decision": "require-reapproval",
            "source_scope": "project",
        },
        "verdict": {
            "action": "require-reapproval",
            "blocking": True,
            "reason": "Current package policy requires fresh approval.",
        },
        "supply_chain_evaluation": {
            "decision": "ask",
            "policy_action": "require-reapproval",
            "reasons": [],
            "user_copy": {
                "harness_message": "Current package policy requires fresh approval.",
                "next_step": "Review the current package request in HOL Guard, then retry.",
                "dashboard_url": None,
            },
        },
    }


@pytest.mark.parametrize("rich_available", [True, False])
@pytest.mark.parametrize(
    "existing_url", [None, "https://guard.example/reconnect", "http://127.0.0.1:5474/requests/old-package"]
)
def test_unavailable_approval_server_explains_recovery_without_relaxing_policy(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
    install_fake_system_keyring,
    rich_available: bool,
    existing_url: str | None,
) -> None:
    install_fake_system_keyring()
    monkeypatch.delenv("HOL_GUARD_TEST_SKIP_LOCAL_APPROVAL_QUEUE", raising=False)
    monkeypatch.setattr(render, "_RICH_AVAILABLE", rich_available)
    store = GuardStore(tmp_path / "guard-home")
    payload = _pending_package_payload()
    payload["primary_approval_url"] = existing_url
    payload["supply_chain_evaluation"]["user_copy"]["dashboard_url"] = existing_url
    if existing_url:
        payload["supply_chain_evaluation"]["user_copy"]["harness_message"] += f" Review: {existing_url}"
    attempted: list[Path] = []

    def unavailable(guard_home: Path) -> str:
        attempted.append(guard_home)
        raise RuntimeError("private startup diagnostic")

    _queue_local_protect_approvals(
        payload,
        store=store,
        guard_home=tmp_path / "guard-home",
        workspace=tmp_path,
        ensure_approval_daemon=unavailable,
        approval_delivery_payload=lambda _harness: {},
        localize_pending_approval_copy=lambda _payload, _harness: None,
    )
    render.emit_guard_payload("protect", payload, False)

    output = " ".join(capsys.readouterr().out.split())
    assert attempted == [tmp_path / "guard-home"]
    assert "hol-guard daemon repair" in output
    assert "private startup diagnostic" not in output
    if existing_url is not None:
        assert existing_url not in output
    assert payload.get("primary_approval_url") is None
    assert payload["supply_chain_evaluation"]["user_copy"]["dashboard_url"] is None
    assert "approval_request_ids" not in payload
    assert payload["executed"] is False
    assert payload["verdict"]["action"] == "require-reapproval"
    assert payload["verdict"]["blocking"] is True


@pytest.mark.parametrize("json_output", [False, True])
def test_package_evaluation_preserves_queued_approval_guidance(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
    install_fake_system_keyring,
    json_output: bool,
) -> None:
    install_fake_system_keyring()
    home = tmp_path / "home"
    home.mkdir()
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    guard_home = home / ".hol-guard"
    now = "2026-05-19T01:00:00Z"
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.delenv("HOL_GUARD_TEST_SKIP_LOCAL_APPROVAL_QUEUE", raising=False)
    store = GuardStore(guard_home)
    evaluation = PackageRequestEvaluation(
        decision="allow",
        policy_action="allow",
        enforcement="enforced",
        entitlement_state="active",
        cache_status="fresh",
        package_intent_hash="b" * 64,
        policy_version="test-policy",
        bundle_version="test-bundle",
        workspace_fingerprint=None,
        reasons=(),
        packages=({"name": "example-package", "requestedVersion": "1.0.0", "decision": "allow"},),
        risk_summary="Package review passed.",
        user_copy=SupplyChainUserCopy(
            title="Package allowed",
            summary="Package review passed.",
            next_step=None,
            dashboard_url=None,
            harness_message="Package review passed.",
        ),
    )
    monkeypatch.setattr(local_supply_chain, "evaluate_package_request_artifact", lambda **_kwargs: evaluation)
    payload, exit_code = build_package_protect_payload(
        command=["npx", "example-package@1.0.0"],
        store=store,
        workspace_dir=workspace,
        dry_run=True,
        now=now,
        config=None,
        unsafe_raw_output=False,
        timeout_seconds=10,
        additional_current_action="require-reapproval",
    )
    _queue_local_protect_approvals(
        payload,
        store=store,
        guard_home=guard_home,
        workspace=workspace,
        ensure_approval_daemon=lambda _home: "http://127.0.0.1:5474",
        approval_delivery_payload=lambda _harness: {},
        localize_pending_approval_copy=lambda response, harness: _localize_pending_approval_copy(
            response, harness=harness
        ),
    )
    render.emit_guard_payload("protect", payload, json_output)

    output = capsys.readouterr().out
    assert exit_code == 2
    requests = store.list_approval_requests(status="pending", limit=10)
    assert len(requests) == 1, json.loads(output).get("verdict") if json_output else output[:1800]
    request_id = requests[0]["request_id"]
    assert requests[0]["policy_action"] == "require-reapproval"
    if json_output:
        payload = json.loads(output)
        assert payload["executed"] is False
        assert payload["dry_run"] is True
        assert payload["approval_request_ids"] == [request_id]
        assert payload["receipt"]["policy_decision"] == "require-reapproval"
        assert f"/requests/{request_id}" in payload["supply_chain_evaluation"]["user_copy"]["dashboard_url"]
    else:
        assert f"http://127.0.0.1:5474/requests/{request_id}" in output


@pytest.mark.parametrize("rich_available", [True, False])
def test_retry_after_approval_server_recovers_queues_matching_request(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
    install_fake_system_keyring,
    rich_available: bool,
) -> None:
    install_fake_system_keyring()
    monkeypatch.delenv("HOL_GUARD_TEST_SKIP_LOCAL_APPROVAL_QUEUE", raising=False)
    monkeypatch.setattr(render, "_RICH_AVAILABLE", rich_available)
    store = GuardStore(tmp_path / "guard-home")

    def unavailable(_guard_home: Path) -> str:
        raise RuntimeError("approval server unavailable")

    for ensure_daemon in (unavailable, lambda _guard_home: "http://127.0.0.1:5474"):
        payload = _pending_package_payload()
        _queue_local_protect_approvals(
            payload,
            store=store,
            guard_home=tmp_path / "guard-home",
            workspace=tmp_path,
            ensure_approval_daemon=ensure_daemon,
            approval_delivery_payload=lambda _harness: {},
            localize_pending_approval_copy=lambda response, harness: _localize_pending_approval_copy(
                response, harness=harness
            ),
        )
        if ensure_daemon is unavailable:
            assert store.list_approval_requests(status="pending", limit=10) == []

    requests = store.list_approval_requests(status="pending", limit=10)
    assert len(requests) == 1
    request = requests[0]
    assert payload["approval_request_ids"] == [request["request_id"]]
    assert request["artifact_id"] == "package-example"
    assert request["artifact_hash"] == "a" * 64
    assert request["policy_action"] == "require-reapproval"
    user_copy = payload["supply_chain_evaluation"]["user_copy"]
    assert f"/requests/{request['request_id']}" in user_copy["dashboard_url"]

    render.emit_guard_payload("protect", payload, False)

    output = capsys.readouterr().out
    assert user_copy["dashboard_url"] in output
    assert "hol-guard daemon repair" not in output
    assert payload["executed"] is False
    assert payload["verdict"]["action"] == "require-reapproval"
    assert payload["verdict"]["blocking"] is True
