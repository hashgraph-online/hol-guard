"""Listing chunks and resolution reuse for the resident approval-scope contract."""

from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard.approval_scope_support import (
    APPROVAL_SCOPE_CONTRACT_VERSION,
    ApprovalScopeContract,
    request_scope_contract_payloads,
)
from codex_plugin_scanner.guard.approvals import apply_approval_resolution
from codex_plugin_scanner.guard.daemon.server import _GuardDaemonHandler
from codex_plugin_scanner.guard.models import GuardApprovalRequest
from codex_plugin_scanner.guard.native_approval_scope import (
    _MAX_REQUEST_BYTES,
    ApprovalScopeUnavailableError,
    native_approval_scopes,
)
from codex_plugin_scanner.guard.store import GuardStore

_CONTRACT_REPLY = {
    "allowed_scopes_by_action": {"allow": ["artifact"], "block": ["artifact"]},
    "recommended_scope_by_action": {"allow": "artifact", "block": "artifact"},
    "scope_restrictions": [],
    "task_capability_eligibility": {
        "eligible": False,
        "reason_codes": ["task_capability_not_enabled"],
    },
    "scope_contract_version": APPROVAL_SCOPE_CONTRACT_VERSION,
    "scope_contract_digest": "ab" * 32,
    "exact_action_persistence_eligible": False,
    "once_only_reason": None,
}


def _install_scope_transport(monkeypatch: pytest.MonkeyPatch) -> list[list[dict[str, object]]]:
    sent: list[list[dict[str, object]]] = []

    def resident_request(**kwargs: object) -> dict[str, object]:
        request = kwargs["request"]
        assert isinstance(request, dict)
        items = request["items"]
        assert isinstance(items, list)
        sent.append([dict(item) for item in items if isinstance(item, dict)])
        return {"status": "ok"}

    def payload(
        response: dict[str, object] | None,
        request: dict[str, object],
        guard_home: Path,
    ) -> dict[str, object]:
        del response, guard_home
        items = request["items"]
        assert isinstance(items, list)
        return {"items": [dict(_CONTRACT_REPLY) for _item in items]}

    monkeypatch.setattr(
        "codex_plugin_scanner.guard.native_approval_scope.ensure_resident_prerequisite",
        lambda guard_home: True,
    )
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.native_approval_scope._resident_request",
        resident_request,
    )
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.native_approval_scope._payload",
        payload,
    )
    return sent


def _listing_request(index: int, envelope: dict[str, object]) -> dict[str, object]:
    return {
        "artifact_id": f"artifact-{index}",
        "artifact_type": "tool_action_request",
        "artifact_hash": f"hash-{index}",
        "artifact_name": "tool",
        "policy_action": "require-reapproval",
        "harness": "codex",
        "publisher": None,
        "source_scope": "project",
        "config_path": "/workspace/repo/.guard/config.toml",
        "wrapper_chain": [],
        "action_identity": None,
        "raw_command_text": "echo test",
        "action_envelope_json": envelope,
        "scanner_evidence": [],
    }


def _wire_bytes(items: list[dict[str, object]]) -> int:
    envelope = {
        "operation": "approval_scope",
        "request": {
            "schema": "guard-approval-scope-request.v1",
            "request_id": "approval-scope-" + ("0" * 32),
            "items": items,
        },
        "deadline_budget_ms": 10000,
    }
    return len(json.dumps(envelope).encode("utf-8"))


def test_listing_narrows_envelopes_and_chunks_when_kept_fields_exceed_the_byte_cap(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    sent = _install_scope_transport(monkeypatch)
    bulky = "x" * 2_500_000
    rows = [
        _listing_request(
            index,
            {
                "action_type": "shell_command",
                "command": bulky,
                "raw_payload_redacted": {
                    "permission_mode": "ask",
                    "file_contents": "secret-" + bulky,
                },
            },
        )
        for index in range(3)
    ]

    payloads = request_scope_contract_payloads(rows)

    assert len(payloads) == 3
    assert all(payload["scope_contract_digest"] == "ab" * 32 for payload in payloads)
    assert len(sent) >= 2
    flat = [item for chunk in sent for item in chunk]
    assert len(flat) == 3
    for item in flat:
        envelope = item["action_envelope_json"]
        assert isinstance(envelope, dict)
        raw = envelope["raw_payload_redacted"]
        assert isinstance(raw, dict)
        assert raw == {"permission_mode": "ask"}
        assert "file_contents" not in raw
        assert envelope["command"] == bulky
    assert all(_wire_bytes(chunk) <= _MAX_REQUEST_BYTES for chunk in sent)
    assert _wire_bytes(flat) > _MAX_REQUEST_BYTES


def test_one_item_over_the_resident_byte_cap_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    sent = _install_scope_transport(monkeypatch)
    rows = [
        _listing_request(
            0,
            {"action_type": "shell_command", "command": "y" * (_MAX_REQUEST_BYTES + 1)},
        )
    ]

    with pytest.raises(ApprovalScopeUnavailableError):
        native_approval_scopes(rows, guard_home=tmp_path)

    assert sent == []


def test_resolution_returns_the_contract_derived_before_commit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = GuardStore(tmp_path / "guard-home")
    request = GuardApprovalRequest(
        request_id="scope-once",
        harness="codex",
        artifact_id="codex:project:tool-action:scope-once",
        artifact_name="Scoped action",
        artifact_type="tool_action_request",
        artifact_hash="hash-scope-once",
        publisher="publisher-a",
        policy_action="require-reapproval",
        recommended_scope="artifact",
        changed_fields=("command",),
        source_scope="project",
        config_path="/workspace/repo/.guard/config.toml",
        workspace="/workspace/repo",
        launch_target="echo test",
        action_envelope_json={"action_type": "shell_command", "command": "echo test"},
        decision_v2_json={"action": "ask", "approval_scopes": ["artifact"]},
        review_command="hol-guard approvals approve scope-once",
        approval_url="http://127.0.0.1:5474/approvals/scope-once",
    )
    store.add_approval_request(request, "2026-07-19T00:00:00+00:00")
    contract = ApprovalScopeContract(
        allow_scopes=("artifact",),
        block_scopes=("artifact",),
        recommended_allow_scope="artifact",
        recommended_block_scope="artifact",
        restrictions=(),
        digest="cd" * 32,
        exact_action_persistence_eligible=False,
    )
    calls = {"n": 0}

    def scopes(requests: list[Mapping[str, object]]) -> list[tuple[ApprovalScopeContract, str | None]]:
        calls["n"] += 1
        if calls["n"] > 1:
            raise ApprovalScopeUnavailableError
        assert len(requests) == 1
        return [(contract, "exact-token")]

    committed = {"ok": False}

    def resolve_row(*args: object, **kwargs: object) -> None:
        del args, kwargs
        assert calls["n"] == 1
        committed["ok"] = True

    monkeypatch.setattr("codex_plugin_scanner.guard.approval_scope_support._native_scopes", scopes)
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.native_policy_snapshot_publisher.provision_native_verifier_key_for_store",
        lambda bound_store: None,
    )
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.approvals.require_approval_decision",
        lambda *args, **kwargs: None,
    )
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.approvals.native_approval_resolution_plan",
        lambda *args, **kwargs: {
            "decision": {
                "harness": "codex",
                "action": "allow",
                "artifact_id": request.artifact_id,
                "artifact_hash": request.artifact_hash,
                "workspace": None,
                "publisher": None,
            },
            "persistence": "not_saved",
            "matching": None,
        },
    )
    monkeypatch.setattr(store, "resolve_approval_request", resolve_row)

    result = apply_approval_resolution(
        store=store,
        request_id=request.request_id,
        action="allow",
        scope="artifact",
        workspace=None,
        reason="once",
        now="2026-07-19T00:01:00+00:00",
    )

    assert committed["ok"] is True
    assert calls["n"] == 1
    assert result["scope_contract_digest"] == "cd" * 32
    assert result["scope_contract_version"] == APPROVAL_SCOPE_CONTRACT_VERSION
    assert result["applied_scope"] == "artifact"


def test_requests_list_reports_scope_unavailable_without_a_fallback_contract() -> None:
    captured: dict[str, object] = {}

    class _Handler:
        server = SimpleNamespace(
            store=SimpleNamespace(
                guard_home=Path("guard-home"),
                list_approval_request_page=lambda **kwargs: (_ for _ in ()).throw(
                    ApprovalScopeUnavailableError()
                ),
            )
        )

        def _native_handler_decision(self, producer: object) -> SimpleNamespace:
            del producer
            return SimpleNamespace(fields={"status": "pending", "limit": 50})

        def _is_hosted_dashboard_origin(self) -> bool:
            return True

        def _write_json(
            self,
            body: dict[str, object],
            status: int = 200,
            extra_headers: dict[str, str] | None = None,
        ) -> None:
            captured["body"] = body
            captured["status"] = status
            captured["headers"] = extra_headers

    _GuardDaemonHandler._handle_requests_list(_Handler(), "")

    assert captured["status"] == 503
    body = captured["body"]
    assert isinstance(body, dict)
    assert body == {"error": "native_approval_scope_unavailable"}
    assert "allowed_scopes" not in body
