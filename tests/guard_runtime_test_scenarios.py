"""Shared runtime test fixtures and helper objects."""

from __future__ import annotations

from tests.guard_runtime_test_dependencies import (
    GuardApprovalRequest,
    GuardStore,
    Path,
    build_approval_context_token,
    guard_commands_module,
    pytest,
)


def _load_claude_pending_question_contract(home_dir: Path, session_id: str) -> tuple[str, list[dict[str, str]]]:
    store = GuardStore(home_dir)
    index_payload = store.get_sync_payload(f"claude_pending_permissions:{session_id}")
    assert isinstance(index_payload, dict)
    pending_keys = index_payload.get("pending_keys")
    assert isinstance(pending_keys, list)
    assert pending_keys
    pending_payload = store.get_sync_payload(str(pending_keys[0]))
    assert isinstance(pending_payload, dict)
    question = str(pending_payload["approval_question"])
    options = pending_payload.get("approval_options")
    assert isinstance(options, list)
    assert options
    return question, [{"label": str(option)} for option in options]


def _install_fake_guard_surface_daemon(
    monkeypatch: pytest.MonkeyPatch,
    store: GuardStore,
    statuses: list[dict[str, object]] | None = None,
) -> None:
    class _FakeDaemonClient:
        def start_session(self, **_kwargs) -> dict[str, object]:
            return {"session_id": "session-1"}

        def queue_blocked_operation(self, **kwargs) -> dict[str, object]:
            evaluation = kwargs["evaluation"]
            artifacts = evaluation["artifacts"] if isinstance(evaluation, dict) else []
            item = artifacts[0] if artifacts and isinstance(artifacts[0], dict) else {}
            request_id = f"request-{len(store.list_approval_requests(limit=50)) + 1}"
            approval_center_url = str(kwargs["approval_center_url"]).rstrip("/")
            request = GuardApprovalRequest(
                request_id=request_id,
                harness=str(kwargs["harness"]),
                artifact_id=str(item.get("artifact_id") or request_id),
                artifact_name=str(item.get("artifact_name") or item.get("artifact_id") or "Guard request"),
                artifact_hash=str(item.get("artifact_hash") or "hash-1"),
                policy_action=str(item.get("policy_action") or "block"),
                recommended_scope="artifact",
                changed_fields=tuple(str(field) for field in item.get("changed_fields", [])),
                source_scope=str(item.get("source_scope") or "project"),
                config_path=str(item.get("config_path") or "~/.codex/config.toml"),
                review_command=f"hol-guard approvals approve {request_id}",
                approval_url=f"{approval_center_url}/requests/{request_id}",
                launch_target=str(item.get("launch_target") or "Codex request"),
                artifact_type=str(item.get("artifact_type") or "artifact"),
            )
            store.add_approval_request(request, "2026-04-30T00:00:00+00:00")
            return {
                "operation": {"operation_id": "operation-1"},
                "approval_requests": [request.to_dict()],
            }

        def update_operation_status(self, **kwargs) -> None:
            if statuses is not None:
                statuses.append(dict(kwargs))

    monkeypatch.setattr(
        guard_commands_module,
        "load_guard_surface_daemon_client",
        lambda _guard_home: _FakeDaemonClient(),
    )


def _assert_pytest_requires_restricted_profile(match):
    assert match is not None
    assert match.action_class == "pytest repository-code execution"
    assert match.guard_default_action == "sandbox-required"
    assert match.reason_code == "pytest_restricted_profile_required"


def _codex_browser_approval_context_token(*, current_action: str) -> str:
    return build_approval_context_token(
        identity={"artifact_id": "artifact-1", "harness": "codex"},
        content={"command": "bash ./guard-canary.sh"},
        capabilities={"action_type": "shell_command"},
        policy={"current_action": current_action},
        sandbox={"mode": "host"},
    )
