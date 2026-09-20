"""Runtime regression tests: guard hook emits claude native permission request."""

from __future__ import annotations

from tests.guard_runtime_test_dependencies import (
    GuardStore,
    guard_commands_module,
    json,
    main,
)
from tests.guard_runtime_test_scenarios import (
    _install_fake_guard_surface_daemon,
)
from tests.guard_runtime_test_support import (
    _build_guard_fixture,
    _run_guard_hook,
    _write_text,
)
from tests.guard_runtime_test_support import (
    _isolate_codex_runtime_marker as _isolate_codex_runtime_marker,
)


def test_guard_hook_emits_claude_native_permission_request_for_package_notice(
    tmp_path,
    capsys,
    monkeypatch,
):
    from codex_plugin_scanner.guard.runtime.supply_chain_package_eval import (
        PackageRequestEvaluation,
        SupplyChainUserCopy,
    )

    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    _build_guard_fixture(home_dir, workspace_dir)
    _write_text(
        home_dir / "config.toml",
        '[risk_actions]\npackage_script = "require-reapproval"\napproval_wait_timeout_seconds = 0\n',
    )
    _write_text(workspace_dir / "package.json", '{"name":"demo"}\n')

    def _package_requires_review(**_kwargs: object) -> PackageRequestEvaluation:
        return PackageRequestEvaluation(
            decision="review",
            policy_action="require-reapproval",
            enforcement="policy",
            entitlement_state="offline",
            cache_status="miss",
            package_intent_hash="intent-hash",
            policy_version="policy-v1",
            bundle_version="bundle-v1",
            workspace_fingerprint="workspace-fingerprint",
            reasons=({"code": "package_review", "message": "Review npm install react@18.3.0"},),
            packages=({"name": "react", "decision": "review", "reasons": ()},),
            risk_summary="HOL Guard is reviewing npm install react@18.3.0.",
            user_copy=SupplyChainUserCopy(
                title="Review package install",
                summary="react@18.3.0 needs review before install.",
                next_step="Confirm the exact version in Claude's approval prompt.",
                dashboard_url="https://hol.org/guard/inbox",
                harness_message="HOL Guard is reviewing npm install react@18.3.0.",
            ),
        )

    monkeypatch.setattr(
        guard_commands_module,
        "evaluate_package_request_artifact",
        _package_requires_review,
    )
    pre_tool_event = {
        "session_id": "session-claude-package-permission-request",
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": "npm install react@18.3.0"},
        "source_scope": "project",
    }
    monkeypatch.setattr(
        guard_commands_module, "schedule_guard_daemon_ensure", lambda _guard_home, **_kwargs: "http://127.0.0.1:4455"
    )
    pre_tool_rc, pre_tool_output = _run_guard_hook(
        home_dir=home_dir,
        workspace_dir=workspace_dir,
        harness="claude-code",
        event=pre_tool_event,
        capsys=capsys,
        monkeypatch=monkeypatch,
    )
    permission_rc, permission_output = _run_guard_hook(
        home_dir=home_dir,
        workspace_dir=workspace_dir,
        harness="claude-code",
        event={**pre_tool_event, "hook_event_name": "PermissionRequest"},
        capsys=capsys,
        monkeypatch=monkeypatch,
    )
    permission_payload = json.loads(permission_output)
    pending_pair = guard_commands_module._load_single_claude_pending_permission(
        GuardStore(home_dir),
        {"session_id": "session-claude-package-permission-request"},
    )

    assert pre_tool_rc == 0
    assert json.loads(pre_tool_output)["hookSpecificOutput"]["permissionDecision"] in {"ask", "deny"}
    assert permission_rc == 0
    assert "HOL Guard is reviewing Claude's approval prompt for Bash" in permission_payload["systemMessage"]
    assert "AskUserQuestion" not in json.dumps(permission_payload["hookSpecificOutput"])
    assert pending_pair is not None
    assert pending_pair[1]["permission_prompt_seen"] is True


def test_guard_hook_emits_claude_permission_request_terminal_notice_stderr(
    tmp_path,
    capsys,
    monkeypatch,
):
    import io
    import sys

    from codex_plugin_scanner.guard.runtime.supply_chain_package_eval import (
        PackageRequestEvaluation,
        SupplyChainUserCopy,
    )

    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    _build_guard_fixture(home_dir, workspace_dir)
    _write_text(
        home_dir / "config.toml",
        '[risk_actions]\npackage_script = "require-reapproval"\napproval_wait_timeout_seconds = 0\n',
    )
    _write_text(workspace_dir / "package.json", '{"name":"demo"}\n')

    def _package_requires_review(**_kwargs: object) -> PackageRequestEvaluation:
        return PackageRequestEvaluation(
            decision="review",
            policy_action="require-reapproval",
            enforcement="policy",
            entitlement_state="offline",
            cache_status="miss",
            package_intent_hash="intent-hash",
            policy_version="policy-v1",
            bundle_version="bundle-v1",
            workspace_fingerprint="workspace-fingerprint",
            reasons=({"code": "package_review", "message": "Review npm install react@18.3.0"},),
            packages=({"name": "react", "decision": "review", "reasons": ()},),
            risk_summary="HOL Guard is reviewing npm install react@18.3.0.",
            user_copy=SupplyChainUserCopy(
                title="Review package install",
                summary="react@18.3.0 needs review before install.",
                next_step="Confirm the exact version in Claude's approval prompt.",
                dashboard_url="https://hol.org/guard/inbox",
                harness_message="HOL Guard is reviewing npm install react@18.3.0.",
            ),
        )

    monkeypatch.setattr(
        guard_commands_module,
        "evaluate_package_request_artifact",
        _package_requires_review,
    )
    pre_tool_event = {
        "session_id": "session-claude-package-permission-request-stderr",
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": "npm install react@18.3.0"},
        "source_scope": "project",
    }
    monkeypatch.setattr(
        guard_commands_module, "schedule_guard_daemon_ensure", lambda _guard_home, **_kwargs: "http://127.0.0.1:4455"
    )
    pre_tool_rc, _ = _run_guard_hook(
        home_dir=home_dir,
        workspace_dir=workspace_dir,
        harness="claude-code",
        event=pre_tool_event,
        capsys=capsys,
        monkeypatch=monkeypatch,
    )
    monkeypatch.setattr(
        sys,
        "stdin",
        io.StringIO(json.dumps({**pre_tool_event, "hook_event_name": "PermissionRequest"})),
    )
    permission_rc = main(
        [
            "guard",
            "hook",
            "--home",
            str(home_dir),
            "--workspace",
            str(workspace_dir),
            "--harness",
            "claude-code",
        ]
    )
    permission_capture = capsys.readouterr()

    assert pre_tool_rc == 0
    assert permission_rc == 0
    assert "HOL Guard" in permission_capture.err
    assert "Bash" in permission_capture.err


def test_guard_hook_localizes_package_review_copy_with_local_approval_url(
    tmp_path,
    capsys,
    monkeypatch,
):
    from codex_plugin_scanner.guard.runtime.supply_chain_package_eval import (
        PackageRequestEvaluation,
        SupplyChainUserCopy,
    )

    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    _build_guard_fixture(home_dir, workspace_dir)
    _write_text(
        home_dir / "config.toml",
        '[risk_actions]\npackage_script = "require-reapproval"\napproval_wait_timeout_seconds = 0\n',
    )
    _write_text(workspace_dir / "package.json", '{"name":"demo"}\n')
    monkeypatch.setattr(
        guard_commands_module, "schedule_guard_daemon_ensure", lambda _guard_home, **_kwargs: "http://127.0.0.1:4455"
    )
    monkeypatch.setattr(
        guard_commands_module,
        "load_guard_surface_daemon_client",
        lambda _guard_home: (_ for _ in ()).throw(RuntimeError("no daemon client")),
    )

    def _package_requires_review(**_kwargs: object) -> PackageRequestEvaluation:
        return PackageRequestEvaluation(
            decision="review",
            policy_action="require-reapproval",
            enforcement="policy",
            entitlement_state="offline",
            cache_status="miss",
            package_intent_hash="intent-hash",
            policy_version="policy-v1",
            bundle_version="bundle-v1",
            workspace_fingerprint="workspace-fingerprint",
            reasons=({"code": "package_review", "message": "Review npm install react@18.3.0"},),
            packages=({"name": "react", "decision": "review", "reasons": ()},),
            risk_summary="HOL Guard is reviewing npm install react@18.3.0.",
            user_copy=SupplyChainUserCopy(
                title="Review package install",
                summary="react@18.3.0 needs review before install.",
                next_step="Confirm the exact version in Claude's approval prompt.",
                dashboard_url="https://hol.org/guard/inbox",
                harness_message=(
                    "HOL Guard is reviewing npm install react@18.3.0. Review evidence: https://hol.org/guard/inbox."
                ),
            ),
        )

    monkeypatch.setattr(
        guard_commands_module,
        "evaluate_package_request_artifact",
        _package_requires_review,
    )

    rc, output = _run_guard_hook(
        home_dir=home_dir,
        workspace_dir=workspace_dir,
        harness="codex",
        event={
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": "npm install react@18.3.0"},
            "source_scope": "project",
        },
        capsys=capsys,
        monkeypatch=monkeypatch,
        as_json=True,
    )

    review_url = output["approval_requests"][0]["approval_url"]
    retry_instruction = (
        f"Open HOL Guard to approve or keep this blocked: {review_url}. After you choose, retry the same Codex action."
    )

    assert rc == 1
    assert review_url.startswith("http://127.0.0.1:4455/requests/")
    assert review_url in output["review_hint"]
    assert output["decision_v2_json"]["retry_instruction"] == retry_instruction
    assert review_url in output["decision_v2_json"]["harness_message"]
    assert "guard/inbox" not in output["decision_v2_json"]["harness_message"]
    assert output["supply_chain_evaluation"]["user_copy"]["dashboard_url"] == review_url
    assert review_url in output["supply_chain_evaluation"]["user_copy"]["harness_message"]
    assert output["approval_requests"][0]["decision_v2_json"]["retry_instruction"] == retry_instruction
    assert review_url in output["approval_requests"][0]["decision_v2_json"]["harness_message"]


def test_guard_hook_localizes_package_review_copy_with_daemon_client_approval_url(
    tmp_path,
    capsys,
    monkeypatch,
):
    from codex_plugin_scanner.guard.runtime.supply_chain_package_eval import (
        PackageRequestEvaluation,
        SupplyChainUserCopy,
    )

    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    _build_guard_fixture(home_dir, workspace_dir)
    _write_text(
        home_dir / "config.toml",
        '[risk_actions]\npackage_script = "require-reapproval"\napproval_wait_timeout_seconds = 0\n',
    )
    _write_text(workspace_dir / "package.json", '{"name":"demo"}\n')
    monkeypatch.setattr(
        guard_commands_module, "schedule_guard_daemon_ensure", lambda _guard_home, **_kwargs: "http://127.0.0.1:4455"
    )
    store = GuardStore(home_dir)
    _install_fake_guard_surface_daemon(monkeypatch, store)

    def _package_requires_review(**_kwargs: object) -> PackageRequestEvaluation:
        return PackageRequestEvaluation(
            decision="review",
            policy_action="require-reapproval",
            enforcement="policy",
            entitlement_state="offline",
            cache_status="miss",
            package_intent_hash="intent-hash",
            policy_version="policy-v1",
            bundle_version="bundle-v1",
            workspace_fingerprint="workspace-fingerprint",
            reasons=({"code": "package_review", "message": "Review npm install react@18.3.0"},),
            packages=({"name": "react", "decision": "review", "reasons": ()},),
            risk_summary="HOL Guard is reviewing npm install react@18.3.0.",
            user_copy=SupplyChainUserCopy(
                title="Review package install",
                summary="react@18.3.0 needs review before install.",
                next_step="Confirm the exact version in Claude's approval prompt.",
                dashboard_url="https://hol.org/guard/inbox",
                harness_message="HOL Guard is reviewing npm install react@18.3.0.",
            ),
        )

    monkeypatch.setattr(
        guard_commands_module,
        "evaluate_package_request_artifact",
        _package_requires_review,
    )

    rc, output = _run_guard_hook(
        home_dir=home_dir,
        workspace_dir=workspace_dir,
        harness="codex",
        event={
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": "npm install react@18.3.0"},
            "source_scope": "project",
        },
        capsys=capsys,
        monkeypatch=monkeypatch,
        as_json=True,
    )

    review_url = output["approval_requests"][0]["approval_url"]
    retry_instruction = (
        f"Open HOL Guard to approve or keep this blocked: {review_url}. After you choose, retry the same Codex action."
    )

    assert rc == 1
    assert review_url == "http://127.0.0.1:4455/requests/request-1"
    assert review_url in output["review_hint"]
    assert output["decision_v2_json"]["retry_instruction"] == retry_instruction
    assert review_url in output["decision_v2_json"]["harness_message"]
    assert output["supply_chain_evaluation"]["user_copy"]["dashboard_url"] == review_url
    assert review_url in output["supply_chain_evaluation"]["user_copy"]["harness_message"]
