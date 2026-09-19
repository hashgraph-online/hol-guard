"""Runtime regression tests: guard hook codex post tool use blocks."""

from __future__ import annotations

from tests.guard_runtime_test_dependencies import (
    GuardStore,
    _codex_post_tool_output_artifact,
    apply_approval_resolution,
    guard_commands_module,
    io,
    json,
    main,
    sys,
    threading,
)
from tests.guard_runtime_test_scenarios import (
    _install_fake_guard_surface_daemon,
)
from tests.guard_runtime_test_support import (
    _build_guard_fixture,
    _write_text,
)
from tests.guard_runtime_test_support import (
    _isolate_codex_runtime_marker as _isolate_codex_runtime_marker,
)


def test_guard_hook_codex_post_tool_use_blocks_authrc_output(
    tmp_path,
    capsys,
    monkeypatch,
):
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    _build_guard_fixture(home_dir, workspace_dir)
    event = {
        "hook_event_name": "PostToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": "cat .authrc"},
        "tool_response": {"stdout": "HOL_GUARD_FAKE_CREDENTIAL=fixture-only\n"},
        "source_scope": "project",
    }
    monkeypatch.setenv("CODEX_HOME", str(home_dir / ".codex"))
    monkeypatch.setattr(
        guard_commands_module, "schedule_guard_daemon_ensure", lambda _guard_home, **_kwargs: "http://127.0.0.1:4455"
    )

    monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps(event)))
    rc = main(
        [
            "guard",
            "hook",
            "--home",
            str(home_dir),
            "--workspace",
            str(workspace_dir),
            "--harness",
            "codex",
        ]
    )
    captured = capsys.readouterr()
    payload = json.loads(captured.out)

    assert rc == 0
    assert payload["continue"] is True
    assert "credential-looking output" in payload["stopReason"]


def test_guard_hook_codex_post_tool_use_explains_merged_stderr_capture(
    tmp_path,
    capsys,
    monkeypatch,
):
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    _build_guard_fixture(home_dir, workspace_dir)
    event = {
        "hook_event_name": "PostToolUse",
        "tool_name": "Bash",
        "tool_input": {
            "command": (
                "cd sub && .venv/bin/python -m pytest "
                "tests/test_guard_harness_smoke.py::TestSmokeEvidenceTemplate::"
                'test_release_checklist_references_smoke_evidence -q 2>&1; echo "__EXIT_CODE__:$?"'
            )
        },
        "tool_response": {"stdout": "HOL_GUARD_FAKE_CREDENTIAL=fixture-only\n"},
        "source_scope": "project",
    }
    monkeypatch.setenv("CODEX_HOME", str(home_dir / ".codex"))
    monkeypatch.setattr(
        guard_commands_module, "schedule_guard_daemon_ensure", lambda _guard_home, **_kwargs: "http://127.0.0.1:4455"
    )

    monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps(event)))
    rc = main(
        [
            "guard",
            "hook",
            "--home",
            str(home_dir),
            "--workspace",
            str(workspace_dir),
            "--harness",
            "codex",
            "--policy-action",
            "block",
        ]
    )
    captured = capsys.readouterr()
    payload = json.loads(captured.out)

    assert rc == 0
    assert payload["continue"] is True
    assert "Combined stdout/stderr looked credential-like before it reached Codex." in payload["stopReason"]
    assert payload["stopReason"].count("terminal policy decision") == 1
    assert "Browser approval cannot override it" in payload["stopReason"]
    assert "/requests/" not in payload["stopReason"]


def test_codex_post_tool_output_allows_focused_pytest_fake_credential_fixture(tmp_path):
    artifact = _codex_post_tool_output_artifact(
        payload={
            "tool_name": "Bash",
            "tool_input": {
                "command": (
                    "python3 -m pytest "
                    "tests/test_guard_harness_smoke.py::TestSmokeEvidenceTemplate::"
                    "test_release_checklist_references_smoke_evidence -q"
                )
            },
            "tool_response": {"stdout": "fake_credential=fixture-only\n"},
        },
        config_path="codex.json",
        source_scope="project",
        cwd=tmp_path,
        home_dir=tmp_path,
    )

    assert artifact is None


def test_codex_post_tool_output_allows_focused_pytest_fixture_with_status_noise(tmp_path):
    artifact = _codex_post_tool_output_artifact(
        payload={
            "tool_name": "Bash",
            "tool_input": {
                "command": (
                    "python3 -m pytest "
                    "tests/test_guard_harness_smoke.py::TestSmokeEvidenceTemplate::"
                    "test_release_checklist_references_smoke_evidence -q -s"
                )
            },
            "tool_response": {
                "stdout": "fake_credential=fixture-only\n.\n1 passed in 0.02s\n",
            },
        },
        config_path="codex.json",
        source_scope="project",
        cwd=tmp_path,
        home_dir=tmp_path,
    )

    assert artifact is None


def test_codex_post_tool_output_does_not_requeue_package_request_after_pretool_block(tmp_path):
    home_dir = tmp_path / "home"
    guard_home = home_dir / ".hol-guard"
    workspace_dir = tmp_path / "workspace"
    guard_home.mkdir(parents=True, exist_ok=True)
    workspace_dir.mkdir(parents=True, exist_ok=True)

    artifact = guard_commands_module._hook_runtime_artifact(
        harness="codex",
        payload={
            "hook_event_name": "PostToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": "npm install -g @getpaseo/cli"},
            "tool_response": {
                "stdout": (
                    "HOL Guard blocked `@getpaseo/cli` before install.\n"
                    "Open HOL Guard to approve or keep this blocked.\n"
                )
            },
            "source_scope": "project",
            "pre_execution_result": "block",
        },
        action_envelope=None,
        data_flow_signals=(),
        home_dir=home_dir,
        guard_home=guard_home,
        workspace=workspace_dir,
    )

    assert artifact is None


def test_codex_post_tool_output_does_not_requeue_package_request_after_camelcase_pretool_block(tmp_path):
    home_dir = tmp_path / "home"
    guard_home = home_dir / ".hol-guard"
    workspace_dir = tmp_path / "workspace"
    guard_home.mkdir(parents=True, exist_ok=True)
    workspace_dir.mkdir(parents=True, exist_ok=True)
    payload = guard_commands_module._normalize_hook_payload(
        {
            "hookEventName": "PostToolUse",
            "toolName": "Bash",
            "toolInput": {"command": "npm install -g @getpaseo/cli"},
            "tool_response": {
                "stdout": (
                    "HOL Guard blocked `@getpaseo/cli` before install.\n"
                    "Open HOL Guard to approve or keep this blocked.\n"
                )
            },
            "sourceScope": "project",
            "preExecutionResult": "block",
        },
        harness="codex",
    )

    artifact = guard_commands_module._hook_runtime_artifact(
        harness="codex",
        payload=payload,
        action_envelope=None,
        data_flow_signals=(),
        home_dir=home_dir,
        guard_home=guard_home,
        workspace=workspace_dir,
    )

    assert payload["pre_execution_result"] == "block"
    assert artifact is None


def test_guard_hook_codex_post_tool_use_blocks_focused_pytest_medium_secret_output(
    tmp_path,
    capsys,
    monkeypatch,
):
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    _build_guard_fixture(home_dir, workspace_dir)
    event = {
        "hook_event_name": "PostToolUse",
        "tool_name": "Bash",
        "tool_input": {
            "command": (
                "python3 -m pytest "
                "tests/test_guard_harness_smoke.py::TestSmokeEvidenceTemplate::"
                "test_release_checklist_references_smoke_evidence -q"
            )
        },
        "tool_response": {"stdout": "Authorization: Bearer guardfixturetoken123456\n"},
        "source_scope": "project",
    }
    monkeypatch.setenv("CODEX_HOME", str(home_dir / ".codex"))
    monkeypatch.setattr(
        guard_commands_module, "schedule_guard_daemon_ensure", lambda _guard_home, **_kwargs: "http://127.0.0.1:4455"
    )

    monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps(event)))
    rc = main(
        [
            "guard",
            "hook",
            "--home",
            str(home_dir),
            "--workspace",
            str(workspace_dir),
            "--harness",
            "codex",
            "--policy-action",
            "block",
        ]
    )
    captured = capsys.readouterr()
    payload = json.loads(captured.out)

    assert rc == 0
    assert payload["continue"] is True
    assert "Focused pytest emitted credential-looking output before it reached Codex." in payload["stopReason"]
    assert "Pytest can execute repository-controlled code" in payload["stopReason"]
    assert payload["stopReason"].count("terminal policy decision") == 1
    assert "Browser approval cannot override it" in payload["stopReason"]
    assert "/requests/" not in payload["stopReason"]


def test_guard_hook_codex_post_tool_use_queues_retryable_browser_approval(
    tmp_path,
    capsys,
    monkeypatch,
):
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    _build_guard_fixture(home_dir, workspace_dir)
    _write_text(home_dir / "config.toml", "approval_wait_timeout_seconds = 2\n")
    event = {
        "hook_event_name": "PostToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": "cat .authrc"},
        "tool_response": {"stdout": "HOL_GUARD_FAKE_CREDENTIAL=fixture-only\n"},
        "source_scope": "project",
    }
    monkeypatch.setenv("CODEX_HOME", str(home_dir / ".codex"))
    monkeypatch.setattr(
        guard_commands_module, "schedule_guard_daemon_ensure", lambda _guard_home, **_kwargs: "http://127.0.0.1:4455"
    )
    store = GuardStore(home_dir)
    _install_fake_guard_surface_daemon(monkeypatch, store)

    monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps(event)))

    rc = main(
        [
            "guard",
            "hook",
            "--home",
            str(home_dir),
            "--workspace",
            str(workspace_dir),
            "--harness",
            "codex",
        ]
    )
    captured = capsys.readouterr()

    assert rc == 0
    payload = json.loads(captured.out)
    assert payload["decision"] == "block"
    assert payload["continue"] is True
    assert "Traceback" not in captured.err
    pending = store.list_approval_requests(limit=10)
    assert len(pending) == 1
    assert f"/requests/{pending[0]['request_id']}" in payload["reason"]


def test_guard_hook_codex_direct_denial_does_not_inline_complete_browser_approval(
    tmp_path,
    capsys,
    monkeypatch,
):
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    _build_guard_fixture(home_dir, workspace_dir)
    _write_text(home_dir / "config.toml", "approval_wait_timeout_seconds = 2\n")
    event = {
        "hook_event_name": "PostToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": "cat .authrc"},
        "tool_response": {"stdout": "HOL_GUARD_FAKE_CREDENTIAL=fixture-only\n"},
        "source_scope": "project",
    }
    monkeypatch.setenv("CODEX_HOME", str(home_dir / ".codex"))
    monkeypatch.setattr(
        guard_commands_module, "schedule_guard_daemon_ensure", lambda _guard_home, **_kwargs: "http://127.0.0.1:4455"
    )
    store = GuardStore(home_dir)
    _install_fake_guard_surface_daemon(monkeypatch, store)

    def tighten_policy_then_approve() -> None:
        for _ in range(40):
            pending = store.list_approval_requests(limit=10)
            if pending:
                _write_text(
                    home_dir / "config.toml",
                    ('approval_wait_timeout_seconds = 2\n[harnesses.codex]\ndefault_action = "block"\n'),
                )
                apply_approval_resolution(
                    store=store,
                    request_id=str(pending[0]["request_id"]),
                    action="allow",
                    scope="artifact",
                    workspace=None,
                    reason="approved stale browser request",
                )
                return
            threading.Event().wait(0.05)

    worker = threading.Thread(target=tighten_policy_then_approve, daemon=True)
    worker.start()
    monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps(event)))

    rc = main(
        [
            "guard",
            "hook",
            "--home",
            str(home_dir),
            "--workspace",
            str(workspace_dir),
            "--harness",
            "codex",
        ]
    )
    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    worker.join(timeout=3)

    assert rc == 0
    assert not worker.is_alive()
    assert payload["decision"] == "block"
    assert payload["continue"] is True
    tool_receipts = [
        receipt
        for receipt in store.list_receipts(limit=20)
        if receipt["provenance_summary"] != "Guard approval decision"
    ]
    assert len(tool_receipts) == 1
    assert tool_receipts[0]["policy_decision"] == "block"
    assert tool_receipts[0]["approval_source"] == "browser"
