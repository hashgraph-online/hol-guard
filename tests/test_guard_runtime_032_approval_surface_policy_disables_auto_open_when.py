"""Runtime regression tests: approval surface policy disables auto open when."""

from __future__ import annotations

from tests.guard_runtime_test_dependencies import (
    GuardStore,
    emit_guard_payload,
    guard_commands_module,
    io,
    json,
    main,
    sys,
)
from tests.guard_runtime_test_support import (
    _build_guard_fixture,
    _write_text,
)
from tests.guard_runtime_test_support import (
    _isolate_codex_runtime_marker as _isolate_codex_runtime_marker,
)


def test_approval_surface_policy_disables_auto_open_when_flow_forbids_browser():
    assert (
        guard_commands_module._approval_surface_policy_for_flow(
            "auto-open-once",
            {"tier": "approval-center", "auto_open_browser": False, "prompt_channel": "native-fallback"},
        )
        == "never-auto-open"
    )


def test_hermes_pretool_does_not_queue_terminal_blocks_for_same_channel_delivery(
    tmp_path,
    capsys,
    monkeypatch,
):
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir(parents=True, exist_ok=True)
    _write_text(home_dir / "config.toml", 'mode = "prompt"\napproval_surface_policy = "auto-open-once"\n')
    GuardStore(home_dir).set_managed_install(
        "hermes",
        True,
        str(workspace_dir),
        {"capabilities": {"same_channel": True}},
        "2026-04-15T00:00:00+00:00",
    )

    captured_surface_policy: list[str] = []

    class _FakeDaemonClient:
        def start_session(self, **kwargs) -> dict[str, object]:
            return {"session_id": "session-1"}

        def queue_blocked_operation(self, **kwargs) -> dict[str, object]:
            captured_surface_policy.append(str(kwargs["approval_surface_policy"]))
            return {
                "operation": {"operation_id": "operation-1"},
                "approval_requests": [{"request_id": "request-1"}],
            }

    monkeypatch.setattr(
        guard_commands_module, "schedule_guard_daemon_ensure", lambda _guard_home, **_kwargs: "http://127.0.0.1:4455"
    )
    monkeypatch.setattr(
        guard_commands_module,
        "load_guard_surface_daemon_client",
        lambda _guard_home: _FakeDaemonClient(),
    )
    monkeypatch.setattr(
        sys,
        "stdin",
        io.StringIO(
            json.dumps(
                {
                    "event": "PreToolUse",
                    "tool_name": "shell",
                    "tool_input": {"command": "docker login ghcr.io", "docker_mode": True},
                    "source_scope": "project",
                }
            )
        ),
    )

    rc = main(
        [
            "hermes",
            "pretool",
            "--home",
            str(home_dir),
            "--workspace",
            str(workspace_dir),
            "--json",
        ]
    )
    output = json.loads(capsys.readouterr().out)

    assert rc == 2
    assert captured_surface_policy == []
    assert output["decision"] == "block"
    assert "approval_delivery" not in output


def test_guard_run_dry_run_human_output_is_summary_first(tmp_path, capsys):
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    _build_guard_fixture(home_dir, workspace_dir)

    rc = main(
        [
            "guard",
            "run",
            "codex",
            "--home",
            str(home_dir),
            "--workspace",
            str(workspace_dir),
            "--dry-run",
        ]
    )
    output = capsys.readouterr().out

    assert rc == 1
    assert "What changed" in output
    assert "Next step" in output
    assert "rerun without --dry-run" in output.lower()
    assert "Fields" not in output
    assert "first_seen" not in output


def test_guard_run_renderer_coalesces_replaced_artifacts(capsys):
    emit_guard_payload(
        "run",
        {
            "harness": "codex",
            "blocked": True,
            "dry_run": True,
            "launched": False,
            "receipts_recorded": 2,
            "artifacts": [
                {
                    "artifact_id": "codex:project:chrome-devtools:new",
                    "artifact_name": "chrome-devtools",
                    "changed": True,
                    "changed_fields": ["first_seen"],
                    "policy_action": "require-reapproval",
                    "artifact_label": "MCP server",
                    "why_now": "It is new in this codex workspace, so Guard paused it for review.",
                    "risk_summary": "Connects to a remote server.",
                },
                {
                    "artifact_id": "codex:project:chrome-devtools:old",
                    "artifact_name": "chrome-devtools",
                    "changed": True,
                    "changed_fields": ["removed"],
                    "policy_action": "require-reapproval",
                    "artifact_label": "MCP server",
                    "why_now": (
                        "It disappeared from the harness config, so Guard paused the change until you "
                        "confirm the removal."
                    ),
                },
            ],
        },
        False,
    )
    output = capsys.readouterr().out

    assert "chrome-devtools" in output
    assert output.lower().count("chrome-devtools") == 1
    assert "definition" in output.lower()
    assert "replaced" in output.lower()
    assert "first_seen" not in output
    assert "removed" not in output


def test_guard_run_renderer_keeps_same_named_artifacts_separate_across_configs(capsys):
    emit_guard_payload(
        "run",
        {
            "harness": "codex",
            "blocked": True,
            "dry_run": True,
            "launched": False,
            "receipts_recorded": 2,
            "artifacts": [
                {
                    "artifact_id": "codex:project:chrome-devtools:new",
                    "artifact_name": "chrome-devtools",
                    "changed": True,
                    "changed_fields": ["first_seen"],
                    "policy_action": "require-reapproval",
                    "artifact_label": "MCP server",
                    "source_scope": "project",
                    "config_path": "/workspace/.codex/config.toml",
                    "why_now": "It is new in this codex workspace, so Guard paused it for review.",
                },
                {
                    "artifact_id": "codex:global:chrome-devtools:old",
                    "artifact_name": "chrome-devtools",
                    "changed": True,
                    "changed_fields": ["removed"],
                    "policy_action": "require-reapproval",
                    "artifact_label": "MCP server",
                    "source_scope": "global",
                    "config_path": "/home/.codex/config.toml",
                    "why_now": (
                        "It disappeared from the global harness config, so Guard paused the change until "
                        "you confirm the removal."
                    ),
                },
            ],
        },
        False,
    )
    output = capsys.readouterr().out

    assert "chrome-devtools" in output
    assert output.lower().count("chrome-devtools") == 2
    assert "definition replaced" not in output.lower()


def test_guard_run_renderer_filters_unchanged_artifacts_and_counts_review_items(capsys):
    emit_guard_payload(
        "run",
        {
            "harness": "codex",
            "blocked": True,
            "dry_run": True,
            "launched": False,
            "receipts_recorded": 3,
            "artifacts": [
                {
                    "artifact_id": "codex:project:stable-tool",
                    "artifact_name": "stable-tool",
                    "changed": False,
                    "changed_fields": [],
                    "policy_action": "allow",
                    "why_now": "Guard matched an existing allow rule for this exact version.",
                },
                {
                    "artifact_id": "codex:project:already-approved",
                    "artifact_name": "already-approved",
                    "changed": True,
                    "changed_fields": ["command"],
                    "policy_action": "allow",
                    "why_now": "Guard matched an existing allow rule for this exact definition.",
                },
                {
                    "artifact_id": "codex:project:review-tool",
                    "artifact_name": "review-tool",
                    "changed": True,
                    "changed_fields": ["first_seen"],
                    "policy_action": "require-reapproval",
                    "why_now": "It is new in this codex workspace, so Guard paused it for review.",
                },
            ],
        },
        False,
    )
    output = capsys.readouterr().out

    assert "stable-tool" not in output
    assert "already-approved" in output
    assert "review-tool" in output
    assert "Needs review 1" in output


def test_guard_run_renderer_explains_authority_contract_failure_without_stale_allow_copy(capsys):
    emit_guard_payload(
        "run",
        {
            "harness": "codex",
            "blocked": True,
            "dry_run": False,
            "launched": False,
            "receipts_recorded": 0,
            "authority_error": "authoritative_decision_inconsistent",
            "authority_error_message": ("Guard detected contradictory decision fields and refused to launch."),
            "artifacts": [
                {
                    "artifact_id": "codex:project:stale-allow",
                    "artifact_name": "stale-allow",
                    "changed": False,
                    "changed_fields": [],
                    "policy_action": "allow",
                }
            ],
        },
        False,
    )
    output = capsys.readouterr().out

    assert "Launch refused: inconsistent decision" in output
    assert "authoritative_decision_inconsistent" in output
    assert "Guard detected contradictory decision fields and refused to" in output
    assert "launch." in output
    assert "Repair and rescan Guard authority" in output
    assert "hol-guard doctor codex" in output
    assert "Needs review 0" not in output
    assert "stale-allow" not in output


def test_guard_run_renderer_keeps_unchanged_blockers_visible(capsys):
    emit_guard_payload(
        "run",
        {
            "harness": "codex",
            "blocked": True,
            "dry_run": True,
            "launched": False,
            "receipts_recorded": 1,
            "artifacts": [
                {
                    "artifact_id": "codex:project:blocked-tool",
                    "artifact_name": "blocked-tool",
                    "changed": False,
                    "changed_fields": [],
                    "policy_action": "require-reapproval",
                    "why_now": "Guard blocked this definition because the configured policy does not trust it yet.",
                }
            ],
        },
        False,
    )
    output = capsys.readouterr().out

    assert "blocked-tool" in output
    assert "Needs review 1" in output


def test_guard_run_renderer_counts_each_visible_blocker_even_when_rows_coalesce(capsys):
    emit_guard_payload(
        "run",
        {
            "harness": "codex",
            "blocked": True,
            "dry_run": True,
            "launched": False,
            "receipts_recorded": 2,
            "artifacts": [
                {
                    "artifact_id": "codex:project:chrome-devtools:new",
                    "artifact_name": "chrome-devtools",
                    "changed": True,
                    "changed_fields": ["first_seen"],
                    "policy_action": "require-reapproval",
                    "why_now": "It is new in this codex workspace, so Guard paused it for review.",
                },
                {
                    "artifact_id": "codex:project:chrome-devtools:old",
                    "artifact_name": "chrome-devtools",
                    "changed": True,
                    "changed_fields": ["removed"],
                    "policy_action": "require-reapproval",
                    "why_now": (
                        "It disappeared from the harness config, so Guard paused the change until you confirm it."
                    ),
                },
            ],
        },
        False,
    )
    output = capsys.readouterr().out

    assert "Needs review 2" in output
    assert output.lower().count("chrome-devtools") == 1


def test_guard_run_renderer_leads_blocked_dry_runs_with_full_review_path(capsys):
    emit_guard_payload(
        "run",
        {
            "harness": "codex",
            "blocked": True,
            "dry_run": True,
            "launched": False,
            "receipts_recorded": 1,
            "artifacts": [
                {
                    "artifact_id": "codex:project:blocked-tool",
                    "artifact_name": "blocked-tool",
                    "changed": False,
                    "changed_fields": [],
                    "policy_action": "require-reapproval",
                    "why_now": "Guard blocked this definition because the configured policy does not trust it yet.",
                }
            ],
        },
        False,
    )
    output = capsys.readouterr().out

    assert "Resolve the blocked launch" in output
    assert "hol-guard run codex" in output
    assert "Inspect only the changed config entries (optional)" in output
    assert "hol-guard diff codex" in output


def test_guard_run_renderer_counts_only_blocking_actions_as_needing_review(capsys):
    emit_guard_payload(
        "run",
        {
            "harness": "codex",
            "blocked": True,
            "dry_run": True,
            "launched": False,
            "receipts_recorded": 2,
            "artifacts": [
                {
                    "artifact_id": "codex:project:warn-only-tool",
                    "artifact_name": "warn-only-tool",
                    "changed": True,
                    "changed_fields": ["command"],
                    "policy_action": "warn",
                    "why_now": "Guard wants to highlight this change, but it does not block launch.",
                },
                {
                    "artifact_id": "codex:project:blocked-tool",
                    "artifact_name": "blocked-tool",
                    "changed": True,
                    "changed_fields": ["first_seen"],
                    "policy_action": "require-reapproval",
                    "why_now": "Guard blocked this definition because the configured policy does not trust it yet.",
                },
            ],
        },
        False,
    )
    output = capsys.readouterr().out

    assert "warn-only-tool" in output
    assert "blocked-tool" in output
    assert "Needs review 1" in output


def test_guard_run_renderer_uses_neutral_blocked_copy_for_policy_only_blockers(capsys):
    emit_guard_payload(
        "run",
        {
            "harness": "codex",
            "blocked": True,
            "dry_run": True,
            "launched": False,
            "receipts_recorded": 1,
            "artifacts": [
                {
                    "artifact_id": "codex:project:blocked-tool",
                    "artifact_name": "blocked-tool",
                    "changed": False,
                    "changed_fields": [],
                    "policy_action": "require-reapproval",
                    "why_now": "Guard blocked this definition because the configured policy does not trust it yet.",
                }
            ],
        },
        False,
    )
    output = capsys.readouterr().out

    assert "Guard found changes that need review before a real launch." not in output
    assert "Guard found artifacts that need review before a real launch." in output
