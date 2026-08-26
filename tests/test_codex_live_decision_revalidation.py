"""Fresh policy and exact-action binding for live Codex completion."""

from __future__ import annotations

import json
from pathlib import Path

from codex_plugin_scanner.guard.cli.commands_support_hook_payload import (
    _action_envelope_json,
    _hook_action_envelope,
)
from codex_plugin_scanner.guard.codex_live_decision_revalidation import revalidate_codex_live_allow


def _fixture(tmp_path: Path) -> tuple[dict[str, object], dict[str, object], Path]:
    home_dir = tmp_path / "home"
    workspace = tmp_path / "workspace"
    hook_payload: dict[str, object] = {
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": "npm install is-even@1.0.0"},
    }
    envelope = _hook_action_envelope(
        harness="codex",
        payload=hook_payload,
        home_dir=home_dir,
        workspace=workspace,
    )
    request: dict[str, object] = {
        "resolution_action": "allow",
        "workspace": str(workspace),
        "action_envelope_json": _action_envelope_json(envelope),
    }
    return request, hook_payload, home_dir


def test_fresh_allow_requires_the_exact_original_action(tmp_path: Path) -> None:
    request, hook_payload, home_dir = _fixture(tmp_path)
    changed = {**hook_payload, "tool_input": {"command": "npm install left-pad@1.3.0"}}

    authorized = revalidate_codex_live_allow(
        request,
        {"hook_input": json.dumps(changed)},
        home_dir=home_dir,
        claimed_saved_allow_hash="approval-context-hash",
        claimed_approval_request_id="request-replay",
        reviewer=lambda _payload, _workspace, _claimed_hash, _request_id: {
            "hookSpecificOutput": {"hookEventName": "PreToolUse"}
        },
    )

    assert authorized is False


def test_fresh_allow_rejects_policy_that_became_terminal(tmp_path: Path) -> None:
    request, hook_payload, home_dir = _fixture(tmp_path)

    authorized = revalidate_codex_live_allow(
        request,
        {"hook_input": json.dumps(hook_payload)},
        home_dir=home_dir,
        reviewer=lambda _payload, _workspace, _claimed_hash, _request_id: {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
            }
        },
    )

    assert authorized is False


def test_fresh_allow_accepts_current_policy_for_the_exact_action(tmp_path: Path) -> None:
    request, hook_payload, home_dir = _fixture(tmp_path)

    authorized = revalidate_codex_live_allow(
        request,
        {"hook_input": json.dumps(hook_payload)},
        home_dir=home_dir,
        reviewer=lambda _payload, _workspace, _claimed_hash, _request_id: {
            "hookSpecificOutput": {"hookEventName": "PreToolUse"}
        },
    )

    assert authorized is True


def test_replay_binds_claimed_context_to_the_exact_input(tmp_path: Path) -> None:
    request, hook_payload, home_dir = _fixture(tmp_path)
    observed: list[tuple[str | None, str | None]] = []

    authorized = revalidate_codex_live_allow(
        request,
        {"hook_input": json.dumps(hook_payload)},
        home_dir=home_dir,
        claimed_saved_allow_hash="approval-context-hash",
        claimed_approval_request_id="request-replay",
        reviewer=lambda _payload, _workspace, claimed_hash, request_id: (
            observed.append((claimed_hash, request_id)) or {"hookSpecificOutput": {"hookEventName": "PreToolUse"}}
        ),
    )

    assert authorized is True
    assert observed == [("approval-context-hash", "request-replay")]


def test_explicit_home_is_part_of_exact_action_binding(tmp_path: Path) -> None:
    custom_home = tmp_path / "custom-home"
    workspace = tmp_path / "workspace"
    hook_payload: dict[str, object] = {
        "hook_event_name": "PreToolUse",
        "tool_name": "Read",
        "tool_input": {"file_path": "~/.config/private.toml"},
    }
    request = {
        "resolution_action": "allow",
        "workspace": str(workspace),
        "action_envelope_json": _action_envelope_json(
            _hook_action_envelope(
                harness="codex",
                payload=hook_payload,
                home_dir=custom_home,
                workspace=workspace,
            )
        ),
    }

    exact = revalidate_codex_live_allow(
        request,
        {"hook_input": json.dumps(hook_payload)},
        home_dir=custom_home,
        reviewer=lambda _payload, _workspace, _claimed_hash, _request_id: {
            "hookSpecificOutput": {"hookEventName": "PreToolUse"}
        },
    )
    wrong_home = revalidate_codex_live_allow(
        request,
        {"hook_input": json.dumps(hook_payload)},
        home_dir=tmp_path,
        reviewer=lambda _payload, _workspace, _claimed_hash, _request_id: {
            "hookSpecificOutput": {"hookEventName": "PreToolUse"}
        },
    )

    assert exact is True
    assert wrong_home is False
