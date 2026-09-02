"""Fresh policy and exact-action binding for live Codex completion."""

from __future__ import annotations

import json
import subprocess
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import cast

from codex_plugin_scanner.guard.cli.commands_support_hook_payload import (
    _action_envelope_json,
    _hook_action_envelope,
)
from codex_plugin_scanner.guard.codex_live_decision_revalidation import revalidate_codex_live_allow
from codex_plugin_scanner.guard.daemon.hook_process_entrypoint import (
    _run_resident_hook_request,  # pyright: ignore[reportPrivateUsage]
)
from codex_plugin_scanner.guard.store import GuardStore


def test_daemon_server_import_is_order_independent() -> None:
    completed = subprocess.run(
        [
            sys.executable,
            "-c",
            (
                "from codex_plugin_scanner.guard.daemon.server import GuardDaemonServer; "
                "print(GuardDaemonServer.__name__)"
            ),
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 0, completed.stderr
    assert completed.stdout.strip() == "GuardDaemonServer"


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


def test_fresh_allow_rejects_nonterminal_ask_output(tmp_path: Path) -> None:
    request, hook_payload, home_dir = _fixture(tmp_path)

    authorized = revalidate_codex_live_allow(
        request,
        {"hook_input": json.dumps(hook_payload)},
        home_dir=home_dir,
        reviewer=lambda _payload, _workspace, _claimed_hash, _request_id: {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "ask",
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
    request: dict[str, object] = {
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


def test_first_exact_live_allow_revalidates_through_resident_worker(tmp_path: Path) -> None:
    home_dir = tmp_path / "home"
    guard_home = tmp_path / "guard-home"
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    payload: dict[str, object] = {
        "hook_event_name": "PreToolUse",
        "tool_name": "Read",
        "tool_input": {"file_path": str(workspace / ".npmrc")},
        "cwd": str(workspace),
    }
    request: dict[str, object] = {
        "payload": payload,
        "harness": "codex",
        "home_dir": str(home_dir),
        "guard_home": str(guard_home),
        "workspace": str(workspace),
    }
    stores: dict[str, GuardStore] = {}
    first = _run_resident_hook_request(
        request,
        stores=stores,
        hook_workers={},
        configured_guard_home=str(guard_home),
    )
    assert first["reason_code"] is None
    store = stores[str(guard_home)]
    approval = store.list_approval_requests(limit=1)[0]
    request_id = str(approval["request_id"])
    artifact_hash = str(approval["artifact_hash"])
    assert store.resolve_one_request_only(
        request_id,
        resolution_action="allow",
        resolution_scope="artifact",
        reason="review decision",
        resolved_at="2026-08-26T04:00:00+00:00",
    )
    assert store.record_local_once_approval(
        request_id=request_id,
        harness="codex",
        artifact_id=str(approval["artifact_id"]),
        artifact_hash=artifact_hash,
        workspace=str(workspace),
        publisher=None,
        action="allow",
        created_at="2026-08-26T04:00:00+00:00",
        expires_at="2099-08-26T04:05:00+00:00",
    )

    def resident_reviewer(
        _payload: dict[str, object],
        _workspace: Path | None,
        claimed_hash: str | None,
        claimed_request_id: str | None,
    ) -> Mapping[str, object] | None:
        second = _run_resident_hook_request(
            {
                **request,
                "claim_saved_approval": False,
                "claimed_saved_allow_hash": claimed_hash,
                "claimed_trusted_request_override": True,
                "claimed_approval_request_id": claimed_request_id,
            },
            stores=stores,
            hook_workers={},
            configured_guard_home=str(guard_home),
        )
        assert second["reason_code"] is None
        second_payload = second["payload"]
        return cast(Mapping[str, object], second_payload) if isinstance(second_payload, Mapping) else None

    authorized = revalidate_codex_live_allow(
        {**approval, "resolution_action": "allow"},
        {"hook_input": json.dumps(payload)},
        home_dir=home_dir,
        claimed_saved_allow_hash=artifact_hash,
        claimed_approval_request_id=request_id,
        reviewer=resident_reviewer,
    )

    assert authorized is True
    assert store.list_approval_requests(status="pending", limit=2) == []
    assert (
        store.peek_local_once_approval(
            harness="codex",
            artifact_id=str(approval["artifact_id"]),
            artifact_hash=artifact_hash,
            workspace=str(workspace),
            publisher=None,
            now="2026-08-26T04:01:00+00:00",
        )
        is not None
    )
