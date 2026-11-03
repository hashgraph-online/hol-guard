"""Fresh policy and exact-action binding for live Codex completion."""

from __future__ import annotations

import json
import subprocess
import sys
from collections.abc import Mapping
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import codex_live_decision_revalidation as revalidation_module
from codex_plugin_scanner.guard.cli import commands_support_hook_payload as hook_payload_support
from codex_plugin_scanner.guard.cli.commands_support_hook_payload import (
    _action_envelope_json,
    _hook_action_envelope,
)
from codex_plugin_scanner.guard.codex_live_decision_revalidation import revalidate_codex_live_allow
from codex_plugin_scanner.guard.daemon.hook_worker import HookWorker
from codex_plugin_scanner.guard.native_hook_adapter import NativeHookAdapterError
from codex_plugin_scanner.guard.store import GuardStore

pytestmark = pytest.mark.usefixtures("approval_questionnaire_mode")


@pytest.fixture
def native_live_allow(
    native_hook_force: Path,
    _native_context_home: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> Path:
    """Answer the live-allow queries from the session's keyed resident.

    The precheck and the settle are decided by the native runtime, and these
    tests build throwaway homes that never had a resident of their own, so the
    queries are routed to the session home instead.
    """

    compose = revalidation_module.native_hook_compose
    monkeypatch.setattr(
        revalidation_module,
        "native_hook_compose",
        lambda kind, fields, *, guard_home: compose(kind, fields, guard_home=_native_context_home),
    )
    return _native_context_home


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
        "request_id": "request-replay",
        "artifact_hash": "approval-context-hash",
        "workspace": str(workspace),
        "action_envelope_json": _action_envelope_json(envelope),
    }
    return request, hook_payload, home_dir


def test_fresh_allow_requires_the_exact_original_action(tmp_path: Path, native_live_allow: Path) -> None:
    request, hook_payload, home_dir = _fixture(tmp_path)
    changed = {**hook_payload, "tool_input": {"command": "npm install left-pad@1.3.0"}}

    authorized = revalidate_codex_live_allow(
        request,
        {"hook_input": json.dumps(changed)},
        home_dir=home_dir,
        request_id="request-replay",
        authority_resolved=True,
        reviewer=lambda _payload, _workspace, _claimed_hash, _request_id: {
            "hookSpecificOutput": {"hookEventName": "PreToolUse"}
        },
    )

    assert authorized is False


def test_a_decision_completes_when_the_action_adapter_cannot_build_an_envelope(
    tmp_path: Path, native_live_allow: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An adapter failure refuses the fresh allow instead of escaping the handler.

    Every live decision runs this path, a deny included. An exception here would
    leave the daemon handler without a completion, and the harness waiting on it
    would never be answered.
    """

    request, hook_payload, home_dir = _fixture(tmp_path)

    def unavailable(**_kwargs: object) -> None:
        raise NativeHookAdapterError("native_hook_adapter_unavailable")

    monkeypatch.setattr(hook_payload_support, "_hook_action_envelope", unavailable)

    authorized = revalidate_codex_live_allow(
        {**request, "resolution_action": "block"},
        {"hook_input": json.dumps(hook_payload)},
        home_dir=home_dir,
        reviewer=lambda _payload, _workspace, _claimed_hash, _request_id: None,
    )

    assert authorized is False


def test_fresh_allow_rejects_a_reviewer_that_raises(tmp_path: Path, native_live_allow: Path) -> None:
    request, hook_payload, home_dir = _fixture(tmp_path)

    def raise_review(*_args: object) -> dict[str, object]:
        raise RuntimeError("native edge unavailable")

    authorized = revalidate_codex_live_allow(
        request,
        {"hook_input": json.dumps(hook_payload)},
        home_dir=home_dir,
        reviewer=raise_review,
    )

    assert authorized is False


def test_fresh_allow_rejects_policy_that_became_terminal(tmp_path: Path, native_live_allow: Path) -> None:
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


def test_fresh_allow_rejects_nonterminal_ask_output(tmp_path: Path, native_live_allow: Path) -> None:
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


def test_fresh_allow_accepts_current_policy_for_the_exact_action(tmp_path: Path, native_live_allow: Path) -> None:
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


def test_replay_binds_claimed_context_to_the_exact_input(tmp_path: Path, native_live_allow: Path) -> None:
    request, hook_payload, home_dir = _fixture(tmp_path)
    observed: list[tuple[str | None, str | None]] = []

    authorized = revalidate_codex_live_allow(
        request,
        {"hook_input": json.dumps(hook_payload)},
        home_dir=home_dir,
        previous={"resolution_action": "allow", "status": "resumed"},
        reviewer=lambda _payload, _workspace, claimed_hash, request_id: (
            observed.append((claimed_hash, request_id)) or {"hookSpecificOutput": {"hookEventName": "PreToolUse"}}
        ),
    )

    assert authorized is True
    assert observed == [("approval-context-hash", "request-replay")]


def test_explicit_home_is_part_of_exact_action_binding(tmp_path: Path, native_live_allow: Path) -> None:
    custom_home = tmp_path / "custom-home"
    workspace = tmp_path / "workspace"
    hook_payload: dict[str, object] = {
        "hook_event_name": "PreToolUse",
        "tool_name": "Read",
        "tool_input": {"file_path": "~/.config/private.toml"},
    }
    request: dict[str, object] = {
        "resolution_action": "allow",
        "request_id": "request-replay",
        "artifact_hash": "approval-context-hash",
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


@pytest.fixture
def acknowledged_live_policy(tmp_path: Path, native_hook_force):
    home = tmp_path / "home"
    workspace = tmp_path / "workspace"
    home.mkdir()
    workspace.mkdir()
    store = GuardStore(tmp_path / "guard-home")
    owner = HookWorker(store=store)
    try:
        # The daemon publishes and ACKs workspace policy before handing an
        # action to the non-publishing resident worker under test.
        snapshot = owner.prepare_workspace_policy(workspace)
        assert snapshot is not None, owner.policy_snapshot_publisher.last_error
        yield store
    finally:
        assert owner.close()


def test_first_exact_live_allow_revalidates_through_resident_worker(
    tmp_path: Path, acknowledged_live_policy: GuardStore, native_live_allow: Path
) -> None:
    home_dir = tmp_path / "home"
    guard_home = tmp_path / "guard-home"
    workspace = tmp_path / "workspace"
    payload: dict[str, object] = {
        "hook_event_name": "PreToolUse",
        "tool_name": "Read",
        "tool_input": {"file_path": str(workspace / ".npmrc")},
        "cwd": str(workspace),
    }
    store = acknowledged_live_policy
    worker = HookWorker(store=store, wait_for_native_policy=False, publish_native_policy=False)

    def review(**claims: object) -> dict[str, object]:
        return worker.review_http_payload(
            payload=dict(payload),
            params={"runtime-harness": ["codex"]},
            default_harness="codex",
            home_dir=home_dir,
            guard_home=guard_home,
            workspace=workspace,
            **claims,  # type: ignore[arg-type]
        )

    first = review()
    approvals = store.list_approval_requests(limit=1)
    assert len(approvals) == 1, first
    approval = approvals[0]
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
        return review(
            claim_saved_approval=False,
            claimed_saved_allow_hash=claimed_hash,
            claimed_approval_request_id=claimed_request_id,
        )

    authorized = revalidate_codex_live_allow(
        {**approval, "resolution_action": "allow"},
        {"hook_input": json.dumps(payload)},
        home_dir=home_dir,
        request_id=request_id,
        authority_resolved=True,
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
