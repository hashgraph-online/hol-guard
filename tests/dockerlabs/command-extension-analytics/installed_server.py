#!/usr/bin/env python3
"""Installed-wheel daemon fixture for the command extension analytics lab."""

from __future__ import annotations

import hashlib
import json
import os
import signal
import sys
import threading
from datetime import datetime, timezone
from pathlib import Path

from codex_plugin_scanner import __version__
from codex_plugin_scanner.guard.cli.commands_support_command_activity import (
    record_post_hook_command_activity_best_effort,
    record_pre_hook_command_activity_best_effort,
)
from codex_plugin_scanner.guard.daemon.server import GuardDaemonServer
from codex_plugin_scanner.guard.local_dashboard_session import build_local_dashboard_session_token
from codex_plugin_scanner.guard.runtime.command_activity_contract import (
    ActivityApprovalReuseStatus,
    ActivityDecisionReason,
)
from codex_plugin_scanner.guard.runtime.command_activity_lifecycle import (
    CommandActivityDecisionFacts,
    build_pre_hook_evidence,
)
from codex_plugin_scanner.guard.runtime.command_evaluation import evaluate_command
from codex_plugin_scanner.guard.runtime.containment_contract import ContainmentPolicy, ContainmentRequest
from codex_plugin_scanner.guard.runtime.containment_executor import execute_contained, file_sha256
from codex_plugin_scanner.guard.store import GuardStore

GUARD_HOME = Path("/guard-home")
WORKSPACE = Path("/workspace")
SENTINEL = "guard-private-command-sentinel"


def _record_real_harnesses(store: GuardStore) -> None:
    codex = {
        "tool_name": "Shell",
        "tool_input": {"command": "git push --force origin HEAD"},
        "tool_call_id": "codex_lab_0000000000000001",
    }
    claude = {
        "tool_name": "Bash",
        "tool_input": {"command": "git push --delete origin stale-lab-branch"},
        "tool_use_id": "claude_lab_0000000000000001",
    }
    cursor = {
        "tool_name": "Shell",
        "tool_input": {"command": f"git push --force https://{SENTINEL}@example.invalid/repo HEAD"},
        "generation_id": "cursor_lab_0000000000000001",
        "cursor_source_hook_event": "beforeShellExecution",
    }
    assert record_pre_hook_command_activity_best_effort(
        store=store,
        guard_home=GUARD_HOME,
        harness="codex",
        event="PreToolUse",
        payload=codex,
        policy_action="allow",
        receipt_id=None,
        prompted=False,
        cwd=WORKSPACE,
        home_dir=GUARD_HOME,
    )
    assert record_post_hook_command_activity_best_effort(
        store=store,
        guard_home=GUARD_HOME,
        harness="codex",
        event="PostToolUse",
        payload=codex,
        succeeded=True,
    )
    assert record_pre_hook_command_activity_best_effort(
        store=store,
        guard_home=GUARD_HOME,
        harness="claude-code",
        event="PreToolUse",
        payload=claude,
        policy_action="review",
        receipt_id="receipt:claude-review",
        prompted=True,
        cwd=WORKSPACE,
        home_dir=GUARD_HOME,
    )
    assert record_pre_hook_command_activity_best_effort(
        store=store,
        guard_home=GUARD_HOME,
        harness="cursor",
        event="PreToolUse",
        payload=cursor,
        policy_action="block",
        receipt_id="receipt:cursor-block",
        prompted=False,
        cwd=WORKSPACE,
        home_dir=GUARD_HOME,
    )


def _record_reason(store: GuardStore, *, activity_id: str, command: str, reason: ActivityDecisionReason) -> None:
    evaluation = evaluate_command(command)
    assert evaluation.matches
    evidence = build_pre_hook_evidence(
        evaluation,
        CommandActivityDecisionFacts(
            policy_action="allow",
            decision_reason_code=reason,
            prompted=False,
            approval_reuse_status=ActivityApprovalReuseStatus.NOT_APPLICABLE,
            receipt_id=None,
        ),
        activity_id=activity_id,
        occurred_at=datetime.now(timezone.utc),
        harness="codex",
    )
    assert store.record_command_activity(evidence)


def _seed_once(store: GuardStore) -> None:
    if store.count_command_activities() > 0:
        return
    _record_real_harnesses(store)
    _record_reason(
        store,
        activity_id="lab:contained",
        command="git push --force origin contained-proof",
        reason=ActivityDecisionReason.CONTAINMENT,
    )
    _record_reason(
        store,
        activity_id="lab:workflow",
        command="git push --force origin workflow-proof",
        reason=ActivityDecisionReason.CAPABILITY,
    )


def _containment_probe() -> dict[str, object]:
    protected = WORKSPACE / ".guard"
    protected.mkdir(exist_ok=True)
    secret_file = protected / "credentials.json"
    _ = secret_file.write_text(SENTINEL, encoding="utf-8")
    output = WORKSPACE / "output"
    output.mkdir(exist_ok=True)
    executable = "/usr/bin/dash"
    request = ContainmentRequest(
        argv=(executable, "-c", f"cat {secret_file}"),
        cwd=str(WORKSPACE),
        environment=(("PATH", "/usr/bin:/bin"),),
        policy=ContainmentPolicy(str(WORKSPACE), (str(output),)),
        inputs=(),
        launch_digest=hashlib.sha256(b"installed-command-analytics-lab").hexdigest(),
        executable_digest=file_sha256(executable),
        operation_id="installed.analytics.probe",
    )
    result = execute_contained(request, timeout_seconds=5)
    return {
        "enforced": result.enforced,
        "exit_code": result.exit_code,
        "protected_value_unchanged": secret_file.read_text(encoding="utf-8") == SENTINEL,
        "secret_hidden": SENTINEL not in result.stdout and SENTINEL not in result.stderr,
    }


def _installed_origin() -> str:
    package_file = Path(sys.modules["codex_plugin_scanner"].__file__ or "").resolve(strict=True)
    if "site-packages" not in package_file.parts or "/workspace" in str(package_file):
        raise RuntimeError("lab must import Guard only from installed site-packages")
    return str(package_file)


def main() -> None:
    expected = os.environ["HOL_GUARD_LAB_EXPECTED_VERSION"]
    if __version__ != expected:
        raise RuntimeError(f"installed version mismatch: expected {expected}, got {__version__}")
    GUARD_HOME.mkdir(parents=True, exist_ok=True)
    store = GuardStore(GUARD_HOME, prime_policy_integrity=False)
    _seed_once(store)
    containment = _containment_probe()
    if containment != {
        "enforced": True,
        "exit_code": 1,
        "protected_value_unchanged": True,
        "secret_hidden": True,
    }:
        raise RuntimeError(f"containment probe failed: {containment}")
    daemon = GuardDaemonServer(
        store,
        host="0.0.0.0",
        port=4781,
        bundle_refresh_interval_seconds=None,
        aibom_refresh_interval_seconds=None,
        home_dir=GUARD_HOME,
        workspace_dir=WORKSPACE,
    )
    daemon.start()
    auth_token = daemon._server.auth_token  # pyright: ignore[reportPrivateUsage]
    session = build_local_dashboard_session_token(auth_token=auth_token, surface="dashboard")
    print(
        "HOL_GUARD_LAB_READY "
        + json.dumps(
            {
                "activity_count": store.count_command_activities(),
                "containment": containment,
                "dashboard_session": session,
                "installed_origin": _installed_origin(),
                "version": __version__,
            },
            separators=(",", ":"),
        ),
        flush=True,
    )
    stop_requested = threading.Event()
    _ = signal.signal(signal.SIGTERM, lambda _signum, _frame: stop_requested.set())
    _ = signal.signal(signal.SIGINT, lambda _signum, _frame: stop_requested.set())
    try:
        while not stop_requested.wait(3600):
            pass
    finally:
        daemon.stop()


if __name__ == "__main__":
    main()
