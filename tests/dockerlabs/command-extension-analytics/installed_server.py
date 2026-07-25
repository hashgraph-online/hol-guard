#!/usr/bin/env python3
"""Installed-wheel daemon fixture for the command extension analytics lab."""

from __future__ import annotations

import json
import os
import signal
import sqlite3
import subprocess
import sys
import threading
import time
from collections.abc import Mapping
from pathlib import Path

from codex_plugin_scanner import __version__
from codex_plugin_scanner.guard.approval_scope_support import request_scope_contract
from codex_plugin_scanner.guard.daemon.server import GuardDaemonServer
from codex_plugin_scanner.guard.local_dashboard_session import build_local_dashboard_session_token
from codex_plugin_scanner.guard.store import GuardStore

GUARD_HOME = Path("/guard-home")
WORKSPACE = Path("/workspace")
SENTINEL = "guard-private-command-sentinel"
SESSION_HANDOFF = GUARD_HOME / ".installed-dashboard-session"
_MAX_HOOK_DIAGNOSTIC_CHARS = 2_000
_GH_EXECUTABLE = GUARD_HOME / "bin" / "gh"
_GH_FIXTURE = Path("/opt/guard-lab/github-cli-fixture.sh")
_REPOSITORY = "hashgraph-online/hol-guard"
_VIEWER = "dashboard-reviewer"
_WORKFLOW_COMMAND = f"{_GH_EXECUTABLE} issue lock 17 --repo {_REPOSITORY}"
_KEYRING_MODULE = """\
import hashlib
import os
from pathlib import Path

from keyring.backend import KeyringBackend
from keyring.errors import PasswordDeleteError


class GuardLabKeyring(KeyringBackend):
    priority = 1
    _root = Path("/guard-home/lab-keyring")

    def _path(self, service, username):
        identity = f"{service}\\0{username}".encode("utf-8")
        return self._root / hashlib.sha256(identity).hexdigest()

    def get_password(self, service, username):
        try:
            return self._path(service, username).read_text(encoding="utf-8")
        except FileNotFoundError:
            return None

    def set_password(self, service, username, password):
        self._root.mkdir(mode=0o700, exist_ok=True)
        path = self._path(service, username)
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            stream.write(password)

    def delete_password(self, service, username):
        try:
            self._path(service, username).unlink()
        except FileNotFoundError as error:
            raise PasswordDeleteError("credential unavailable") from error
"""


def _safe_hook_diagnostic(value: str) -> str:
    redacted = value.replace(SENTINEL, "[REDACTED]")
    if len(redacted) <= _MAX_HOOK_DIAGNOSTIC_CHARS:
        return redacted
    return redacted[-_MAX_HOOK_DIAGNOSTIC_CHARS:]


def _write_dashboard_session_handoff(session: str) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_CLOEXEC | os.O_NOFOLLOW
    descriptor = os.open(SESSION_HANDOFF, flags, 0o600)
    _ = os.fchmod(descriptor, 0o600)
    with os.fdopen(descriptor, "w", encoding="ascii") as stream:
        _ = stream.write(f"{session}\n")


def _run_installed_hook(
    harness: str,
    payload: Mapping[str, object],
    *,
    expected_status: int = 0,
) -> None:
    command = [
        "hol-guard",
        "guard",
        "hook",
        "--guard-home",
        str(GUARD_HOME),
        "--home",
        str(GUARD_HOME),
        "--workspace",
        str(WORKSPACE),
        "--harness",
        harness,
        "--json",
    ]
    completed = subprocess.run(
        command,
        input=json.dumps(payload),
        capture_output=True,
        check=False,
        cwd=WORKSPACE,
        encoding="utf-8",
        env={**os.environ, "HOME": str(GUARD_HOME)},
        timeout=30,
    )
    if completed.returncode != expected_status:
        diagnostic = (
            f"installed {harness} hook returned {completed.returncode}, expected {expected_status}; "
            + f"stdout={_safe_hook_diagnostic(completed.stdout)!r}; "
            + f"stderr={_safe_hook_diagnostic(completed.stderr)!r}"
        )
        raise RuntimeError(diagnostic)


def _invoke_real_harnesses() -> int:
    codex_pre = {
        "hook_event_name": "PreToolUse",
        "tool_name": "Shell",
        "tool_input": {"command": "git diff --stat"},
        "tool_call_id": "codex_lab_0000000000000001",
    }
    codex_post = {**codex_pre, "hook_event_name": "PostToolUse", "success": True}
    claude_no_post = {
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": "git status --short"},
        "tool_use_id": "claude_lab_0000000000000001",
    }
    claude_review = {
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": "git push --delete origin stale-lab-branch"},
        "tool_use_id": "claude_lab_0000000000000002",
    }
    cursor_block = {
        "hook_event_name": "PreToolUse",
        "tool_name": "Shell",
        "tool_input": {"command": f"shutdown -h now # {SENTINEL}"},
        "generation_id": "cursor_lab_0000000000000001",
        "cursor_source_hook_event": "beforeShellExecution",
    }
    _run_installed_hook("codex", codex_pre)
    _run_installed_hook("codex", codex_post)
    _run_installed_hook("claude-code", claude_no_post)
    _run_installed_hook("claude-code", claude_review, expected_status=1)
    _run_installed_hook("cursor", cursor_block, expected_status=1)
    return 2


def _pending_workflow_request(store: GuardStore) -> dict[str, object]:
    payload = {
        "hook_event_name": "PreToolUse",
        "tool_name": "Shell",
        "tool_input": {"command": _WORKFLOW_COMMAND},
        "tool_call_id": "codex_lab_workflow_initial_0001",
    }
    _run_installed_hook("codex", payload, expected_status=1)
    pending = [
        request
        for request in store.list_approval_requests(status="pending", harness="codex")
        if request.get("artifact_name") == "Shell GitHub bounded maintenance command"
    ]
    if len(pending) != 1:
        raise RuntimeError(f"workflow approval request mismatch: {pending!r}")
    contract = request_scope_contract(pending[0])
    if not contract.task_capability_eligible or "artifact" not in contract.allow_scopes:
        raise RuntimeError("workflow request did not expose the exact task-capability contract")
    request_id = pending[0].get("request_id")
    if not isinstance(request_id, str) or not request_id:
        raise RuntimeError("workflow request omitted its identifier")
    return {
        "request_id": request_id,
        "scope_contract_digest": contract.digest,
        "scope_contract_version": contract.version,
    }


def _await_exact_allow(store: GuardStore, request_id: str) -> None:
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        request = store.get_approval_request(request_id)
        if request is not None and request.get("status") == "resolved":
            if request.get("resolution_action") != "allow" or request.get("resolution_scope") != "artifact":
                raise RuntimeError("workflow request resolved outside its exact contract")
            issued = store.list_events(event_name="workflow_capability.issued")
            claimed = store.list_events(event_name="workflow_capability.claimed")
            if len(issued) == 1 and not claimed:
                return
        time.sleep(0.05)
    raise RuntimeError("workflow request and capability issuance did not complete")


def _assert_capability_event_privacy(store: GuardStore) -> None:
    events = store.list_events(event_name="workflow_capability.issued") + store.list_events(
        event_name="workflow_capability.claimed"
    )
    encoded = json.dumps(events, sort_keys=True, separators=(",", ":"))
    forbidden = (_WORKFLOW_COMMAND, _REPOSITORY, _VIEWER, str(_GH_EXECUTABLE), SENTINEL)
    if any(value in encoded for value in forbidden):
        raise RuntimeError("workflow capability events exposed private execution context")


def _complete_workflow_authorization(store: GuardStore, request_id: str) -> dict[str, object]:
    _await_exact_allow(store, request_id)
    issued = store.list_events(event_name="workflow_capability.issued")
    if len(issued) != 1 or store.list_events(event_name="workflow_capability.claimed"):
        raise RuntimeError("workflow capability issuance did not remain unclaimed")
    original = _GH_EXECUTABLE.read_bytes()
    _ = _GH_EXECUTABLE.write_bytes(original + b"\n# executable-drift\n")
    _GH_EXECUTABLE.chmod(0o700)
    drift = {
        "hook_event_name": "PreToolUse",
        "tool_name": "Shell",
        "tool_input": {"command": _WORKFLOW_COMMAND},
        "tool_call_id": "codex_lab_workflow_drift_0002",
    }
    _run_installed_hook("codex", drift, expected_status=1)
    if len(store.list_events(event_name="workflow_capability.issued")) != 1:
        raise RuntimeError("executable drift changed capability issuance")
    if store.list_events(event_name="workflow_capability.claimed"):
        raise RuntimeError("executable drift depleted the one-shot capability")
    _ = _GH_EXECUTABLE.write_bytes(original)
    _GH_EXECUTABLE.chmod(0o700)
    retry = {**drift, "tool_call_id": "codex_lab_workflow_retry_0003"}
    _run_installed_hook("codex", retry)
    claimed = store.list_events(event_name="workflow_capability.claimed")
    if len(claimed) != 1:
        raise RuntimeError("restored workflow retry did not claim exactly once")
    _assert_capability_event_privacy(store)
    return {
        "activity_proof": "drift-rejected-restored-one-shot-reuse",
        "capability_claimed": 1,
        "capability_issued": 1,
        "drift_claimed": 0,
        "request_flow": "authenticated-daemon-api",
    }


def _prepare_workspace() -> None:
    completed = subprocess.run(
        ["git", "init", "--quiet", str(WORKSPACE)],
        capture_output=True,
        check=False,
        encoding="utf-8",
        env={**os.environ, "HOME": str(GUARD_HOME)},
        timeout=10,
    )
    if completed.returncode != 0:
        raise RuntimeError(f"workspace git initialization failed: {_safe_hook_diagnostic(completed.stderr)!r}")
    remote = subprocess.run(
        ["git", "-C", str(WORKSPACE), "remote", "get-url", "origin"],
        capture_output=True,
        check=False,
        encoding="utf-8",
        env={**os.environ, "HOME": str(GUARD_HOME)},
        timeout=10,
    )
    if remote.returncode != 0:
        configured = subprocess.run(
            ["git", "-C", str(WORKSPACE), "remote", "add", "origin", f"https://github.com/{_REPOSITORY}.git"],
            capture_output=True,
            check=False,
            encoding="utf-8",
            env={**os.environ, "HOME": str(GUARD_HOME)},
            timeout=10,
        )
        if configured.returncode != 0:
            raise RuntimeError(f"workspace remote setup failed: {_safe_hook_diagnostic(configured.stderr)!r}")
    _GH_EXECUTABLE.parent.mkdir(mode=0o700, exist_ok=True)
    _ = _GH_EXECUTABLE.write_bytes(_GH_FIXTURE.read_bytes())
    _GH_EXECUTABLE.chmod(0o700)
    os.environ["PATH"] = f"{_GH_EXECUTABLE.parent}:{os.environ.get('PATH', '')}"
    os.environ["GITHUB_TOKEN"] = SENTINEL
    keyring_module = GUARD_HOME / "guard_lab_keyring.py"
    _ = keyring_module.write_text(_KEYRING_MODULE, encoding="utf-8")
    keyring_module.chmod(0o600)
    os.environ["PYTHONPATH"] = str(GUARD_HOME)
    os.environ["PYTHON_KEYRING_BACKEND"] = "guard_lab_keyring.GuardLabKeyring"
    if str(GUARD_HOME) not in sys.path:
        sys.path.insert(0, str(GUARD_HOME))


def _completed_workflow_evidence(store: GuardStore) -> dict[str, object] | None:
    if len(store.list_events(event_name="workflow_capability.issued")) != 1:
        return None
    if len(store.list_events(event_name="workflow_capability.claimed")) != 1:
        return None
    _assert_capability_event_privacy(store)
    return {
        "activity_proof": "drift-rejected-restored-one-shot-reuse",
        "capability_claimed": 1,
        "capability_issued": 1,
        "drift_claimed": 0,
        "request_flow": "authenticated-daemon-api",
    }


def _assert_seeded_activity(store: GuardStore) -> None:
    with sqlite3.connect(store.path) as connection:
        rows = connection.execute(
            """
            select harness, hook_phase, execution_status, proof_level,
                   policy_action, decision_reason_code, match_count, prompted,
                   approval_reuse_status
            from command_activity
            order by harness, execution_status, activity_id
            """
        ).fetchall()
    expected = [
        (
            "claude-code",
            "pre",
            "allowed_unconfirmed",
            "pre_hook",
            "warn",
            "no_match",
            0,
            0,
            "not-applicable",
        ),
        (
            "claude-code",
            "pre",
            "prevented",
            "pre_hook",
            "require-reapproval",
            "extension_match",
            1,
            1,
            "not-applicable",
        ),
        ("codex", "pre", "allowed_unconfirmed", "pre_hook", "allow", "capability", 1, 0, "accepted"),
        (
            "codex",
            "post_success",
            "confirmed_success",
            "post_hook",
            "warn",
            "no_match",
            0,
            0,
            "not-applicable",
        ),
        ("codex", "pre", "prevented", "pre_hook", "require-reapproval", "extension_match", 1, 1, "not-applicable"),
        ("codex", "pre", "prevented", "pre_hook", "require-reapproval", "extension_match", 1, 1, "rejected"),
        ("cursor", "pre", "prevented", "pre_hook", "block", "extension_match", 1, 1, "not-applicable"),
    ]
    if sorted(rows) != sorted(expected):
        raise RuntimeError(f"installed hook activity mismatch: {rows!r}")


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
    _prepare_workspace()
    store = GuardStore(GUARD_HOME, prime_policy_integrity=False)
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
    try:
        workflow_authorization = _completed_workflow_evidence(store)
        prompt_free_hook_count = 2
        auth_token = daemon._server.auth_token  # pyright: ignore[reportPrivateUsage]
        session = build_local_dashboard_session_token(auth_token=auth_token, surface="dashboard")
        _write_dashboard_session_handoff(session)
        if workflow_authorization is None:
            if store.count_command_activities() != 0:
                raise RuntimeError("incomplete workflow authorization state cannot be resumed")
            pending = _pending_workflow_request(store)
            print(
                "HOL_GUARD_LAB_PENDING "
                + json.dumps(
                    pending,
                    separators=(",", ":"),
                ),
                flush=True,
            )
            workflow_authorization = _complete_workflow_authorization(store, str(pending["request_id"]))
            prompt_free_hook_count = _invoke_real_harnesses()
        _assert_seeded_activity(store)
        print(
            "HOL_GUARD_LAB_READY "
            + json.dumps(
                {
                    "activity_count": store.count_command_activities(),
                    "installed_origin": _installed_origin(),
                    "prompt_free_hook_count": prompt_free_hook_count,
                    "version": __version__,
                    "workflow_authorization": workflow_authorization,
                },
                separators=(",", ":"),
            ),
            flush=True,
        )
        stop_requested = threading.Event()
        _ = signal.signal(signal.SIGTERM, lambda _signum, _frame: stop_requested.set())
        _ = signal.signal(signal.SIGINT, lambda _signum, _frame: stop_requested.set())
        while not stop_requested.wait(3600):
            pass
    finally:
        SESSION_HANDOFF.unlink(missing_ok=True)
        daemon.stop()


if __name__ == "__main__":
    main()
