"""Route ZCode's native containment receipt through its updatedInput contract."""

from __future__ import annotations

import hashlib
import json
import os
import shlex
import stat
import sys
import tempfile
import time
from collections.abc import Mapping, Sequence
from pathlib import Path

from ..codex_hook_launch_runtime import isolated_guard_cli_command

_PROFILES = {
    "native_pytest_readonly_containment_required": "pytest-readonly-v2",
    "native_node_test_readonly_containment_required": "node-test-readonly-v1",
    "native_vitest_readonly_containment_required": "vitest-readonly-v1",
    "native_package_test_readonly_containment_required": "package-test-readonly-v1",
    "native_python_eval_readonly_containment_required": "python-eval-readonly-v1",
    "native_node_eval_readonly_containment_required": "node-eval-readonly-v1",
    "native_git_readonly_containment_required": "git-readonly-v1",
    "native_node_tool_readonly_containment_required": "node-tool-readonly-v1",
    "native_node_build_output_containment_required": "node-build-output-v1",
}


def cleanup_stale_zcode_requests() -> None:
    """Reclaim abandoned private snapshots after a full day, never follow links."""
    if os.name != "posix":
        return
    cutoff = time.time() - 86_400
    try:
        with os.scandir(tempfile.gettempdir()) as entries:
            for index, entry in enumerate(entries):
                if index >= 4096:
                    break
                if not entry.name.startswith("hol-guard-contained-test-"):
                    continue
                try:
                    descriptor = os.open(entry.path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
                    try:
                        parent = os.fstat(descriptor)
                        if (
                            parent.st_uid != os.getuid()
                            or stat.S_IMODE(parent.st_mode) != 0o700
                            or parent.st_mtime > cutoff
                        ):
                            continue
                        request = os.stat("request.json", dir_fd=descriptor, follow_symlinks=False)
                        if (
                            not stat.S_ISREG(request.st_mode)
                            or request.st_uid != os.getuid()
                            or stat.S_IMODE(request.st_mode) != 0o600
                            or request.st_nlink != 1
                            or request.st_mtime > cutoff
                        ):
                            continue
                        os.unlink("request.json", dir_fd=descriptor)
                    finally:
                        os.close(descriptor)
                    os.rmdir(entry.path)
                except OSError:
                    continue
    except OSError:
        pass


def route_zcode_containment(
    response: dict[str, object],
    *,
    harness: str,
    payload: Mapping[str, object],
    guard_home: Path,
    home_dir: Path,
    workspace: Path | None,
) -> dict[str, object]:
    """Rewrite at the authority edge so frozen/stdlib hook clients also work."""
    # The execution sink needs the denial/profile receipt, not another rewrite.
    # An untrusted caller setting this flag only keeps its original call denied.
    if harness != "zcode" or workspace is None or payload.get("guard_containment_receipt_only") is True:
        return response
    config = {
        "harness": "zcode",
        "guard_home": str(guard_home),
        "python_executable": sys.executable,
        "package_root": str(Path(__file__).resolve().parents[3]),
    }
    routed = contained_zcode_response(
        response,
        input_text=json.dumps({**payload, "cwd": str(workspace)}),
        config=config,
        cli_args=["--home", str(home_dir)],
    )
    return routed if routed is not None else response


def contained_zcode_response(
    response: Mapping[str, object],
    *,
    input_text: str,
    config: Mapping[str, object],
    cli_args: Sequence[str],
) -> dict[str, object] | None:
    """Allow only the rewritten sink; native authority is rechecked at execution."""
    reason = response.get("reason_code")
    if (
        sys.platform != "darwin"
        or config.get("harness") != "zcode"
        or response.get("decision") != "deny"
        or response.get("policy_action") != "sandbox-required"
        or response.get("observe_mode") is True
        or not isinstance(reason, str)
        or reason not in _PROFILES
        or response.get("required_execution_profile") != _PROFILES[reason]
    ):
        return None
    directory: Path | None = None
    try:
        payload = json.loads(input_text)
        if not isinstance(payload, dict):
            return None
        event = payload.get("hook_event_name", payload.get("hookEventName"))
        tool = payload.get("tool_name", payload.get("toolName"))
        original = payload.get("tool_input", payload.get("toolInput"))
        if event not in {"PreToolUse", "pre_tool_use"} or tool not in {
            "Bash",
            "bash",
            "run_terminal_command",
            "run_command",
        }:
            return None
        if not isinstance(original, dict) or not isinstance(original.get("command"), str):
            return None
        workspace_value = payload.get("cwd", payload.get("workspace"))
        if workspace_value is None and "--workspace" in cli_args:
            workspace_value = cli_args[cli_args.index("--workspace") + 1]
        if not isinstance(workspace_value, str):
            return None
        workspace = Path(workspace_value).expanduser().resolve(strict=True)
        if not workspace.is_dir():
            return None
        snapshot_payload = {
            "hook_event_name": "PreToolUse",
            "tool_name": "bash",
            "tool_input": original,
            "cwd": str(workspace),
            "session_id": payload.get("session_id", payload.get("sessionId")),
            "tool_call_id": payload.get("tool_call_id", payload.get("toolCallId", payload.get("tool_use_id"))),
        }
        serialized = json.dumps(
            {
                "schema": "guard-contained-test-request.v1",
                "workspace": str(workspace),
                "payload": snapshot_payload,
            }
        ).encode()
        if len(serialized) > 1_048_576:
            return None
        cleanup_stale_zcode_requests()
        directory = Path(tempfile.mkdtemp(prefix="hol-guard-contained-test-"))
        # mkdtemp creates an owner-only directory; do not widen its permissions.
        request = directory / "request.json"
        descriptor = os.open(request, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(serialized)
        args = [
            "guard",
            "execute-contained-test",
            "--harness",
            "zcode",
            "--guard-home",
            str(config["guard_home"]),
            "--workspace",
            str(workspace),
            "--request-file",
            str(request),
            "--request-sha256",
            hashlib.sha256(serialized).hexdigest(),
        ]
        if "--home" in cli_args:
            args.extend(["--home", cli_args[cli_args.index("--home") + 1]])
        if getattr(sys, "frozen", False):
            from ..stable_guard_cli import resolve_frozen_guard_cli

            command = (resolve_frozen_guard_cli(), *args)
        else:
            command = isolated_guard_cli_command(
                str(config["python_executable"]),
                Path(str(config["package_root"])),
                args,
            )
        return {
            "policy_action": "allow",
            "reason_code": "native_contained_execution_routed",
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "allow",
                "updatedInput": {**original, "command": shlex.join(command)},
            },
        }
    except (OSError, ValueError, KeyError, IndexError, TypeError):
        if directory is not None:
            try:
                (directory / "request.json").unlink(missing_ok=True)
                directory.rmdir()
            except OSError:
                pass
        return None
