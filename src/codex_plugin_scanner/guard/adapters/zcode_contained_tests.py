"""Route native containment receipts through the PreToolUse updatedInput contract.

ZCode, Claude Code and Codex 0.131+ apply a hook's ``updatedInput``, so a contained test run is
rewritten into Guard's execution sink instead of stopping for review.

Whether a receipt is rewritten, and under which profile, is the resident's
answer (``native_containment_sink``): the harness, host and profile tables live
there. This module writes the request snapshot and quotes the sink command.
"""

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
from ..native_hook_containment_route import ContainmentSink, native_containment_sink

_FILE_ATTRIBUTE_REPARSE_POINT = 0x400


def cleanup_stale_zcode_requests() -> None:
    """Reclaim abandoned private snapshots after a full day, never follow links."""
    cutoff = time.time() - 86_400
    if os.name != "posix":
        root = _request_root()
        if root is not None:
            cleanup_stale_windows_requests(Path(root), cutoff)
        return
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


def cleanup_stale_windows_requests(root: Path, cutoff: float) -> None:
    """Remove only a plain directory holding a plain request file, never a
    reparse point at either level."""
    try:
        with os.scandir(root) as entries:
            for index, entry in enumerate(entries):
                if index >= 4096:
                    break
                if not entry.name.startswith("hol-guard-contained-test-"):
                    continue
                try:
                    directory = os.lstat(entry.path)
                    request_path = os.path.join(entry.path, "request.json")
                    request = os.lstat(request_path)
                    if (
                        not stat.S_ISDIR(directory.st_mode)
                        or not stat.S_ISREG(request.st_mode)
                        or getattr(directory, "st_file_attributes", 0) & _FILE_ATTRIBUTE_REPARSE_POINT
                        or getattr(request, "st_file_attributes", 0) & _FILE_ATTRIBUTE_REPARSE_POINT
                        or directory.st_mtime > cutoff
                        or request.st_mtime > cutoff
                    ):
                        continue
                    os.unlink(request_path)
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
    sink: ContainmentSink | None = None,
    deadline: float | None = None,
) -> dict[str, object]:
    """Rewrite at the authority edge so frozen/stdlib hook clients also work.

    The resident answers whether the sink takes the call (``sink``, when the
    caller already asked); without a workspace there is no snapshot to write,
    so the receipt stands. No resident answer raises
    ``NativeHookDecisionError`` for the caller's outage response.
    """
    if workspace is None:
        return response
    if sink is None:
        sink = native_containment_sink(
            response, harness=harness, bridge=False, payload=payload, guard_home=guard_home, deadline=deadline
        )
    if sink.profile is None:
        return response
    config = {
        "harness": harness,
        "guard_home": str(guard_home),
        "python_executable": sys.executable,
        "package_root": str(Path(__file__).resolve().parents[3]),
    }
    routed = contained_zcode_response(
        response,
        input_text=json.dumps({**payload, "cwd": str(workspace)}),
        config=config,
        cli_args=["--home", str(home_dir)],
        sink=sink,
    )
    return routed if routed is not None else response


def contained_sink_command_prefix(
    python_executable: str | None = None, package_root: Path | None = None
) -> tuple[str, ...]:
    """The argv prefix ``route_zcode_containment`` starts the sink with."""
    return _sink_command_prefix(
        {
            "python_executable": python_executable or sys.executable,
            "package_root": str(package_root or Path(__file__).resolve().parents[3]),
        }
    )


def _sink_command_prefix(config: Mapping[str, object]) -> tuple[str, ...]:
    if getattr(sys, "frozen", False):
        from ..stable_guard_cli import resolve_frozen_guard_cli

        return (resolve_frozen_guard_cli(),)
    package_root = Path(str(config["package_root"]))
    command = isolated_guard_cli_command(str(config["python_executable"]), package_root, ())
    if sys.platform != "win32":
        return command
    # Git Bash hands a native program each doubled backslash as a single one,
    # which breaks the escaped package root in the bootstrap. The same
    # directory written with forward slashes needs no escaping.
    root = str(package_root.resolve())
    return (*command[:-1], command[-1].replace(repr(root), repr(root.replace("\\", "/")), 1))


def _request_root() -> str | None:
    """Where the sink looks for a snapshot; on Windows not TEMP, which the
    harness shell may set differently from this hook."""
    if sys.platform != "win32":
        return None
    from ..windows_paths import trusted_windows_local_temp

    return str(trusted_windows_local_temp())


def contained_zcode_response(
    response: Mapping[str, object],
    *,
    input_text: str,
    config: Mapping[str, object],
    cli_args: Sequence[str],
    sink: ContainmentSink | None = None,
) -> dict[str, object] | None:
    """Allow only the rewritten sink; native authority is rechecked at execution.

    ``sink`` is the resident's answer when the caller already asked it; the
    Codex bridge, which has confirmed the running Codex applies
    ``updatedInput``, lets this ask with Codex routed.
    """
    try:
        payload = json.loads(input_text)
    except ValueError:
        return None
    if not isinstance(payload, dict):
        return None
    if sink is None:
        harness = config.get("harness")
        sink = native_containment_sink(
            response,
            harness=harness if isinstance(harness, str) else "",
            bridge=True,
            payload=payload,
            guard_home=Path(str(config["guard_home"])) if config.get("guard_home") else None,
        )
    if sink.profile is None:
        return None
    directory: Path | None = None
    try:
        original = payload.get("tool_input", payload.get("toolInput"))
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
        directory = Path(tempfile.mkdtemp(prefix="hol-guard-contained-test-", dir=_request_root()))
        # mkdtemp creates an owner-only directory; do not widen its permissions.
        request = directory / "request.json"
        descriptor = os.open(request, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(serialized)
        args = [
            "guard",
            "execute-contained-test",
            "--harness",
            str(config["harness"]),
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
        command = (*_sink_command_prefix(config), *args)
        if sys.platform == "win32" and config.get("harness") == "codex":
            from ..windows_powershell_quote import powershell_join

            shell_command = powershell_join(command)
        else:
            shell_command = shlex.join(command)
        if shell_command is None:
            raise ValueError("sink command cannot be quoted for this shell")
        return {
            "policy_action": "allow",
            "reason_code": "native_contained_execution_routed",
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "allow",
                "updatedInput": {**original, "command": shell_command},
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
