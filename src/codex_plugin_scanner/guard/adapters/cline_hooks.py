"""Managed native Cline hook installation and health proofs."""

from __future__ import annotations

import json
import os
import shlex
import stat
import subprocess
import time
from hashlib import sha256
from pathlib import Path

from .base import HarnessContext
from .cline_paths import cline_hook_roots as _resolve_cline_hook_roots
from .cline_paths import ensure_safe_cline_destination
from .cline_state_paths import canonical_cline_state_path as _canonical_state_path
from .cline_state_paths import cline_hook_command as _hook_command
from .cline_state_paths import uninstall_persisted_cline_hooks as uninstall_cline_hooks
from .guard_cli_attestation import resolve_attested_guard_cli

_MARKER = "HOL_GUARD_MANAGED_CLINE_HOOK_V1"
_SCHEMA = 1
_MAX_BYTES = 256 * 1024
_MAX_PRETOOL_BYTES = 64 * 1024
_MAX_DEPTH = 48
_TIMEOUT = 9
_PROOF_MAX_AGE = 7 * 24 * 60 * 60
_EVENTS = ("PreToolUse", "PostToolUse", "UserPromptSubmit", "TaskStart", "TaskError", "SessionShutdown")


def cline_hook_roots(context: HarnessContext) -> tuple[Path, ...]:
    """Return global hook roots accepted by Cline UI and data-dir runtimes."""

    return _resolve_cline_hook_roots(context)


def _state_path(context: HarnessContext) -> Path:
    return context.guard_home / "managed" / "cline" / "native-hooks-state.json"


def _adapter_state_path(context: HarnessContext) -> Path:
    return context.guard_home / "managed" / "cline" / "adapter-state.json"


def _proof_path(context: HarnessContext, event: str) -> Path:
    return context.guard_home / "managed" / "cline" / "proofs" / f"native-{event.lower()}.json"


def _worker_path(context: HarnessContext, event: str) -> Path:
    return context.guard_home / "managed" / "cline" / "hook-workers" / f"{event}.py"


def _managed(path: Path) -> bool:
    try:
        return path.is_file() and not path.is_symlink() and _MARKER in path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return False


def _slot_for_event(root: Path, event: str, *, windows: bool | None = None) -> Path:
    """Return Cline's canonical slot, refusing to replace a user hook."""

    is_windows = os.name == "nt" if windows is None else windows
    path = root / f"{event}{'.ps1' if is_windows else ''}"
    if path.exists() and not _managed(path):
        raise RuntimeError(f"Cline already has a user-owned {event} hook in {root}; Guard will not overwrite it")
    return path


def _write(path: Path, text: str, *, executable: bool = False) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.hol-guard.tmp-{os.getpid()}")
    with temporary.open("w", encoding="utf-8") as handle:
        handle.write(text)
        handle.flush()
        os.fsync(handle.fileno())
    if executable and os.name != "nt":
        temporary.chmod(stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)
    os.replace(temporary, path)


def _hook_source(context: HarnessContext, *, event_name: str, guard_cli: list[str]) -> str:
    """Generate the bounded Python worker invoked by platform launchers."""

    proof = str(_proof_path(context, event_name))
    adapter_state = str(_adapter_state_path(context))
    blocking = event_name == "PreToolUse"
    return f"""# {_MARKER}
from __future__ import annotations
import json
import os
import subprocess
import sys
import time
from pathlib import Path

EVENT={event_name!r}
BLOCKING={blocking!r}
MAX_BYTES={_MAX_BYTES}
MAX_PRETOOL_BYTES={_MAX_PRETOOL_BYTES}
MAX_DEPTH={_MAX_DEPTH}
TIMEOUT={_TIMEOUT}
GUARD={guard_cli!r}
PROOF=Path({proof!r})
ADAPTER_STATE=Path({adapter_state!r})


def emit(value):
    sys.stdout.write(json.dumps(value, separators=(",", ":")) + "\\n")
    sys.stdout.flush()


def fail(message):
    emit({{
        "cancel": bool(BLOCKING),
        "errorMessage": message if BLOCKING else "",
        "contextModification": message,
    }})


def active_transport():
    if os.environ.get("HOL_GUARD_CLINE_CANARY") == "1":
        return "hooks"
    try:
        value = json.loads(ADAPTER_STATE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    transport = value.get("active_transport") if isinstance(value, dict) else None
    return transport if isinstance(transport, str) else None


def depth_ok(value):
    stack = [(value, 1)]
    while stack:
        item, depth = stack.pop()
        if depth > MAX_DEPTH:
            return False
        if isinstance(item, dict):
            stack.extend((nested, depth + 1) for nested in item.values())
        elif isinstance(item, list):
            stack.extend((nested, depth + 1) for nested in item)
    return True


def pretool_size_ok(value):
    if EVENT != "PreToolUse":
        return True
    current = value.get("tool_call")
    legacy = value.get("preToolUse")
    if isinstance(current, dict):
        action = current
    elif isinstance(legacy, dict):
        action = legacy
    else:
        action = value
    try:
        encoded = json.dumps(action, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    except (TypeError, ValueError):
        return False
    return len(encoded) <= MAX_PRETOOL_BYTES


def parse_output(text):
    text = text.strip()
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    for candidate in [text, *reversed(lines)]:
        if not candidate.startswith("{{"):
            continue
        try:
            value = json.loads(candidate)
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict):
            return value
    return None


def reason(value):
    for key in ("reason", "stopReason", "review_hint", "systemMessage", "message", "error"):
        item = value.get(key)
        if isinstance(item, str) and item.strip():
            return item.strip()
    specific = value.get("hookSpecificOutput")
    if isinstance(specific, dict):
        for key in ("permissionDecisionReason", "additionalContext"):
            item = specific.get(key)
            if isinstance(item, str) and item.strip():
                return item.strip()
        nested = specific.get("decision")
        if isinstance(nested, dict) and isinstance(nested.get("message"), str):
            return nested["message"].strip()
    return "HOL Guard blocked this action."


def blocked(value):
    if value.get("blocked") is True or value.get("continue") is False:
        return True
    decision = value.get("decision")
    if isinstance(decision, str) and decision.lower() in {{"deny", "block", "ask"}}:
        return True
    action = value.get("policy_action", value.get("policyAction"))
    if isinstance(action, str):
        if action.lower() in {{"review", "require-reapproval", "sandbox-required", "block"}}:
            return True
    specific = value.get("hookSpecificOutput")
    if isinstance(specific, dict):
        permission = specific.get("permissionDecision")
        if isinstance(permission, str) and permission.lower() in {{"deny", "block", "ask"}}:
            return True
        nested = specific.get("decision")
        if isinstance(nested, dict):
            behavior = nested.get("behavior")
            if isinstance(behavior, str) and behavior.lower() in {{"deny", "block", "ask"}}:
                return True
    return False


def command_payloads(value):
    if EVENT != "PreToolUse":
        return [value]
    current = value.get("tool_call")
    legacy = value.get("preToolUse")
    name = current.get("name") if isinstance(current, dict) else None
    if name is None and isinstance(legacy, dict):
        name = legacy.get("toolName")
    if name != "run_commands":
        return [value]
    raw = current.get("input") if isinstance(current, dict) else None
    if raw is None and isinstance(legacy, dict):
        raw = legacy.get("parameters")
    commands = raw
    if isinstance(raw, dict):
        commands = raw.get("commands", raw.get("command", raw.get("cmd")))
    if isinstance(commands, str):
        try:
            commands = json.loads(commands)
        except json.JSONDecodeError:
            commands = [commands]
    if isinstance(commands, str):
        commands = [commands]
    if not isinstance(commands, list):
        return [value]
    command_id = ""
    if isinstance(current, dict):
        command_id = current.get("id", "")
    out = []
    for item in commands:
        if isinstance(item, dict):
            item = item.get("command", item.get("cmd"))
        if not isinstance(item, str) or not item.strip():
            continue
        entry = {{
            "hookName": "PreToolUse",
            "hook_event_name": "PreToolUse",
            "tool_call": {{
                "id": command_id,
                "name": "run_command",
                "input": {{"command": item}},
            }},
        }}
        cwd = value.get("cwd")
        if isinstance(cwd, str) and cwd.strip():
            entry["cwd"] = cwd.strip()
        out.append(entry)
    return out or [value]


def proof(outcome):
    if os.environ.get("HOL_GUARD_CLINE_CANARY") == "1":
        return
    try:
        PROOF.parent.mkdir(parents=True, exist_ok=True)
        temp = PROOF.with_name(PROOF.name + ".tmp")
        payload = {{
            "schema_version": 1,
            "event": EVENT,
            "source": "cline",
            "outcome": outcome,
            "timestamp": time.time(),
        }}
        temp.write_text(json.dumps(payload, sort_keys=True), encoding="utf-8")
        os.replace(temp, PROOF)
    except OSError:
        pass


def emergency_continue(value):
    if not BLOCKING:
        return False
    try:
        from codex_plugin_scanner.guard.daemon.hook_availability_policy import hook_action_is_emergency_safe
        return hook_action_is_emergency_safe(value)
    except Exception:
        return False


def main():
    raw = sys.stdin.buffer.read(MAX_BYTES + 1)
    if len(raw) > MAX_BYTES:
        fail("HOL Guard rejected an oversized Cline hook request.")
        return 0
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        fail("HOL Guard could not parse the Cline hook request safely.")
        return 0
    if not isinstance(value, dict) or not depth_ok(value):
        fail("HOL Guard rejected an invalid Cline hook request.")
        return 0
    if not pretool_size_ok(value):
        fail("HOL Guard rejected an oversized Cline pre-tool request.")
        return 0
    transport = active_transport()
    if transport != "hooks":
        if transport is None:
            fail("HOL Guard Cline transport state is unavailable; this action was not allowed to proceed safely.")
        else:
            emit({{"cancel": False, "errorMessage": "", "contextModification": ""}})
        return 0
    denied = False
    why = ""
    degraded = False
    for item in command_payloads(value):
        try:
            result = subprocess.run(
                [*GUARD, "--harness", "cline", "--json"],
                input=json.dumps(item),
                capture_output=True,
                text=True,
                timeout=TIMEOUT,
                check=False,
            )
        except (OSError, subprocess.SubprocessError):
            if emergency_continue(item):
                degraded = True
                continue
            fail("HOL Guard evaluation was unavailable; this Cline action was not allowed to proceed.")
            return 0
        decision = parse_output(result.stdout)
        if decision is None:
            if emergency_continue(item):
                degraded = True
                continue
            fail("HOL Guard returned an invalid decision; this Cline action was not allowed to proceed.")
            return 0
        if blocked(decision):
            denied = True
            why = reason(decision)
            break
    if BLOCKING:
        outcome = "blocked" if denied else ("degraded" if degraded else "allowed")
    else:
        outcome = "observed"
    proof(outcome)
    if BLOCKING:
        emit({{
            "cancel": denied,
            "errorMessage": why if denied else "",
            "contextModification": why if denied else "",
        }})
    else:
        emit({{"cancel": False, "contextModification": why if denied else ""}})
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
"""


def _posix_wrapper(*, worker: Path, python: str) -> str:
    return "\n".join(
        (
            "#!/bin/sh",
            f"# {_MARKER}",
            f"exec {shlex.quote(python)} -I -s {shlex.quote(worker.as_posix())}",
            "",
        )
    )


def _ps_quote(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def _powershell_wrapper(*, worker: Path, python: str, blocking: bool) -> str:
    message = (
        "HOL Guard evaluation was unavailable; this Cline action was not allowed to proceed."
        if blocking
        else "HOL Guard hook diagnostic: evaluation was unavailable."
    )
    cancel = "$true" if blocking else "$false"
    failure_payload = (
        f"@{{cancel={cancel};"
        f"errorMessage={_ps_quote(message)};"
        f"contextModification={_ps_quote(message)}}} | ConvertTo-Json -Compress"
    )
    return "\n".join(
        (
            f"# {_MARKER}",
            f"$Python = {_ps_quote(python)}",
            f"$Worker = {_ps_quote(str(worker))}",
            '$Args = @("-I", "-s", $Worker)',
            "$Raw = [Console]::In.ReadToEnd()",
            "try {",
            "  $Lines = $Raw | & $Python @Args 2>$null",
            "  $Code = $LASTEXITCODE",
            "  $Text = ($Lines -join [Environment]::NewLine)",
            "  if ($Code -ne 0 -or [string]::IsNullOrWhiteSpace($Text)) {",
            "    " + failure_payload,
            "    exit 0",
            "  }",
            "  [Console]::Out.WriteLine($Text)",
            "} catch {",
            "    " + failure_payload,
            "}",
            "exit 0",
            "",
        )
    )


def _load_state(context: HarnessContext) -> dict[str, object]:
    try:
        value = json.loads(_state_path(context).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return value if isinstance(value, dict) else {}


def install_cline_hooks(context: HarnessContext) -> dict[str, object]:
    """Install global Cline hooks, then run a synthetic wire-contract canary."""

    attested = resolve_attested_guard_cli(context)
    if attested.python is None:
        raise RuntimeError("Cline native hooks require a standalone Python Guard runtime.")
    guard = [*attested.command, "guard", "hook"]
    interpreter = str(attested.python.executable)
    root = cline_hook_roots(context)[0]
    paths: dict[str, str] = {}
    digests: dict[str, str] = {}
    workers: dict[str, str] = {}
    worker_digests: dict[str, str] = {}
    for event in _EVENTS:
        slot = _slot_for_event(root, event)
        worker = _worker_path(context, event)
        ensure_safe_cline_destination(context, slot)
        ensure_safe_cline_destination(context, worker)
        worker_source = _hook_source(context, event_name=event, guard_cli=guard)
        _write(worker, worker_source)
        if os.name == "nt":
            launcher = _powershell_wrapper(worker=worker, python=interpreter, blocking=event == "PreToolUse")
            _write(slot, launcher)
        else:
            launcher = _posix_wrapper(worker=worker, python=interpreter)
            _write(slot, launcher, executable=True)
        paths[event] = str(slot)
        digests[event] = sha256(launcher.encode()).hexdigest()
        workers[event] = str(worker)
        worker_digests[event] = sha256(worker_source.encode()).hexdigest()
    state = {
        "schema_version": _SCHEMA,
        "transport": "hooks",
        "root": str(root),
        "paths": paths,
        "sha256": digests,
        "workers": workers,
        "worker_sha256": worker_digests,
        "guard_cli_identity": attested.manifest_payload(),
    }
    _write(_state_path(context), json.dumps(state, indent=2, sort_keys=True) + "\n")
    canary = run_cline_hook_canary(context)
    if canary.get("ok") is not True:
        uninstall_cline_hooks(context)
        raise RuntimeError("Guard-generated Cline native hooks did not pass their bounded canary")
    return {
        "transport": "hooks",
        "managed_hooks_root": str(root),
        "managed_hook_paths": paths,
        "managed_hook_sha256": digests,
        "guard_cli_identity": attested.manifest_payload(),
        "synthetic_canary": canary,
        "post_tool_output_mediation": "observation-only",
    }


def run_cline_hook_canary(context: HarnessContext) -> dict[str, object]:
    state = _load_state(context)
    paths = state.get("paths")
    path = _canonical_state_path(
        context,
        "PreToolUse",
        paths.get("PreToolUse") if isinstance(paths, dict) else None,
        saved_root=state.get("root"),
    )
    if path is None or not _managed(path):
        return {"ok": False, "reason": "pretool_hook_missing"}
    command = _hook_command(path)
    if not command:
        return {"ok": False, "reason": "hook_interpreter_not_available"}
    payload = {
        "hookName": "PreToolUse",
        "taskId": "hol-guard-cline-canary",
        "workspaceRoots": [str(context.workspace_dir or context.home_dir)],
        "preToolUse": {"toolName": "read_files", "parameters": {"paths": "[]"}},
    }
    env = {**os.environ, "HOL_GUARD_CLINE_CANARY": "1"}
    try:
        result = subprocess.run(
            command,
            input=json.dumps(payload),
            capture_output=True,
            text=True,
            timeout=_TIMEOUT + 1,
            env=env,
            check=False,
            shell=False,
        )
        output = json.loads(result.stdout.strip())
    except (OSError, subprocess.SubprocessError, json.JSONDecodeError) as exc:
        return {"ok": False, "reason": type(exc).__name__}
    return {"ok": result.returncode == 0 and isinstance(output, dict) and isinstance(output.get("cancel"), bool)}


def _proof_state(context: HarnessContext, event: str) -> dict[str, object]:
    try:
        value = json.loads(_proof_path(context, event).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {"present": False, "fresh": False, "live": False}
    timestamp = value.get("timestamp") if isinstance(value, dict) else None
    fresh = isinstance(timestamp, (int, float)) and time.time() - float(timestamp) <= _PROOF_MAX_AGE
    return {
        "present": True,
        "fresh": fresh,
        "live": fresh and value.get("source") == "cline",
        "event": event,
        "outcome": value.get("outcome"),
    }


def cline_native_hook_state(context: HarnessContext) -> dict[str, object]:
    state = _load_state(context)
    paths, digests = state.get("paths"), state.get("sha256")
    workers, worker_digests = state.get("workers"), state.get("worker_sha256")
    missing: list[str] = []
    modified: list[str] = []
    if not isinstance(paths, dict) or not isinstance(digests, dict):
        return {"installed": False, "integrity_ok": False, "ready": False, "missing_events": list(_EVENTS)}
    for event in _EVENTS:
        path_value, digest = paths.get(event), digests.get(event)
        if not isinstance(path_value, str) or not isinstance(digest, str):
            missing.append(event)
            continue
        path = _canonical_state_path(context, event, path_value, saved_root=state.get("root"))
        if path is None:
            missing.append(event)
            continue
        try:
            actual = sha256(path.read_bytes()).hexdigest()
        except OSError:
            missing.append(event)
            continue
        if not _managed(path):
            missing.append(event)
        elif actual != digest:
            modified.append(event)
    if not isinstance(workers, dict) or not isinstance(worker_digests, dict):
        missing.extend(f"{event}:worker" for event in _EVENTS)
    else:
        for event in _EVENTS:
            value, digest = workers.get(event), worker_digests.get(event)
            if not isinstance(value, str) or not isinstance(digest, str):
                missing.append(f"{event}:worker")
                continue
            worker = _canonical_state_path(context, event, value, worker=True)
            if worker is None:
                missing.append(f"{event}:worker")
                continue
            try:
                actual = sha256(worker.read_bytes()).hexdigest()
            except OSError:
                missing.append(f"{event}:worker")
                continue
            if not _managed(worker):
                missing.append(f"{event}:worker")
            elif actual != digest:
                modified.append(f"{event}:worker")
    canary = run_cline_hook_canary(context) if not missing and not modified else {"ok": False}
    pre, post = _proof_state(context, "PreToolUse"), _proof_state(context, "PostToolUse")
    pretool_blocking_proven = pre.get("live") is True and pre.get("outcome") == "blocked"
    posttool_observation_proven = post.get("live") is True and post.get("outcome") == "observed"
    return {
        "installed": not missing,
        "integrity_ok": not missing and not modified,
        "synthetic_canary_ok": canary.get("ok") is True,
        "live_pretool_proof": pre,
        "live_posttool_proof": post,
        "pretool_blocking_proven": pretool_blocking_proven,
        "posttool_observation_proven": posttool_observation_proven,
        "post_tool_output_mediation": "observation-only",
        "missing_events": missing,
        "modified_events": modified,
        "ready": not missing and not modified and canary.get("ok") is True and pretool_blocking_proven,
    }


__all__ = [
    "cline_hook_roots",
    "cline_native_hook_state",
    "install_cline_hooks",
    "run_cline_hook_canary",
    "uninstall_cline_hooks",
]
