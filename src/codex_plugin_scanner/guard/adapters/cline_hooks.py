"""Managed native Cline hook installation and health proofs."""

from __future__ import annotations

import json
import os
import stat
import subprocess
import time
from hashlib import sha256
from pathlib import Path
from typing import cast

from .base import HarnessContext
from .bounded_cli_hook_bridge import bounded_cli_hook_command
from .cline_paths import cline_hook_roots as _resolve_cline_hook_roots
from .cline_paths import ensure_safe_cline_destination
from .cline_state_paths import bound_cline_state_paths
from .cline_state_paths import cline_hook_command as _hook_command
from .cline_state_paths import uninstall_persisted_cline_hooks as uninstall_cline_hooks
from .guard_cli_attestation import resolve_attested_guard_cli
from .native_hook_bridge import native_hook_bridge_executable

_MARKER = "HOL_GUARD_MANAGED_CLINE_HOOK_V1"
_SCHEMA = 1
NATIVE_CLINE_HOOK_WORKER_FEATURE = "cline-hook-worker-v1"
_TIMEOUT = 9
# The bounded bridge answers inside the worker's own subprocess timeout.
_BRIDGE_TIMEOUT_SECONDS = 8
_EVENTS = ("PreToolUse", "PostToolUse", "UserPromptSubmit", "TaskStart", "TaskError", "SessionShutdown")
_PROOF_EVENTS = ("PreToolUse", "PostToolUse")
_FILE_KEYS = {"slot", "worker", "worker_sha256", "launcher", "launcher_sha256"}
_PROOF_KEYS = ({"present", "fresh", "live"}, {"present", "fresh", "live", "event", "outcome"})
_VERDICT_KEYS = {"installed", "integrity_ok", "ready", "missing_events"}
_FULL_VERDICT_KEYS = _VERDICT_KEYS | {
    "synthetic_canary_ok",
    "live_pretool_proof",
    "live_posttool_proof",
    "pretool_blocking_proven",
    "posttool_observation_proven",
    "post_tool_output_mediation",
    "modified_events",
}


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
    return context.guard_home / "managed" / "cline" / "hook-workers" / f"{event}.json"


def _managed(path: Path) -> bool:
    try:
        return path.is_file() and not path.is_symlink() and _MARKER in path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return False


def _claim_slot(root: Path, name: str, event: str) -> Path:
    """Return Cline's slot for one event, refusing to replace a user hook."""

    path = root / name
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


def _hook_files(context: HarnessContext, request: dict[str, object]) -> dict[str, object]:
    """Ask the native ``cline_hook_files`` kind; a refusal is the adapter's RuntimeError."""

    from ..native_context import _resolve_existing_digest_home
    from ..native_runner_authority import native_runner_authority

    try:
        return native_runner_authority(
            "cline_hook_files", request, guard_home=_resolve_existing_digest_home(context.guard_home)
        )
    except ValueError as error:
        raise RuntimeError(f"Cline native hook files failed: {error}") from error


def _malformed() -> RuntimeError:
    return RuntimeError("Cline native hook files answer is malformed")


def _render_hook_files(context: HarnessContext, *, runtime: str, guard_cli: list[str]) -> dict[str, dict[str, str]]:
    """Every event's worker configuration and launcher, rendered natively."""

    events = {
        event: {"worker": str(_worker_path(context, event)), "proof": str(_proof_path(context, event))}
        for event in _EVENTS
    }
    request: dict[str, object] = {
        "op": "render",
        "windows": os.name == "nt",
        "runtime": runtime,
        "guard_cli": guard_cli,
        "adapter_state": str(_adapter_state_path(context)),
        "events": events,
    }
    files = _hook_files(context, request).get("files")
    if not isinstance(files, dict) or files.keys() != set(_EVENTS):
        raise _malformed()
    for entry in files.values():
        if not isinstance(entry, dict) or entry.keys() != _FILE_KEYS:
            raise _malformed()
        if not all(isinstance(value, str) for value in entry.values()):
            raise _malformed()
        if entry["slot"] in {"", ".", ".."} or Path(entry["slot"]).name != entry["slot"]:
            raise _malformed()
    return cast(dict[str, dict[str, str]], files)


def _bounded_hook_argv(context: HarnessContext, interpreter: str) -> tuple[str, ...]:
    """The bounded hook bridge argv: the daemon answers first, the CLI is the fallback."""

    guard_args = ["guard", "hook", "--guard-home", str(context.guard_home), "--harness", "cline"]
    if context.home_dir.resolve() != Path.home().resolve():
        guard_args.extend(["--home", str(context.home_dir)])
    return bounded_cli_hook_command(
        python_executable=interpreter,
        package_root=Path(__file__).resolve().parents[3],
        guard_home=context.guard_home,
        cli_args=guard_args,
        harness="cline",
        timeout_seconds=_BRIDGE_TIMEOUT_SECONDS,
    )


def _read_text(path: Path) -> str | None:
    try:
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return None


def _load_state(context: HarnessContext, text: str | None = None) -> dict[str, object]:
    try:
        value = json.loads(text if text is not None else _read_text(_state_path(context)) or "")
    except json.JSONDecodeError:
        return {}
    return value if isinstance(value, dict) else {}


def install_cline_hooks(context: HarnessContext) -> dict[str, object]:
    """Install global Cline hooks, then run a synthetic wire-contract canary."""

    attested = resolve_attested_guard_cli(context)
    if attested.python is None:
        raise RuntimeError("Cline native hooks require a standalone Python Guard runtime.")
    runtime = native_hook_bridge_executable(NATIVE_CLINE_HOOK_WORKER_FEATURE, guard_home=context.guard_home)
    if runtime is None:
        raise RuntimeError("Cline native hooks require the HOL Guard native runtime.")
    interpreter = str(attested.python.executable)
    guard = list(_bounded_hook_argv(context, interpreter))
    root = cline_hook_roots(context)[0]
    files = _render_hook_files(context, runtime=str(runtime), guard_cli=guard)
    paths: dict[str, str] = {}
    digests: dict[str, str] = {}
    workers: dict[str, str] = {}
    worker_digests: dict[str, str] = {}
    for event in _EVENTS:
        rendered = files[event]
        slot, worker = _claim_slot(root, rendered["slot"], event), _worker_path(context, event)
        ensure_safe_cline_destination(context, slot)
        ensure_safe_cline_destination(context, worker)
        _write(worker, rendered["worker"])
        legacy_worker = worker.with_suffix(".py")
        if _managed(legacy_worker):
            legacy_worker.unlink()
        _write(slot, rendered["launcher"], executable=os.name != "nt")
        paths[event], digests[event] = str(slot), rendered["launcher_sha256"]
        workers[event], worker_digests[event] = str(worker), rendered["worker_sha256"]
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
        "managed_hook_workers": workers,
        "managed_hook_sha256": digests,
        "guard_cli_identity": attested.manifest_payload(),
        "synthetic_canary": canary,
        "post_tool_output_mediation": "observation-only",
    }


def run_cline_hook_canary(context: HarnessContext) -> dict[str, object]:
    path = bound_cline_state_paths(context, _load_state(context))[0].get("PreToolUse")
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


def _observed(path: Path | None) -> dict[str, object] | None:
    """What Guard reads back from one hook file bound to its canonical slot, if any."""

    try:
        return None if path is None else {"sha256": sha256(path.read_bytes()).hexdigest(), "managed": _managed(path)}
    except OSError:
        return None


def _valid_verdict(key: str, value: object) -> bool:
    if key.endswith("_events"):
        return isinstance(value, list) and all(isinstance(item, str) for item in value)
    if key.startswith("live_"):
        return (
            isinstance(value, dict)
            and value.keys() in _PROOF_KEYS
            and all(isinstance(value[name], bool) for name in ("present", "fresh", "live"))
            and isinstance(value.get("event", ""), str)
        )
    if key == "post_tool_output_mediation":
        return value == "observation-only"
    return isinstance(value, bool)


def cline_native_hook_state(context: HarnessContext) -> dict[str, object]:
    text = _read_text(_state_path(context))
    launchers, workers = bound_cline_state_paths(context, _load_state(context, text))
    request: dict[str, object] = {
        "op": "state",
        "now": time.time(),
        "state_text": text,
        "launchers": {event: _observed(launchers.get(event)) for event in _EVENTS},
        "workers": {event: _observed(workers.get(event)) for event in _EVENTS},
        "proofs": {event: _read_text(_proof_path(context, event)) for event in _PROOF_EVENTS},
    }
    answer = _hook_files(context, request)
    verdict, canary = answer.get("state"), answer.get("canary")
    if answer.keys() != {"state", "canary"} or not isinstance(verdict, dict) or not isinstance(canary, bool):
        raise _malformed()
    verdict = cast(dict[str, object], verdict)
    if verdict.keys() not in (_VERDICT_KEYS, _FULL_VERDICT_KEYS) or not all(
        _valid_verdict(key, value) for key, value in verdict.items()
    ):
        raise _malformed()
    if canary:
        # ``ready`` assumes the canary passes; it runs only over intact files.
        canary_ok = run_cline_hook_canary(context).get("ok") is True
        verdict["synthetic_canary_ok"] = canary_ok
        verdict["ready"] = verdict["ready"] is True and canary_ok
    return verdict


__all__ = [
    "cline_hook_roots",
    "cline_native_hook_state",
    "install_cline_hooks",
    "run_cline_hook_canary",
    "uninstall_cline_hooks",
]
