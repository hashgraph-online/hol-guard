"""Managed Cline AgentPlugin transport for full pre/post tool mediation."""

from __future__ import annotations

import json
import os
import time
from contextlib import suppress
from hashlib import sha256
from pathlib import Path

from ..native_context import _resolve_existing_digest_home
from ..native_runner_authority import NativeRunnerAuthorityError, native_runner_authority
from .base import HarnessContext
from .bounded_cli_hook_bridge import bounded_cli_hook_command
from .cline_paths import cline_plugin_root as _resolve_cline_plugin_root
from .cline_plugin_probe import probe_cline_plugin_syntax
from .guard_cli_attestation import GuardCliAttestation, guard_hook_command, resolve_attested_guard_cli

_MANAGED_MARKER = "HOL_GUARD_MANAGED_CLINE_PLUGIN_V1"
_SCHEMA_VERSION = 1
_BRIDGE_TIMEOUT_SECONDS = 8
_PROOF_MAX_AGE_SECONDS = 7 * 24 * 60 * 60


def cline_plugin_root(context: HarnessContext) -> Path:
    return _resolve_cline_plugin_root(context)


def _state_path(context: HarnessContext) -> Path:
    return context.guard_home / "managed" / "cline" / "plugin-state.json"


def _adapter_state_path(context: HarnessContext) -> Path:
    return context.guard_home / "managed" / "cline" / "adapter-state.json"


def _proof_path(context: HarnessContext, name: str) -> Path:
    return context.guard_home / "managed" / "cline" / "proofs" / f"plugin-{name}.json"


def _atomic_write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.hol-guard.tmp-{os.getpid()}")
    with temporary.open("w", encoding="utf-8", newline="\n") as handle:
        handle.write(content)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, path)


def _is_managed_source(source: str) -> bool:
    return _MANAGED_MARKER in source


def _is_managed_plugin(path: Path) -> bool:
    try:
        return path.is_file() and not path.is_symlink() and _is_managed_source(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError):
        return False


def _plugin_source(context: HarnessContext, guard_cli: list[str], hook_argv: list[str] | None = None) -> str:
    """Render the managed plugin source natively from its recorded template."""

    hook = hook_argv if hook_argv is not None else [*guard_cli, "--harness", "cline", "--json"]
    args: dict[str, object] = {
        "guard_cli": list(guard_cli),
        "hook_argv": list(hook),
        "adapter_state": str(_adapter_state_path(context)),
        "proof_loaded": str(_proof_path(context, "loaded")),
        "proof_pretool": str(_proof_path(context, "pretool")),
        "proof_posttool": str(_proof_path(context, "posttool")),
    }
    # Rendering is pure: it must not create the Guard home before install publishes it.
    answer = native_runner_authority(
        "cline_plugin_render", args, guard_home=_resolve_existing_digest_home(context.guard_home)
    )
    source = answer.get("source")
    if not isinstance(source, str):
        raise NativeRunnerAuthorityError("Cline plugin render answer is malformed")
    return source


def _package_json() -> str:
    payload = {
        "name": "hol-guard-cline-plugin",
        "version": "1.0.0",
        "private": True,
        "type": "module",
        "cline": {"plugins": [{"paths": ["./index.js"], "capabilities": ["hooks"]}]},
    }
    return json.dumps(payload, indent=2) + "\n"


def _load_state(context: HarnessContext) -> dict[str, object]:
    try:
        payload = json.loads(_state_path(context).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return payload if isinstance(payload, dict) else {}


def _bounded_hook_argv(context: HarnessContext, attested: GuardCliAttestation) -> list[str] | None:
    """The bounded hook bridge argv: the daemon answers first, the CLI is the fallback."""

    if attested.frozen or attested.python is None:
        return None
    guard_args = ["guard", "hook", "--guard-home", str(context.guard_home), "--harness", "cline"]
    if context.home_dir.resolve() != Path.home().resolve():
        guard_args.extend(["--home", str(context.home_dir)])
    return list(
        bounded_cli_hook_command(
            python_executable=str(attested.python.executable),
            package_root=Path(__file__).resolve().parents[3],
            guard_home=context.guard_home,
            cli_args=guard_args,
            harness="cline",
            timeout_seconds=_BRIDGE_TIMEOUT_SECONDS,
        )
    )


def install_cline_plugin(context: HarnessContext) -> dict[str, object]:
    """Install a Guard-owned Cline plugin without replacing user-owned files."""

    root = cline_plugin_root(context)
    index_path = root / "index.js"
    package_path = root / "package.json"
    if root.is_symlink() or index_path.is_symlink() or package_path.is_symlink():
        raise RuntimeError("Guard refused a symlinked Cline plugin destination")
    if index_path.exists() and not _is_managed_plugin(index_path):
        raise RuntimeError(f"Cline plugin path is user-owned; Guard will not overwrite {index_path}")
    for proof_name in ("loaded", "pretool", "posttool"):
        with suppress(OSError):
            _proof_path(context, proof_name).unlink()
    attested = resolve_attested_guard_cli(context)
    source = _plugin_source(
        context, guard_hook_command(attested, harness="cline")[:-3], _bounded_hook_argv(context, attested)
    )
    root.mkdir(parents=True, exist_ok=True)
    _atomic_write(index_path, source)
    _atomic_write(package_path, _package_json())
    state = {
        "schema_version": _SCHEMA_VERSION,
        "transport": "plugin",
        "root": str(root),
        "index_path": str(index_path),
        "package_path": str(package_path),
        "index_sha256": sha256(source.encode("utf-8")).hexdigest(),
        "guard_cli_identity": attested.manifest_payload(),
    }
    _atomic_write(_state_path(context), json.dumps(state, indent=2, sort_keys=True) + "\n")
    return {
        "transport": "plugin",
        "managed_plugin_path": str(index_path),
        "managed_plugin_package": str(package_path),
        "plugin_sha256": state["index_sha256"],
        "guard_cli_identity": attested.manifest_payload(),
        "post_tool_output_mediation": "replaceable",
    }


def _proof_state(context: HarnessContext, name: str) -> dict[str, object]:
    try:
        payload = json.loads(_proof_path(context, name).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {"present": False, "fresh": False, "live": False}
    timestamp = payload.get("timestamp") if isinstance(payload, dict) else None
    fresh = isinstance(timestamp, (int, float)) and time.time() - float(timestamp) <= _PROOF_MAX_AGE_SECONDS
    return {
        "present": True,
        "fresh": fresh,
        "live": fresh and payload.get("source") == "cline-plugin",
        "proof": name,
        "outcome": payload.get("outcome"),
    }


def cline_plugin_state(context: HarnessContext) -> dict[str, object]:
    state = _load_state(context)
    index_path_value = state.get("index_path")
    expected = state.get("index_sha256")
    integrity_ok = False
    installed = isinstance(index_path_value, str) and Path(index_path_value).is_file()
    if isinstance(index_path_value, str) and installed and isinstance(expected, str):
        path = Path(index_path_value)
        try:
            integrity_ok = _is_managed_plugin(path) and sha256(path.read_bytes()).hexdigest() == expected
        except OSError:
            integrity_ok = False
    loaded = _proof_state(context, "loaded")
    pretool = _proof_state(context, "pretool")
    posttool = _proof_state(context, "posttool")
    pretool_blocking_proven = pretool.get("live") is True and pretool.get("outcome") == "blocked"
    posttool_replacement_proven = posttool.get("live") is True and posttool.get("outcome") == "replaced"
    return {
        "installed": installed,
        "integrity_ok": integrity_ok,
        "loaded_proof": loaded,
        "live_pretool_proof": pretool,
        "live_posttool_proof": posttool,
        "pretool_blocking_proven": pretool_blocking_proven,
        "posttool_replacement_proven": posttool_replacement_proven,
        "post_tool_output_mediation": "replaceable",
        "ready": bool(
            integrity_ok
            and loaded.get("live") is True
            and loaded.get("outcome") == "loaded"
            and pretool_blocking_proven
            and posttool_replacement_proven
        ),
    }


def cline_plugin_syntax_probe(context: HarnessContext) -> dict[str, object]:
    """Validate the managed plugin without executing its JavaScript."""

    return probe_cline_plugin_syntax(context, _load_state(context))


def uninstall_cline_plugin(context: HarnessContext) -> dict[str, object]:
    state = _load_state(context)
    index_value = state.get("index_path")
    package_value = state.get("package_path")
    retained: list[str] = []
    removed: list[str] = []
    if isinstance(index_value, str):
        index_path = Path(index_value)
        if index_path.exists():
            if _is_managed_plugin(index_path):
                index_path.unlink()
                removed.append(str(index_path))
            else:
                retained.append(str(index_path))
    if not retained and isinstance(package_value, str):
        package_path = Path(package_value)
        if package_path.is_file():
            try:
                payload = json.loads(package_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                payload = None
            if isinstance(payload, dict) and payload.get("name") == "hol-guard-cline-plugin":
                package_path.unlink()
                removed.append(str(package_path))
    root = cline_plugin_root(context)
    if not retained and root.is_dir():
        with suppress(OSError):
            root.rmdir()
    if not retained and _state_path(context).is_file():
        _state_path(context).unlink()
    return {
        "transport": "plugin",
        "removed": removed,
        "retained_modified_or_unowned": retained,
        "complete": not retained,
    }


__all__ = [
    "cline_plugin_root",
    "cline_plugin_state",
    "cline_plugin_syntax_probe",
    "install_cline_plugin",
    "uninstall_cline_plugin",
]
