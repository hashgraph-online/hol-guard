"""OpenCode pretool plugin generation for HOL Guard runtime interception."""

from __future__ import annotations

import json
import os
from pathlib import Path

from ..codex_hook_windows_job import windows_system_executable_path
from .base import HarnessContext
from .guard_cli_attestation import resolve_attested_guard_cli
from .hook_python import (
    HookPythonExecutableIdentity,
    HookPythonFileMetadata,
)
from .opencode_pretool_template import _PLUGIN_TEMPLATE
from .opencode_v2_entrypoint import OPENCODE_V2_ENTRYPOINT

PLUGIN_FILENAME = "hol-guard-pretool.ts"
_INTERCEPT_TOOLS = ("bash", "ctx_shell", "shell", "sh", "zsh", "terminal", "oc_bash")
_HOOK_ARGV_ENV = "HOL_GUARD_HOOK_ARGV"
_INHERIT_ENV_KEYS = (
    "PATH",
    "HOME",
    "USER",
    "TMPDIR",
    "TEMP",
    "TMP",
    "LANG",
    "LC_ALL",
    "SYSTEMROOT",
    "HOL_GUARD_NATIVE",
    "HOL_GUARD_NATIVE_BINARY",
)


def _trusted_pythonpath_entries(package_root: str) -> list[str]:
    trimmed = package_root.strip()
    return [trimmed] if trimmed else []


def _pretool_hook_launcher_code(
    *,
    import_roots: tuple[str, ...] = (),
    package_root: str | None = None,
) -> str:
    trusted_entries = list(import_roots)
    if not trusted_entries and package_root is not None:
        trusted_entries = _trusted_pythonpath_entries(package_root)
    return (
        "import json,os,sys;"
        f"trusted={json.dumps(trusted_entries)};"
        "sys.path[:0]=trusted;"
        "from codex_plugin_scanner.guard.codex_hook_windows_job import "
        "assign_current_process_to_windows_hook_job;"
        "_windows_job=assign_current_process_to_windows_hook_job() if os.name=='nt' else None;"
        "sys.stderr.write('HOL_GUARD_WINDOWS_JOB_CONTAINED\\n') if _windows_job is not None else None;"
        "sys.stderr.flush() if _windows_job is not None else None;"
        "from pathlib import Path;"
        "import codex_plugin_scanner;"
        "from codex_plugin_scanner.guard.adapters.bounded_cli_hook_bridge import run_bounded_cli_hook;"
        f"argv=json.loads(os.environ[{_HOOK_ARGV_ENV!r}]);"
        "guard_index=argv.index('--guard-home');"
        "guard_home=argv[guard_index+1];"
        "package_root=Path(codex_plugin_scanner.__file__).resolve().parent.parent;"
        "config={'python_executable':sys.executable,'package_root':str(package_root),"
        "'guard_home':guard_home,'cli_args':argv,'harness':'opencode','timeout_seconds':25};"
        "raise SystemExit(run_bounded_cli_hook(config,input_text=sys.stdin.read(1000001)))"
    )


def _pretool_hook_env(*, package_root: str | None = None) -> dict[str, str]:
    del package_root
    return {
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONIOENCODING": "utf-8",
        "PYTHONNOUSERSITE": "1",
        "PYTHONSAFEPATH": "1",
    }


def managed_plugin_path(context: HarnessContext) -> Path:
    return context.guard_home / "opencode" / "plugins" / PLUGIN_FILENAME


def global_plugin_path(context: HarnessContext) -> Path:
    return context.home_dir / ".config" / "opencode" / "plugins" / PLUGIN_FILENAME


def _metadata_payload(metadata: HookPythonFileMetadata) -> dict[str, str]:
    return {
        "device": str(metadata.device),
        "inode": str(metadata.inode),
        "mode": str(metadata.mode),
        "size": str(metadata.size),
        "mtimeNs": str(metadata.mtime_ns),
    }


def _python_identity_payload(identity: HookPythonExecutableIdentity) -> dict[str, object]:
    return {
        "invocationPath": str(identity.invocation_path),
        "invocationType": identity.invocation_type,
        "invocationLinkTarget": identity.invocation_link_target,
        "invocationStat": _metadata_payload(identity.invocation_stat),
        "targetPath": str(identity.target_path),
        "targetStat": _metadata_payload(identity.target_stat),
        "targetSha256": identity.target_sha256,
    }


def pretool_plugin_source(context: HarnessContext) -> str:
    guard_cli = resolve_attested_guard_cli(context)
    identity = guard_cli.frozen_identity or (guard_cli.python.identity if guard_cli.python is not None else None)
    if identity is None:
        raise RuntimeError("Guard could not attest the OpenCode hook runtime.")
    import_roots = tuple(str(root) for root in guard_cli.python.import_roots) if guard_cli.python is not None else ()
    try:
        taskkill_path = windows_system_executable_path("taskkill.exe") if os.name == "nt" else None
    except (OSError, ValueError):
        taskkill_path = None
    template = (_PLUGIN_TEMPLATE + OPENCODE_V2_ENTRYPOINT).replace("__HOOK_ARGV_ENV__", _HOOK_ARGV_ENV)
    return (
        template.replace("__GUARD_HOME__", json.dumps(str(context.guard_home.resolve())))
        .replace("__GUARD_PYTHON__", json.dumps(_python_identity_payload(identity)))
        .replace("__GUARD_FROZEN__", json.dumps(guard_cli.frozen))
        .replace("__GUARD_HOOK_LAUNCHER__", json.dumps(_pretool_hook_launcher_code(import_roots=import_roots)))
        .replace("__GUARD_HOOK_ENV__", json.dumps(_pretool_hook_env()))
        .replace("__GUARD_INHERIT_ENV_KEYS__", json.dumps(list(_INHERIT_ENV_KEYS)))
        .replace("__GUARD_TASKKILL_PATH__", json.dumps(taskkill_path))
        .replace("__INTERCEPT_TOOLS__", json.dumps(list(_INTERCEPT_TOOLS)))
    )


def install_pretool_plugin(context: HarnessContext) -> dict[str, object]:
    source = pretool_plugin_source(context)
    managed_path = managed_plugin_path(context)
    global_path = global_plugin_path(context)
    managed_path.parent.mkdir(parents=True, exist_ok=True)
    global_path.parent.mkdir(parents=True, exist_ok=True)
    managed_path.write_text(source, encoding="utf-8")
    global_path.write_text(source, encoding="utf-8")
    return {
        "managed_plugin_path": str(managed_path),
        "global_plugin_path": str(global_path),
    }


def remove_pretool_plugin(context: HarnessContext) -> dict[str, object]:
    managed_path = managed_plugin_path(context)
    global_path = global_plugin_path(context)
    removed_paths: list[str] = []
    for path in (global_path, managed_path):
        if path.is_file():
            path.unlink()
            removed_paths.append(str(path))
    return {"removed_plugin_paths": removed_paths}


def opencode_config_has_mcp_servers(config_path: Path) -> bool:
    from ...ecosystems.opencode import _load_json_or_jsonc

    if not config_path.is_file():
        return False
    payload, parse_error, _ = _load_json_or_jsonc(config_path)
    if parse_error or not isinstance(payload, dict):
        return False
    mcp = payload.get("mcp")
    return isinstance(mcp, dict) and bool(mcp)


def _mcp_command_uses_guard_proxy(command: object) -> bool:
    if isinstance(command, list):
        return any("opencode-mcp-proxy" in str(part) for part in command)
    if isinstance(command, str):
        return "opencode-mcp-proxy" in command
    return False


def opencode_config_uses_guard_proxy(config_path: Path) -> bool:
    from ...ecosystems.opencode import _load_json_or_jsonc

    if not config_path.is_file():
        return False
    payload, parse_error, _ = _load_json_or_jsonc(config_path)
    if parse_error or not isinstance(payload, dict):
        return False
    mcp = payload.get("mcp")
    if not isinstance(mcp, dict):
        return False
    native_servers: dict[str, dict[str, object]] = {}
    companions: dict[str, dict[str, object]] = {}
    for name, server in mcp.items():
        if not isinstance(name, str) or not isinstance(server, dict):
            continue
        if name.startswith("hol-guard::"):
            companions[name] = server
        else:
            native_servers[name] = server
    if not native_servers:
        return any(_mcp_command_uses_guard_proxy(server.get("command")) for server in companions.values())
    for name, server in native_servers.items():
        if _mcp_command_uses_guard_proxy(server.get("command")):
            continue
        companion = companions.get(f"hol-guard::{name}")
        if companion is None or not _mcp_command_uses_guard_proxy(companion.get("command")):
            return False
    return True


__all__ = [
    "PLUGIN_FILENAME",
    "global_plugin_path",
    "install_pretool_plugin",
    "managed_plugin_path",
    "opencode_config_has_mcp_servers",
    "opencode_config_uses_guard_proxy",
    "pretool_plugin_source",
    "remove_pretool_plugin",
]
