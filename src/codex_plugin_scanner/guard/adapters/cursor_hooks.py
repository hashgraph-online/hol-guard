"""Cursor IDE native hooks (.cursor/hooks.json) for HOL Guard."""

from __future__ import annotations

import json
import shlex
import shutil
import stat
import sys
from collections.abc import Mapping
from hashlib import sha256
from pathlib import Path

from .base import HarnessContext

HOOK_SCRIPT_NAME = "hol-guard-cursor-hook.py"
_MANAGED_HOOK_EVENTS = (
    "beforeShellExecution",
    "beforeMCPExecution",
    "beforeReadFile",
)
_MANAGED_HOOK_TIMEOUT_SECONDS = 45
_LEGACY_MANAGED_COMMAND_MARKERS = (
    "hol-guard-cursor-hook.py",
    "HOL_GUARD_HOOK_ARGV",
    "--harness",
    "cursor",
)


def prepare_cursor_hook_payload(payload: Mapping[str, object]) -> dict[str, object]:
    """Map Cursor hook stdin JSON into Guard hook normalization shape."""

    normalized = dict(payload)
    raw_event = _raw_hook_event_name(normalized)
    if raw_event == "beforeshellexecution":
        normalized["hook_event_name"] = "PreToolUse"
        normalized.setdefault("tool_name", "Shell")
        tool_input = _tool_input_dict(normalized.get("tool_input"))
        command = normalized.get("command")
        if isinstance(command, str) and command.strip():
            tool_input.setdefault("command", command.strip())
        cwd = normalized.get("cwd")
        if isinstance(cwd, str) and cwd.strip():
            tool_input.setdefault("working_directory", cwd.strip())
        normalized["tool_input"] = tool_input
        return normalized
    if raw_event == "beforemcpexecution":
        normalized["hook_event_name"] = "PreToolUse"
        tool_name = normalized.get("tool_name")
        if isinstance(tool_name, str) and tool_name.strip():
            normalized["tool_name"] = tool_name.strip()
        else:
            normalized.setdefault("tool_name", "MCP")
        tool_input = _tool_input_dict(normalized.get("tool_input"))
        for key in ("url", "command"):
            value = normalized.get(key)
            if isinstance(value, str) and value.strip():
                tool_input.setdefault(key, value.strip())
        normalized["tool_input"] = tool_input
        return normalized
    if raw_event == "beforereadfile":
        normalized["hook_event_name"] = "PreToolUse"
        normalized.setdefault("tool_name", "Read")
        tool_input = _tool_input_dict(normalized.get("tool_input"))
        file_path = normalized.get("file_path")
        if isinstance(file_path, str) and file_path.strip():
            tool_input.setdefault("file_path", file_path.strip())
            tool_input.setdefault("path", file_path.strip())
        normalized["tool_input"] = tool_input
        return normalized
    if raw_event == "pretooluse":
        normalized["hook_event_name"] = "PreToolUse"
    return normalized


def cursor_hook_response_from_guard(
    *,
    policy_action: str,
    guard_payload: Mapping[str, object],
    hook_event_name: str,
) -> dict[str, object]:
    """Translate Guard hook JSON into Cursor hook stdout JSON."""

    permission = _cursor_permission_for_policy(policy_action, guard_payload)
    reason = _cursor_block_reason(guard_payload)
    raw_event = hook_event_name.strip().lower()
    if raw_event == "beforereadfile":
        read_permission = _cursor_read_file_permission(permission)
        response: dict[str, object] = {"permission": read_permission}
        if read_permission == "deny":
            response["user_message"] = reason
        return {key: value for key, value in response.items() if value is not None}
    response: dict[str, object] = {"permission": permission}
    if permission != "allow":
        response["user_message"] = reason
        response["agent_message"] = reason
    return {key: value for key, value in response.items() if value is not None}


def cursor_hook_should_block(*, policy_action: str) -> bool:
    return policy_action in {"block", "sandbox-required"}


def cursor_hooks_path(context: HarnessContext) -> Path:
    """Cursor hooks are always installed in the global Cursor config."""

    return context.home_dir / ".cursor" / "hooks.json"


def cursor_hook_script_path(context: HarnessContext) -> Path:
    return context.home_dir / ".cursor" / "hooks" / HOOK_SCRIPT_NAME


def _legacy_project_cursor_hooks_path(workspace_dir: Path) -> Path:
    return workspace_dir / ".cursor" / "hooks.json"


def _legacy_project_cursor_hook_script_path(workspace_dir: Path) -> Path:
    return workspace_dir / ".cursor" / "hooks" / HOOK_SCRIPT_NAME


def managed_hook_script_path(context: HarnessContext) -> Path:
    return context.guard_home / "managed" / "cursor" / HOOK_SCRIPT_NAME


def install_cursor_hooks(context: HarnessContext) -> dict[str, object]:
    """Install Guard-managed Cursor hooks and bridge script."""

    hooks_path = cursor_hooks_path(context)
    script_path = cursor_hook_script_path(context)
    managed_script_path = managed_hook_script_path(context)
    managed_script_path.parent.mkdir(parents=True, exist_ok=True)
    script_source = cursor_hook_script_source(context)
    managed_script_path.write_text(script_source, encoding="utf-8")
    _make_executable(managed_script_path)
    script_path.parent.mkdir(parents=True, exist_ok=True)
    script_path.write_text(script_source, encoding="utf-8")
    _make_executable(script_path)

    original_text = hooks_path.read_text(encoding="utf-8") if hooks_path.is_file() else None
    backup_path = _hooks_backup_path(hooks_path, context)
    if not backup_path.exists():
        backup_path.parent.mkdir(parents=True, exist_ok=True)
        backup_path.write_text(
            json.dumps({"existed": original_text is not None, "content": original_text}, indent=2) + "\n",
            encoding="utf-8",
        )
    state_path = _hooks_state_path(hooks_path, context)
    state_path.parent.mkdir(parents=True, exist_ok=True)
    workspace_dir = str(context.workspace_dir.resolve()) if context.workspace_dir is not None else None
    state_path.write_text(
        json.dumps(
            {
                "managed_hooks_path": str(hooks_path),
                "managed_hook_script_path": str(script_path),
                "backup_path": str(backup_path),
                "workspace_dir": workspace_dir,
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )

    payload = _managed_hooks_payload(_json_object(hooks_path, recover_missing=True))
    hooks = _inline_hooks(payload)
    for event_name in _MANAGED_HOOK_EVENTS:
        entry = _managed_hook_entry(context, script_path=script_path, event_name=event_name)
        hooks[event_name] = _merge_hook_entries(hooks.get(event_name), entry, event_name=event_name)
    hooks["preToolUse"] = _strip_managed_hook_entries(hooks.get("preToolUse"), script_path=script_path)
    payload["hooks"] = hooks
    hooks_path.parent.mkdir(parents=True, exist_ok=True)
    hooks_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    _cleanup_legacy_project_cursor_hooks(context)
    return {
        "managed_hooks_path": str(hooks_path),
        "managed_hook_script_path": str(script_path),
        "managed_hook_events": list(_MANAGED_HOOK_EVENTS),
        "backup_path": str(backup_path),
        "state_path": str(state_path),
    }


def uninstall_cursor_hooks(context: HarnessContext) -> dict[str, object]:
    """Remove Guard-managed Cursor hooks and restore prior hooks.json."""

    return _uninstall_cursor_hooks_at_paths(
        hooks_path=cursor_hooks_path(context),
        script_path=cursor_hook_script_path(context),
        context=context,
        remove_managed_copy=True,
    )


def _uninstall_cursor_hooks_at_paths(
    *,
    hooks_path: Path,
    script_path: Path,
    context: HarnessContext,
    remove_managed_copy: bool,
) -> dict[str, object]:
    backup_path = _hooks_backup_path(hooks_path, context)
    state_path = _hooks_state_path(hooks_path, context)
    backup_payload = _backup_payload(backup_path)
    restored = False
    if backup_payload["readable"] is True:
        if backup_payload["existed"] and isinstance(backup_payload["content"], str):
            hooks_path.parent.mkdir(parents=True, exist_ok=True)
            hooks_path.write_text(str(backup_payload["content"]), encoding="utf-8")
            restored = True
        elif backup_payload["existed"] is not True and hooks_path.is_file():
            hooks_path.unlink()
            restored = True
        elif backup_payload["existed"] is not True:
            restored = True
    if restored and backup_path.is_file():
        backup_path.unlink()
    if restored and state_path.is_file():
        state_path.unlink()
    if (
        not restored
        and hooks_path.is_file()
        and _remove_managed_hook_entries(hooks_path=hooks_path, script_path=script_path)
    ):
        restored = True
        if state_path.is_file():
            state_path.unlink()
    if script_path.is_file():
        try:
            script_source = script_path.read_text(encoding="utf-8")
        except OSError:
            script_source = ""
        if _is_managed_hook_script(script_source):
            script_path.unlink()
    if remove_managed_copy:
        managed_script_path = managed_hook_script_path(context)
        if managed_script_path.is_file():
            managed_script_path.unlink()
    return {
        "managed_hooks_path": str(hooks_path),
        "restored": restored,
        "removed_hook_script": not script_path.is_file(),
    }


def _cleanup_legacy_project_cursor_hooks(context: HarnessContext) -> None:
    if context.workspace_dir is None:
        return
    hooks_path = _legacy_project_cursor_hooks_path(context.workspace_dir)
    script_path = _legacy_project_cursor_hook_script_path(context.workspace_dir)
    if not hooks_path.is_file() and not script_path.is_file():
        return
    managed = False
    if script_path.is_file():
        try:
            managed = _is_managed_hook_script(script_path.read_text(encoding="utf-8"))
        except OSError:
            managed = False
    if hooks_path.is_file() and not managed:
        try:
            payload = json.loads(hooks_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            payload = {}
        if isinstance(payload, dict):
            hooks = payload.get("hooks")
            if isinstance(hooks, dict):
                for entries in hooks.values():
                    if not isinstance(entries, list):
                        continue
                    for entry in entries:
                        if _is_managed_hook_entry(entry, command=str(script_path.resolve())):
                            managed = True
                            break
                    if managed:
                        break
    if not managed:
        return
    _uninstall_cursor_hooks_at_paths(
        hooks_path=hooks_path,
        script_path=script_path,
        context=context,
        remove_managed_copy=False,
    )
    _prune_empty_project_cursor_dir(context.workspace_dir)


def _prune_empty_project_cursor_dir(workspace_dir: Path) -> None:
    hooks_dir = workspace_dir / ".cursor" / "hooks"
    cursor_dir = workspace_dir / ".cursor"
    if hooks_dir.is_dir():
        try:
            if not any(hooks_dir.iterdir()):
                hooks_dir.rmdir()
        except OSError:
            return
    if not cursor_dir.is_dir():
        return
    try:
        remaining = list(cursor_dir.iterdir())
    except OSError:
        return
    if not remaining:
        try:
            cursor_dir.rmdir()
        except OSError:
            return


def _remove_managed_hook_entries(*, hooks_path: Path, script_path: Path) -> bool:
    try:
        payload = json.loads(hooks_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return False
    if not isinstance(payload, dict):
        return False
    hooks = payload.get("hooks")
    has_managed_hooks = False
    has_other_hooks = False
    if not isinstance(hooks, dict):
        return False
    cleaned_hooks: dict[str, object] = {}
    managed_command = str(script_path.resolve())
    for event, entries in hooks.items():
        if isinstance(entries, list):
            filtered: list[object] = []
            for entry in entries:
                if _is_managed_hook_entry(entry, command=managed_command):
                    has_managed_hooks = True
                else:
                    filtered.append(entry)
            if filtered:
                cleaned_hooks[str(event)] = filtered
                has_other_hooks = True
        else:
            cleaned_hooks[str(event)] = entries
            has_other_hooks = True
    if not has_managed_hooks:
        return False
    if has_other_hooks:
        payload["hooks"] = cleaned_hooks
        hooks_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    else:
        hooks_path.unlink()
    return True


def _resolve_guard_cli_command() -> list[str]:
    """Prefer the installed hol-guard CLI so hooks use the same runtime as install."""

    hol_guard = shutil.which("hol-guard")
    if hol_guard:
        return [hol_guard]
    return [sys.executable, "-m", "codex_plugin_scanner.cli"]


def _uses_top_level_hook_command(guard_cli: list[str]) -> bool:
    return bool(guard_cli) and Path(guard_cli[0]).name == "hol-guard"


def _embedded_guard_hook_argv(context: HarnessContext) -> list[str]:
    guard_argv = [
        "hook",
        "--guard-home",
        str(context.guard_home),
        "--harness",
        "cursor",
        "--json",
    ]
    if context.home_dir.resolve() != Path.home().resolve():
        guard_argv.extend(["--home", str(context.home_dir)])
    return guard_argv


def cursor_hook_script_source(context: HarnessContext) -> str:
    guard_cli = _resolve_guard_cli_command()
    guard_argv = _embedded_guard_hook_argv(context)
    if not _uses_top_level_hook_command(guard_cli):
        guard_argv = ["guard", *guard_argv]
    return (
        _HOOK_SCRIPT_TEMPLATE.replace("__GUARD_HOME__", json.dumps(str(context.guard_home.resolve())))
        .replace("__GUARD_CLI__", json.dumps(guard_cli))
        .replace(
            "__GUARD_HOOK_ARGV__",
            json.dumps(guard_argv),
        )
        .replace(
            "__GUARD_INHERIT_ENV_KEYS__",
            json.dumps(list(_INHERIT_ENV_KEYS)),
        )
        .replace(
            "__GUARD_HOOK_TIMEOUT_SECONDS__",
            str(max(_MANAGED_HOOK_TIMEOUT_SECONDS - 3, 1)),
        )
    )


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
    "CURSOR_PROJECT_DIR",
    "CURSOR_VERSION",
    "CURSOR_TRACE_ID",
    "CURSOR_SESSION_ID",
    "CURSOR_TRANSCRIPT_PATH",
)

_HOOK_SCRIPT_TEMPLATE = '''#!/usr/bin/env python3
"""Managed by HOL Guard. Re-run `hol-guard install cursor` after moving Guard home."""
from __future__ import annotations

import json
import os
import subprocess
import sys
from collections.abc import Mapping
from pathlib import Path

GUARD_HOME = __GUARD_HOME__
GUARD_CLI = __GUARD_CLI__
GUARD_HOOK_ARGV = __GUARD_HOOK_ARGV__
GUARD_INHERIT_ENV_KEYS = __GUARD_INHERIT_ENV_KEYS__
GUARD_HOOK_TIMEOUT_SECONDS = __GUARD_HOOK_TIMEOUT_SECONDS__


def _hook_process_env() -> dict[str, str]:
    env: dict[str, str] = {}
    for key in GUARD_INHERIT_ENV_KEYS:
        value = os.environ.get(key)
        if isinstance(value, str) and value:
            env[key] = value
    return env


def _workspace_from_cursor_input(payload: dict[str, object]) -> str | None:
    project_dir = os.environ.get("CURSOR_PROJECT_DIR")
    if isinstance(project_dir, str) and project_dir.strip():
        return project_dir.strip()
    roots = payload.get("workspace_roots") or payload.get("workspaceRoots")
    if isinstance(roots, list):
        for item in roots:
            if isinstance(item, str) and item.strip():
                return item.strip()
    cwd = payload.get("cwd")
    if isinstance(cwd, str) and cwd.strip():
        return cwd.strip()
    return None


def _tool_input_dict(value: object) -> dict[str, object]:
    if isinstance(value, dict):
        return dict(value)
    if isinstance(value, list):
        return {"arguments": list(value)}
    if isinstance(value, str) and value.strip():
        try:
            parsed = json.loads(value)
        except json.JSONDecodeError:
            return {"raw": value.strip()}
        if isinstance(parsed, dict):
            return dict(parsed)
        if isinstance(parsed, list):
            return {"arguments": list(parsed)}
    return {}


def _raw_hook_event_name(payload: dict[str, object]) -> str:
    for key in ("hook_event_name", "hookEventName", "hook_name", "hookName", "event", "eventName"):
        value = payload.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip().lower()
    return ""


def _prepare_cursor_hook_payload(payload: dict[str, object]) -> dict[str, object]:
    normalized = dict(payload)
    raw_event = _raw_hook_event_name(normalized)
    if raw_event == "beforeshellexecution":
        normalized["hook_event_name"] = "PreToolUse"
        normalized.setdefault("tool_name", "Shell")
        tool_input = _tool_input_dict(normalized.get("tool_input"))
        command = normalized.get("command")
        if isinstance(command, str) and command.strip():
            tool_input.setdefault("command", command.strip())
        cwd = normalized.get("cwd")
        if isinstance(cwd, str) and cwd.strip():
            tool_input.setdefault("working_directory", cwd.strip())
        normalized["tool_input"] = tool_input
        return normalized
    if raw_event == "beforemcpexecution":
        normalized["hook_event_name"] = "PreToolUse"
        tool_name = normalized.get("tool_name")
        if isinstance(tool_name, str) and tool_name.strip():
            normalized["tool_name"] = tool_name.strip()
        else:
            normalized.setdefault("tool_name", "MCP")
        tool_input = _tool_input_dict(normalized.get("tool_input"))
        for key in ("url", "command"):
            value = normalized.get(key)
            if isinstance(value, str) and value.strip():
                tool_input.setdefault(key, value.strip())
        normalized["tool_input"] = tool_input
        return normalized
    if raw_event == "beforereadfile":
        normalized["hook_event_name"] = "PreToolUse"
        normalized.setdefault("tool_name", "Read")
        tool_input = _tool_input_dict(normalized.get("tool_input"))
        file_path = normalized.get("file_path")
        if isinstance(file_path, str) and file_path.strip():
            tool_input.setdefault("file_path", file_path.strip())
            tool_input.setdefault("path", file_path.strip())
        normalized["tool_input"] = tool_input
        return normalized
    if raw_event == "pretooluse":
        normalized["hook_event_name"] = "PreToolUse"
    return normalized


def _guard_payload_has_actionable_risk(guard_payload: dict[str, object]) -> bool:
    risk_signals = guard_payload.get("risk_signals")
    if isinstance(risk_signals, list) and risk_signals:
        return True
    approval_requests = guard_payload.get("approval_requests")
    if isinstance(approval_requests, list) and approval_requests:
        return True
    for key in ("review_hint", "risk_summary", "why_now", "risk_headline"):
        value = guard_payload.get(key)
        if isinstance(value, str) and value.strip():
            return True
    decision = guard_payload.get("decision_v2_json")
    if isinstance(decision, Mapping):
        signals = decision.get("signals")
        if isinstance(signals, list) and signals:
            return True
    return False


def _cursor_permission(policy_action: str, guard_payload: dict[str, object]) -> str:
    if policy_action in {"block", "sandbox-required"}:
        return "deny"
    if policy_action in {"require-reapproval", "review"}:
        return "ask"
    if policy_action == "warn" and _guard_payload_has_actionable_risk(guard_payload):
        return "ask"
    return "allow"


def _cursor_read_file_permission(permission: str) -> str:
    if permission in {"deny", "ask"}:
        return "deny"
    return "allow"


def _cursor_reason(guard_payload: dict[str, object]) -> str:
    primary_url = guard_payload.get("primary_approval_url")
    reason: str | None = None
    for key in ("review_hint", "risk_summary", "why_now", "risk_headline"):
        value = guard_payload.get(key)
        if isinstance(value, str) and value.strip():
            reason = value.strip()
            break
    if reason is None:
        decision = guard_payload.get("decision_v2_json")
        if isinstance(decision, Mapping):
            for key in ("harness_message", "retry_instruction", "user_body", "user_title"):
                value = decision.get(key)
                if isinstance(value, str) and value.strip():
                    reason = value.strip()
                    break
    if reason is None:
        if isinstance(primary_url, str) and primary_url.strip():
            return f"HOL Guard needs approval for this Cursor action. Review it at {primary_url.strip()}."
        return "HOL Guard blocked this Cursor action."
    if isinstance(primary_url, str) and primary_url.strip():
        url_str = primary_url.strip()
        if url_str in reason:
            return reason
        return f"{reason} Review: {url_str}"
    return reason


def _emit_cursor_response(
    *,
    hook_event_name: str,
    policy_action: str,
    guard_payload: dict[str, object],
) -> tuple[dict[str, object], int]:
    permission = _cursor_permission(policy_action, guard_payload)
    reason = _cursor_reason(guard_payload)
    if hook_event_name.strip().lower() == "beforereadfile":
        read_permission = "deny" if permission in {"deny", "ask"} else "allow"
        response = {
            "permission": read_permission,
        }
        if read_permission == "deny":
            response["user_message"] = reason
        return response, 2 if read_permission == "deny" else 0
    response: dict[str, object] = {"permission": permission}
    if permission != "allow":
        response["user_message"] = reason
        response["agent_message"] = reason
    exit_code = 2 if permission == "deny" else 0
    return response, exit_code


def main() -> int:
    raw = sys.stdin.read()
    if not raw.strip():
        print(json.dumps({"permission": "allow"}))
        return 0
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError:
        print(json.dumps({"permission": "deny", "user_message": "HOL Guard could not parse Cursor hook input."}))
        return 2
    if not isinstance(payload, dict):
        print(json.dumps({"permission": "deny", "user_message": "HOL Guard received invalid Cursor hook input."}))
        return 2
    hook_event_name = str(payload.get("hook_event_name") or payload.get("hookEventName") or "preToolUse")
    prepared = _prepare_cursor_hook_payload(payload)
    workspace = _workspace_from_cursor_input(prepared)
    guard_argv = list(GUARD_HOOK_ARGV)
    if workspace:
        if "--workspace" in guard_argv:
            workspace_index = guard_argv.index("--workspace")
            if workspace_index + 1 < len(guard_argv):
                guard_argv[workspace_index + 1] = workspace
        else:
            guard_argv.extend(["--workspace", workspace])
    try:
        proc = subprocess.run(
            [*GUARD_CLI, *guard_argv],
            input=json.dumps(prepared),
            capture_output=True,
            text=True,
            cwd=GUARD_HOME,
            env=_hook_process_env(),
            timeout=GUARD_HOOK_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired:
        print(
            json.dumps(
                {
                    "permission": "deny",
                    "user_message": (
                        f"HOL Guard hook timed out after {GUARD_HOOK_TIMEOUT_SECONDS}s. "
                        "Run `hol-guard status`, approve pending requests, then retry."
                    ),
                }
            )
        )
        return 2
    except Exception as exc:
        print(
            json.dumps(
                {
                    "permission": "deny",
                    "user_message": f"HOL Guard hook execution failed: {exc}",
                }
            )
        )
        return 2
    guard_payload: dict[str, object] = {}
    if proc.stdout.strip():
        try:
            parsed = json.loads(proc.stdout)
            if isinstance(parsed, dict):
                guard_payload = parsed
        except json.JSONDecodeError:
            guard_payload = {}
    policy_action = str(guard_payload.get("policy_action") or "allow")
    if proc.returncode != 0 and not guard_payload:
        print(
            json.dumps(
                {
                    "permission": "deny",
                    "user_message": (proc.stderr or "HOL Guard hook failed.").strip()
                    or "HOL Guard hook failed.",
                }
            )
        )
        return 2
    response, exit_code = _emit_cursor_response(
        hook_event_name=hook_event_name,
        policy_action=policy_action,
        guard_payload=guard_payload,
    )
    print(json.dumps(response))
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
'''


def _managed_hook_entry(
    context: HarnessContext,
    *,
    script_path: Path,
    event_name: str,
) -> dict[str, object]:
    del context
    entry: dict[str, object] = {
        "command": str(script_path.resolve()),
        "timeout": _MANAGED_HOOK_TIMEOUT_SECONDS,
        "failClosed": event_name in _MANAGED_HOOK_EVENTS,
    }
    return entry


def _strip_managed_hook_entries(entries: object, *, script_path: Path) -> list[object]:
    if not isinstance(entries, list):
        return []
    command = str(script_path.resolve())
    return [entry for entry in entries if not _is_managed_hook_entry(entry, command=command)]


def _merge_hook_entries(entries: object, hook_entry: dict[str, object], *, event_name: str) -> list[object]:
    del event_name
    normalized = list(entries) if isinstance(entries, list) else []
    command = str(hook_entry.get("command", ""))
    preserved = [entry for entry in normalized if not _is_managed_hook_entry(entry, command=command)]
    return [*preserved, hook_entry]


def _is_managed_hook_entry(entry: object, *, command: str) -> bool:
    if not isinstance(entry, dict):
        return False
    entry_command = entry.get("command")
    if isinstance(entry_command, str) and entry_command == command:
        return True
    return _is_managed_hook_command(entry_command)


def _is_managed_hook_command(command: object) -> bool:
    if not isinstance(command, str):
        return False
    lowered = command.lower()
    if HOOK_SCRIPT_NAME.lower() in lowered:
        return True
    if "hol_guard_hook_argv" not in lowered.replace("-", "_"):
        return False
    if "--harness" not in lowered or "cursor" not in lowered:
        return False
    try:
        tokens = shlex.split(command)
    except ValueError:
        tokens = command.split()
    if tokens and Path(tokens[0]).name == HOOK_SCRIPT_NAME:
        return True
    return Path(tokens[0]).name.lower().startswith("python") if tokens else False


def _is_managed_hook_script(source: str) -> bool:
    return "Managed by HOL Guard" in source and HOOK_SCRIPT_NAME in source


def _managed_hooks_payload(payload: dict[str, object]) -> dict[str, object]:
    normalized: dict[str, object] = {"version": 1, "hooks": {}}
    version = payload.get("version")
    if isinstance(version, int):
        normalized["version"] = version
    hooks = payload.get("hooks")
    if isinstance(hooks, dict):
        normalized["hooks"] = {
            str(name): list(entries) if isinstance(entries, list) else entries for name, entries in hooks.items()
        }
        return normalized
    normalized["hooks"] = {
        str(name): list(entries)
        for name, entries in payload.items()
        if name != "version" and name not in _MANAGED_HOOK_EVENTS and isinstance(entries, list)
    }
    return normalized


def _inline_hooks(payload: dict[str, object]) -> dict[str, object]:
    hooks = payload.get("hooks")
    if isinstance(hooks, dict):
        normalized = {
            str(hook_name): list(entries) if isinstance(entries, list) else entries
            for hook_name, entries in hooks.items()
        }
        payload["hooks"] = normalized
        return normalized
    normalized: dict[str, object] = {}
    payload["hooks"] = normalized
    return normalized


def _raw_hook_event_name(payload: Mapping[str, object]) -> str:
    for key in ("hook_event_name", "hookEventName", "hook_name", "hookName", "event", "eventName"):
        value = payload.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip().lower()
    return ""


def _tool_input_dict(value: object) -> dict[str, object]:
    if isinstance(value, dict):
        return dict(value)
    if isinstance(value, list):
        return {"arguments": list(value)}
    if isinstance(value, str) and value.strip():
        try:
            parsed = json.loads(value)
        except json.JSONDecodeError:
            return {"raw": value.strip()}
        if isinstance(parsed, dict):
            return dict(parsed)
        if isinstance(parsed, list):
            return {"arguments": list(parsed)}
    return {}


def _guard_payload_has_actionable_risk_for_policy(guard_payload: Mapping[str, object]) -> bool:
    risk_signals = guard_payload.get("risk_signals")
    if isinstance(risk_signals, list) and risk_signals:
        return True
    approval_requests = guard_payload.get("approval_requests")
    if isinstance(approval_requests, list) and approval_requests:
        return True
    for key in ("review_hint", "risk_summary", "why_now", "risk_headline"):
        value = guard_payload.get(key)
        if isinstance(value, str) and value.strip():
            return True
    decision = guard_payload.get("decision_v2_json")
    if isinstance(decision, Mapping):
        signals = decision.get("signals")
        if isinstance(signals, list) and signals:
            return True
    return False


def _cursor_permission_for_policy(
    policy_action: str,
    guard_payload: Mapping[str, object] | None = None,
) -> str:
    if policy_action in {"block", "sandbox-required"}:
        return "deny"
    if policy_action in {"require-reapproval", "review"}:
        return "ask"
    if (
        policy_action == "warn"
        and guard_payload is not None
        and _guard_payload_has_actionable_risk_for_policy(guard_payload)
    ):
        return "ask"
    return "allow"


def _cursor_read_file_permission(permission: str) -> str:
    if permission in {"deny", "ask"}:
        return "deny"
    return "allow"


def _cursor_block_reason(guard_payload: Mapping[str, object]) -> str:
    for key in ("review_hint", "risk_summary", "why_now", "risk_headline"):
        value = guard_payload.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    decision = guard_payload.get("decision_v2_json")
    if isinstance(decision, Mapping):
        for key in ("harness_message", "retry_instruction", "user_body", "user_title"):
            value = decision.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()
    return "HOL Guard blocked this Cursor action."


def _json_object(path: Path, *, recover_missing: bool) -> dict[str, object]:
    if not path.is_file():
        if recover_missing:
            return {}
        raise RuntimeError(f"Guard refused to overwrite missing Cursor hooks config at {path}")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"Guard refused to overwrite unreadable Cursor hooks config at {path}") from exc
    if not isinstance(payload, dict):
        raise RuntimeError(f"Guard refused to overwrite non-object Cursor hooks config at {path}")
    return payload


def _hooks_backup_path(target_path: Path, context: HarnessContext) -> Path:
    digest = sha256(str(target_path.resolve()).encode("utf-8")).hexdigest()[:12]
    return context.guard_home / "managed" / "cursor" / f"hooks-{digest}.backup.json"


def _hooks_state_path(target_path: Path, context: HarnessContext) -> Path:
    digest = sha256(str(target_path.resolve()).encode("utf-8")).hexdigest()[:12]
    return context.guard_home / "managed" / "cursor" / f"hooks-{digest}.state.json"


def _backup_payload(backup_path: Path) -> dict[str, str | bool | None]:
    try:
        payload = json.loads(backup_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {"readable": False, "existed": False, "content": None}
    if not isinstance(payload, dict):
        return {"readable": False, "existed": False, "content": None}
    existed = payload.get("existed") is True
    content = payload.get("content")
    return {"readable": True, "existed": existed, "content": content if isinstance(content, str) else None}


def _make_executable(path: Path) -> None:
    path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


__all__ = [
    "HOOK_SCRIPT_NAME",
    "cursor_hook_response_from_guard",
    "cursor_hook_should_block",
    "cursor_hooks_path",
    "install_cursor_hooks",
    "prepare_cursor_hook_payload",
    "uninstall_cursor_hooks",
]
