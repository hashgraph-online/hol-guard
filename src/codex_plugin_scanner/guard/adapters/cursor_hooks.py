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
from .cursor_native_approval import ensure_cursor_hook_attestation_secret

HOOK_SCRIPT_NAME = "hol-guard-cursor-hook.py"
_BLOCKING_MANAGED_HOOK_EVENTS = (
    "beforeShellExecution",
    "beforeMCPExecution",
    "beforeReadFile",
)
_OBSERVER_MANAGED_HOOK_EVENTS = ("afterShellExecution", "afterMCPExecution")
_MANAGED_HOOK_EVENTS = _BLOCKING_MANAGED_HOOK_EVENTS + _OBSERVER_MANAGED_HOOK_EVENTS
_MANAGED_HOOK_TIMEOUT_SECONDS = 45
_LEGACY_MANAGED_COMMAND_MARKERS = (
    "hol-guard-cursor-hook.py",
    "HOL_GUARD_HOOK_ARGV",
    "--harness",
    "cursor",
)


def _infer_cursor_hook_event_name(payload: Mapping[str, object]) -> dict[str, object]:
    normalized = dict(payload)
    if _raw_hook_event_name(normalized):
        return normalized
    file_path = normalized.get("file_path")
    if isinstance(file_path, str) and file_path.strip():
        normalized["hook_event_name"] = "beforeReadFile"
        return normalized
    command = normalized.get("command")
    if isinstance(command, str) and command.strip():
        normalized["hook_event_name"] = "beforeShellExecution"
        return normalized
    if normalized.get("tool_name") is not None or normalized.get("tool_input") is not None:
        normalized["hook_event_name"] = "preToolUse"
    return normalized


# Payload normalizers below are mirrored inside _HOOK_SCRIPT_TEMPLATE for the installed
# Cursor hook script. Keep both copies in sync when changing observer or MCP behavior.


def _cursor_shell_hook_payload(normalized: dict[str, object], *, hook_event_name: str) -> dict[str, object]:
    payload = dict(normalized)
    payload["hook_event_name"] = hook_event_name
    payload.setdefault("tool_name", "Shell")
    tool_input = _tool_input_dict(payload.get("tool_input"))
    command = payload.get("command")
    if isinstance(command, str) and command.strip():
        tool_input.setdefault("command", command.strip())
    cwd = payload.get("cwd")
    if isinstance(cwd, str) and cwd.strip():
        tool_input.setdefault("working_directory", cwd.strip())
    payload["tool_input"] = tool_input
    return payload


def _cursor_mcp_hook_payload(normalized: dict[str, object], *, hook_event_name: str) -> dict[str, object]:
    payload = dict(normalized)
    payload["hook_event_name"] = hook_event_name
    tool_input = _tool_input_dict(payload.get("tool_input"))
    payload["tool_input"] = tool_input
    tool_name = payload.get("tool_name")
    if isinstance(tool_name, str) and tool_name.strip():
        payload["tool_name"] = tool_name.strip()
    else:
        payload.setdefault("tool_name", "MCP")
    return payload


def prepare_cursor_hook_payload(payload: Mapping[str, object]) -> dict[str, object]:
    """Map Cursor hook stdin JSON into Guard hook normalization shape."""

    normalized = _infer_cursor_hook_event_name(payload)
    raw_event = _raw_hook_event_name(normalized)
    if raw_event == "aftershellexecution":
        return _cursor_shell_hook_payload(normalized, hook_event_name="afterShellExecution")
    if raw_event == "aftermcpexecution":
        return _cursor_mcp_hook_payload(normalized, hook_event_name="afterMCPExecution")
    if raw_event == "beforeshellexecution":
        prepared = _cursor_shell_hook_payload(normalized, hook_event_name="PreToolUse")
        prepared["cursor_source_hook_event"] = "beforeShellExecution"
        return prepared
    if raw_event == "beforemcpexecution":
        prepared = _cursor_mcp_hook_payload(normalized, hook_event_name="PreToolUse")
        tool_input = _tool_input_dict(prepared.get("tool_input"))
        for key in ("url", "command"):
            value = normalized.get(key)
            if isinstance(value, str) and value.strip():
                tool_input.setdefault(key, value.strip())
        prepared["tool_input"] = tool_input
        prepared["cursor_source_hook_event"] = "beforeMCPExecution"
        return prepared
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


def _validated_hol_guard_src_path(path_str: str) -> str | None:
    """Accept only directories that look like a hol-guard source tree."""

    try:
        if not isinstance(path_str, str) or not path_str.strip():
            return None
        candidate = Path(path_str.strip()).expanduser().resolve()
    except (OSError, RuntimeError, ValueError, TypeError):
        return None
    if not candidate.is_dir():
        return None
    if not (candidate / "codex_plugin_scanner").is_dir():
        return None
    return str(candidate)


def cursor_hook_would_prompt_user(
    *,
    policy_action: str,
    guard_payload: Mapping[str, object] | None = None,
) -> bool:
    """Return True when Guard maps this hook result to Cursor permission ask."""

    if policy_action in {"require-reapproval", "review"}:
        return True
    return (
        policy_action == "warn"
        and guard_payload is not None
        and _guard_payload_has_actionable_risk_for_policy(guard_payload)
    )


def cursor_hook_requires_approval_center_queue(
    *,
    policy_action: str,
    guard_payload: Mapping[str, object] | None = None,
) -> bool:
    """Return True when Cursor native prompts should also appear in the approval center.

    Currently equivalent to ``cursor_hook_would_prompt_user``; kept separate so the
    two concepts can diverge without touching call sites.
    """

    return cursor_hook_would_prompt_user(
        policy_action=policy_action,
        guard_payload=guard_payload,
    )


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
    ensure_cursor_hook_attestation_secret(context.guard_home)

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
    pre_tool_use = hooks.get("preToolUse")
    if pre_tool_use is not None:
        stripped = _strip_managed_hook_entries(pre_tool_use, script_path=script_path)
        if stripped:
            hooks["preToolUse"] = stripped
        else:
            hooks.pop("preToolUse", None)
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
    """Prefer the installed guard-only CLI so hooks use the leanest runtime."""

    plugin_guard = shutil.which("plugin-guard")
    if plugin_guard:
        return [plugin_guard]
    hol_guard = shutil.which("hol-guard")
    if hol_guard:
        return [hol_guard]
    return [sys.executable, "-m", "codex_plugin_scanner.cli"]


def _uses_top_level_hook_command(guard_cli: list[str]) -> bool:
    if not guard_cli:
        return False
    # hol-guard/plugin-guard entrypoints expose `hook` at the top level (combined-mode
    # hol-guard rewrites `hook` to `guard hook` internally). Only module invocations
    # need an explicit `guard` prefix.
    return Path(guard_cli[0]).name in {"hol-guard", "plugin-guard"}


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
    "HOL_GUARD_SRC",
)

_HOOK_SCRIPT_TEMPLATE = '''#!/usr/bin/env python3
"""Managed by HOL Guard. Re-run `hol-guard install cursor` after moving Guard home."""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import shlex
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
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
    dev_src = os.environ.get("HOL_GUARD_SRC")
    validated = _validated_hol_guard_src_path(dev_src) if isinstance(dev_src, str) else None
    if validated is not None:
        env["PYTHONPATH"] = validated
    else:
        dev_src_file = Path(GUARD_HOME) / "cursor-dev-src"
        if dev_src_file.is_file():
            try:
                configured_src = dev_src_file.read_text(encoding="utf-8").strip()
            except OSError:
                configured_src = ""
            validated = _validated_hol_guard_src_path(configured_src)
            if validated is not None:
                env["PYTHONPATH"] = validated
    return env


def _guard_hook_arg_value(flag: str) -> str | None:
    try:
        index = GUARD_HOOK_ARGV.index(flag)
    except ValueError:
        return None
    if index + 1 >= len(GUARD_HOOK_ARGV):
        return None
    value = GUARD_HOOK_ARGV[index + 1]
    return value if isinstance(value, str) and value.strip() else None


def _daemon_hook_env_overlay(guard_env: Mapping[str, str]) -> dict[str, str]:
    overlay: dict[str, str] = {}
    for key in (
        "HOL_GUARD_MANAGED_CURSOR_HOOK",
        "HOL_GUARD_CURSOR_APPROVAL_BINDING",
        "HOL_GUARD_CURSOR_AFTER_SHELL_PROOF",
        "CURSOR_PROJECT_DIR",
        "CURSOR_VERSION",
        "CURSOR_TRACE_ID",
        "CURSOR_SESSION_ID",
        "CURSOR_TRANSCRIPT_PATH",
    ):
        value = guard_env.get(key)
        if isinstance(value, str) and value:
            overlay[key] = value
    return overlay


def _daemon_hook_result(
    payload_json: str,
    *,
    workspace: str | None,
    hook_env_overlay: Mapping[str, str] | None = None,
) -> tuple[int, str, str] | None:
    state_path = Path(GUARD_HOME) / "daemon-state.json"
    token_path = Path(GUARD_HOME) / "daemon-auth-token"
    try:
        state = json.loads(state_path.read_text(encoding="utf-8"))
        auth_token = token_path.read_text(encoding="utf-8").strip()
    except (OSError, ValueError):
        return None
    if not isinstance(state, dict):
        return None
    port = state.get("port")
    if not isinstance(port, int) or port <= 0 or not auth_token:
        return None
    # Validate the recorded PID is still alive before trusting the state file.
    # A stale state file after a crash could point at an attacker-controlled listener.
    pid = state.get("pid")
    if not isinstance(pid, int) or pid <= 0:
        return None
    try:
        os.kill(pid, 0)
    except OSError:
        return None
    # Probe /healthz before sending the hook payload and auth token.
    # Ensures the listener is actually the Guard daemon, not a spoofed process.
    # Validate the response body — not just HTTP 200 — so an attacker listener
    # that returns 200 but doesn't know the daemon's compatibility version is rejected.
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        health_req = urllib.request.Request(f"http://127.0.0.1:{port}/healthz", method="GET")
        with opener.open(health_req, timeout=2) as health_response:
            if health_response.status != 200:
                return None
            health_body = health_response.read().decode("utf-8", errors="replace")
    except (OSError, urllib.error.URLError):
        return None
    try:
        health_json = json.loads(health_body)
    except ValueError:
        return None
    if not isinstance(health_json, dict) or health_json.get("ok") is not True:
        return None
    state_compat = state.get("compatibility_version")
    if isinstance(state_compat, str) and health_json.get("compatibility_version") != state_compat:
        return None
    # Challenge-response: prove the listener knows the auth_token before sending it.
    # A spoofed listener can return public healthz values but cannot forge the HMAC.
    # The proof is bound to the daemon's listening port so a relay attacker cannot
    # proxy the nonce to the real daemon and reuse its proof from a different port.
    # Old daemons without /v1/healthz/verify fail with HTTPError — return None to
    # fall through to the CLI path. Never bypass the HMAC challenge.
    nonce = os.urandom(16).hex()
    proof_message = f"{port}:{nonce}"
    try:
        verify_req = urllib.request.Request(
            f"http://127.0.0.1:{port}/v1/healthz/verify",
            data=json.dumps({"nonce": nonce}).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with opener.open(verify_req, timeout=2) as verify_response:
            verify_body = verify_response.read().decode("utf-8", errors="replace")
            try:
                verify_json = json.loads(verify_body)
            except ValueError:
                return None
            if not isinstance(verify_json, dict) or not isinstance(verify_json.get("proof"), str):
                return None
            expected_proof = hmac.new(
                auth_token.encode("utf-8"),
                proof_message.encode("utf-8"),
                hashlib.sha256,
            ).hexdigest()
            if not hmac.compare_digest(verify_json["proof"], expected_proof):
                return None
    except (urllib.error.HTTPError, OSError, urllib.error.URLError):
        return None
    params = [("guard-home", GUARD_HOME)]
    if workspace:
        params.append(("workspace", workspace))
    home_dir = _guard_hook_arg_value("--home")
    if home_dir:
        params.append(("home", home_dir))
    try:
        request_payload = json.loads(payload_json)
    except ValueError:
        return None
    if not isinstance(request_payload, dict):
        return None
    if hook_env_overlay:
        request_payload["hook_env"] = dict(hook_env_overlay)
    query = urllib.parse.urlencode(params)
    request = urllib.request.Request(
        f"http://127.0.0.1:{port}/v1/hooks/cursor?{query}",
        data=json.dumps(request_payload).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "X-Guard-Token": auth_token,
        },
        method="POST",
    )
    try:
        with opener.open(request, timeout=max(GUARD_HOOK_TIMEOUT_SECONDS - 2, 1)) as response:
            body = response.read().decode("utf-8", errors="replace")
    except (OSError, urllib.error.URLError):
        return None
    # Reject empty or non-dict responses — they default policy_action to "allow".
    # Fall through to the CLI subprocess path instead of trusting a malformed response.
    body_stripped = body.strip()
    if not body_stripped:
        return None
    try:
        parsed_body = json.loads(body_stripped)
    except ValueError:
        return None
    if not isinstance(parsed_body, dict):
        return None
    return (0, body_stripped, "")


def _validated_hol_guard_src_path(path_str: str) -> str | None:
    try:
        if not isinstance(path_str, str) or not path_str.strip():
            return None
        candidate = Path(path_str.strip()).expanduser().resolve()
    except (OSError, RuntimeError, ValueError, TypeError):
        return None
    if not candidate.is_dir():
        return None
    if not (candidate / "codex_plugin_scanner").is_dir():
        return None
    return str(candidate)


def _workspace_from_cursor_input(payload: dict[str, object]) -> str | None:
    project_dir = os.environ.get("CURSOR_PROJECT_DIR")
    if isinstance(project_dir, str) and project_dir.strip():
        candidate = project_dir.strip()
        if Path(candidate).is_dir():
            return candidate
    roots = payload.get("workspace_roots") or payload.get("workspaceRoots")
    if isinstance(roots, list):
        for item in roots:
            if isinstance(item, str) and item.strip():
                candidate = item.strip()
                if Path(candidate).is_dir():
                    return candidate
    cwd = payload.get("cwd")
    if isinstance(cwd, str) and cwd.strip():
        candidate = cwd.strip()
        if Path(candidate).is_dir():
            return candidate
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


def _infer_cursor_hook_event_name(payload: dict[str, object]) -> dict[str, object]:
    normalized = dict(payload)
    if _raw_hook_event_name(normalized):
        return normalized
    file_path = normalized.get("file_path")
    if isinstance(file_path, str) and file_path.strip():
        normalized["hook_event_name"] = "beforeReadFile"
        return normalized
    command = normalized.get("command")
    if isinstance(command, str) and command.strip():
        normalized["hook_event_name"] = "beforeShellExecution"
        return normalized
    if normalized.get("tool_name") is not None or normalized.get("tool_input") is not None:
        normalized["hook_event_name"] = "preToolUse"
    return normalized


def _cursor_shell_hook_payload(normalized: dict[str, object], hook_event_name: str) -> dict[str, object]:
    payload = dict(normalized)
    payload["hook_event_name"] = hook_event_name
    payload.setdefault("tool_name", "Shell")
    tool_input = _tool_input_dict(payload.get("tool_input"))
    command = payload.get("command")
    if isinstance(command, str) and command.strip():
        tool_input.setdefault("command", command.strip())
    cwd = payload.get("cwd")
    if isinstance(cwd, str) and cwd.strip():
        tool_input.setdefault("working_directory", cwd.strip())
    payload["tool_input"] = tool_input
    return payload


def _cursor_mcp_hook_payload(normalized: dict[str, object], hook_event_name: str) -> dict[str, object]:
    payload = dict(normalized)
    payload["hook_event_name"] = hook_event_name
    tool_input = _tool_input_dict(payload.get("tool_input"))
    payload["tool_input"] = tool_input
    tool_name = payload.get("tool_name")
    if isinstance(tool_name, str) and tool_name.strip():
        payload["tool_name"] = tool_name.strip()
    else:
        payload.setdefault("tool_name", "MCP")
    return payload


def _prepare_cursor_hook_payload(payload: dict[str, object]) -> dict[str, object]:
    normalized = _infer_cursor_hook_event_name(payload)
    raw_event = _raw_hook_event_name(normalized)
    if raw_event == "aftershellexecution":
        return _cursor_shell_hook_payload(normalized, "afterShellExecution")
    if raw_event == "aftermcpexecution":
        return _cursor_mcp_hook_payload(normalized, "afterMCPExecution")
    if raw_event == "beforeshellexecution":
        prepared = _cursor_shell_hook_payload(normalized, "PreToolUse")
        prepared["cursor_source_hook_event"] = "beforeShellExecution"
        return prepared
    if raw_event == "beforemcpexecution":
        prepared = _cursor_mcp_hook_payload(normalized, "PreToolUse")
        tool_input = _tool_input_dict(prepared.get("tool_input"))
        for key in ("url", "command"):
            value = normalized.get(key)
            if isinstance(value, str) and value.strip():
                tool_input.setdefault(key, value.strip())
        prepared["tool_input"] = tool_input
        prepared["cursor_source_hook_event"] = "beforeMCPExecution"
        return prepared
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


def _cursor_generation_id(payload: Mapping[str, object]) -> str | None:
    for key in ("generation_id", "generationId"):
        value = payload.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


def _cursor_conversation_id(payload: Mapping[str, object]) -> str | None:
    for key in ("conversation_id", "conversationId", "session_id", "sessionId"):
        value = payload.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    session_id = os.environ.get("CURSOR_SESSION_ID")
    if isinstance(session_id, str) and session_id.strip():
        return session_id.strip()
    return None


def _normalize_cursor_shell_command(command: str) -> str:
    stripped = command.strip()
    if not stripped or len(stripped) > 8192:
        return stripped
    lowered = stripped.lower()
    needle = "lean-ctx"
    start = 0
    while True:
        idx = lowered.find(needle, start)
        if idx == -1:
            return stripped
        if idx == 0 or stripped[idx - 1] == "/":
            tail = stripped[idx + len(needle) :].lstrip()
            if tail.startswith("-c"):
                rest = tail[2:].lstrip()
                try:
                    tokens = shlex.split(rest, posix=True, comments=False)
                except ValueError:
                    tokens = None
                if tokens:
                    inner = tokens[0]
                    suffix = tokens[1:]
                    return " ".join((inner, *suffix)) if suffix else inner
                if rest.startswith("'"):
                    parts = []
                    index = 1
                    while index < len(rest):
                        character = rest[index]
                        if character != "'":
                            parts.append(character)
                            index += 1
                            continue
                        if index + 3 < len(rest) and rest[index : index + 4] == "'\\''":
                            parts.append("'")
                            index += 4
                            continue
                        inner = "".join(parts)
                        suffix = rest[index + 1 :].lstrip()
                        return " ".join((inner, suffix)) if suffix else inner
                return stripped
        start = idx + 1
    return stripped


# Installed hook helpers below mirror cursor_native_approval.py; keep both copies in sync.


def _cursor_hook_payload_is_mcp_execution(payload: Mapping[str, object]) -> bool:
    source_event = payload.get("cursor_source_hook_event")
    if isinstance(source_event, str) and source_event.strip().lower() == "beforemcpexecution":
        return True
    for key in ("hook_event_name", "hookEventName", "hook_name", "hookName", "event", "eventName"):
        value = payload.get(key)
        if isinstance(value, str):
            lowered = value.strip().lower()
            if lowered in {"beforemcpexecution", "aftermcpexecution"}:
                return True
    return False


def _is_shell_wrapper_command(command: str) -> bool:
    stripped = command.strip()
    if not stripped:
        return False
    try:
        parts = shlex.split(stripped, posix=True, comments=False)
    except ValueError:
        return False
    if not parts:
        return False
    binary = Path(parts[0]).name.lower()
    if binary == "lean-ctx":
        return True
    if binary not in {"ash", "bash", "dash", "fish", "sh", "zsh"}:
        return False
    return len(parts) > 1 and parts[1] == "-c"


def _nested_cursor_shell_command(tool_input: Mapping[str, object]) -> str | None:
    for key in ("command", "cmd", "shell_command", "shellCommand"):
        value = tool_input.get(key)
        if isinstance(value, str) and value.strip():
            return _normalize_cursor_shell_command(value)
    return None


def _cursor_shell_command(payload: Mapping[str, object]) -> str | None:
    tool_input = payload.get("tool_input")
    nested_command: str | None = None
    if isinstance(tool_input, dict):
        nested_command = _nested_cursor_shell_command(tool_input)
    command = payload.get("command")
    top_level: str | None = None
    if isinstance(command, str) and command.strip():
        top_level = _normalize_cursor_shell_command(command)
    if _cursor_hook_payload_is_mcp_execution(payload):
        if nested_command is not None:
            return nested_command
        return top_level
    if nested_command is not None and (
        top_level is None or (isinstance(command, str) and _is_shell_wrapper_command(command))
    ):
        return nested_command
    if top_level is not None:
        return top_level
    return nested_command


def _cursor_shell_binding_path(conversation_id: str, command: str) -> Path:
    cleaned = conversation_id.strip()
    if not cleaned or "/" in cleaned or "\\\\" in cleaned or cleaned in {".", ".."}:
        segment = hashlib.sha256(cleaned.encode("utf-8")).hexdigest()[:32] if cleaned else "missing-conversation"
    else:
        segment = cleaned
    normalized_command = _normalize_cursor_shell_command(command)
    fingerprint = hashlib.sha256(normalized_command.encode("utf-8")).hexdigest()[:24]
    return Path(GUARD_HOME) / "cursor-shell-bindings" / segment / fingerprint


def _read_cursor_shell_binding_file(conversation_id: str, command: str) -> str | None:
    binding_path = _cursor_shell_binding_path(conversation_id, command)
    try:
        binding = binding_path.read_text(encoding="utf-8").strip()
    except OSError:
        return None
    return binding or None


def _resolve_approval_binding(payload: Mapping[str, object]) -> str | None:
    binding = _cursor_generation_id(payload)
    if binding is not None:
        return binding
    conversation_id = _cursor_conversation_id(payload)
    command = _cursor_shell_command(payload)
    if conversation_id is None or command is None:
        return None
    return _read_cursor_shell_binding_file(conversation_id, command)


def _load_cursor_hook_attestation_secret() -> bytes | None:
    secret_path = Path(GUARD_HOME) / "secrets" / "cursor-hook-attestation.key"
    try:
        secret = secret_path.read_bytes()
    except OSError:
        return None
    return secret or None


def _compute_cursor_after_observer_proof(
    payload: Mapping[str, object],
    observer_event: str,
    approval_binding: str | None = None,
) -> str | None:
    conversation_id = _cursor_conversation_id(payload)
    command = _cursor_shell_command(payload)
    resolved_binding = approval_binding or _resolve_approval_binding(payload)
    secret = _load_cursor_hook_attestation_secret()
    if conversation_id is None or command is None or resolved_binding is None or secret is None:
        return None
    message = chr(0).join(
        (conversation_id, command, resolved_binding, observer_event.strip())
    ).encode("utf-8")
    return hmac.new(secret, message, hashlib.sha256).hexdigest()


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
    inferred = _infer_cursor_hook_event_name(payload)
    hook_event_name = str(inferred.get("hook_event_name") or inferred.get("hookEventName") or "preToolUse")
    prepared = _prepare_cursor_hook_payload(inferred)
    workspace = _workspace_from_cursor_input(prepared)
    guard_argv = list(GUARD_HOOK_ARGV)
    if workspace:
        if "--workspace" in guard_argv:
            workspace_index = guard_argv.index("--workspace")
            if workspace_index + 1 < len(guard_argv):
                guard_argv[workspace_index + 1] = workspace
        else:
            guard_argv.extend(["--workspace", workspace])
    guard_env = _hook_process_env()
    guard_env["HOL_GUARD_MANAGED_CURSOR_HOOK"] = "1"
    if hook_event_name.strip().lower() in {"aftershellexecution", "aftermcpexecution"}:
        approval_binding = _resolve_approval_binding(prepared)
        proof = _compute_cursor_after_observer_proof(prepared, hook_event_name, approval_binding)
        if approval_binding:
            guard_env["HOL_GUARD_CURSOR_APPROVAL_BINDING"] = approval_binding
        if proof:
            guard_env["HOL_GUARD_CURSOR_AFTER_SHELL_PROOF"] = proof
    payload_json = json.dumps(prepared)
    daemon_result = _daemon_hook_result(
        payload_json,
        workspace=workspace,
        hook_env_overlay=_daemon_hook_env_overlay(guard_env),
    )
    try:
        if daemon_result is not None:
            proc = subprocess.CompletedProcess(
                [*GUARD_CLI, *guard_argv],
                daemon_result[0],
                stdout=daemon_result[1],
                stderr=daemon_result[2],
            )
        else:
            proc = subprocess.run(
                [*GUARD_CLI, *guard_argv],
                input=payload_json,
                capture_output=True,
                text=True,
                cwd=GUARD_HOME,
                env=guard_env,
                timeout=GUARD_HOOK_TIMEOUT_SECONDS,
            )
    except subprocess.TimeoutExpired:
        print(
            json.dumps(
                {
                    "permission": "deny",
                    "user_message": (
                        f"HOL Guard hook timed out after {GUARD_HOOK_TIMEOUT_SECONDS}s. "
                        "Open the Guard approval center or native Cursor prompt, resolve pending requests, then retry."
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
    if hook_event_name.strip().lower() in {"aftershellexecution", "aftermcpexecution"}:
        print("{}")
        return 0
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
        "failClosed": event_name in _BLOCKING_MANAGED_HOOK_EVENTS,
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
    if "hol-guard-cursor-hook" in lowered:
        return True
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
