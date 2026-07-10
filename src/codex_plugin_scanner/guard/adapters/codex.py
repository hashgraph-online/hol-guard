"""Codex harness adapter."""

from __future__ import annotations

import hashlib
import importlib
import json
import re
import shlex
import sys
from copy import deepcopy
from pathlib import Path
from typing import Any
from urllib.parse import urlencode

from ..aibom_detection import (
    enrich_mcp_server_metadata,
    extend_codex_runtime_inventory,
    extend_detection_with_workspace_aibom,
)
from ..codex_config import dump_toml, read_toml_payload, write_toml_payload
from ..config import MAX_APPROVAL_WAIT_TIMEOUT_SECONDS, load_guard_config, resolve_guard_home
from ..launcher import merge_guard_launcher_env
from ..models import GuardArtifact, HarnessDetection
from ..shims import install_guard_shim, remove_guard_shim
from .base import HarnessAdapter, HarnessContext, _command_available, _warnings_include_setup_failure
from .codex_remote_control import codex_remote_launch_environment, guarded_codex_launch_command
from .mcp_servers import (
    ManagedMcpServer,
    is_guard_proxy_command,
    managed_stdio_servers,
    proxy_cli_args,
    proxy_process_env,
    skipped_stdio_server_names,
)

tomllib: Any
try:  # pragma: no cover - Python 3.11+
    import tomllib as tomllib  # type: ignore[attr-defined]
except ModuleNotFoundError:  # pragma: no cover - Python 3.10
    tomllib = importlib.import_module("tomli")


def _read_toml(path: Path) -> dict[str, object]:
    if not path.is_file():
        return {}
    try:
        with path.open("rb") as handle:
            payload = tomllib.load(handle)
        return payload if isinstance(payload, dict) else {}
    except (OSError, tomllib.TOMLDecodeError):
        return {}


def _artifact_from_guard_proxy_args(
    *,
    args: tuple[str, ...],
    fallback_name: str,
    fallback_scope: str,
    fallback_config_path: Path,
    harness: str,
) -> GuardArtifact | None:
    """Expose the wrapped server for status/review without re-wrapping it."""

    parsed = _parse_guard_proxy_args(args)
    command = parsed.get("command")
    if not isinstance(command, str) or not command:
        return None
    name_value = parsed.get("server-name")
    name = name_value if isinstance(name_value, str) and name_value else fallback_name
    source_scope_value = parsed.get("source-scope")
    source_scope = source_scope_value if isinstance(source_scope_value, str) and source_scope_value else fallback_scope
    config_path_value = parsed.get("config-path")
    config_path = (
        config_path_value if isinstance(config_path_value, str) and config_path_value else str(fallback_config_path)
    )
    transport_value = parsed.get("transport")
    transport = transport_value if isinstance(transport_value, str) and transport_value else "stdio"
    server_args_value = parsed.get("arg")
    server_args = server_args_value if isinstance(server_args_value, tuple) else ()
    env_keys_value = parsed.get("server-env-key")
    env_keys = tuple(sorted(env_keys_value)) if isinstance(env_keys_value, tuple) else ()
    return GuardArtifact(
        artifact_id=f"codex:{source_scope}:{name}",
        name=name,
        harness=harness,
        artifact_type="mcp_server",
        source_scope=source_scope,
        config_path=config_path,
        command=command,
        args=server_args,
        transport=transport,
        metadata={
            "env": {},
            "env_keys": list(env_keys),
            "guard_managed_proxy": True,
        },
    )


def _parse_guard_proxy_args(args: tuple[str, ...]) -> dict[str, str | tuple[str, ...]]:
    parsed: dict[str, str | tuple[str, ...]] = {}
    repeated: dict[str, list[str]] = {"arg": [], "server-env-key": []}
    index = 0
    while index < len(args):
        token = args[index]
        if not token.startswith("--"):
            index += 1
            continue
        key_value = token[2:]
        if "=" in key_value:
            key, value = key_value.split("=", 1)
            if key in repeated:
                repeated[key].append(value)
            else:
                parsed[key] = value
            index += 1
            continue
        key = key_value
        if key in repeated:
            if index + 1 < len(args):
                repeated[key].append(args[index + 1])
                index += 2
            else:
                index += 1
            continue
        if index + 1 < len(args) and not args[index + 1].startswith("--"):
            parsed[key] = args[index + 1]
            index += 2
        else:
            index += 1
    for key, values in repeated.items():
        parsed[key] = tuple(values)
    return parsed


_MANAGED_HOOK_STATUS_MESSAGE = "HOL Guard checking tool action"
_MANAGED_PROMPT_HOOK_STATUS_MESSAGE = "HOL Guard checking prompt"
_MANAGED_PERMISSION_HOOK_STATUS_MESSAGE = "HOL Guard checking Codex approval request"
_MANAGED_POST_TOOL_HOOK_STATUS_MESSAGE = "HOL Guard checking tool result"
_LEGACY_MANAGED_HOOK_STATUS_MESSAGES = {
    "HOL Guard checking Bash command",
    _MANAGED_HOOK_STATUS_MESSAGE,
    _MANAGED_PROMPT_HOOK_STATUS_MESSAGE,
    _MANAGED_PERMISSION_HOOK_STATUS_MESSAGE,
    _MANAGED_POST_TOOL_HOOK_STATUS_MESSAGE,
}
_MANAGED_HOOK_TIMEOUT_SECONDS = 30
_MANAGED_HOOK_TIMEOUT_GRACE_SECONDS = 5
_CODEX_GUARD_TOOL_MATCHER = "Bash|Read|Write|Edit|MultiEdit|^apply_patch$|mcp__.*"
_CODEX_GUARD_PERMISSION_MATCHER = "Bash|Read|Write|Edit|MultiEdit|^apply_patch$|mcp__.*"
_SHELL_GUARD_BEGIN = "# >>> HOL Guard Codex shell guard >>>"
_SHELL_GUARD_END = "# <<< HOL Guard Codex shell guard <<<"
_DAEMON_BRIDGE_PATH_SUFFIX = (
    "codex_plugin_scanner",
    "guard",
    "adapters",
    "codex_daemon_hook_bridge.py",
)
_GUARD_INSTALL_PATH_SEGMENTS = (
    ("uv", "tools", "hol-guard"),
    ("pipx", "venvs", "hol-guard"),
)


def _json_object(path: Path) -> dict[str, object]:
    if not path.is_file():
        return {}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return payload if isinstance(payload, dict) else {}


def _strict_json_object(path: Path, *, label: str) -> dict[str, object]:
    if path.exists() and not path.is_file():
        raise RuntimeError(f"Guard refused to overwrite non-file {label} at {path}")
    if not path.is_file():
        return {}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"Guard refused to overwrite unreadable {label} at {path}") from exc
    if not isinstance(payload, dict):
        raise RuntimeError(f"Guard refused to overwrite non-object {label} at {path}")
    return payload


def _local_hook_command_parts(context: HarnessContext) -> tuple[str, ...]:
    resolved_home = context.home_dir.resolve()
    resolved_user_home = Path.home().resolve()
    guard_args = [
        "guard",
        "hook",
        "--harness",
        "codex",
    ]
    if resolved_home != resolved_user_home:
        guard_args.extend(["--home", str(context.home_dir)])
        if context.guard_home.resolve() != resolved_home:
            guard_args.extend(["--guard-home", str(context.guard_home)])
    if context.workspace_dir is not None:
        guard_args.extend(["--workspace", str(context.workspace_dir)])
    return (sys.executable, "-m", "codex_plugin_scanner.cli", *guard_args)


def _runtime_guard_home(context: HarnessContext) -> Path:
    if context.home_dir.resolve() == Path.home().resolve():
        return resolve_guard_home()
    return context.guard_home


def _daemon_start_command(guard_home: Path) -> tuple[str, ...]:
    package_root = Path(__file__).resolve().parents[3]
    code = (
        "import sys;"
        f"sys.path.insert(0, {str(package_root)!r});"
        "from pathlib import Path;"
        "from codex_plugin_scanner.guard.daemon import ensure_guard_daemon;"
        f"ensure_guard_daemon(Path({str(guard_home)!r}))"
    )
    return (sys.executable, "-c", code)


def _hook_command_parts(context: HarnessContext) -> tuple[str, ...]:
    guard_home = _runtime_guard_home(context)
    query = {"guard-home": str(guard_home)}
    if context.home_dir.resolve() != Path.home().resolve():
        query["home"] = str(context.home_dir)
    if context.workspace_dir is not None:
        query["workspace"] = str(context.workspace_dir)
    long_timeout = _post_tool_hook_timeout_seconds(context)
    config = {
        "state_path": str(guard_home / "daemon-state.json"),
        "fallback_command": list(_local_hook_command_parts(context)),
        "start_command": list(_daemon_start_command(guard_home)),
        "query": urlencode(query),
        "hook_timeouts": {
            "PreToolUse": long_timeout,
            "PermissionRequest": _MANAGED_HOOK_TIMEOUT_SECONDS,
            "UserPromptSubmit": _MANAGED_HOOK_TIMEOUT_SECONDS,
            "PostToolUse": long_timeout,
        },
    }
    bridge_path = Path(__file__).with_name("codex_daemon_hook_bridge.py")
    return (sys.executable, str(bridge_path), json.dumps(config, separators=(",", ":")))


def _hook_command(context: HarnessContext) -> str:
    return shlex.join(_hook_command_parts(context))


def _managed_hook_entry(
    context: HarnessContext,
    status_message: str,
    *,
    timeout_seconds: int = _MANAGED_HOOK_TIMEOUT_SECONDS,
) -> dict[str, object]:
    environment = merge_guard_launcher_env(pin_package=True)
    environment.update(codex_remote_launch_environment(context.home_dir))
    return {
        "type": "command",
        "command": _hook_command(context),
        "timeout": timeout_seconds,
        "statusMessage": status_message,
        "env": environment,
    }


def _pre_tool_hook_group(context: HarnessContext) -> dict[str, object]:
    return {
        "matcher": _CODEX_GUARD_TOOL_MATCHER,
        "hooks": [
            _managed_hook_entry(
                context,
                _MANAGED_HOOK_STATUS_MESSAGE,
                timeout_seconds=_post_tool_hook_timeout_seconds(context),
            )
        ],
    }


def _prompt_hook_group(context: HarnessContext) -> dict[str, object]:
    return {
        "hooks": [_managed_hook_entry(context, _MANAGED_PROMPT_HOOK_STATUS_MESSAGE)],
    }


def _permission_request_hook_group(context: HarnessContext) -> dict[str, object]:
    return {
        "matcher": _CODEX_GUARD_PERMISSION_MATCHER,
        "hooks": [_managed_hook_entry(context, _MANAGED_PERMISSION_HOOK_STATUS_MESSAGE)],
    }


def _post_tool_hook_timeout_seconds(context: HarnessContext) -> int:
    configured_wait_timeout = load_guard_config(
        context.guard_home,
        context.workspace_dir,
    ).approval_wait_timeout_seconds
    return (
        min(
            max(configured_wait_timeout, 0),
            MAX_APPROVAL_WAIT_TIMEOUT_SECONDS,
        )
        + _MANAGED_HOOK_TIMEOUT_GRACE_SECONDS
    )


def _post_tool_hook_group(context: HarnessContext) -> dict[str, object]:
    return {
        "matcher": "Bash",
        "hooks": [
            _managed_hook_entry(
                context,
                _MANAGED_POST_TOOL_HOOK_STATUS_MESSAGE,
                timeout_seconds=_post_tool_hook_timeout_seconds(context),
            )
        ],
    }


def _managed_hook_groups(context: HarnessContext) -> dict[str, dict[str, object]]:
    return {
        "PreToolUse": _pre_tool_hook_group(context),
        "PermissionRequest": _permission_request_hook_group(context),
        "UserPromptSubmit": _prompt_hook_group(context),
        "PostToolUse": _post_tool_hook_group(context),
    }


def _split_hook_command(command: object) -> list[str] | None:
    if not isinstance(command, str):
        return None
    try:
        tokens = shlex.split(command)
    except ValueError:
        return None
    return tokens


def _tokens_are_managed_hook_command(tokens: list[str]) -> bool:
    if tokens and Path(tokens[0]).name == "hol-guard-codex-hook.sh":
        return True
    if len(tokens) < 2:
        return False
    executable = Path(tokens[0]).name.lower()
    if not executable.startswith("python"):
        return False
    if _is_daemon_bridge_hook_command(tokens):
        return True
    if len(tokens) < 3:
        return False
    if _argv_is_direct_codex_hook(tokens):
        return True
    return bool(_argv_is_inline_codex_hook(tokens))


def _is_managed_hook_command(command: object) -> bool:
    tokens = _split_hook_command(command)
    if tokens is None:
        return False
    return _tokens_are_managed_hook_command(tokens)


def _python_script_and_args(tokens: list[str]) -> tuple[str, list[str]] | None:
    """Return (script_path, remaining_args) after a python executable and its flags."""
    if not tokens or not Path(tokens[0]).name.lower().startswith("python"):
        return None
    index = 1
    while index < len(tokens):
        token = tokens[index]
        if token in {"-c", "-m"}:
            return None
        if token.startswith("-"):
            # Flags that consume a following argument (e.g. -W error, -X faulthandler).
            if token in {"-W", "-X", "-Q"} and index + 1 < len(tokens):
                index += 2
                continue
            index += 1
            continue
        return token, tokens[index + 1 :]
    return None


def _is_daemon_bridge_hook_command(tokens: list[str]) -> bool:
    script_and_args = _python_script_and_args(tokens)
    if script_and_args is None:
        return False
    script_path, remaining = script_and_args
    managed_bridge_path = Path(__file__).with_name("codex_daemon_hook_bridge.py").resolve()
    try:
        if Path(script_path).resolve() == managed_bridge_path:
            return True
    except OSError:
        pass
    bridge_path = Path(script_path)
    return (
        len(remaining) >= 1
        and bridge_path.parts[-len(_DAEMON_BRIDGE_PATH_SUFFIX) :] == _DAEMON_BRIDGE_PATH_SUFFIX
        and _bridge_config_targets_codex(remaining[0])
    )


def _tokens_are_unambiguously_managed_hook_command(tokens: list[str]) -> bool:
    """Return True for hook commands that only Guard installs.

    Direct ``python -m codex_plugin_scanner.cli guard hook`` entries are ambiguous:
    a user can hand-author the same command. Bridge paths and the shell wrapper are
    unique to Guard installs and can be reclaimed without a statusMessage marker.
    """
    if tokens and Path(tokens[0]).name == "hol-guard-codex-hook.sh":
        return True
    if len(tokens) < 2:
        return False
    executable = Path(tokens[0]).name.lower()
    if not executable.startswith("python"):
        return False
    return _is_daemon_bridge_hook_command(tokens)


def _is_unambiguously_managed_hook_command(command: object) -> bool:
    tokens = _split_hook_command(command)
    if tokens is None:
        return False
    return _tokens_are_unambiguously_managed_hook_command(tokens)


def _bridge_config_targets_codex(config_text: str) -> bool:
    try:
        config_value: object = json.loads(config_text)
    except json.JSONDecodeError:
        return False
    if not isinstance(config_value, dict):
        return False
    config = {key: value for key, value in config_value.items() if isinstance(key, str)}
    fallback_value = config.get("fallback_command")
    if not isinstance(fallback_value, list) or not all(isinstance(token, str) for token in fallback_value):
        return False
    fallback_command = [token for token in fallback_value if isinstance(token, str)]
    return _argv_is_direct_codex_hook(fallback_command)


def _argv_is_direct_codex_hook(tokens: list[str]) -> bool:
    if not tokens or not Path(tokens[0]).name.lower().startswith("python"):
        return False
    for index, token in enumerate(tokens[1:], start=1):
        if token == "-c":
            return False
        if token != "-m":
            continue
        if index + 3 >= len(tokens):
            return False
        return (
            tokens[index + 1] == "codex_plugin_scanner.cli"
            and tokens[index + 2] == "guard"
            and tokens[index + 3] == "hook"
            and _argv_targets_codex(tokens[index + 4 :])
        )
    return False


def _argv_is_inline_codex_hook(tokens: list[str]) -> bool:
    if not tokens or not Path(tokens[0]).name.lower().startswith("python"):
        return False
    for index, token in enumerate(tokens[1:], start=1):
        if token == "-m":
            return False
        if token != "-c":
            continue
        if index + 1 >= len(tokens):
            return False
        code = tokens[index + 1]
        has_guard_call = (
            re.search(r"['\"]guard['\"]", code) is not None
            and re.search(r"['\"]hook['\"]", code) is not None
            and re.search(r"['\"]--harness['\"]", code) is not None
            and re.search(r"['\"]codex['\"]", code) is not None
        )
        return "codex_plugin_scanner.cli" in code and "main([" in code and has_guard_call
    return False


def _python_executable_is_guard_install(executable: str) -> bool:
    """True when the interpreter path is a Guard pipx/uv install, not a substring lookalike."""
    parts = tuple(part.lower() for part in Path(executable).parts)
    return any(
        any(parts[index : index + len(segment)] == segment for index in range(len(parts) - len(segment) + 1))
        for segment in _GUARD_INSTALL_PATH_SEGMENTS
    )


def _argv_targets_codex(argv: list[str]) -> bool:
    for index, token in enumerate(argv):
        if token == "--harness" and index + 1 < len(argv) and argv[index + 1] == "codex":
            return True
        if token.startswith("--harness=") and token.split("=", 1)[1] == "codex":
            return True
    return False


def _is_managed_hook_group(group: object) -> bool:
    if not isinstance(group, dict):
        return False
    hooks = group.get("hooks")
    if not isinstance(hooks, list):
        return False
    return any(_is_managed_hook_entry(entry) for entry in hooks)


def _is_managed_hook_entry(entry: object) -> bool:
    if not isinstance(entry, dict):
        return False
    if entry.get("type") != "command":
        return False
    tokens = _split_hook_command(entry.get("command"))
    if tokens is None or not _tokens_are_managed_hook_command(tokens):
        return False
    # Bridge/wrapper commands are uniquely Guard-owned.
    if _tokens_are_unambiguously_managed_hook_command(tokens):
        return True
    status_message = entry.get("statusMessage")
    if isinstance(status_message, str) and status_message in _LEGACY_MANAGED_HOOK_STATUS_MESSAGES:
        return True
    # Stale pipx/uv direct hooks may lose statusMessage but still live under Guard install paths.
    return _python_executable_is_guard_install(tokens[0])


def _remove_managed_hook_entries(group: object) -> object | None:
    if not isinstance(group, dict):
        return group
    hooks = group.get("hooks")
    if not isinstance(hooks, list):
        return group
    remaining_hooks = [entry for entry in hooks if not _is_managed_hook_entry(entry)]
    if len(remaining_hooks) == len(hooks):
        return group
    if not remaining_hooks:
        return None
    updated_group = dict(group)
    updated_group["hooks"] = remaining_hooks
    return updated_group


def _merge_hook_groups(groups: object, managed_group: dict[str, object]) -> list[object]:
    return [*_remove_hook_groups(groups), managed_group]


def _remove_hook_groups(groups: object) -> list[object]:
    if not isinstance(groups, list):
        return []
    remaining: list[object] = []
    for group in groups:
        cleaned_group = _remove_managed_hook_entries(group)
        if cleaned_group is not None:
            remaining.append(cleaned_group)
    return remaining


def _remove_managed_hook_events(hooks: dict[str, object]) -> tuple[dict[str, object], bool]:
    updated_hooks = dict(hooks)
    changed = False
    for event_name in ("PreToolUse", "PermissionRequest", "UserPromptSubmit", "PostToolUse"):
        original_groups = deepcopy(updated_hooks.get(event_name))
        remaining = _remove_hook_groups(original_groups)
        managed_removed = isinstance(original_groups, list) and remaining != original_groups
        if not managed_removed:
            continue
        changed = True
        if remaining:
            updated_hooks[event_name] = remaining
        else:
            updated_hooks.pop(event_name, None)
    return updated_hooks, changed


def _append_unique_hook_groups(existing_groups: object, incoming_groups: object) -> list[object]:
    merged = list(existing_groups) if isinstance(existing_groups, list) else []
    if not isinstance(incoming_groups, list):
        return merged
    for group in incoming_groups:
        if group not in merged:
            merged.append(group)
    return merged


def _migrate_hooks_json_into_config(config_payload: dict[str, object], hooks_payload: dict[str, object]) -> bool:
    json_hooks = hooks_payload.get("hooks")
    if not isinstance(json_hooks, dict):
        return False
    config_hooks = config_payload.get("hooks")
    if not isinstance(config_hooks, dict):
        config_hooks = {}
    cleaned_json_hooks, _ = _remove_managed_hook_events(json_hooks)
    changed = False
    for event_name, groups in cleaned_json_hooks.items():
        merged_groups = _append_unique_hook_groups(config_hooks.get(event_name), groups)
        if merged_groups != config_hooks.get(event_name):
            changed = True
        config_hooks[event_name] = merged_groups
    if config_hooks:
        config_payload["hooks"] = config_hooks
    return changed


def _hooks_payload_has_unmanaged_entries(hooks_payload: dict[str, object]) -> bool:
    hooks = hooks_payload.get("hooks")
    if not isinstance(hooks, dict):
        return False
    cleaned_hooks, _ = _remove_managed_hook_events(hooks)
    return any(
        isinstance(cleaned_hooks.get(event_name), list) and bool(cleaned_hooks.get(event_name))
        for event_name in ("PreToolUse", "PermissionRequest", "UserPromptSubmit", "PostToolUse")
    )


def _payload_has_hooks_feature_enabled(config_payload: dict[str, object]) -> bool:
    features = config_payload.get("features")
    if not isinstance(features, dict):
        return False
    return features.get("hooks") is True or features.get("codex_hooks") is True


def _remove_managed_shell_guard_block(text: str) -> str:
    pattern = re.compile(
        rf"\n?{re.escape(_SHELL_GUARD_BEGIN)}.*?{re.escape(_SHELL_GUARD_END)}\n?",
        re.DOTALL,
    )
    return pattern.sub("\n", text).strip("\n")


def _codex_zshenv_guard_script() -> str:
    return """# Managed by HOL Guard. Loaded by zsh only for Codex-owned shell commands.
if [[ -n "${CODEX_MANAGED_BY_BUN:-}" || -n "${CODEX_MANAGED_PACKAGE_ROOT:-}" ]]; then
  function TRAPDEBUG() {
    emulate -L zsh
    local cmd="${ZSH_DEBUG_CMD:-}"
    [[ -z "$cmd" ]] && return 0
    [[ "$cmd" == "TRAPDEBUG () {"* ]] && return 0
    [[ "$cmd" == *"codex-zshenv-guard.zsh"* ]] && return 0
    local normalized_cmd="${cmd//\\\"/}"
    normalized_cmd="${normalized_cmd//\\'/}"
    case "$normalized_cmd" in
      *".npmrc"*|*".pypirc"*|*".netrc"*|*"id_rsa"*|*"id_ed25519"*|*"npm_token"*|*"NPM_TOKEN"*|*"_authToken"*|*".env"* )
        print -u2 "HOL Guard blocked Codex before it could read a secret-looking local file."
        print -u2 "Blocked command: ${cmd}"
        return 1
        ;;
    esac
    return 0
  }
fi
"""


def _codex_bashenv_guard_script() -> str:
    return """# Managed by HOL Guard. Loaded by bash only for Codex-owned shell commands.
if [[ -n "${CODEX_MANAGED_BY_BUN:-}" || -n "${CODEX_MANAGED_PACKAGE_ROOT:-}" ]]; then
  shopt -s extdebug 2>/dev/null || true
  __hol_guard_codex_bash_debug_trap() {
    local cmd="${BASH_COMMAND:-}"
    [[ -z "$cmd" ]] && return 0
    [[ "$cmd" == "__hol_guard_codex_bash_debug_trap"* ]] && return 0
    [[ "$cmd" == *"codex-bashenv-guard.bash"* ]] && return 0
    local normalized_cmd="${cmd//\\\"/}"
    normalized_cmd="${normalized_cmd//\\'/}"
    case "$normalized_cmd" in
      *".npmrc"*|*".pypirc"*|*".netrc"*|*"id_rsa"*|*"id_ed25519"*|*"npm_token"*|*"NPM_TOKEN"*|*"_authToken"*|*".env"* )
        printf '%s\\n' "HOL Guard blocked Codex before it could read a secret-looking local file." >&2
        printf '%s\\n' "Blocked command: ${cmd}" >&2
        exit 126
        ;;
    esac
    return 0
  }
  trap '__hol_guard_codex_bash_debug_trap' DEBUG
fi
"""


def _codex_fish_guard_script() -> str:
    return """# Managed by HOL Guard. Loaded by fish only for Codex-owned shell commands.
if set -q CODEX_MANAGED_BY_BUN; or set -q CODEX_MANAGED_PACKAGE_ROOT
  function __hol_guard_codex_fish_preexec --on-event fish_preexec
    set -l cmd "$argv"
    set -l normalized_cmd (string replace -a '"' '' -- "$cmd")
    set normalized_cmd (string replace -a "'" "" -- "$normalized_cmd")
    switch "$normalized_cmd"
      case "*.npmrc*" "*.pypirc*" "*.netrc*" "*id_rsa*" "*id_ed25519*" "*token*" "*TOKEN*" "*authToken*" "*.env*"
        echo "HOL Guard blocked Codex before it could read a secret-looking local file." >&2
        echo "Blocked command: $cmd" >&2
        exit 126
    end
  end
end
"""


def codex_native_hook_state(context: HarnessContext) -> dict[str, object]:
    config_path = CodexHarnessAdapter._hook_config_path(context)
    hooks_path = CodexHarnessAdapter._hooks_path(context)
    config_payload = _read_toml(config_path)
    features = config_payload.get("features") if isinstance(config_payload, dict) else None
    toml_hooks = config_payload.get("hooks") if isinstance(config_payload, dict) else None
    hooks_payload = _json_object(hooks_path)
    json_hooks = hooks_payload.get("hooks") if isinstance(hooks_payload, dict) else None
    hooks = toml_hooks if isinstance(toml_hooks, dict) else json_hooks
    pre_tool_groups = hooks.get("PreToolUse") if isinstance(hooks, dict) else None
    permission_groups = hooks.get("PermissionRequest") if isinstance(hooks, dict) else None
    prompt_groups = hooks.get("UserPromptSubmit") if isinstance(hooks, dict) else None
    post_tool_groups = hooks.get("PostToolUse") if isinstance(hooks, dict) else None
    pre_tool_hook_installed = isinstance(pre_tool_groups, list) and any(
        _is_managed_hook_group(group) for group in pre_tool_groups
    )
    permission_hook_installed = isinstance(permission_groups, list) and any(
        _is_managed_hook_group(group) for group in permission_groups
    )
    prompt_hook_installed = isinstance(prompt_groups, list) and any(
        _is_managed_hook_group(group) for group in prompt_groups
    )
    post_tool_hook_installed = isinstance(post_tool_groups, list) and any(
        _is_managed_hook_group(group) for group in post_tool_groups
    )
    managed_hook_installed = (
        pre_tool_hook_installed and permission_hook_installed and prompt_hook_installed and post_tool_hook_installed
    )
    features_is_table = isinstance(features, dict)
    hooks_feature_enabled = not features_is_table or features.get("hooks") is not False
    legacy_codex_hooks_enabled = features_is_table and features.get("codex_hooks") is True
    return {
        "config_path": str(config_path),
        "config_present": config_path.is_file(),
        "hooks_path": str(hooks_path),
        "hooks_present": hooks_path.is_file(),
        "toml_hooks_present": isinstance(toml_hooks, dict)
        and any(
            bool(toml_hooks.get(event_name))
            for event_name in ("PreToolUse", "PermissionRequest", "UserPromptSubmit", "PostToolUse")
        ),
        "json_hooks_present": isinstance(json_hooks, dict)
        and any(
            bool(json_hooks.get(event_name))
            for event_name in ("PreToolUse", "PermissionRequest", "UserPromptSubmit", "PostToolUse")
        ),
        "hooks_enabled": hooks_feature_enabled,
        "codex_hooks_enabled": hooks_feature_enabled,
        "legacy_codex_hooks_enabled": legacy_codex_hooks_enabled,
        "managed_pre_tool_hook_installed": pre_tool_hook_installed,
        "managed_permission_request_hook_installed": permission_hook_installed,
        "managed_prompt_hook_installed": prompt_hook_installed,
        "managed_post_tool_hook_installed": post_tool_hook_installed,
        "managed_hook_installed": managed_hook_installed,
        "protection_active": hooks_feature_enabled and managed_hook_installed,
    }


class CodexHarnessAdapter(HarnessAdapter):
    """Discover Codex MCP servers and wrapper surfaces."""

    harness = "codex"
    executable = "codex"
    approval_tier = "native-or-center"
    approval_summary = (
        "Guard installs native Codex Bash hooks for shell interception, PermissionRequest hooks for Codex approval "
        "prompts, prompt hooks for sensitive file-read requests, keeps same-chat approvals for managed MCP tool "
        "calls, and falls back to the local approval center when Codex cannot answer."
    )
    fallback_hint = (
        "If Codex cannot render or return the inline approval request, or a native Bash hook blocks a "
        "sensitive command, Guard will queue it in the local approval center."
    )
    approval_prompt_channel = "native"
    approval_auto_open_browser = False

    def launch_command(self, context: HarnessContext, passthrough_args: list[str]) -> list[str]:
        return guarded_codex_launch_command(
            executable=self.resolved_executable(context) or self.executable,
            home_dir=context.home_dir,
            passthrough_args=passthrough_args,
        )

    def launch_environment(self, context: HarnessContext) -> dict[str, str]:
        return codex_remote_launch_environment(context.home_dir)

    @staticmethod
    def _scope_for(context: HarnessContext, path: Path) -> str:
        if context.workspace_dir is not None and path.is_relative_to(context.workspace_dir):
            return "project"
        return "global"

    def policy_path(self, context: HarnessContext) -> Path:
        return context.home_dir / ".codex" / "config.toml"

    @staticmethod
    def _hooks_path(context: HarnessContext) -> Path:
        return context.home_dir / ".codex" / "hooks.json"

    @staticmethod
    def _all_hook_paths(context: HarnessContext) -> tuple[Path, ...]:
        paths = [context.home_dir / ".codex" / "hooks.json"]
        if context.workspace_dir is not None:
            paths.append(context.workspace_dir / ".codex" / "hooks.json")
        return tuple(paths)

    @staticmethod
    def _config_hook_pairs(context: HarnessContext) -> tuple[tuple[Path, Path], ...]:
        pairs = [(context.home_dir / ".codex" / "config.toml", context.home_dir / ".codex" / "hooks.json")]
        if context.workspace_dir is not None:
            pairs.append(
                (context.workspace_dir / ".codex" / "config.toml", context.workspace_dir / ".codex" / "hooks.json")
            )
        return tuple(pairs)

    def detect(self, context: HarnessContext) -> HarnessDetection:
        config_paths = [context.home_dir / ".codex" / "config.toml"]
        if context.workspace_dir is not None:
            config_paths.append(context.workspace_dir / ".codex" / "config.toml")
        artifacts: list[GuardArtifact] = []
        found_paths: list[str] = []
        for config_path in config_paths:
            payload = _read_toml(config_path)
            if not payload:
                continue
            found_paths.append(str(config_path))
            scope = self._scope_for(context, config_path)
            mcp_servers = payload.get("mcp_servers")
            if isinstance(mcp_servers, dict):
                for name, server_config in mcp_servers.items():
                    if not isinstance(name, str) or not isinstance(server_config, dict):
                        continue
                    command = server_config.get("command")
                    args = tuple(str(value) for value in server_config.get("args", []) if isinstance(value, str))
                    if is_guard_proxy_command(command if isinstance(command, str) else None, args):
                        proxy_artifact = _artifact_from_guard_proxy_args(
                            args=args,
                            fallback_name=name,
                            fallback_scope=scope,
                            fallback_config_path=config_path,
                            harness=self.harness,
                        )
                        if proxy_artifact is not None:
                            artifacts.append(proxy_artifact)
                        continue
                    url = server_config.get("url")
                    env = server_config.get("env")
                    enabled = server_config.get("enabled", True) is not False
                    mcp_metadata = enrich_mcp_server_metadata(
                        {
                            "name": name,
                            "enabled": enabled,
                            "env": {
                                str(key): str(value)
                                for key, value in env.items()
                                if isinstance(key, str) and isinstance(value, str)
                            }
                            if isinstance(env, dict)
                            else {},
                            "env_keys": sorted(env.keys()) if isinstance(env, dict) else [],
                        },
                        command=command if isinstance(command, str) else None,
                        args=args,
                        url=url if isinstance(url, str) else None,
                        transport="http" if isinstance(url, str) else "stdio",
                    )
                    artifacts.append(
                        GuardArtifact(
                            artifact_id=f"codex:{scope}:{name}",
                            name=name,
                            harness=self.harness,
                            artifact_type="mcp_server",
                            source_scope=scope,
                            config_path=str(config_path),
                            command=command if isinstance(command, str) else None,
                            args=args,
                            url=url if isinstance(url, str) else None,
                            transport="http" if isinstance(url, str) else "stdio",
                            metadata=mcp_metadata,
                        )
                    )
        hooks_paths = [context.home_dir / ".codex" / "hooks.json"]
        if context.workspace_dir is not None:
            hooks_paths.append(context.workspace_dir / ".codex" / "hooks.json")
        for hooks_path in hooks_paths:
            hooks_payload = _json_object(hooks_path)
            hooks = hooks_payload.get("hooks")
            if not isinstance(hooks, dict):
                continue
            found_paths.append(str(hooks_path))
            scope = self._scope_for(context, hooks_path)
            hook_groups = hooks.get("PreToolUse")
            if not isinstance(hook_groups, list):
                continue
            for group_index, group in enumerate(hook_groups):
                if not isinstance(group, dict):
                    continue
                handlers = group.get("hooks")
                if not isinstance(handlers, list):
                    continue
                for handler_index, handler in enumerate(handlers):
                    if not isinstance(handler, dict):
                        continue
                    command = handler.get("command")
                    artifacts.append(
                        GuardArtifact(
                            artifact_id=f"codex:{scope}:pretooluse:{group_index}:{handler_index}",
                            name="PreToolUse",
                            harness=self.harness,
                            artifact_type="hook",
                            source_scope=scope,
                            config_path=str(hooks_path),
                            command=command if isinstance(command, str) else None,
                        )
                    )
        detection = HarnessDetection(
            harness=self.harness,
            installed=bool(found_paths) or _command_available(self.executable),
            command_available=_command_available(self.executable),
            config_paths=tuple(found_paths),
            artifacts=tuple(artifacts),
            warnings=(),
        )
        extended = extend_detection_with_workspace_aibom(
            detection,
            home_dir=context.home_dir,
            workspace_dir=context.workspace_dir,
        )
        return extend_codex_runtime_inventory(
            extended,
            home_dir=context.home_dir,
            workspace_dir=context.workspace_dir,
        )

    def install(self, context: HarnessContext) -> dict[str, object]:
        detection = self.detect(context)
        managed_servers = managed_stdio_servers(detection)
        skipped_servers = skipped_stdio_server_names(detection)
        target_config_path = self._target_config_path(context)
        hook_config_path = self._hook_config_path(context)
        hook_payloads = self._load_hook_payloads(context)
        original_text = target_config_path.read_text(encoding="utf-8") if target_config_path.is_file() else None
        payload = read_toml_payload(target_config_path)
        hook_payload = payload if hook_config_path == target_config_path else read_toml_payload(hook_config_path)
        for config_path, hooks_path in self._config_hook_pairs(context):
            json_hook_payload = hook_payloads.get(hooks_path, {})
            if not json_hook_payload:
                continue
            if config_path == target_config_path:
                hook_config_payload = payload
            elif config_path == hook_config_path:
                hook_config_payload = hook_payload
            else:
                hook_config_payload = read_toml_payload(config_path)
            if not _payload_has_hooks_feature_enabled(hook_config_payload) and _hooks_payload_has_unmanaged_entries(
                json_hook_payload
            ):
                raise RuntimeError(
                    "Guard refused to enable existing Codex hook entries without explicit approval. "
                    f"Review or remove unmanaged hooks in {hooks_path} before running install."
                )
        target_hooks_path = self._hooks_path(context)
        target_hook_payload = hook_payloads.get(target_hooks_path, {})
        target_hooks_migrated = _migrate_hooks_json_into_config(hook_payload, target_hook_payload)
        backup_path = self._backup_path(context)
        if not backup_path.exists():
            backup_path.parent.mkdir(parents=True, exist_ok=True)
            backup_text = dump_toml(payload) if target_hooks_migrated else original_text or ""
            backup_path.write_text(backup_text, encoding="utf-8")
        mcp_servers = payload.get("mcp_servers")
        if not isinstance(mcp_servers, dict):
            mcp_servers = {}
        features = hook_payload.get("features")
        if not isinstance(features, dict):
            features = {}
        features.pop("codex_hooks", None)
        features["hooks"] = True
        hook_payload["features"] = features
        self._install_config_hooks(hook_payload, context)
        workspace_payload = (
            read_toml_payload(context.workspace_dir / ".codex" / "config.toml")
            if context.workspace_dir is not None
            else {}
        )
        workspace_servers = workspace_payload.get("mcp_servers")
        existing_workspace_server_names = (
            {name for name, value in workspace_servers.items() if isinstance(name, str) and isinstance(value, dict)}
            if isinstance(workspace_servers, dict)
            else set()
        )
        for server in managed_servers:
            if self._should_skip_workspace_override(
                context=context,
                server=server,
                existing_workspace_server_names=existing_workspace_server_names,
            ):
                mcp_servers.pop(server.name, None)
                continue
            mcp_servers[server.name] = self._proxy_server_entry(context, server)
        payload["mcp_servers"] = mcp_servers
        write_toml_payload(target_config_path, payload)
        if hook_config_path != target_config_path:
            write_toml_payload(hook_config_path, hook_payload)
        self._migrate_alternate_hook_configs(
            context,
            payloads=hook_payloads,
            skip_config_path=hook_config_path,
        )
        self._remove_managed_hooks_from_alternate_configs(context, skip_config_path=hook_config_path)
        self._remove_managed_mcp_servers_from_alternate_configs(
            context,
            managed_servers=managed_servers,
            skip_config_path=target_config_path,
        )
        hooks_path = self._remove_json_hook_files(context, payloads=hook_payloads)
        shell_guard_paths = self._install_shell_guards(context)
        shim_manifest = install_guard_shim(self.harness, context)
        return {
            "harness": self.harness,
            "active": True,
            "config_path": str(target_config_path),
            **shim_manifest,
            "mode": "codex-mcp-proxy",
            "managed_config_path": str(target_config_path),
            "managed_hook_config_path": str(hook_config_path),
            "managed_hooks_path": str(hooks_path),
            "managed_shell_guard_path": str(shell_guard_paths["zsh"]),
            "managed_shell_guard_paths": {shell: str(path) for shell, path in shell_guard_paths.items()},
            "backup_path": str(backup_path),
            "managed_servers": [server.name for server in managed_servers],
            "skipped_servers": list(skipped_servers),
            "source_config_paths": list(detection.config_paths),
        }

    def uninstall(self, context: HarnessContext) -> dict[str, object]:
        target_config_path = self._target_config_path(context)
        hook_config_path = self._hook_config_path(context)
        backup_path = self._backup_path(context)
        if backup_path.is_file():
            original_text = backup_path.read_text(encoding="utf-8")
            if original_text:
                target_config_path.parent.mkdir(parents=True, exist_ok=True)
                target_config_path.write_text(original_text, encoding="utf-8")
            elif target_config_path.is_file():
                target_config_path.unlink()
            backup_path.unlink()
        hooks_path = self._remove_hooks(context)
        self._remove_managed_hooks_from_alternate_configs(context, skip_config_path=target_config_path)
        self._remove_managed_mcp_servers_from_alternate_configs(
            context,
            managed_servers=(),
            skip_config_path=target_config_path,
        )
        self._uninstall_shell_guard(context)
        shim_manifest = remove_guard_shim(self.harness, context)
        return {
            "harness": self.harness,
            "active": False,
            "config_path": str(target_config_path),
            **shim_manifest,
            "mode": "codex-mcp-proxy",
            "managed_config_path": str(target_config_path),
            "managed_hook_config_path": str(hook_config_path),
            "managed_hooks_path": str(hooks_path),
            "backup_path": str(backup_path),
        }

    def diagnostics(self, context: HarnessContext) -> dict[str, object]:
        payload = super().diagnostics(context)
        hook_state = codex_native_hook_state(context)
        warning_items = payload.get("warnings")
        warnings = (
            [str(item) for item in warning_items if isinstance(item, str)] if isinstance(warning_items, list) else []
        )
        if bool(hook_state["config_present"]) and not bool(hook_state["codex_hooks_enabled"]):
            warnings.append(
                "Codex config was found, but native hooks are disabled. Run `hol-guard install codex` or "
                "`hol-guard update` to repair protection."
            )
        if bool(hook_state["config_present"]) and not bool(hook_state["managed_hook_installed"]):
            warnings.append(
                "Codex config was found, but Guard's managed Codex hooks are missing. Run "
                "`hol-guard install codex` or `hol-guard update` to repair protection."
            )
        payload["warnings"] = warnings
        if payload.get("setup_status") == "active" and _warnings_include_setup_failure(warnings):
            payload["setup_status"] = "broken"
        payload["native_hook_state"] = hook_state
        return payload

    @staticmethod
    def _target_config_path(context: HarnessContext) -> Path:
        return context.home_dir / ".codex" / "config.toml"

    @staticmethod
    def _hook_config_path(context: HarnessContext) -> Path:
        return context.home_dir / ".codex" / "config.toml"

    @staticmethod
    def _backup_path(context: HarnessContext) -> Path:
        target_path = str(CodexHarnessAdapter._target_config_path(context).resolve())
        digest = hashlib.sha256(target_path.encode("utf-8")).hexdigest()[:12]
        return context.guard_home / "managed" / "codex" / f"{digest}.backup.toml"

    def _proxy_server_entry(self, context: HarnessContext, server: ManagedMcpServer) -> dict[str, object]:
        args = proxy_cli_args(
            proxy_command="codex-mcp-proxy",
            guard_home=str(context.guard_home),
            server=server,
            home=str(context.home_dir) if context.home_dir.resolve() != Path.home().resolve() else None,
            workspace=str(context.workspace_dir) if context.workspace_dir is not None else None,
        )
        entry: dict[str, object] = {
            "command": sys.executable,
            "args": args,
        }
        env = merge_guard_launcher_env(proxy_process_env(getattr(server, "env", {})))
        if env:
            entry["env"] = env
        return entry

    @staticmethod
    def _should_skip_workspace_override(
        *,
        context: HarnessContext,
        server: ManagedMcpServer,
        existing_workspace_server_names: set[str],
    ) -> bool:
        if context.workspace_dir is None:
            return False
        if server.source_scope == "project":
            return False
        return server.name in existing_workspace_server_names

    def _load_hook_payloads(self, context: HarnessContext) -> dict[Path, dict[str, object]]:
        return {
            hooks_path: _strict_json_object(hooks_path, label="Codex hooks file")
            for hooks_path in self._all_hook_paths(context)
        }

    def _migrate_alternate_hook_configs(
        self,
        context: HarnessContext,
        *,
        payloads: dict[Path, dict[str, object]],
        skip_config_path: Path,
    ) -> None:
        for config_path, hooks_path in self._config_hook_pairs(context):
            if config_path == skip_config_path:
                continue
            hooks_payload = payloads.get(hooks_path, {})
            if not hooks_payload:
                continue
            config_payload = read_toml_payload(config_path)
            if _migrate_hooks_json_into_config(config_payload, hooks_payload) and config_payload:
                write_toml_payload(config_path, config_payload)

    def _remove_managed_hooks_from_alternate_configs(
        self,
        context: HarnessContext,
        *,
        skip_config_path: Path,
    ) -> None:
        for config_path, _hooks_path in self._config_hook_pairs(context):
            if config_path == skip_config_path or not config_path.is_file():
                continue
            config_payload = read_toml_payload(config_path)
            hooks = config_payload.get("hooks")
            if not isinstance(hooks, dict):
                features = config_payload.get("features")
                if isinstance(features, dict):
                    features.pop("hooks", None)
                    features.pop("codex_hooks", None)
                    if features:
                        config_payload["features"] = features
                    else:
                        config_payload.pop("features", None)
                    write_toml_payload(config_path, config_payload)
                continue
            cleaned_hooks, managed_removed = _remove_managed_hook_events(hooks)
            if not managed_removed:
                continue
            if cleaned_hooks:
                config_payload["hooks"] = cleaned_hooks
            else:
                config_payload.pop("hooks", None)
                features = config_payload.get("features")
                if isinstance(features, dict):
                    features.pop("hooks", None)
                    features.pop("codex_hooks", None)
                    if not features:
                        config_payload.pop("features", None)
            write_toml_payload(config_path, config_payload)

    def _remove_managed_mcp_servers_from_alternate_configs(
        self,
        context: HarnessContext,
        *,
        managed_servers: tuple[ManagedMcpServer, ...],
        skip_config_path: Path,
    ) -> None:
        managed_names_by_path: dict[Path, set[str]] = {}
        for server in managed_servers:
            managed_names_by_path.setdefault(Path(server.config_path), set()).add(server.name)
        for config_path, _hooks_path in self._config_hook_pairs(context):
            if config_path == skip_config_path or not config_path.is_file():
                continue
            config_payload = read_toml_payload(config_path)
            mcp_servers = config_payload.get("mcp_servers")
            if not isinstance(mcp_servers, dict):
                continue
            names = managed_names_by_path.get(config_path, set())
            changed = False
            cleaned_servers: dict[str, object] = {}
            for name, server_config in mcp_servers.items():
                if (
                    isinstance(name, str)
                    and name in names
                    and isinstance(server_config, dict)
                    and not is_guard_proxy_command(
                        server_config.get("command") if isinstance(server_config.get("command"), str) else None,
                        tuple(str(value) for value in server_config.get("args", []) if isinstance(value, str)),
                    )
                ):
                    changed = True
                    continue
                cleaned_servers[name] = server_config
            if not changed:
                continue
            if cleaned_servers:
                config_payload["mcp_servers"] = cleaned_servers
            else:
                config_payload.pop("mcp_servers", None)
            write_toml_payload(config_path, config_payload)

    def _remove_json_hook_files(
        self,
        context: HarnessContext,
        *,
        payloads: dict[Path, dict[str, object]],
    ) -> Path:
        target_hooks_path = self._hooks_path(context)
        for hooks_path in self._all_hook_paths(context):
            if hooks_path in payloads and hooks_path.is_file():
                hooks_path.unlink()
        return target_hooks_path

    def _install_hooks(self, context: HarnessContext, *, payloads: dict[Path, dict[str, object]] | None = None) -> Path:
        target_hooks_path = self._hooks_path(context)
        hook_payloads = payloads or self._load_hook_payloads(context)
        for hooks_path in self._all_hook_paths(context):
            original_payload = deepcopy(hook_payloads.get(hooks_path, {}))
            payload = deepcopy(original_payload)
            hooks = payload.get("hooks")
            if not isinstance(hooks, dict):
                hooks = {}
            cleaned_hooks, managed_removed = _remove_managed_hook_events(hooks)
            if not managed_removed:
                payload = deepcopy(original_payload)
            elif cleaned_hooks:
                payload["hooks"] = cleaned_hooks
            else:
                payload.pop("hooks", None)
            self._write_hooks_payload(hooks_path, payload, original_payload=original_payload)
        return target_hooks_path

    @staticmethod
    def _install_config_hooks(payload: dict[str, object], context: HarnessContext) -> None:
        hooks = payload.get("hooks")
        if not isinstance(hooks, dict):
            hooks = {}
        cleaned_hooks, _ = _remove_managed_hook_events(hooks)
        for event_name, managed_group in _managed_hook_groups(context).items():
            cleaned_hooks[event_name] = _merge_hook_groups(cleaned_hooks.get(event_name), managed_group)
        payload["hooks"] = cleaned_hooks

    @staticmethod
    def _install_shell_guards(context: HarnessContext) -> dict[str, Path]:
        guard_root = context.guard_home / "managed" / "codex"
        guard_root.mkdir(parents=True, exist_ok=True)
        zsh_guard_path = guard_root / "codex-zshenv-guard.zsh"
        bash_guard_path = guard_root / "codex-bashenv-guard.bash"
        fish_guard_path = guard_root / "codex-fish-guard.fish"

        zsh_guard_path.write_text(_codex_zshenv_guard_script(), encoding="utf-8")
        bash_guard_path.write_text(_codex_bashenv_guard_script(), encoding="utf-8")
        fish_guard_path.write_text(_codex_fish_guard_script(), encoding="utf-8")

        CodexHarnessAdapter._install_shell_guard_block(
            context.home_dir / ".zshenv",
            [
                _SHELL_GUARD_BEGIN,
                f'if [ -r "{zsh_guard_path}" ]; then',
                f'  source "{zsh_guard_path}"',
                "fi",
                _SHELL_GUARD_END,
            ],
        )
        bash_block = [
            _SHELL_GUARD_BEGIN,
            f'if [ -r "{bash_guard_path}" ]; then',
            f'  export BASH_ENV="{bash_guard_path}"',
            '  if [ -n "${BASH_VERSION:-}" ]; then',
            f'    . "{bash_guard_path}"',
            "  fi",
            "fi",
            _SHELL_GUARD_END,
        ]
        bash_login_files = [
            context.home_dir / ".bash_profile",
            context.home_dir / ".bash_login",
            context.home_dir / ".profile",
        ]
        bash_startup_paths = [path for path in bash_login_files if path.is_file()]
        bashrc_path = context.home_dir / ".bashrc"
        if bashrc_path.is_file():
            bash_startup_paths.append(bashrc_path)
        if not bash_startup_paths:
            bash_startup_paths = [context.home_dir / ".bash_profile", bashrc_path]
        for bash_startup_path in bash_startup_paths:
            CodexHarnessAdapter._install_shell_guard_block(bash_startup_path, bash_block)
        fish_conf_path = context.home_dir / ".config" / "fish" / "conf.d" / "hol-guard-codex.fish"
        fish_conf_path.parent.mkdir(parents=True, exist_ok=True)
        fish_conf_path.write_text(
            "\n".join(
                [
                    _SHELL_GUARD_BEGIN,
                    f'if test -r "{fish_guard_path}"',
                    f'  source "{fish_guard_path}"',
                    "end",
                    _SHELL_GUARD_END,
                    "",
                ]
            ),
            encoding="utf-8",
        )
        return {
            "zsh": zsh_guard_path,
            "bash": bash_guard_path,
            "fish": fish_guard_path,
            "fish_conf": fish_conf_path,
        }

    @staticmethod
    def _install_shell_guard_block(path: Path, block_lines: list[str]) -> None:
        original = path.read_text(encoding="utf-8") if path.is_file() else ""
        source_block = "\n".join(block_lines)
        cleaned = _remove_managed_shell_guard_block(original).rstrip()
        updated = f"{cleaned}\n\n{source_block}\n" if cleaned else f"{source_block}\n"
        if updated != original:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(updated, encoding="utf-8")

    @staticmethod
    def _uninstall_shell_guard(context: HarnessContext) -> None:
        guard_root = context.guard_home / "managed" / "codex"
        for guard_path in (
            guard_root / "codex-zshenv-guard.zsh",
            guard_root / "codex-bashenv-guard.bash",
            guard_root / "codex-fish-guard.fish",
        ):
            if guard_path.is_file():
                guard_path.unlink()

        for startup_path in (
            context.home_dir / ".zshenv",
            context.home_dir / ".bashrc",
            context.home_dir / ".bash_profile",
            context.home_dir / ".bash_login",
            context.home_dir / ".profile",
            context.home_dir / ".config" / "fish" / "conf.d" / "hol-guard-codex.fish",
        ):
            CodexHarnessAdapter._remove_shell_guard_block(startup_path)

    @staticmethod
    def _remove_shell_guard_block(path: Path) -> None:
        if not path.is_file():
            return
        original = path.read_text(encoding="utf-8")
        cleaned = _remove_managed_shell_guard_block(original).rstrip()
        if cleaned:
            path.write_text(f"{cleaned}\n", encoding="utf-8")
        else:
            path.unlink()

    def _remove_hooks(self, context: HarnessContext, *, payloads: dict[Path, dict[str, object]] | None = None) -> Path:
        target_hooks_path = self._hooks_path(context)
        hook_payloads = payloads or {}
        for hooks_path in self._all_hook_paths(context):
            original_payload = deepcopy(hook_payloads.get(hooks_path, _json_object(hooks_path)))
            payload = deepcopy(original_payload)
            if not payload and hooks_path.exists():
                continue
            hooks = payload.get("hooks")
            if isinstance(hooks, dict):
                cleaned_hooks, managed_removed = _remove_managed_hook_events(hooks)
                if not managed_removed:
                    payload = deepcopy(original_payload)
                elif cleaned_hooks:
                    payload["hooks"] = cleaned_hooks
                else:
                    payload.pop("hooks", None)
            self._write_hooks_payload(hooks_path, payload, original_payload=original_payload)
        return target_hooks_path

    @staticmethod
    def _write_hooks_payload(
        hooks_path: Path,
        payload: dict[str, object],
        *,
        original_payload: dict[str, object] | None = None,
    ) -> None:
        if original_payload is not None and payload == original_payload:
            return
        if payload:
            hooks_path.parent.mkdir(parents=True, exist_ok=True)
            hooks_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        elif hooks_path.exists():
            hooks_path.unlink()
