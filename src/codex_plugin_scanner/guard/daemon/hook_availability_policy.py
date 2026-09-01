"""Mechanical emergency-safe hook floor when native review cannot complete.

This is not a Python semantic policy engine. It classifies the action class from
the hook envelope and either continues an exact inspection profile or pauses.
See ``docs/guard/adr/0009-native-and-daemon-critical-failure.md``.
"""

from __future__ import annotations

import shlex
from collections.abc import Mapping
from pathlib import Path

from ..runtime.secret_sensitivity import classify_secret_path
from .hook_request_parsing import pre_tool_command, runtime_hook_event_name

EMERGENCY_SAFE_REASON_CODE = "native_degraded_emergency_safe"
EMERGENCY_SAFE_REASON = (
    "HOL Guard could not complete native review and continued this local inspection "
    "under the emergency-safe action-class floor."
)

_INSPECTION_TOOLS = frozenset(
    {
        "read",
        "read_file",
        "read_files",
        "open_file",
        "view",
        "view_file",
        "cat_file",
        "grep",
        "glob",
        "rg",
        "search",
        "search_files",
        "semanticsearch",
        "codesearch",
        "globfilesearch",
        "list_dir",
        "listdir",
        "list_directory",
        "list_files",
        "list_code_definition_names",
        "ls",
    }
)
_SAFE_INSPECTION_BINARIES = frozenset(
    {
        "rg",
        "grep",
        "egrep",
        "fgrep",
        "ag",
        "ack",
        "cat",
        "head",
        "tail",
        "wc",
        "file",
        "stat",
        "bat",
        "fd",
        "tree",
    }
)
_UNSAFE_FIND_FLAGS = frozenset(
    {
        "-delete",
        "-exec",
        "-execdir",
        "-ok",
        "-okdir",
        "-fprint",
        "-fprintf",
        "-fls",
    }
)
_UNSAFE_ABSOLUTE_PREFIXES = (
    "/etc/",
    "/private/etc/",
    "/root/",
    "/var/root/",
    "/private/var/root/",
    "/proc/",
    "/sys/",
    "/dev/",
    "/private/dev/",
)
_BLOCKED_SOURCE_EVENTS = frozenset(
    {
        "beforewritefile",
        "beforemcpexecution",
        "aftershellexecution",
        "aftermcpexecution",
        "afterwritefile",
        "afterreadfile",
    }
)
_MUTATING_TOOLS = frozenset(
    {
        "edit",
        "edit_file",
        "multiedit",
        "write",
        "write_file",
        "apply_patch",
        "delete",
        "delete_file",
        "move",
        "rename",
        "bash",
        "shell",
        "mcp",
    }
)
_SAFE_GIT_SUBCOMMANDS = frozenset(
    {
        "status",
        "diff",
        "log",
        "show",
        "rev-parse",
        "describe",
        "shortlog",
        "blame",
        "ls-files",
        "ls-tree",
        "cat-file",
        "grep",
        "help",
        "version",
    }
)
_SAFE_GIT_STASH_SUBCOMMANDS = frozenset({"list", "show"})
_UNSAFE_GIT_FLAGS = frozenset(
    {
        "-d",
        "-D",
        "--delete",
        "--force",
        "-f",
        "--hard",
        "--exec",
        "--upload-pack",
        "--receive-pack",
        "--config",
        "-c",
        "--work-tree",
        "--git-dir",
        "-C",
        "--output",
        "--ext-diff",
        "--textconv",
    }
)
_SAFE_HOL_GUARD_SUBCOMMANDS = frozenset(
    {
        "status",
        "doctor",
        "version",
        "--version",
        "-V",
    }
)
_UNSAFE_INSPECTION_FLAGS = frozenset(
    {
        "--pre",
        "--exec",
        "--exec-batch",
        "--execdir",
    }
)
_UNSAFE_FD_FLAGS = frozenset(
    {
        "--exec",
        "--exec-batch",
        "--execdir",
        "-x",
        "-X",
    }
)
_UNSAFE_SHELL_MARKERS = ("|", ";", "`", "$(", "${", ">", "<", "\n", "\r", "&&", "||", "&")
_PATH_KEYS = (
    "path",
    "file_path",
    "filePath",
    "filepath",
    "file",
    "filename",
    "target_path",
    "targetPath",
)


def hook_action_is_emergency_safe(
    payload: Mapping[str, object],
    *,
    workspace: Path | None = None,
    home_dir: Path | None = None,
) -> bool:
    """Return True only for the ratified local-inspection emergency-safe profile."""

    event_name = runtime_hook_event_name(payload)
    if event_name != "PreToolUse":
        return False
    if _payload_source_events(payload) & _BLOCKED_SOURCE_EVENTS:
        return False
    if _payload_is_mcp(payload):
        return False
    if workspace is None:
        cwd = payload.get("cwd")
        if isinstance(cwd, str) and cwd.strip():
            workspace = Path(cwd.strip())
    tool_name = _tool_name(payload)
    if tool_name in _MUTATING_TOOLS and tool_name not in {"bash", "shell"}:
        return False
    paths = _payload_paths(payload)
    for path in paths:
        if classify_secret_path(path, cwd=workspace, home_dir=home_dir) is not None:
            return False
        if not _path_is_workspace_local(path, workspace):
            return False
    command = _payload_command(payload)
    if command is not None:
        return _command_is_emergency_safe(command, workspace=workspace, home_dir=home_dir)
    if tool_name in _INSPECTION_TOOLS:
        return True
    return bool(paths) and tool_name in {"", "read"}


def availability_harness_response(
    payload: Mapping[str, object],
    *,
    harness: str,
    event_name: str,
    reason_code: str,
    reason: str,
    workspace: Path | None = None,
    home_dir: Path | None = None,
) -> dict[str, object]:
    """Render a schema-valid harness result when native review is unavailable."""

    from .hook_worker_responses import harness_json_from_native_pre_tool, post_tool_fail_safe_response

    if event_name != "PreToolUse":
        return post_tool_fail_safe_response(harness, reason=reason, reason_code=reason_code)
    if not hook_action_is_emergency_safe(
        payload,
        workspace=workspace,
        home_dir=home_dir,
    ):
        return harness_json_from_native_pre_tool(
            harness,
            {
                "decision": "deny",
                "minimum_action": "block",
                "policy_action": "block",
                "reason_code": reason_code,
                "reason": reason,
            },
        )
    return harness_json_from_native_pre_tool(
        harness,
        {
            "decision": "allow",
            "minimum_action": "warn",
            "policy_action": "warn",
            "reason_code": EMERGENCY_SAFE_REASON_CODE,
            "reason": EMERGENCY_SAFE_REASON,
        },
    )


_CURSOR_UNAVAILABLE_MESSAGE = (
    "HOL Guard paused this action because native review was unavailable "
    "and the action is outside the emergency-safe inspection floor."
)
_CURSOR_UNAVAILABLE_DENY = {
    "permission": "deny",
    "user_message": _CURSOR_UNAVAILABLE_MESSAGE,
    "agent_message": _CURSOR_UNAVAILABLE_MESSAGE,
}


def cursor_fallback_permission(
    payload: Mapping[str, object],
    *,
    hook_event_name: str,
    workspace: Path | None = None,
    home_dir: Path | None = None,
) -> tuple[dict[str, object], int]:
    """Return Cursor hook stdout when daemon or native review cannot complete."""

    compact = hook_event_name.strip().lower().replace("_", "").replace("-", "")
    if compact in {"aftershellexecution", "aftermcpexecution"}:
        return {}, 0
    if compact in {"beforewritefile", "beforemcpexecution"}:
        return dict(_CURSOR_UNAVAILABLE_DENY), 2
    if hook_action_is_emergency_safe(payload, workspace=workspace, home_dir=home_dir):
        return {"permission": "allow"}, 0
    response = {
        "permission": "deny",
        "user_message": _CURSOR_UNAVAILABLE_MESSAGE,
    }
    if compact != "beforereadfile":
        response["agent_message"] = _CURSOR_UNAVAILABLE_MESSAGE
    return response, 2


def _payload_source_events(payload: Mapping[str, object]) -> set[str]:
    events: set[str] = set()
    for key in (
        "cursor_source_hook_event",
        "hook_event_name",
        "hookEventName",
        "event",
        "eventName",
        "hook_name",
        "hookName",
    ):
        value = payload.get(key)
        if isinstance(value, str) and value.strip():
            events.add(value.strip().lower().replace("_", "").replace("-", ""))
    return events


def _payload_is_mcp(payload: Mapping[str, object]) -> bool:
    if "beforemcpexecution" in _payload_source_events(payload):
        return True
    tool_name = _tool_name(payload)
    return tool_name.startswith("mcp") or tool_name in {"mcp", "call_mcp_tool"}


def _tool_name(payload: Mapping[str, object]) -> str:
    for key in ("tool_name", "toolName", "tool"):
        value = payload.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip().lower()
    for nested_key in ("tool_call", "preToolUse", "tool_input"):
        nested = payload.get(nested_key)
        if not isinstance(nested, Mapping):
            continue
        for key in ("name", "toolName", "tool_name", "tool"):
            value = nested.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip().lower()
    return ""


def _payload_command(payload: Mapping[str, object]) -> str | None:
    command = pre_tool_command(payload)
    if command is not None:
        return command
    for nested_key in ("tool_call", "preToolUse"):
        nested = payload.get(nested_key)
        if not isinstance(nested, Mapping):
            continue
        for input_key in ("input", "parameters", "arguments"):
            tool_input = nested.get(input_key)
            if not isinstance(tool_input, Mapping):
                continue
            for key in ("command", "cmd", "shell_command", "shellCommand"):
                value = tool_input.get(key)
                if isinstance(value, str) and value.strip():
                    return value.strip()
    return None


def _payload_paths(payload: Mapping[str, object]) -> list[str]:
    paths: list[str] = []
    candidates: list[object] = [payload, payload.get("tool_input"), payload.get("arguments")]
    for nested_key in ("tool_call", "preToolUse"):
        nested = payload.get(nested_key)
        if isinstance(nested, Mapping):
            candidates.extend((nested, nested.get("input"), nested.get("parameters"), nested.get("arguments")))
    for candidate in candidates:
        if not isinstance(candidate, Mapping):
            continue
        for key in _PATH_KEYS:
            value = candidate.get(key)
            if isinstance(value, str) and value.strip():
                paths.append(value.strip())
        raw_paths = candidate.get("paths")
        if isinstance(raw_paths, list):
            paths.extend(item.strip() for item in raw_paths if isinstance(item, str) and item.strip())
    return paths


def _posix_forms(path: str) -> tuple[str, ...]:
    posix = path.strip().replace("\\", "/").lower()
    if not posix:
        return ()
    forms = [posix]
    if posix.startswith("/private/"):
        forms.append(posix[len("/private") :] or "/")
    elif posix.startswith("/tmp/") or posix in {"/tmp", "/var"} or posix.startswith("/var/"):
        forms.append("/private" + posix)
    return tuple(dict.fromkeys(forms))


def _workspace_anchor(workspace: Path | None) -> str | None:
    if workspace is None:
        return None
    posix = str(workspace).replace("\\", "/").rstrip("/")
    if not posix or posix == "/" or posix.endswith(":"):
        return None
    if any(
        form == prefix.rstrip("/") or form.startswith(prefix)
        for form in _posix_forms(posix)
        for prefix in _UNSAFE_ABSOLUTE_PREFIXES
    ):
        return None
    parts = [part for part in posix.split("/") if part and part != "."]
    if not parts or any(part == ".." for part in parts):
        return None
    lowered = posix.lower()
    if lowered.startswith("/users/") or lowered.startswith("/home/"):
        if len(parts) < 3:
            return None
    elif posix.startswith("/") and len(parts) < 2:
        return None
    elif len(posix) > 1 and posix[1] == ":":
        if len(parts) < 2:
            return None
        if len(parts) < 3 and parts[1].lower() in {"users", "documents and settings"}:
            return None
    return posix


def _path_is_workspace_local(path: str, workspace: Path | None) -> bool:
    posix = path.strip().replace("\\", "/")
    if not posix or posix.startswith("//"):
        return False
    forms = _posix_forms(posix)
    if not forms:
        return False
    if any(
        form == prefix.rstrip("/") or form.startswith(prefix) for form in forms for prefix in _UNSAFE_ABSOLUTE_PREFIXES
    ):
        return False
    parts = tuple(part for part in posix.split("/") if part not in {"", "."})
    if any(part == ".." for part in parts):
        return False
    candidate_is_absolute = posix.startswith("/") or (len(posix) > 1 and posix[1] == ":")
    workspace_posix = _workspace_anchor(workspace)
    if workspace_posix is None:
        return not candidate_is_absolute
    if candidate_is_absolute:
        workspace_forms = _posix_forms(workspace_posix)
        return any(form == prefix or form.startswith(prefix + "/") for form in forms for prefix in workspace_forms)
    return True


def _token_looks_like_path(token: str) -> bool:
    if token in {"..", "."}:
        return True
    if token.startswith("-"):
        return False
    return "/" in token or "\\" in token or token.startswith(".") or ".." in token


def _flag_name(token: str) -> str:
    return token.split("=", 1)[0]


def _command_is_emergency_safe(
    command: str,
    *,
    workspace: Path | None,
    home_dir: Path | None,
) -> bool:
    stripped = command.strip()
    if not stripped or len(stripped) > 4096:
        return False
    if any(marker in stripped for marker in _UNSAFE_SHELL_MARKERS):
        return False
    try:
        tokens = shlex.split(stripped, posix=True, comments=False)
    except ValueError:
        return False
    if not tokens:
        return False
    binary = Path(tokens[0]).name.lower()
    args = tokens[1:]
    if any(classify_secret_path(token, cwd=workspace, home_dir=home_dir) is not None for token in args):
        return False
    if any(not _path_is_workspace_local(token, workspace) for token in args if _token_looks_like_path(token)):
        return False
    if binary in {"pwd", "true", "which"}:
        return not args
    if binary in {"ls", "dir"}:
        return not any(_flag_name(token) in _UNSAFE_INSPECTION_FLAGS for token in args)
    if binary == "fd":
        return not any(_flag_name(token) in _UNSAFE_FD_FLAGS | _UNSAFE_INSPECTION_FLAGS for token in args)
    if binary in _SAFE_INSPECTION_BINARIES:
        return not any(_flag_name(token) in _UNSAFE_INSPECTION_FLAGS for token in args)
    if binary == "find":
        return not any(token in _UNSAFE_FIND_FLAGS or _flag_name(token) in _UNSAFE_INSPECTION_FLAGS for token in args)
    if binary == "git":
        return _git_command_is_emergency_safe(args)
    if binary in {"hol-guard", "plugin-guard"}:
        return _hol_guard_command_is_emergency_safe(args)
    return False


def _git_command_is_emergency_safe(args: list[str]) -> bool:
    if not args:
        return False
    if args[0] in {"--version", "--help"}:
        return True
    subcommand = args[0]
    if subcommand == "stash":
        return len(args) > 1 and args[1] in _SAFE_GIT_STASH_SUBCOMMANDS
    if subcommand not in _SAFE_GIT_SUBCOMMANDS:
        return False
    return not any(_flag_name(token) in _UNSAFE_GIT_FLAGS for token in args[1:])


def _hol_guard_command_is_emergency_safe(args: list[str]) -> bool:
    if not args:
        return False
    first = args[0]
    if first in _SAFE_HOL_GUARD_SUBCOMMANDS:
        return True
    return first == "guard" and len(args) > 1 and args[1] in _SAFE_HOL_GUARD_SUBCOMMANDS


__all__ = [
    "EMERGENCY_SAFE_REASON",
    "EMERGENCY_SAFE_REASON_CODE",
    "availability_harness_response",
    "cursor_fallback_permission",
    "hook_action_is_emergency_safe",
]
