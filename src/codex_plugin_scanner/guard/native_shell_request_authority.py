"""Bound transport for fused GitHub shell classification and pure PR flags."""

from __future__ import annotations

import hashlib
import os
import shutil
import threading
from collections import OrderedDict
from dataclasses import asdict, is_dataclass
from pathlib import Path
from typing import Any

from .fork_safety import forget_in_child
from .native_codex_tool_output import _environment_snapshot
from .native_context import _native_runtime_status_memo, _resolve_digest_home
from .native_git_execution_safety import _account_home_directory, _process_groups
from .native_resident_client import native_resident_client_ready
from .native_runner_authority import NativeRunnerAuthorityError, native_runner_authority

_FLAGS: OrderedDict[tuple[str, str, int], dict[str, bool]] = OrderedDict()
_LOCK = threading.Lock()
forget_in_child(_FLAGS)


def _wire(value: Any) -> Any:
    if isinstance(value, Path):
        return str(value)
    if is_dataclass(value) and not isinstance(value, type):
        return _wire(asdict(value))
    if isinstance(value, dict):
        return {key: _wire(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set, frozenset)):
        return [_wire(item) for item in value]
    return value


def shell_request_authority(entry: str, arguments: dict[str, Any]) -> Any:
    status = _native_runtime_status_memo()
    if (
        not status.available
        or not status.compatible
        or status.identity is None
        or status.capabilities is None
        or not {"runner-authority-v1", "resident-protocol-v2"}.issubset(status.capabilities.features)
    ):
        raise NativeRunnerAuthorityError("native_shell_request_authority_unavailable")
    home = _resolve_digest_home(None)
    command = str(arguments.get("command_text", ""))
    depth = int(arguments.get("depth", 0))
    key = (status.identity.sha256, hashlib.sha256(command.encode("utf-8", "surrogatepass")).hexdigest(), depth)
    flag_entries = {
        "_gh_pr_create_body_has_shell_command_substitution",
        "_gh_pr_create_has_active_shell_expansion",
        "_gh_pr_edit_has_shell_command_substitution",
    }
    if entry in flag_entries and native_resident_client_ready(status.identity.path, home):
        with _LOCK:
            cached = _FLAGS.get(key)
            if cached is not None:
                _FLAGS.move_to_end(key)
                return cached[entry]
    request = {"entry": "pr_flags" if entry in flag_entries else entry, "arguments": _wire(arguments)}
    if entry in {
        "classify_github_shell_capabilities",
        "_github_pipeline_companion_is_read_only",
        "_gh_pr_create_uses_safe_static_body_file",
        "_gh_pr_edit_uses_safe_static_body_file",
    }:
        request["facts"] = {
            "process_cwd": os.getcwd(),
            "home": str(Path.home()),
            "account_home": _account_home_directory(),
            "groups": _process_groups(),
            "environment": _environment_snapshot(),
            "git_executable": shutil.which("git"),
        }
    payload = native_runner_authority("shell_request_authority", request, home)
    flags = payload.get("flags")
    if isinstance(flags, dict):
        if not flag_entries.issubset(flags) or not all(isinstance(flags[name], bool) for name in flag_entries):
            raise NativeRunnerAuthorityError("native_shell_request_flags_invalid")
        with _LOCK:
            _FLAGS[key] = dict(flags)
            _FLAGS.move_to_end(key)
            while len(_FLAGS) > 128:
                _FLAGS.popitem(last=False)
    if entry in flag_entries:
        return payload["flags"][entry]
    return payload["value"]
