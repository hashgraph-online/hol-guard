"""Request parameters and hook path validation."""

from __future__ import annotations

from . import server as _server


def _optional_string(value: object) -> str | None:
    if isinstance(value, str) and value.strip():
        return value.strip()
    return None


def _coalesce_string(self: _server._GuardDaemonHandler, mapping: dict[str, object], *keys: str) -> str | None:
    for key in keys:
        value = self._optional_string(mapping.get(key))
        if value is not None:
            return value
    return None


def _query_string(query_string: str, key: str) -> str | None:
    value = _server.parse_qs(query_string).get(key, [None])[-1]
    if isinstance(value, str) and value.strip():
        return value.strip()
    return None


def _query_bool(query_string: str, key: str, *, default: bool) -> bool:
    value = _server.parse_qs(query_string).get(key, [None])[-1]
    if not isinstance(value, str):
        return default
    normalized = value.strip().lower()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False
    return default


def _query_limit(query_string: str, *, default: int, maximum: int) -> int | None:
    raw_value = _server.parse_qs(query_string).get("limit", [None])[-1]
    if raw_value is None:
        return default
    try:
        value = int(raw_value)
    except (TypeError, ValueError):
        return None
    if value < 1:
        return None
    return min(value, maximum)


def _validated_hook_directory_string(
    self: _server._GuardDaemonHandler,
    parameter: str,
    value: str | None,
    *,
    roots: tuple[_server.Path, ...] | None = None,
) -> str | None:
    if value is None:
        return None
    return _server.os.fspath(self._validate_hook_directory_path(parameter, value, roots=roots))


def _normalized_hook_workspace_string(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    stripped = value.strip()
    if not stripped or stripped.lower() in {"none", "null"}:
        return None
    # Mirror the CLI hook contract until runtime callers stop emitting `/None`
    # as the explicit "no workspace" sentinel.
    candidate = _server.os.path.expanduser(stripped)
    if _server.os.path.basename(candidate) == "None":
        candidate = _server.os.path.dirname(candidate)
        if not candidate.strip():
            return None
    candidate = _server.os.path.normpath(candidate)
    try:
        temporary_root = _server.trusted_temporary_root_for_path(_server.Path(candidate))
    except OSError:
        temporary_root = None
    if temporary_root is not None and _server.os.path.realpath(candidate) == _server.os.path.realpath(temporary_root):
        return None
    return candidate


def _runtime_hook_exec_command_workdir(payload: dict[str, object]) -> tuple[bool, str | None]:
    tool_name = payload.get("tool_name")
    if not isinstance(tool_name, str) or tool_name.strip().casefold() != "exec_command":
        return False, None
    tool_input = payload.get("tool_input")
    if not isinstance(tool_input, dict) or "workdir" not in tool_input:
        return False, None
    value = tool_input.get("workdir")
    if not isinstance(value, str):
        return True, None
    stripped = value.strip()
    if not stripped or stripped.casefold() in {"none", "null"}:
        return True, None
    candidate = _server.os.path.normpath(_server.os.path.expanduser(stripped))
    try:
        temporary_root = _server.trusted_temporary_root_for_path(_server.Path(candidate))
    except OSError:
        temporary_root = None
    if temporary_root is not None and _server.os.path.realpath(candidate) == _server.os.path.realpath(temporary_root):
        return True, None
    return True, candidate


def _validate_hook_directory_path(
    self: _server._GuardDaemonHandler,
    parameter: str,
    value: str,
    *,
    roots: tuple[_server.Path, ...] | None = None,
) -> _server.Path:
    expanded = _server.os.path.expanduser(value)
    if not _server.os.path.isabs(expanded):
        raise _server._HookPathValidationError(parameter, "relative_path")
    try:
        candidate = _server.os.path.realpath(expanded)
    except OSError:
        raise _server._HookPathValidationError(parameter, "path_resolve_failed") from None
    effective_roots = roots
    if parameter in {"home", "workspace"} and effective_roots is None:
        effective_roots = self._hook_safe_roots()
    if effective_roots is not None:
        root_match = False
        for root in effective_roots:
            root_path = _server.os.path.realpath(_server.os.fspath(root))
            try:
                if _server.os.path.commonpath([candidate, root_path]) == root_path:
                    root_match = True
                    break
            except ValueError:
                continue
        if not root_match and parameter == "workspace":
            root_match = self._is_owned_temporary_hook_workspace(candidate)
        if not root_match:
            raise _server._HookPathValidationError(parameter, "unexpected_root")
    return _server.Path(candidate)


def _is_owned_temporary_hook_workspace(candidate: str) -> bool:
    candidate_path = _server.Path(candidate)
    try:
        temporary_root = _server.trusted_temporary_root_for_path(candidate_path)
    except OSError:
        return False
    if temporary_root is None:
        return False
    try:
        # codeql[py/path-injection] candidate is canonical and contained by a trusted temp root.
        candidate_stat = candidate_path.stat()
    except OSError:
        return False
    if not _server.stat.S_ISDIR(candidate_stat.st_mode):
        return False
    getuid = getattr(_server.os, "getuid", None)
    if not callable(getuid):
        current_home = _server.Path.home().resolve()
        return _server._GuardDaemonHandler._path_is_within_root(
            temporary_root,
            current_home,
        ) and _server._GuardDaemonHandler._path_is_within_root(
            candidate_path,
            temporary_root,
        )
    return candidate_stat.st_uid == getuid()


def _validated_hook_guard_home(self: _server._GuardDaemonHandler, value: str | None) -> str | None:
    if value is None:
        return None
    expanded = _server.os.path.expanduser(value)
    if not _server.os.path.isabs(expanded):
        raise _server._HookPathValidationError("guard-home", "relative_path")
    try:
        candidate = _server.os.path.realpath(expanded)
    except OSError:
        raise _server._HookPathValidationError("guard-home", "path_resolve_failed") from None
    expected = _server.os.fspath(self._daemon_server().hook_config_scope.canonical_home)
    if candidate != expected:
        raise _server._HookPathValidationError("guard-home", "unexpected_guard_home")
    return expected


def _hook_safe_roots(self: _server._GuardDaemonHandler) -> tuple[_server.Path, ...]:
    return self._daemon_server().hook_config_scope.allowed_roots


def _path_is_within_root(candidate: _server.Path | str, root: _server.Path | str) -> bool:
    candidate_path = _server.os.fspath(candidate)
    root_path = _server.os.fspath(root)
    try:
        return _server.os.path.commonpath([candidate_path, root_path]) == root_path
    except ValueError:
        return False


def _scope_target_is_valid(
    scope: str,
    *,
    artifact_id: str | None,
    workspace: str | None,
    publisher: str | None,
) -> bool:
    if scope in {"global", "harness"}:
        return True
    if scope == "artifact":
        return artifact_id is not None
    if scope == "workspace":
        return workspace is not None
    if scope == "publisher":
        return publisher is not None
    return False


def _resolve_request_action(path_parts: list[str], payload: dict[str, object]) -> tuple[str | None, str | None, bool]:
    if len(path_parts) == 4 and path_parts[:2] == ["v1", "requests"] and path_parts[3] in {"approve", "block"}:
        return path_parts[2], "allow" if path_parts[3] == "approve" else "block", True
    if len(path_parts) == 3 and path_parts[0] == "approvals" and path_parts[2] == "decision":
        action = payload.get("action")
        if not isinstance(action, str) or not action.strip():
            return path_parts[1], None, True
        return path_parts[1], action.strip(), True
    if len(path_parts) == 4 and path_parts[:2] == ["v1", "approvals"] and path_parts[3] == "decision":
        action = payload.get("action")
        if not isinstance(action, str) or not action.strip():
            return path_parts[2], None, True
        return path_parts[2], action.strip(), True
    return None, None, False
