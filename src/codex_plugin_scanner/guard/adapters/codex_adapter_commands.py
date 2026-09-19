"""Codex hook commands and managed event definitions."""

from __future__ import annotations


def _hook_workspace_dir(context: _codex.HarnessContext) -> _codex.Path | None:
    return context.workspace_dir if context.workspace_override_explicit else None


def _local_hook_command_parts_for_home_mode(
    context: _codex.HarnessContext,
    *,
    home_is_current: bool,
    python_executable: str,
) -> tuple[str, ...]:
    runtime_guard_home = (_codex.resolve_guard_home() if home_is_current else context.guard_home).resolve(strict=False)
    guard_args = [
        "guard",
        "hook",
        "--harness",
        "codex",
    ]
    if not home_is_current:
        guard_args.extend(["--home", str(context.home_dir)])
        if runtime_guard_home != context.home_dir.resolve():
            guard_args.extend(["--guard-home", str(runtime_guard_home)])
    hook_workspace = _codex._hook_workspace_dir(context)
    if hook_workspace is not None:
        guard_args.extend(["--workspace", str(hook_workspace)])
    package_root = _codex.Path(_codex.__file__).resolve().parents[3]
    return _codex.isolated_guard_cli_command(python_executable, package_root, guard_args)


def _guard_python_executable() -> str:
    """Use a prune-safe frozen launcher, else the current interpreter identity."""

    if bool(getattr(_codex.sys, "frozen", False)):
        return _codex.resolve_frozen_guard_cli()
    return str(_codex.Path(_codex.sys.executable).expanduser().absolute())


def _home_is_current(context: _codex.HarnessContext) -> bool:
    return not context.home_override_explicit and context.home_dir.resolve() == _codex.Path.home().resolve()


def _runtime_guard_home(context: _codex.HarnessContext) -> _codex.Path:
    guard_home = _codex.resolve_guard_home() if _codex._home_is_current(context) else context.guard_home
    return guard_home.resolve(strict=False)


def _local_hook_command_parts(context: _codex.HarnessContext) -> tuple[str, ...]:
    return _codex._local_hook_command_parts_for_home_mode(
        context,
        home_is_current=_codex._home_is_current(context),
        python_executable=_codex._guard_python_executable(),
    )


def _hook_command_parts_for_home_mode(
    context: _codex.HarnessContext,
    *,
    home_is_current: bool,
    python_executable: str,
) -> tuple[str, ...]:
    guard_home = (_codex.resolve_guard_home() if home_is_current else context.guard_home).resolve(strict=False)
    # Bind the daemon fast path to the install context explicitly. Omitting
    # ``home`` for the common current-user install silently forced every
    # PostToolUse event through the legacy CLI path.
    query = {"guard-home": str(guard_home), "home": str(context.home_dir.resolve(strict=False))}
    hook_workspace = _codex._hook_workspace_dir(context)
    if hook_workspace is not None:
        query["workspace"] = str(hook_workspace)
    long_timeout = _codex._post_tool_hook_timeout_seconds(context)
    config = {
        "state_path": str(guard_home / "daemon-state.json"),
        "manifest_path": str(
            _codex.hook_manifest_path(
                guard_home,
                _codex.CodexHarnessAdapter._hook_config_path(context),
            )
        ),
        "fallback_command": list(
            _codex._local_hook_command_parts_for_home_mode(
                context,
                home_is_current=home_is_current,
                python_executable=python_executable,
            )
        ),
        "start_command": list(
            _codex._daemon_start_command(guard_home, context.home_dir, python_executable=python_executable)
        ),
        "query": _codex.urlencode(query),
        "hook_timeouts": {
            "PreToolUse": long_timeout,
            "PermissionRequest": _codex._MANAGED_HOOK_TIMEOUT_SECONDS,
            "UserPromptSubmit": _codex._MANAGED_HOOK_TIMEOUT_SECONDS,
            "PostToolUse": long_timeout,
        },
    }
    bridge_path = _codex.Path(_codex.__file__).with_name("codex_daemon_hook_bridge.py").resolve()
    return (python_executable, "-I", str(bridge_path), _codex.json.dumps(config, separators=(",", ":")))


def _hook_command_parts(context: _codex.HarnessContext) -> tuple[str, ...]:
    return _codex._hook_command_parts_for_home_mode(
        context,
        home_is_current=_codex._home_is_current(context),
        python_executable=_codex._guard_python_executable(),
    )


def _hook_command(context: _codex.HarnessContext) -> str:
    return _codex.shlex.join(_codex._hook_command_parts(context))


def _pre_tool_hook_group(context: _codex.HarnessContext) -> dict[str, object]:
    return {
        "matcher": _codex._CODEX_GUARD_TOOL_MATCHER,
        "hooks": [
            _codex._managed_hook_entry(
                context,
                _codex._MANAGED_HOOK_STATUS_MESSAGE,
                timeout_seconds=_codex._post_tool_hook_timeout_seconds(context),
            )
        ],
    }


def _prompt_hook_group(context: _codex.HarnessContext) -> dict[str, object]:
    return {
        "hooks": [_codex._managed_hook_entry(context, _codex._MANAGED_PROMPT_HOOK_STATUS_MESSAGE)],
    }


def _permission_request_hook_group(context: _codex.HarnessContext) -> dict[str, object]:
    return {
        "matcher": _codex._CODEX_GUARD_PERMISSION_MATCHER,
        "hooks": [_codex._managed_hook_entry(context, _codex._MANAGED_PERMISSION_HOOK_STATUS_MESSAGE)],
    }


def _post_tool_hook_timeout_seconds(context: _codex.HarnessContext) -> int:
    configured_wait_timeout = _codex.load_guard_config(
        context.guard_home,
        _codex._hook_workspace_dir(context),
    ).approval_wait_timeout_seconds
    return (
        min(
            max(configured_wait_timeout, 0),
            _codex.MAX_APPROVAL_WAIT_TIMEOUT_SECONDS,
        )
        + _codex._MANAGED_HOOK_TIMEOUT_GRACE_SECONDS
    )


def _post_tool_hook_group(context: _codex.HarnessContext) -> dict[str, object]:
    return {
        "matcher": _codex._CODEX_GUARD_POST_TOOL_MATCHER,
        "hooks": [
            _codex._managed_hook_entry(
                context,
                _codex._MANAGED_POST_TOOL_HOOK_STATUS_MESSAGE,
                timeout_seconds=_codex._post_tool_hook_timeout_seconds(context),
            )
        ],
    }


def _managed_hook_groups(context: _codex.HarnessContext) -> dict[str, dict[str, object]]:
    return {
        "PreToolUse": _codex._pre_tool_hook_group(context),
        "PermissionRequest": _codex._permission_request_hook_group(context),
        "UserPromptSubmit": _codex._prompt_hook_group(context),
        "PostToolUse": _codex._post_tool_hook_group(context),
    }


# Bind the facade after all declarations for direct helper imports.
from . import codex as _codex  # noqa: E402
