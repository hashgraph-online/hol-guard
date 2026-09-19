"""Codex authenticated manifest construction and live enforcement state."""

from __future__ import annotations


def _manifest_event_bindings(context: _codex.HarnessContext) -> list[dict[str, object]]:
    argv = list(_codex._hook_command_parts(context))
    bindings: list[dict[str, object]] = []
    for event_name, group in _codex._managed_hook_groups(context).items():
        handlers = group.get("hooks")
        if not isinstance(handlers, list) or len(handlers) != 1 or not isinstance(handlers[0], dict):
            raise RuntimeError(f"Guard's {event_name} hook definition is not canonical.")
        bindings.append(
            {
                "argv": argv,
                "event": event_name,
                "group": _codex.deepcopy(group),
                "group_matcher": group.get("matcher"),
                "handler": _codex.deepcopy(handlers[0]),
                "handler_id": f"codex:{event_name}:guard-handler-v1",
                "handler_index": 0,
            }
        )
    return bindings


def _hook_packaged_file_paths() -> tuple[tuple[str, _codex.Path], ...]:
    scanner_root = _codex.Path(_codex.__file__).resolve().parents[2]
    guard_root = _codex.Path(_codex.__file__).resolve().parents[1]
    return (
        ("bridge", _codex.Path(_codex.__file__).with_name("codex_daemon_hook_bridge.py").resolve()),
        ("bridge_resume", _codex.Path(_codex.__file__).with_name("codex_daemon_hook_resume.py").resolve()),
        ("bridge_runtime", guard_root / "codex_hook_bridge_runtime.py"),
        ("fallback_entrypoint", scanner_root / "cli.py"),
        ("daemon_entrypoint", guard_root / "daemon" / "__init__.py"),
        ("daemon_manager", guard_root / "daemon" / "manager.py"),
        ("launch_runtime", guard_root / "codex_hook_launch_runtime.py"),
        ("runtime_trust", guard_root / "codex_hook_runtime_trust.py"),
        ("windows_job", guard_root / "codex_hook_windows_job.py"),
    )


def _hook_manifest_spec(context: _codex.HarnessContext) -> _codex.CodexHookManifestSpec:
    return _codex.CodexHookManifestSpec(
        guard_home=context.guard_home,
        home_dir=context.home_dir,
        runtime_guard_home=_codex._runtime_guard_home(context),
        workspace_dir=_codex._hook_workspace_dir(context),
        config_path=_codex.CodexHarnessAdapter._hook_config_path(context),
        interpreter_path=_codex.Path(_codex._guard_python_executable()),
        package_version=_codex.__version__,
        packaged_file_paths=_codex._hook_packaged_file_paths(),
        fallback_argv=_codex._local_hook_command_parts(context),
        daemon_start_argv=_codex._daemon_start_command(
            _codex._runtime_guard_home(context),
            context.home_dir,
            python_executable=_codex._guard_python_executable(),
        ),
        event_bindings=tuple(_codex._manifest_event_bindings(context)),
        workspace_rebinding_allowed=not context.workspace_override_explicit,
    )


def _current_install_legacy_bindings(
    context: _codex.HarnessContext, hooks: dict[str, object]
) -> list[dict[str, object]]:
    """Select exact current bridge entries for explicit legacy re-adoption only."""

    current_argv = list(_codex._hook_command_parts(context))
    return _codex.exact_legacy_hook_bindings(
        hooks,
        expected_bindings=_codex._manifest_event_bindings(context),
        current_argv=current_argv,
        legacy_argv=[_codex.sys.executable, *current_argv[1:]],
        legacy_status_messages=_codex._LEGACY_MANAGED_HOOK_STATUS_MESSAGES,
    )


def _verify_live_hook_manifest(
    context: _codex.HarnessContext,
    *,
    config_path: _codex.Path,
    hooks: object,
) -> dict[str, object]:
    spec = _codex._hook_manifest_spec(context)
    if spec.config_path != config_path:
        raise RuntimeError("Codex hook verification received a non-canonical config target.")
    return _codex.verify_live_hook_manifest(spec, hooks=hooks)


def codex_native_hook_state(context: _codex.HarnessContext) -> dict[str, object]:
    config_path = _codex.CodexHarnessAdapter._hook_config_path(context)
    hooks_path = _codex.CodexHarnessAdapter._hooks_path(context)
    config_payload = _codex._read_toml(config_path)
    features = config_payload.get("features") if isinstance(config_payload, dict) else None
    toml_hooks = config_payload.get("hooks") if isinstance(config_payload, dict) else None
    hooks_payload = _codex._json_object(hooks_path)
    json_hooks = hooks_payload.get("hooks") if isinstance(hooks_payload, dict) else None
    hooks = toml_hooks if isinstance(toml_hooks, dict) else json_hooks
    integrity = _codex._verify_live_hook_manifest(context, config_path=config_path, hooks=hooks)
    event_matches = _codex.overlay_live_owned_event_matches(integrity, hooks)
    pre_tool_hook_installed = event_matches.get("PreToolUse") is True
    permission_hook_installed = event_matches.get("PermissionRequest") is True
    prompt_hook_installed = event_matches.get("UserPromptSubmit") is True
    post_tool_hook_installed = event_matches.get("PostToolUse") is True
    managed_hook_installed = all(
        (pre_tool_hook_installed, permission_hook_installed, prompt_hook_installed, post_tool_hook_installed)
    )
    authoritative_shell_hook_installed = pre_tool_hook_installed and permission_hook_installed
    integrity_valid = integrity.get("integrity_status") == "valid"
    features_is_table = isinstance(features, dict)
    hooks_feature_enabled = not features_is_table or features.get("hooks") is not False
    legacy_codex_hooks_enabled = features_is_table and features.get("codex_hooks") is True
    return {
        "config_path": str(config_path),
        "config_present": config_path.is_file(),
        "hooks_path": str(hooks_path),
        "hooks_present": hooks_path.is_file(),
        "toml_hooks_present": _codex._hooks_have_registered_entries(toml_hooks),
        "json_hooks_present": _codex._hooks_have_registered_entries(json_hooks),
        "hooks_enabled": hooks_feature_enabled,
        "codex_hooks_enabled": hooks_feature_enabled,
        "legacy_codex_hooks_enabled": legacy_codex_hooks_enabled,
        "managed_pre_tool_hook_installed": pre_tool_hook_installed,
        "managed_permission_request_hook_installed": permission_hook_installed,
        "managed_prompt_hook_installed": prompt_hook_installed,
        "managed_post_tool_hook_installed": post_tool_hook_installed,
        "managed_hook_installed": managed_hook_installed,
        "shell_enforcement_boundary": _codex._AUTHORITATIVE_ENFORCEMENT_BOUNDARY,
        "shell_hook_installed": authoritative_shell_hook_installed,
        "shell_protection_active": hooks_feature_enabled and authoritative_shell_hook_installed and integrity_valid,
        "shell_reason_code": (
            None
            if hooks_feature_enabled and authoritative_shell_hook_installed and integrity_valid
            else _codex._AUTHORITATIVE_HOOK_UNAVAILABLE_REASON
        ),
        "protection_active": hooks_feature_enabled and managed_hook_installed and integrity_valid,
        **{key: value for key, value in integrity.items() if key != "event_matches"},
    }


def _require_codex_authoritative_shell_hook(context: _codex.HarnessContext) -> None:
    hook_state = _codex.codex_native_hook_state(context)
    if bool(hook_state["shell_protection_active"]):
        return
    raise RuntimeError(
        f"{_codex._AUTHORITATIVE_HOOK_UNAVAILABLE_REASON}: Guard refused to launch Codex because the managed "
        "PreToolUse and PermissionRequest hooks are missing or disabled. Run `hol-guard install codex` "
        "or `hol-guard update` to repair the native-hook enforcement boundary."
    )


# Bind the facade after all declarations for direct helper imports.
from . import codex as _codex  # noqa: E402
