"""Codex discovery and provenance-preserving artifact inventory."""

from __future__ import annotations


def _artifact_from_guard_proxy_args(
    *,
    args: tuple[str, ...],
    fallback_name: str,
    fallback_scope: str,
    fallback_config_path: _codex.Path,
    harness: str,
    environment: object = None,
) -> _codex.GuardArtifact | None:
    """Expose the wrapped server for status/review without re-wrapping it."""

    parsed = _codex._parse_guard_proxy_args(args)
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
    raw_environment = environment if isinstance(environment, dict) else {}
    configured_environment = {key: value for key in env_keys if isinstance((value := raw_environment.get(key)), str)}
    metadata = _codex.enrich_mcp_server_metadata(
        {
            "env": configured_environment,
            "env_keys": list(env_keys),
            "guard_managed_proxy": True,
            "name": name,
        },
        command=command,
        args=server_args,
        url=None,
        transport=transport,
    )
    return _codex.GuardArtifact(
        artifact_id=f"codex:{source_scope}:{name}",
        name=name,
        harness=harness,
        artifact_type="mcp_server",
        source_scope=source_scope,
        config_path=config_path,
        command=command,
        args=server_args,
        transport=transport,
        metadata=metadata,
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


def _json_object(path: _codex.Path) -> dict[str, object]:
    if not path.is_file():
        return {}
    try:
        payload = _codex.json.loads(path.read_text(encoding="utf-8"))
    except (OSError, _codex.json.JSONDecodeError):
        return {}
    return payload if isinstance(payload, dict) else {}


def _codex_hook_inventory(
    payload: dict[str, object],
    *,
    source_path: _codex.Path,
    source_scope: str,
    source_format: str,
    source_hooks_enabled: bool,
    context: _codex.HarnessContext,
    authenticated_bindings: _codex.Sequence[_codex.Mapping[str, object]] = (),
) -> _codex.CodexHookInventory:
    hooks = payload.get("hooks")
    legacy_bindings = _codex._current_install_legacy_bindings(context, hooks if isinstance(hooks, dict) else {})
    return _codex.enumerate_codex_hooks(
        payload,
        source_path=source_path,
        source_scope=source_scope,
        source_format="json" if source_format == "json" else "toml",
        source_hooks_enabled=source_hooks_enabled,
        authenticated_bindings=authenticated_bindings,
        legacy_bindings=legacy_bindings,
    )


def _require_complete_preactivation_inventory(inventory: _codex.CodexHookInventory) -> None:
    if inventory.issues:
        issue = inventory.issues[0]
        raise RuntimeError(f"{issue.reason_code}: {issue.coordinate} in {issue.source_path}. {issue.message}")
    unmanaged = inventory.unmanaged_active_executables
    if inventory.records and not inventory.records[0].source_hooks_enabled and unmanaged:
        coordinates = ", ".join(record.coordinate for record in unmanaged)
        raise RuntimeError(
            f"{_codex.CODEX_HOOK_INVENTORY_UNMANAGED_EXECUTABLE}: Guard refused to enable existing Codex hook entries "
            f"without explicit approval; unmanaged executable hooks are present at {coordinates} in "
            f"{inventory.source_path}. Review or remove those hooks before running install."
        )


def _codex_hook_artifacts(
    records: _codex.Sequence[_codex.CodexHookInventoryRecord],
    *,
    harness: str,
) -> tuple[_codex.GuardArtifact, ...]:
    by_identity: dict[str, list[_codex.CodexHookInventoryRecord]] = {}
    for record in records:
        if record.ownership != "unmanaged":
            continue
        by_identity.setdefault(record.canonical_identity, []).append(record)
    artifacts: list[_codex.GuardArtifact] = []
    for identity, matching_records in sorted(by_identity.items()):
        ordered = sorted(
            matching_records,
            key=lambda record: (record.source_path, record.source_format, record.coordinate),
        )
        primary = ordered[0]
        provenance = [
            {
                "path": record.source_path,
                "format": record.source_format,
                "coordinate": record.coordinate,
            }
            for record in ordered
        ]
        metadata: dict[str, object] = {
            "codex_hook_identity_schema": _codex.CODEX_HOOK_IDENTITY_SCHEMA,
            "codex_hook_identity": identity,
            "event": primary.event_name,
            "matcher": primary.matcher if isinstance(primary.matcher, str | type(None)) else None,
            "handler_type": primary.handler_type,
            "timeout": primary.timeout,
            "env_keys": list(primary.environment_keys),
            "command_argv": list(primary.command_argv) if primary.command_argv is not None else None,
            "active": primary.active and primary.source_hooks_enabled,
            "executable": primary.executable,
            "ownership": sorted({record.ownership for record in ordered}),
            "source_provenance": provenance,
            "source_formats": sorted({record.source_format for record in ordered}),
            "source_paths": sorted({record.source_path for record in ordered}),
        }
        artifacts.append(
            _codex.GuardArtifact(
                artifact_id=f"codex:{primary.source_scope}:hook:{identity}",
                name=primary.event_name,
                harness=harness,
                artifact_type="hook",
                source_scope=primary.source_scope,
                config_path=primary.source_path,
                command=primary.command,
                metadata=metadata,
            )
        )
    return tuple(artifacts)


def _hooks_have_registered_entries(hooks: object) -> bool:
    if not isinstance(hooks, dict):
        return False
    return any(isinstance(groups, list) and bool(groups) for groups in hooks.values())


def detect(self: _codex.CodexHarnessAdapter, context: _codex.HarnessContext) -> _codex.HarnessDetection:
    artifacts: list[_codex.GuardArtifact] = []
    found_paths: list[str] = []
    hook_records: list[_codex.CodexHookInventoryRecord] = []
    warnings: list[str] = []
    config_payloads: dict[_codex.Path, dict[str, object]] = {}
    authenticated_manifest = _codex.load_hook_manifest_baseline(_codex._hook_manifest_spec(context))
    authenticated_bindings = _codex._manifest_bindings(authenticated_manifest)
    hook_config_path = self._hook_config_path(context)
    for config_path, _hooks_path in self._config_hook_pairs(context):
        payload = _codex._read_toml(config_path)
        config_payloads[config_path] = payload
        if not payload:
            continue
        found_paths.append(str(config_path))
        scope = self._scope_for(context, config_path)
        inventory = _codex._codex_hook_inventory(
            payload,
            source_path=config_path,
            source_scope=scope,
            source_format="toml",
            source_hooks_enabled=_codex._payload_has_hooks_feature_enabled(payload),
            context=context,
            authenticated_bindings=authenticated_bindings if config_path == hook_config_path else (),
        )
        hook_records.extend(inventory.records)
        warnings.extend(
            f"{issue.reason_code}: {issue.coordinate} in {issue.source_path}. {issue.message}"
            for issue in inventory.issues
        )
        mcp_servers = payload.get("mcp_servers")
        if isinstance(mcp_servers, dict):
            for name, server_config in mcp_servers.items():
                if not isinstance(name, str) or not isinstance(server_config, dict):
                    continue
                command = server_config.get("command")
                raw_args = server_config.get("args")
                if raw_args is not None and not isinstance(raw_args, list):
                    continue
                args = tuple(str(value) for value in (raw_args or []) if isinstance(value, str))
                if _codex.is_guard_proxy_command(command if isinstance(command, str) else None, args):
                    proxy_artifact = _codex._artifact_from_guard_proxy_args(
                        args=args,
                        fallback_name=name,
                        fallback_scope=scope,
                        fallback_config_path=config_path,
                        harness=self.harness,
                        environment=server_config.get("env"),
                    )
                    if proxy_artifact is not None:
                        artifacts.append(proxy_artifact)
                    continue
                url = server_config.get("url")
                env = server_config.get("env")
                environment = (
                    {
                        key.strip(): value
                        for key, value in env.items()
                        if isinstance(key, str) and key.strip() and isinstance(value, str)
                    }
                    if isinstance(env, dict)
                    else {}
                )
                enabled = server_config.get("enabled", True) is not False
                mcp_metadata = _codex.enrich_mcp_server_metadata(
                    {
                        "name": name,
                        "enabled": enabled,
                        "env": environment,
                        "env_keys": sorted(environment),
                    },
                    command=command if isinstance(command, str) else None,
                    args=args,
                    url=url if isinstance(url, str) else None,
                    transport="http" if isinstance(url, str) else "stdio",
                )
                artifacts.append(
                    _codex.GuardArtifact(
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
    for config_path, hooks_path in self._config_hook_pairs(context):
        hooks_payload = _codex._json_object(hooks_path)
        if not hooks_path.is_file():
            continue
        found_paths.append(str(hooks_path))
        scope = self._scope_for(context, hooks_path)
        config_payload = config_payloads.get(config_path, {})
        inventory = _codex._codex_hook_inventory(
            hooks_payload,
            source_path=hooks_path,
            source_scope=scope,
            source_format="json",
            source_hooks_enabled=_codex._payload_has_hooks_feature_enabled(config_payload),
            context=context,
        )
        hook_records.extend(inventory.records)
        warnings.extend(
            f"{issue.reason_code}: {issue.coordinate} in {issue.source_path}. {issue.message}"
            for issue in inventory.issues
        )
    artifacts.extend(_codex._codex_hook_artifacts(hook_records, harness=self.harness))
    detection = _codex.HarnessDetection(
        harness=self.harness,
        installed=bool(found_paths) or _codex._command_available(self.executable),
        command_available=_codex._command_available(self.executable),
        config_paths=tuple(found_paths),
        artifacts=tuple(artifacts),
        warnings=tuple(warnings),
    )
    extended = _codex.extend_detection_with_workspace_aibom(
        detection,
        home_dir=context.home_dir,
        workspace_dir=context.workspace_dir,
    )
    return _codex.extend_codex_runtime_inventory(
        extended,
        home_dir=context.home_dir,
        workspace_dir=context.workspace_dir,
    )


# Bind the facade after all declarations for direct helper imports.
from . import codex as _codex  # noqa: E402
