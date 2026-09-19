"""Codex config migration and exact managed-entry cleanup."""

from __future__ import annotations


def _append_unique_hook_groups(
    existing_groups: object,
    incoming_groups: object,
    *,
    event_name: str,
    source_scope: str,
    source_hooks_enabled: bool,
) -> list[object]:
    merged = list(existing_groups) if isinstance(existing_groups, list) else []
    if not isinstance(incoming_groups, list):
        return merged
    identities = {
        _codex.canonical_codex_hook_group_identity(
            source_scope=source_scope,
            source_hooks_enabled=source_hooks_enabled,
            event_name=event_name,
            group=group,
        )
        for group in merged
        if isinstance(group, _codex.Mapping)
    }
    conflict_keys = {
        key
        for group in merged
        if isinstance(group, _codex.Mapping)
        for key in _codex.canonical_codex_hook_conflict_keys(
            source_scope=source_scope,
            source_hooks_enabled=source_hooks_enabled,
            event_name=event_name,
            group=group,
        )
    }
    for group in incoming_groups:
        if not isinstance(group, _codex.Mapping):
            if group not in merged:
                merged.append(group)
            continue
        identity = _codex.canonical_codex_hook_group_identity(
            source_scope=source_scope,
            source_hooks_enabled=source_hooks_enabled,
            event_name=event_name,
            group=group,
        )
        if identity in identities:
            continue
        incoming_conflicts = set(
            _codex.canonical_codex_hook_conflict_keys(
                source_scope=source_scope,
                source_hooks_enabled=source_hooks_enabled,
                event_name=event_name,
                group=group,
            )
        )
        if incoming_conflicts & conflict_keys:
            raise RuntimeError(
                f"{_codex._CODEX_HOOK_MIGRATION_CONFLICT}: Codex hook sources define the same {event_name!r} "
                "matcher and command with different execution-affecting fields. Reconcile the definitions before "
                "retrying migration."
            )
        merged.append(_codex.deepcopy(group))
        identities.add(identity)
        conflict_keys.update(incoming_conflicts)
    return merged


def _migrate_hooks_json_into_config(
    config_payload: dict[str, object],
    hooks_payload: dict[str, object],
    *,
    context: _codex.HarnessContext,
    source_scope: str,
    owned_bindings: _codex.Sequence[_codex.Mapping[str, object]] = (),
) -> bool:
    json_hooks = hooks_payload.get("hooks")
    if not isinstance(json_hooks, dict):
        return False
    config_hooks = config_payload.get("hooks")
    if not isinstance(config_hooks, dict):
        config_hooks = {}
    cleaned_json_hooks, _ = _codex._remove_manifest_bound_hook_events(json_hooks, owned_bindings)
    legacy_bindings = _codex._current_install_legacy_bindings(context, cleaned_json_hooks)
    cleaned_json_hooks, _ = _codex._remove_manifest_bound_hook_events(cleaned_json_hooks, legacy_bindings)
    source_hooks_enabled = _codex._payload_has_hooks_feature_enabled(config_payload)
    changed = False
    for event_name, groups in cleaned_json_hooks.items():
        if not isinstance(event_name, str):
            continue
        merged_groups = _codex._append_unique_hook_groups(
            config_hooks.get(event_name),
            groups,
            event_name=event_name,
            source_scope=source_scope,
            source_hooks_enabled=source_hooks_enabled,
        )
        if merged_groups != config_hooks.get(event_name):
            changed = True
        config_hooks[event_name] = merged_groups
    if config_hooks:
        config_payload["hooks"] = config_hooks
    return changed


def _payload_has_hooks_feature_enabled(config_payload: _codex.Mapping[str, object]) -> bool:
    features = config_payload.get("features")
    if not isinstance(features, _codex.Mapping):
        return True
    return features.get("hooks") is not False


def _refresh_managed_proxy_interpreters(mcp_servers: dict[str, object]) -> tuple[str, ...]:
    current_interpreter = _codex._guard_python_executable()
    migrated: list[str] = []
    for name, server_config in mcp_servers.items():
        if not isinstance(server_config, dict):
            continue
        command = server_config.get("command")
        raw_args = server_config.get("args")
        if not isinstance(raw_args, list):
            continue
        args = tuple(str(value) for value in raw_args if isinstance(value, str))
        if not _codex.is_guard_proxy_command(command if isinstance(command, str) else None, args):
            continue
        if command == current_interpreter:
            continue
        server_config["command"] = current_interpreter
        migrated.append(name)
    return tuple(sorted(migrated))


def _remove_managed_hooks_from_alternate_configs(
    self: _codex.CodexHarnessAdapter,
    context: _codex.HarnessContext,
    *,
    skip_config_path: _codex.Path,
) -> None:
    # No authenticated manifest is issued for alternate Codex configs.
    # Only an exact current bridge can be re-adopted during explicit repair;
    # basename, status-message, and path-suffix matches remain untouched.
    for config_path, _hooks_path in self._config_hook_pairs(context):
        if config_path == skip_config_path or not config_path.is_file():
            continue
        config_payload = _codex.read_toml_payload(config_path)
        hooks = config_payload.get("hooks")
        changed = False
        if isinstance(hooks, dict):
            legacy_bindings = _codex._current_install_legacy_bindings(context, hooks)
            cleaned_hooks, managed_removed = _codex._remove_manifest_bound_hook_events(hooks, legacy_bindings)
            if managed_removed:
                changed = True
                if cleaned_hooks:
                    config_payload["hooks"] = cleaned_hooks
                else:
                    config_payload.pop("hooks", None)
        if not _codex._hooks_have_registered_entries(config_payload.get("hooks")):
            features = config_payload.get("features")
            if isinstance(features, dict):
                for feature_name in ("codex_hooks", "hooks"):
                    if feature_name in features:
                        features.pop(feature_name, None)
                        changed = True
                if features:
                    config_payload["features"] = features
                else:
                    config_payload.pop("features", None)
        if changed:
            _codex.atomic_write_text(config_path, _codex.dump_toml(config_payload), mode=0o600)


def _remove_managed_mcp_servers_from_alternate_configs(
    self: _codex.CodexHarnessAdapter,
    context: _codex.HarnessContext,
    *,
    managed_servers: tuple[_codex.ManagedMcpServer, ...],
    skip_config_path: _codex.Path,
) -> None:
    managed_names_by_path: dict[_codex.Path, set[str]] = {}
    for server in managed_servers:
        managed_names_by_path.setdefault(_codex.Path(server.config_path), set()).add(server.name)
    for config_path, _hooks_path in self._config_hook_pairs(context):
        if config_path == skip_config_path or not config_path.is_file():
            continue
        config_payload = _codex.read_toml_payload(config_path)
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
                and not _codex.is_guard_proxy_command(
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
        _codex.write_toml_payload(config_path, config_payload)


# Bind the facade after all declarations for direct helper imports.
from . import codex as _codex  # noqa: E402
