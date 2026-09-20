"""Codex installation and removal transactions."""

from __future__ import annotations


def install(self: _codex.CodexHarnessAdapter, context: _codex.HarnessContext) -> dict[str, object]:
    detection = self.detect(context)
    managed_servers = _codex.managed_stdio_servers(detection)
    skipped_servers = _codex.skipped_stdio_server_names(detection)
    target_config_path = self._target_config_path(context)
    hook_config_path = self._hook_config_path(context)
    previous_manifest = _codex.load_hook_manifest_baseline(_codex._hook_manifest_spec(context))
    owned_bindings = _codex._manifest_bindings(previous_manifest)
    hook_payloads = self._load_hook_payloads(context)
    config_payloads = {
        config_path: _codex._strict_toml_object(config_path, label="Codex config file")
        for config_path, _hooks_path in self._config_hook_pairs(context)
    }
    config_snapshots = {
        config_path: _codex.snapshot_regular_file(config_path)
        for config_path, _hooks_path in self._config_hook_pairs(context)
    }
    manifest_path = _codex.hook_manifest_path(context.guard_home, hook_config_path)
    manifest_snapshot = _codex.snapshot_regular_file(manifest_path)
    inventory_hook_payloads = _codex.deepcopy(hook_payloads)
    inventory_config_payloads = _codex.deepcopy(config_payloads)
    original_text = target_config_path.read_text(encoding="utf-8") if target_config_path.is_file() else None
    payload = config_payloads[target_config_path]
    hook_payload = payload if hook_config_path == target_config_path else config_payloads[hook_config_path]
    for config_path, hooks_path in self._config_hook_pairs(context):
        json_hook_payload = hook_payloads.get(hooks_path, {})
        if config_path == target_config_path:
            hook_config_payload = payload
        elif config_path == hook_config_path:
            hook_config_payload = hook_payload
        else:
            hook_config_payload = config_payloads[config_path]
        hooks_feature_enabled = _codex._payload_has_hooks_feature_enabled(hook_config_payload)
        source_scope = self._scope_for(context, config_path)
        config_inventory = _codex._codex_hook_inventory(
            hook_config_payload,
            source_path=config_path,
            source_scope=source_scope,
            source_format="toml",
            source_hooks_enabled=hooks_feature_enabled,
            context=context,
            authenticated_bindings=owned_bindings if config_path == hook_config_path else (),
        )
        json_inventory = _codex._codex_hook_inventory(
            json_hook_payload,
            source_path=hooks_path,
            source_scope=source_scope,
            source_format="json",
            source_hooks_enabled=hooks_feature_enabled,
            context=context,
        )
        _codex._require_complete_preactivation_inventory(config_inventory)
        _codex._require_complete_preactivation_inventory(json_inventory)
    _codex._require_hook_inventory_sources_unchanged(
        config_payloads=inventory_config_payloads,
        hook_payloads=inventory_hook_payloads,
    )
    target_hooks_path = self._hooks_path(context)
    target_hook_payload = hook_payloads.get(target_hooks_path, {})
    target_hooks_migrated = _codex._migrate_hooks_json_into_config(
        hook_payload,
        target_hook_payload,
        context=context,
        source_scope=self._scope_for(context, hook_config_path),
        owned_bindings=owned_bindings,
    )
    if target_hooks_migrated:
        _codex._write_hook_migration_backup(context, config_path=hook_config_path)
    backup_path = self._backup_path(context)
    if not backup_path.exists():
        backup_path.parent.mkdir(parents=True, exist_ok=True)
        backup_text = _codex.dump_toml(payload) if target_hooks_migrated else original_text or ""
        backup_path.write_text(backup_text, encoding="utf-8")
    mcp_servers = payload.get("mcp_servers")
    if not isinstance(mcp_servers, dict):
        mcp_servers = {}
    migrated_proxy_servers = self._refresh_managed_proxy_interpreters(mcp_servers)
    skipped_servers = tuple(name for name in skipped_servers if name not in migrated_proxy_servers)
    features = hook_payload.get("features")
    if not isinstance(features, dict):
        features = {}
    features.pop("codex_hooks", None)
    features["hooks"] = True
    hook_payload["features"] = features
    self._install_config_hooks(hook_payload, context, owned_bindings=owned_bindings)
    workspace_payload = (
        _codex.read_toml_payload(context.workspace_dir / ".codex" / "config.toml")
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
    hook_state = self._write_authenticated_hook_config(
        context,
        config_path=target_config_path,
        payload=payload,
        previous_manifest=previous_manifest,
    )
    if hook_config_path != target_config_path:
        raise RuntimeError("Codex hook authentication currently requires one canonical global config target.")
    self._migrate_alternate_hook_configs(
        context,
        payloads=hook_payloads,
        config_payloads=config_payloads,
        skip_config_path=hook_config_path,
        owned_bindings=(),
    )
    self._remove_managed_hooks_from_alternate_configs(context, skip_config_path=hook_config_path)
    self._remove_managed_mcp_servers_from_alternate_configs(
        context,
        managed_servers=managed_servers,
        skip_config_path=target_config_path,
    )
    self._verify_json_hook_migrations(
        context,
        payloads=hook_payloads,
        owned_bindings=owned_bindings,
    )
    hooks_path = self._remove_json_hook_files(
        context,
        payloads=hook_payloads,
        config_snapshots=config_snapshots,
        manifest_path=manifest_path,
        manifest_snapshot=manifest_snapshot,
    )
    self._uninstall_shell_guard(context)
    _codex._require_codex_authoritative_shell_hook(context)
    shim_manifest = _codex.install_guard_shim(self.harness, context)
    return {
        "harness": self.harness,
        "active": True,
        "config_path": str(target_config_path),
        **shim_manifest,
        "mode": "codex-mcp-proxy",
        "managed_config_path": str(target_config_path),
        "managed_hook_config_path": str(hook_config_path),
        "managed_hook_manifest_path": str(hook_state["manifest_path"]),
        "managed_hook_integrity": str(hook_state["integrity_status"]),
        "hook_workspace_explicit": context.workspace_override_explicit,
        "managed_hooks_path": str(hooks_path),
        "enforcement_boundary": _codex._AUTHORITATIVE_ENFORCEMENT_BOUNDARY,
        "legacy_shell_guard_cleanup": "complete",
        "backup_path": str(backup_path),
        "managed_servers": [server.name for server in managed_servers],
        "migrated_proxy_servers": list(migrated_proxy_servers),
        "runtime_restart_required": bool(migrated_proxy_servers),
        "skipped_servers": list(skipped_servers),
        "source_config_paths": list(detection.config_paths),
    }


def uninstall(self: _codex.CodexHarnessAdapter, context: _codex.HarnessContext) -> dict[str, object]:
    target_config_path = self._target_config_path(context)
    hook_config_path = self._hook_config_path(context)
    authenticated_manifest = _codex.load_hook_manifest_baseline(_codex._hook_manifest_spec(context))
    owned_bindings = _codex._manifest_bindings(authenticated_manifest)
    backup_path = self._backup_path(context)
    if backup_path.is_file():
        original_text = backup_path.read_text(encoding="utf-8")
        if original_text:
            _codex.atomic_write_text(target_config_path, original_text, mode=0o600)
        elif target_config_path.is_file():
            target_config_path.unlink()
        backup_path.unlink()
    elif target_config_path.is_file() and owned_bindings:
        target_payload = _codex.read_toml_payload(target_config_path)
        target_hooks = target_payload.get("hooks")
        if isinstance(target_hooks, dict):
            cleaned_hooks, managed_removed = _codex._remove_manifest_bound_hook_events(target_hooks, owned_bindings)
            if managed_removed:
                if cleaned_hooks:
                    target_payload["hooks"] = cleaned_hooks
                else:
                    target_payload.pop("hooks", None)
                _codex.atomic_write_text(target_config_path, _codex.dump_toml(target_payload), mode=0o600)
    hooks_path = self._remove_hooks(context)
    self._remove_managed_hooks_from_alternate_configs(context, skip_config_path=target_config_path)
    self._remove_managed_mcp_servers_from_alternate_configs(
        context,
        managed_servers=(),
        skip_config_path=target_config_path,
    )
    _codex.remove_hook_manifest(context.guard_home, hook_config_path)
    _codex.remove_hook_secret_if_unused(context.guard_home)
    self._uninstall_shell_guard(context)
    shim_manifest = _codex.remove_guard_shim(self.harness, context)
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


# Bind the facade after all declarations for direct helper imports.
from . import codex as _codex  # noqa: E402
