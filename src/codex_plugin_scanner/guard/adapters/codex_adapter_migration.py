"""Codex migration evidence, readback, and rollback."""

from __future__ import annotations


def _canonical_hook_semantics(
    payload: _codex.Mapping[str, object],
    *,
    source_scope: str,
) -> dict[str, tuple[str, ...]]:
    hooks = payload.get("hooks")
    if not isinstance(hooks, _codex.Mapping):
        return {}
    source_hooks_enabled = _codex._payload_has_hooks_feature_enabled(payload)
    semantics: dict[str, tuple[str, ...]] = {}
    for event_name, groups in hooks.items():
        if not isinstance(event_name, str) or not isinstance(groups, list):
            continue
        semantics[event_name] = tuple(
            _codex.canonical_codex_hook_group_identity(
                source_scope=source_scope,
                source_hooks_enabled=source_hooks_enabled,
                event_name=event_name,
                group=group,
            )
            for group in groups
            if isinstance(group, _codex.Mapping)
        )
    return semantics


def _require_hook_semantics_readback(
    expected: _codex.Mapping[str, object],
    actual: _codex.Mapping[str, object],
    *,
    source_scope: str,
    source_path: _codex.Path,
) -> None:
    if _codex._canonical_hook_semantics(expected, source_scope=source_scope) != _codex._canonical_hook_semantics(
        actual,
        source_scope=source_scope,
    ):
        raise RuntimeError(
            f"{_codex._CODEX_HOOK_MIGRATION_READBACK_MISMATCH}: Rendered Codex hooks at {source_path} did not preserve "
            "their canonical event, matcher, handler, environment, timeout, status, and command semantics. The "
            "legacy source was retained; repair the config and retry migration."
        )


def _migration_group_identities(
    payload: _codex.Mapping[str, object],
    *,
    source_scope: str,
    source_hooks_enabled: bool,
) -> set[str]:
    hooks = payload.get("hooks")
    if not isinstance(hooks, _codex.Mapping):
        return set()
    return {
        _codex.canonical_codex_hook_group_identity(
            source_scope=source_scope,
            source_hooks_enabled=source_hooks_enabled,
            event_name=event_name,
            group=group,
        )
        for event_name, groups in hooks.items()
        if isinstance(event_name, str) and isinstance(groups, list)
        for group in groups
        if isinstance(group, _codex.Mapping)
    }


def _unmanaged_migration_payload(
    hooks_payload: _codex.Mapping[str, object],
    *,
    context: _codex.HarnessContext,
    owned_bindings: _codex.Sequence[_codex.Mapping[str, object]],
) -> dict[str, object]:
    hooks = hooks_payload.get("hooks")
    if not isinstance(hooks, dict):
        return {}
    cleaned_hooks, _ = _codex._remove_manifest_bound_hook_events(hooks, owned_bindings)
    legacy_bindings = _codex._current_install_legacy_bindings(context, cleaned_hooks)
    cleaned_hooks, _ = _codex._remove_manifest_bound_hook_events(cleaned_hooks, legacy_bindings)
    return {"hooks": cleaned_hooks} if cleaned_hooks else {}


def _write_hook_migration_backup(
    context: _codex.HarnessContext,
    *,
    config_path: _codex.Path,
) -> _codex.Path:
    resolved_path = str(config_path.resolve())
    digest = _codex.hashlib.sha256(resolved_path.encode("utf-8")).hexdigest()[:16]
    backup_path = context.guard_home / "managed" / "codex" / "migration-backups" / f"{digest}.json"
    if backup_path.exists():
        return backup_path
    content = config_path.read_text(encoding="utf-8") if config_path.is_file() else ""
    backup_payload = {
        "schema": "codex-hook-migration-backup-v1",
        "config_path": resolved_path,
        "existed": config_path.is_file(),
        "content": content,
    }
    _codex.atomic_write_text(
        backup_path, _codex.json.dumps(backup_payload, sort_keys=True, indent=2) + "\n", mode=0o600
    )
    return backup_path


def _load_hook_payloads(
    self: _codex.CodexHarnessAdapter, context: _codex.HarnessContext
) -> dict[_codex.Path, dict[str, object]]:
    return {
        hooks_path: _codex._strict_json_object(hooks_path, label="Codex hooks file")
        for hooks_path in self._all_hook_paths(context)
    }


def _migrate_alternate_hook_configs(
    self: _codex.CodexHarnessAdapter,
    context: _codex.HarnessContext,
    *,
    payloads: dict[_codex.Path, dict[str, object]],
    config_payloads: dict[_codex.Path, dict[str, object]],
    skip_config_path: _codex.Path,
    owned_bindings: _codex.Sequence[_codex.Mapping[str, object]] = (),
) -> None:
    for config_path, hooks_path in self._config_hook_pairs(context):
        if config_path == skip_config_path:
            continue
        hooks_payload = payloads.get(hooks_path, {})
        if not hooks_payload:
            continue
        config_payload = config_payloads[config_path]
        if (
            _codex._migrate_hooks_json_into_config(
                config_payload,
                hooks_payload,
                context=context,
                source_scope=self._scope_for(context, config_path),
                owned_bindings=owned_bindings,
            )
            and config_payload
        ):
            _codex._write_hook_migration_backup(context, config_path=config_path)
            original_text = config_path.read_text(encoding="utf-8") if config_path.is_file() else None
            try:
                _codex.atomic_write_text(config_path, _codex.dump_toml(config_payload), mode=0o600)
                written_payload = _codex._strict_toml_object(config_path, label="rendered Codex config file")
                _codex._require_hook_semantics_readback(
                    config_payload,
                    written_payload,
                    source_scope=self._scope_for(context, config_path),
                    source_path=config_path,
                )
            except BaseException:
                if original_text is None:
                    config_path.unlink(missing_ok=True)
                else:
                    _codex.atomic_write_text(config_path, original_text, mode=0o600)
                raise


def _verify_json_hook_migrations(
    self: _codex.CodexHarnessAdapter,
    context: _codex.HarnessContext,
    *,
    payloads: _codex.Mapping[_codex.Path, _codex.Mapping[str, object]],
    owned_bindings: _codex.Sequence[_codex.Mapping[str, object]],
) -> None:
    hook_config_path = self._hook_config_path(context)
    for config_path, hooks_path in self._config_hook_pairs(context):
        hooks_payload = payloads.get(hooks_path)
        if not hooks_payload:
            continue
        source_scope = self._scope_for(context, config_path)
        expected_payload = _codex._unmanaged_migration_payload(
            hooks_payload,
            context=context,
            owned_bindings=owned_bindings if config_path == hook_config_path else (),
        )
        written_payload = _codex._strict_toml_object(config_path, label="migrated Codex config file")
        source_hooks_enabled = _codex._payload_has_hooks_feature_enabled(written_payload)
        expected = _codex._migration_group_identities(
            expected_payload,
            source_scope=source_scope,
            source_hooks_enabled=source_hooks_enabled,
        )
        if not expected:
            continue
        actual = _codex._migration_group_identities(
            written_payload,
            source_scope=source_scope,
            source_hooks_enabled=source_hooks_enabled,
        )
        if not expected.issubset(actual):
            raise RuntimeError(
                f"{_codex._CODEX_HOOK_MIGRATION_READBACK_MISMATCH}: {config_path} does not contain every canonical "
                f"hook migrated from {hooks_path}. The legacy JSON source was retained; repair the config and "
                "retry migration."
            )


def _remove_json_hook_files(
    self: _codex.CodexHarnessAdapter,
    context: _codex.HarnessContext,
    *,
    payloads: dict[_codex.Path, dict[str, object]],
    config_snapshots: _codex.Mapping[_codex.Path, bytes | None],
    manifest_path: _codex.Path,
    manifest_snapshot: bytes | None,
) -> _codex.Path:
    target_hooks_path = self._hooks_path(context)
    snapshots = {
        hooks_path: _codex.snapshot_regular_file(hooks_path)
        for hooks_path in self._all_hook_paths(context)
        if hooks_path in payloads and hooks_path.is_file()
    }
    try:
        for hooks_path in snapshots:
            hooks_path.unlink()
    except BaseException as removal_error:
        rollback_errors: list[BaseException] = []
        for path, snapshot in (*config_snapshots.items(), (manifest_path, manifest_snapshot), *snapshots.items()):
            try:
                _codex.restore_private_file(path, snapshot)
            except BaseException as rollback_error:
                rollback_errors.append(rollback_error)
        if manifest_snapshot is None:
            try:
                _codex.remove_hook_secret_if_unused(context.guard_home)
            except BaseException as rollback_error:
                rollback_errors.append(rollback_error)
        if rollback_errors:
            raise RuntimeError(
                "codex_hook_migration_rollback_failed: Guard could not fully restore Codex hook sources after "
                "legacy JSON removal failed. Run `hol-guard install codex` to repair the installation."
            ) from removal_error
        raise
    return target_hooks_path


# Bind the facade after all declarations for direct helper imports.
from . import codex as _codex  # noqa: E402
