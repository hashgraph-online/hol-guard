"""Codex authenticated hook writes and legacy shell cleanup."""

from __future__ import annotations


def _line_marker_at(content: bytes, index: int, marker: bytes) -> bool:
    if index < 0 or content[index : index + len(marker)] != marker:
        return False
    before_is_boundary = index == 0 or content[index - 1 : index] == b"\n"
    after_index = index + len(marker)
    after_is_boundary = after_index == len(content) or content[after_index : after_index + 1] in {b"\r", b"\n"}
    return before_is_boundary and after_is_boundary


def _find_line_marker(content: bytes, marker: bytes, start: int) -> int:
    index = content.find(marker, start)
    while index >= 0 and not _codex._line_marker_at(content, index, marker):
        index = content.find(marker, index + len(marker))
    return index


def _trailing_line_break_length(content: bytes) -> int:
    if content.endswith(b"\r\n"):
        return 2
    if content.endswith(b"\n"):
        return 1
    return 0


def _remove_managed_shell_guard_blocks(content: bytes) -> bytes:
    """Remove only legacy Guard marker blocks while preserving every other byte."""

    begin = _codex._SHELL_GUARD_BEGIN.encode("utf-8")
    end = _codex._SHELL_GUARD_END.encode("utf-8")
    search_from = 0
    while (block_start := _codex._find_line_marker(content, begin, search_from)) >= 0:
        block_end_start = _codex._find_line_marker(content, end, block_start + len(begin))
        if block_end_start < 0:
            break
        removal_start = block_start
        prefix = content[:block_start]
        last_break_length = _codex._trailing_line_break_length(prefix)
        if last_break_length and _codex._trailing_line_break_length(prefix[:-last_break_length]):
            # Legacy installation inserted one blank separator before its block.
            removal_start -= last_break_length
        removal_end = block_end_start + len(end)
        if content[removal_end : removal_end + 2] == b"\r\n":
            removal_end += 2
        elif content[removal_end : removal_end + 1] == b"\n":
            removal_end += 1
        content = content[:removal_start] + content[removal_end:]
        search_from = removal_start
    return content


def _install_hooks(
    self: _codex.CodexHarnessAdapter,
    context: _codex.HarnessContext,
    *,
    payloads: dict[_codex.Path, dict[str, object]] | None = None,
) -> _codex.Path:
    target_hooks_path = self._hooks_path(context)
    hook_payloads = payloads or self._load_hook_payloads(context)
    for hooks_path in self._all_hook_paths(context):
        original_payload = _codex.deepcopy(hook_payloads.get(hooks_path, {}))
        payload = _codex.deepcopy(original_payload)
        hooks = payload.get("hooks")
        if not isinstance(hooks, dict):
            hooks = {}
        legacy_bindings = _codex._current_install_legacy_bindings(context, hooks)
        cleaned_hooks, managed_removed = _codex._remove_manifest_bound_hook_events(hooks, legacy_bindings)
        if not managed_removed:
            payload = _codex.deepcopy(original_payload)
        elif cleaned_hooks:
            payload["hooks"] = cleaned_hooks
        else:
            payload.pop("hooks", None)
        self._write_hooks_payload(hooks_path, payload, original_payload=original_payload)
    return target_hooks_path


def _install_config_hooks(
    payload: dict[str, object],
    context: _codex.HarnessContext,
    *,
    owned_bindings: _codex.Sequence[_codex.Mapping[str, object]] = (),
) -> None:
    hooks = payload.get("hooks")
    if not isinstance(hooks, dict):
        hooks = {}
    cleaned_hooks, _ = _codex._remove_manifest_bound_hook_events(hooks, owned_bindings)
    legacy_bindings = _codex._current_install_legacy_bindings(context, cleaned_hooks)
    cleaned_hooks, _ = _codex._remove_manifest_bound_hook_events(cleaned_hooks, legacy_bindings)
    _codex.install_managed_codex_hook_groups(
        cleaned_hooks,
        _codex._managed_hook_groups(context),
        current_guard_home=context.guard_home,
    )
    payload["hooks"] = cleaned_hooks


def _write_authenticated_hook_config(
    context: _codex.HarnessContext,
    *,
    config_path: _codex.Path,
    payload: dict[str, object],
    previous_manifest: dict[str, object] | None,
) -> dict[str, object]:
    # fmt: off
    """Commit manifest first, then config, rolling both back on any failure.

        During the short manifest-first window an old config fails closed against
        the new manifest.  Codex never observes a newly registered hook before
        its complete authenticated identity has been durably committed.
        """
    # fmt: on

    if config_path.exists() or config_path.is_symlink():
        _codex.validate_regular_file(config_path, role="config_target", executable_required=False)
        original_config = config_path.read_text(encoding="utf-8")
    else:
        original_config = None
    manifest_path = _codex.hook_manifest_path(context.guard_home, config_path)
    secret_path = _codex.hook_secret_path(context.guard_home)
    original_manifest = _codex.snapshot_regular_file(manifest_path)
    original_secret = _codex.snapshot_regular_file(secret_path)
    try:
        manifest = _codex.build_authenticated_hook_manifest(
            _codex._hook_manifest_spec(context), previous_manifest=previous_manifest
        )
        _codex._assert_package_reauthentication_is_safe(previous_manifest, manifest)
        _codex.write_hook_manifest(context.guard_home, config_path, manifest)
        _codex.atomic_write_text(config_path, _codex.dump_toml(payload), mode=0o600)
        written_payload = _codex._strict_toml_object(config_path, label="rendered Codex config file")
        _codex._require_hook_semantics_readback(
            payload,
            written_payload,
            source_scope=_codex.CodexHarnessAdapter._scope_for(context, config_path),
            source_path=config_path,
        )
        state = _codex.codex_native_hook_state(context)
        if not bool(state.get("protection_active")):
            reason = str(state.get("integrity_reason") or "codex_hook_integrity_readback_failed")
            raise RuntimeError(
                f"{_codex._AUTHORITATIVE_HOOK_UNAVAILABLE_REASON}: Codex hook authentication readback failed: {reason}"
            )
        return state
    except BaseException:
        rollback_error: BaseException | None = None
        try:
            if original_config is None:
                if config_path.is_symlink():
                    raise RuntimeError("Guard refused to unlink a symlink while rolling back Codex config.")
                config_path.unlink(missing_ok=True)
            else:
                _codex.atomic_write_text(config_path, original_config, mode=0o600)
            _codex.restore_private_file(manifest_path, original_manifest)
            _codex.restore_private_file(secret_path, original_secret)
        except BaseException as exc:  # pragma: no cover - catastrophic local I/O failure
            rollback_error = exc
        if rollback_error is not None:
            raise RuntimeError("Codex hook transaction failed and rollback could not be completed.") from rollback_error
        raise


def _uninstall_shell_guard(context: _codex.HarnessContext) -> None:
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
        _codex.CodexHarnessAdapter._remove_shell_guard_block(startup_path)


def _remove_shell_guard_block(path: _codex.Path) -> None:
    if not path.is_file():
        return
    original = path.read_bytes()
    cleaned = _codex._remove_managed_shell_guard_blocks(original)
    if cleaned == original:
        return
    if cleaned:
        path.write_bytes(cleaned)
    else:
        path.unlink()


# Bind the facade after all declarations for direct helper imports.
from . import codex as _codex  # noqa: E402
