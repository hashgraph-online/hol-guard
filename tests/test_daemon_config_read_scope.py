"""Admission-to-capture scope binding for daemon configuration inputs."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import config_source_io
from codex_plugin_scanner.guard.config_source_io import GuardConfigSourceError, capture_guard_config
from codex_plugin_scanner.guard.daemon import config_read_scope
from codex_plugin_scanner.guard.daemon.config_read_scope import HookConfigReadScope
from codex_plugin_scanner.guard.native_policy_snapshot import get_native_policy_snapshot_publisher
from codex_plugin_scanner.guard.store import GuardStore


def _alias(link: Path, target: Path) -> None:
    try:
        link.symlink_to(target, target_is_directory=True)
    except OSError:
        pytest.skip("creating directory aliases requires runner support")


@pytest.mark.parametrize("spelling", ["alias", "parent"])
def test_workspace_alias_resolved_at_admission_keeps_config(tmp_path: Path, spelling: str) -> None:
    from codex_plugin_scanner.guard.daemon.hook_process_request import (
        build_hook_process_review_request,
        coerce_resident_hook_request,
    )
    from codex_plugin_scanner.guard.daemon.server import _GuardDaemonHandler

    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / ".hol-guard.toml").write_text('sandbox_analysis = "strict"\n', encoding="utf-8")
    alias = tmp_path / "alias"
    _alias(alias, workspace)
    scope = HookConfigReadScope.for_guard_home(tmp_path / "guard")
    candidate = alias if spelling == "alias" else workspace / ".." / workspace.name
    handler = object.__new__(_GuardDaemonHandler)
    admitted = handler._validated_hook_directory_string("workspace", str(candidate), roots=(tmp_path,))
    assert admitted == str(workspace.resolve())
    request = build_hook_process_review_request(
        payload={"hook_event_name": "PreToolUse"},
        harness="cursor",
        home_dir=tmp_path,
        guard_home=scope.canonical_home,
        workspace=Path(admitted),
        hook_env={},
        claim_saved_approval=False,
        claimed_saved_allow_hash=None,
        claimed_trusted_request_override=False,
        claimed_approval_request_id=None,
    )
    parsed = coerce_resident_hook_request(request)
    assert parsed is not None and parsed.workspace == workspace.resolve()
    assert scope.read_toml(parsed.workspace / ".hol-guard.toml") == {"sandbox_analysis": "strict"}


@pytest.mark.parametrize("filename", ["config.toml", ".ai-plugin-scanner-guard.toml", ".hol-guard.toml"])
def test_retarget_after_admission_is_rejected_before_leaf_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, filename: str
) -> None:
    admitted = tmp_path / "admitted"
    other = tmp_path / "other"
    admitted.mkdir()
    other.mkdir()
    (other / filename).write_text('sandbox_analysis = "off"\n', encoding="utf-8")
    scope = HookConfigReadScope.for_guard_home(tmp_path / "guard")
    canonical = admitted.resolve()
    admitted.rename(tmp_path / "original")
    _alias(admitted, other)
    monkeypatch.setattr(config_source_io, "_capture_in_parent", lambda *_: pytest.fail("rejected scope was read"))
    # Both directories are within allowed roots. Root membership alone is not
    # sufficient: the canonical workspace selected at admission must survive.
    with pytest.raises(GuardConfigSourceError, match="guard_config_scope_changed"):
        scope(canonical / filename)


def test_trusted_home_alias_is_pinned_at_scope_construction(tmp_path: Path) -> None:
    original, other = tmp_path / "original", tmp_path / "other"
    original.mkdir()
    other.mkdir()
    (original / "config.toml").write_text('default_action = "block"\n', encoding="utf-8")
    (other / "config.toml").write_text('default_action = "allow"\n', encoding="utf-8")
    alias = tmp_path / "guard-alias"
    _alias(alias, original)
    scope = HookConfigReadScope.for_guard_home(alias)
    alias.unlink()
    _alias(alias, other)
    assert scope.read_toml(alias / "config.toml") == {"default_action": "block"}


def test_held_scope_rejection_happens_before_any_leaf_read(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    allowed, outside = tmp_path / "allowed", tmp_path / "outside"
    allowed.mkdir()
    outside.mkdir()
    scope = HookConfigReadScope(allowed, allowed, allowed, (allowed,))
    monkeypatch.setattr(config_read_scope, "trusted_temporary_root_for_path", lambda _: None)
    monkeypatch.setattr(config_source_io, "_capture_in_parent", lambda *_: pytest.fail("outside scope was read"))
    with pytest.raises(GuardConfigSourceError, match="guard_config_unexpected_root"):
        scope(outside / ".hol-guard.toml")


def test_temporary_scope_uses_held_directory_owner(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    if not callable(getattr(os, "getuid", None)):
        pytest.skip("POSIX ownership policy")
    allowed = tmp_path / "allowed"
    scope = HookConfigReadScope(allowed, allowed, allowed, (allowed,))
    parent = tmp_path.resolve()
    held = parent.stat()
    monkeypatch.setattr(config_read_scope, "trusted_temporary_root_for_path", lambda _: parent)
    monkeypatch.setattr(os, "getuid", lambda: held.st_uid)
    scope._validate_held_parent(parent, held)
    monkeypatch.setattr(os, "getuid", lambda: held.st_uid + 1)
    with pytest.raises(GuardConfigSourceError, match="guard_config_unexpected_root"):
        scope._validate_held_parent(parent, held)


def test_validator_error_is_normalized_for_publisher_ack_withdrawal(tmp_path: Path) -> None:
    def reject(_parent: Path, _held: os.stat_result) -> None:
        raise ValueError("caller policy rejected the directory")

    with pytest.raises(GuardConfigSourceError, match="guard_config_scope_rejected"):
        capture_guard_config(tmp_path / "config.toml", parent_validator=reject)


def test_publisher_reuse_preserves_the_exact_capture_dependency(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard")
    scope = HookConfigReadScope.for_guard_home(store.guard_home)
    ordinary = get_native_policy_snapshot_publisher(store)
    scoped = get_native_policy_snapshot_publisher(store, config_capture=scope)
    try:
        assert ordinary is not scoped
        assert get_native_policy_snapshot_publisher(store) is ordinary
        assert get_native_policy_snapshot_publisher(store, config_capture=scope) is scoped
        assert scoped.config_capture is scope
    finally:
        ordinary.close()
        scoped.close()


def test_rejected_capture_withdraws_ack_in_direct_and_fallback_reads(tmp_path: Path) -> None:
    def reject(_path: Path):
        raise GuardConfigSourceError("fixture_scope_rejected")

    publisher = get_native_policy_snapshot_publisher(GuardStore(tmp_path / "guard"), config_capture=reject)
    try:
        for reader in (publisher._capture_config_policy_input, publisher._uncached_config_reader):
            publisher._acked = True
            with pytest.raises(GuardConfigSourceError, match="fixture_scope_rejected"):
                reader(tmp_path / "guard" / "config.toml")
            assert not publisher._acked
    finally:
        publisher.close()


@pytest.mark.parametrize("rejected_name", ["config.toml", ".hol-guard.toml"])
def test_foundation_compiler_rejection_withdraws_ack_for_home_and_workspace(tmp_path: Path, rejected_name: str) -> None:
    store = GuardStore(tmp_path / "guard")
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    observed: list[Path] = []

    def capture(path: Path):
        observed.append(path)
        if path.name == rejected_name:
            raise GuardConfigSourceError("fixture_compiler_scope_rejected")
        return capture_guard_config(path)

    publisher = get_native_policy_snapshot_publisher(store, config_capture=capture)
    try:
        publisher.register_workspace(workspace)
        publisher._acked = True
        with pytest.raises(GuardConfigSourceError, match="fixture_compiler_scope_rejected"):
            publisher._compiled_effective_policy()
        assert observed[-1].name == rejected_name
        assert not publisher._acked
    finally:
        publisher.close()


def test_foundation_compiler_preserves_falsey_capture_and_ordinary_policy(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard")
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (store.guard_home / "config.toml").write_text('default_action = "block"\n', encoding="utf-8")
    (workspace / ".hol-guard.toml").write_text('sandbox_analysis = "strict"\n', encoding="utf-8")
    observed: set[Path] = set()

    class Capture:
        def __bool__(self) -> bool:
            return False

        def __call__(self, path: Path):
            observed.add(path)
            return capture_guard_config(path)

    ordinary = get_native_policy_snapshot_publisher(store)
    scoped = get_native_policy_snapshot_publisher(store, config_capture=Capture())
    try:
        ordinary.register_workspace(workspace)
        scoped.register_workspace(workspace)
        assert scoped._compiled_effective_policy() == ordinary._compiled_effective_policy()
        assert observed == {
            store.guard_home / "config.toml",
            workspace / ".ai-plugin-scanner-guard.toml",
            workspace / ".hol-guard.toml",
        }
    finally:
        ordinary.close()
        scoped.close()
