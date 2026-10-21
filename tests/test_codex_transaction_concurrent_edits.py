"""A failed Codex transaction must preserve intervening configuration edits."""

import os
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import codex_hook_rollback as rollback
from codex_plugin_scanner.guard.adapters import codex as adapter_module
from codex_plugin_scanner.guard.adapters import codex_lifecycle_lock as locks
from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.adapters.codex import CodexHarnessAdapter
from codex_plugin_scanner.guard.codex_hook_file_integrity import CodexHookIntegrityError
from codex_plugin_scanner.guard.codex_hook_integrity import hook_manifest_path, hook_secret_path


@pytest.mark.parametrize("existing_installation", [False, True])
def test_config_edit_during_failed_write_survives_rollback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, existing_installation: bool
) -> None:
    profile = tmp_path / "account-profile"
    profile.mkdir(mode=0o700)
    monkeypatch.setattr(locks, "_account_home", lambda: profile)
    context = HarnessContext(
        home_dir=tmp_path / "home",
        workspace_dir=None,
        guard_home=tmp_path / "guard-home",
    )
    adapter = CodexHarnessAdapter()
    if existing_installation:
        adapter.install(context)
    config_path = adapter._hook_config_path(context)
    original_write = adapter_module.atomic_write_text
    concurrent_text = 'model = "user-selected-model"\n'
    injected = False
    transaction_files: dict[Path, bytes] = {}

    def interrupted_write(path: Path, text: str, *, mode: int = 0o600, on_publish=None) -> None:
        nonlocal injected
        if path == config_path and not injected:
            injected = True
            for participant in (
                hook_manifest_path(context.guard_home, config_path),
                hook_secret_path(context.guard_home),
            ):
                transaction_files[participant] = participant.read_bytes()
            original_write(path, concurrent_text, mode=mode)
            raise OSError("injected configuration write failure after another writer")
        original_write(path, text, mode=mode, on_publish=on_publish)

    monkeypatch.setattr(adapter_module, "atomic_write_text", interrupted_write)
    with pytest.raises(CodexHookIntegrityError, match="Codex publication needs recovery"):
        adapter.install(context)

    assert injected
    assert config_path.is_file()
    assert config_path.read_text(encoding="utf-8") == concurrent_text
    assert not adapter_module.codex_native_hook_state(context)["protection_active"]
    assert transaction_files
    for participant, snapshot in transaction_files.items():
        assert participant.read_bytes() == snapshot


def test_deleted_config_after_publish_preserves_pending_manifest_and_secret(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    profile = tmp_path / "account-profile"
    profile.mkdir(mode=0o700)
    monkeypatch.setattr(locks, "_account_home", lambda: profile)
    context = HarnessContext(
        home_dir=tmp_path / "home",
        workspace_dir=None,
        guard_home=tmp_path / "guard-home",
    )
    adapter = CodexHarnessAdapter()
    config_path = adapter._hook_config_path(context)
    manifest_path = hook_manifest_path(context.guard_home, config_path)
    secret_path = hook_secret_path(context.guard_home)
    original_readback = adapter_module._strict_toml_object
    injected = False
    pending_participants: dict[Path, bytes] = {}

    def deleting_readback(path: Path, *, label: str) -> dict[str, object]:
        nonlocal injected
        if path == config_path and label == "rendered Codex config file" and not injected:
            injected = True
            pending_participants[manifest_path] = manifest_path.read_bytes()
            pending_participants[secret_path] = secret_path.read_bytes()
            path.unlink()
            raise OSError("injected readback failure after a competing deletion")
        return original_readback(path, label=label)

    monkeypatch.setattr(adapter_module, "_strict_toml_object", deleting_readback)
    with pytest.raises(CodexHookIntegrityError, match="Codex publication needs recovery"):
        adapter.install(context)

    assert injected
    assert not config_path.exists()
    for participant, snapshot in pending_participants.items():
        assert participant.read_bytes() == snapshot
    assert not adapter_module.codex_native_hook_state(context)["protection_active"]


@pytest.mark.parametrize(
    "substitution",
    [
        "removed",
        "hardlink",
        pytest.param("symlink", marks=pytest.mark.skipif(os.name == "nt", reason="Windows symlink privileges")),
    ],
)
def test_failed_write_preserves_substituted_config_targets(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, substitution: str
) -> None:
    profile = tmp_path / "account-profile"
    profile.mkdir(mode=0o700)
    monkeypatch.setattr(locks, "_account_home", lambda: profile)
    context = HarnessContext(home_dir=tmp_path / "home", workspace_dir=None, guard_home=tmp_path / "guard-home")
    adapter = CodexHarnessAdapter()
    adapter.install(context)
    config_path = adapter._hook_config_path(context)
    target = config_path.parent / "user-target.toml"
    target.write_bytes(b'owner = "other-writer"\n')
    original_write = adapter_module.atomic_write_text
    injected = False

    def interrupted_write(path: Path, text: str, *, mode: int = 0o600, on_publish=None) -> None:
        nonlocal injected
        if path == config_path and not injected:
            injected = True
            path.unlink()
            if substitution == "symlink":
                path.symlink_to(target)
            elif substitution == "hardlink":
                os.link(target, path)
            raise OSError("injected write failure after target substitution")
        original_write(path, text, mode=mode, on_publish=on_publish)

    monkeypatch.setattr(adapter_module, "atomic_write_text", interrupted_write)
    with pytest.raises(CodexHookIntegrityError, match="Codex publication needs recovery"):
        adapter.install(context)

    assert injected
    assert target.read_bytes() == b'owner = "other-writer"\n'
    if substitution == "removed":
        assert not config_path.exists()
    elif substitution == "symlink":
        assert config_path.is_symlink()
    else:
        assert config_path.stat().st_ino == target.stat().st_ino
        assert config_path.stat().st_nlink == 2


def test_failed_descriptor_wrapping_releases_the_open_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = tmp_path / "config.toml"
    path.write_bytes(b"original")
    opened: list[int] = []

    def failed_fdopen(descriptor: int, mode: str) -> None:
        opened.append(descriptor)
        raise OSError("injected descriptor wrapping failure")

    monkeypatch.setattr(rollback.os, "fdopen", failed_fdopen)
    with pytest.raises(RuntimeError, match="codex_hook_rollback_conflict"):
        rollback.require_unchanged_config_for_rollback(
            path,
            b"original",
            b"candidate",
            original_identity=rollback.rollback_file_identity(path),
            written_identity=None,
        )

    assert len(opened) == 1
    with pytest.raises(OSError):
        os.fstat(opened[0])
    assert path.read_bytes() == b"original"


@pytest.mark.parametrize("existing_installation", [False, True])
def test_matching_replacement_is_not_owned_by_the_failed_transaction(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, existing_installation: bool
) -> None:
    profile = tmp_path / "account-profile"
    profile.mkdir(mode=0o700)
    monkeypatch.setattr(locks, "_account_home", lambda: profile)
    context = HarnessContext(home_dir=tmp_path / "home", workspace_dir=None, guard_home=tmp_path / "guard-home")
    adapter = CodexHarnessAdapter()
    if existing_installation:
        adapter.install(context)
    config_path = adapter._hook_config_path(context)
    original_write = adapter_module.atomic_write_text
    replacement: bytes | None = None
    replacement_identity = None

    def interrupted_write(path: Path, text: str, *, mode: int = 0o600, on_publish=None):
        nonlocal replacement, replacement_identity
        if path == config_path and replacement is None:
            replacement = text.encode("utf-8")
            original_write(path, text, mode=mode)
            replacement_identity = path.stat().st_ino
            raise OSError("injected write failure after a matching external replacement")
        return original_write(path, text, mode=mode, on_publish=on_publish)

    monkeypatch.setattr(adapter_module, "atomic_write_text", interrupted_write)
    with pytest.raises(CodexHookIntegrityError, match="Codex publication needs recovery"):
        adapter.install(context)
    assert replacement is not None
    assert config_path.read_bytes() == replacement
    assert config_path.stat().st_ino == replacement_identity


@pytest.mark.parametrize("existing_installation", [False, True])
def test_matching_replacement_after_completed_write_is_preserved(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, existing_installation: bool
) -> None:
    profile = tmp_path / "account-profile"
    profile.mkdir(mode=0o700)
    monkeypatch.setattr(locks, "_account_home", lambda: profile)
    context = HarnessContext(home_dir=tmp_path / "home", workspace_dir=None, guard_home=tmp_path / "guard-home")
    adapter = CodexHarnessAdapter()
    if existing_installation:
        adapter.install(context)
    config_path = adapter._hook_config_path(context)
    original_readback = adapter_module._strict_toml_object
    replacement: bytes | None = None
    replacement_identity = None

    def replaced_readback(path: Path, *, label: str):
        nonlocal replacement, replacement_identity
        if path == config_path and label == "rendered Codex config file":
            replacement = path.read_bytes()
            previous_identity = path.stat().st_ino
            adapter_module.atomic_write_text(path, replacement.decode("utf-8"), mode=0o600)
            replacement_identity = path.stat().st_ino
            assert replacement_identity != previous_identity
            raise OSError("injected readback failure after a matching external replacement")
        return original_readback(path, label=label)

    monkeypatch.setattr(adapter_module, "_strict_toml_object", replaced_readback)
    with pytest.raises(CodexHookIntegrityError, match="Codex publication needs recovery"):
        adapter.install(context)
    assert replacement is not None
    assert config_path.read_bytes() == replacement
    assert config_path.stat().st_ino == replacement_identity


def test_invalid_utf8_snapshot_is_rejected_before_manifest_or_secret_writes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    profile = tmp_path / "account-profile"
    profile.mkdir(mode=0o700)
    monkeypatch.setattr(locks, "_account_home", lambda: profile)
    context = HarnessContext(home_dir=tmp_path / "home", workspace_dir=None, guard_home=tmp_path / "guard-home")
    adapter = CodexHarnessAdapter()
    adapter.install(context)
    config_path = adapter._hook_config_path(context)
    manifest_path = hook_manifest_path(context.guard_home, config_path)
    secret_path = hook_secret_path(context.guard_home)
    manifest_before, secret_before = manifest_path.read_bytes(), secret_path.read_bytes()
    config_path.write_bytes(b"\xff")

    with pytest.raises(RuntimeError, match="codex_hook_config_invalid"):
        adapter._write_authenticated_hook_config(context, config_path=config_path, payload={}, previous_manifest=None)
    assert config_path.read_bytes() == b"\xff"
    assert manifest_path.read_bytes() == manifest_before
    assert secret_path.read_bytes() == secret_before


def test_matching_bytes_and_inode_with_changed_timestamp_are_not_original_state(tmp_path: Path) -> None:
    path = tmp_path / "config.toml"
    path.write_bytes(b"original")
    before = path.stat()
    original_identity = rollback.rollback_file_identity(path)
    path.write_bytes(b"original")
    os.utime(path, ns=(before.st_atime_ns, before.st_mtime_ns + 1_000_000_000))
    assert path.stat().st_ino == before.st_ino
    assert path.stat().st_mtime_ns != before.st_mtime_ns
    with pytest.raises(RuntimeError, match="codex_hook_rollback_conflict"):
        rollback.require_unchanged_config_for_rollback(
            path, b"original", b"candidate", original_identity=original_identity, written_identity=None
        )
    assert path.read_bytes() == b"original"


def test_substituted_target_during_snapshot_is_reported_as_invalid_not_conflict(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    profile = tmp_path / "account-profile"
    profile.mkdir(mode=0o700)
    monkeypatch.setattr(locks, "_account_home", lambda: profile)
    context = HarnessContext(home_dir=tmp_path / "home", workspace_dir=None, guard_home=tmp_path / "guard-home")
    adapter = CodexHarnessAdapter()
    adapter.install(context)
    config_path = adapter._hook_config_path(context)
    target = config_path.parent / "other-owner.toml"
    target.write_bytes(b'owner = "other-writer"\n')
    original_identity = rollback.rollback_file_identity
    captured = False

    def first_then_substitute(path: Path):
        nonlocal captured
        result = original_identity(path)
        if path == config_path and not captured:
            captured = True
            path.unlink()
            os.link(target, path)
        return result

    monkeypatch.setattr(adapter_module, "rollback_file_identity", first_then_substitute)
    with pytest.raises(RuntimeError, match="codex_hook_config_invalid"):
        adapter._write_authenticated_hook_config(context, config_path=config_path, payload={}, previous_manifest=None)
    assert config_path.stat().st_ino == target.stat().st_ino
    assert config_path.stat().st_nlink == 2
    assert target.read_bytes() == b'owner = "other-writer"\n'
