"""A failed Codex transaction must preserve intervening configuration edits."""

import os
from collections.abc import Callable
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import codex_harness_client as adapter_module
from codex_plugin_scanner.guard import codex_hook_rollback as rollback
from codex_plugin_scanner.guard.codex_harness_client import codex_paths
from codex_plugin_scanner.guard.codex_hook_file_integrity import CodexHookIntegrityError
from codex_plugin_scanner.guard.codex_hook_integrity import atomic_write_text
from codex_plugin_scanner.guard.harness_context import HarnessContext
from codex_plugin_scanner.guard.runtime_transition import TransitionFile
from tests import codex_hook_publication_helpers as publication_helpers
from tests import codex_publication_steps as publication_steps
from tests import harness_ops_support as harness_support
from tests.codex_hook_paths_support import hook_manifest_path, hook_secret_path
from tests.codex_publication_steps import use_stepwise_publication
from tests.transition_fault_support import interrupt_publication_at


def _interrupt_config_write(
    monkeypatch: pytest.MonkeyPatch, config_path: Path, interfere: Callable[[bytes], None]
) -> None:
    """Run ``interfere`` in place of the install's first config write, which then fails."""

    def interrupted(change: TransitionFile) -> None:
        assert change.after is not None
        interfere(change.after)

    interrupt_publication_at(monkeypatch, config_path, OSError("injected configuration write failure"), interrupted)


@pytest.mark.parametrize("existing_installation", [False, True])
def test_config_edit_during_failed_write_survives_rollback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, existing_installation: bool
) -> None:
    context = HarnessContext(
        home_dir=tmp_path / "home",
        workspace_dir=None,
        guard_home=tmp_path / "guard-home",
    )
    if existing_installation:
        harness_support.install("codex", context)
    config_path = codex_paths(context).config
    concurrent_text = 'model = "user-selected-model"\n'
    injected = False
    transaction_files: dict[Path, bytes] = {}

    def concurrent_edit(_rendered: bytes) -> None:
        nonlocal injected
        injected = True
        for participant in (
            hook_manifest_path(context.guard_home, config_path),
            hook_secret_path(context.guard_home),
        ):
            transaction_files[participant] = participant.read_bytes()
        atomic_write_text(config_path, concurrent_text, mode=0o600)

    _interrupt_config_write(monkeypatch, config_path, concurrent_edit)
    with pytest.raises(CodexHookIntegrityError, match="Codex publication needs recovery"):
        harness_support.install("codex", context)

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
    context = HarnessContext(
        home_dir=tmp_path / "home",
        workspace_dir=None,
        guard_home=tmp_path / "guard-home",
    )
    config_path = codex_paths(context).config
    manifest_path = hook_manifest_path(context.guard_home, config_path)
    secret_path = hook_secret_path(context.guard_home)
    use_stepwise_publication(monkeypatch)
    original_readback = publication_steps.readback
    injected = False
    pending_participants: dict[Path, bytes] = {}

    def deleting_readback(readback_context: HarnessContext) -> dict[str, object]:
        nonlocal injected
        if not injected:
            injected = True
            pending_participants[manifest_path] = manifest_path.read_bytes()
            pending_participants[secret_path] = secret_path.read_bytes()
            config_path.unlink()
            raise OSError("injected readback failure after a competing deletion")
        return original_readback(readback_context)

    monkeypatch.setattr(publication_steps, "readback", deleting_readback)
    with pytest.raises(CodexHookIntegrityError, match="Codex publication needs recovery"):
        harness_support.install("codex", context)

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
    context = HarnessContext(home_dir=tmp_path / "home", workspace_dir=None, guard_home=tmp_path / "guard-home")
    harness_support.install("codex", context)
    config_path = codex_paths(context).config
    target = config_path.parent / "user-target.toml"
    target.write_bytes(b'owner = "other-writer"\n')
    injected = False

    def substitute(_rendered: bytes) -> None:
        nonlocal injected
        injected = True
        config_path.unlink()
        if substitution == "symlink":
            config_path.symlink_to(target)
        elif substitution == "hardlink":
            os.link(target, config_path)

    _interrupt_config_write(monkeypatch, config_path, substitute)
    with pytest.raises(CodexHookIntegrityError, match="Codex publication needs recovery"):
        harness_support.install("codex", context)

    assert injected
    assert target.read_bytes() == b'owner = "other-writer"\n'
    if substitution == "removed":
        assert not config_path.exists()
    elif substitution == "symlink":
        assert config_path.is_symlink()
    else:
        assert config_path.stat().st_ino == target.stat().st_ino
        assert config_path.stat().st_nlink == 2


@pytest.mark.parametrize("existing_installation", [False, True])
def test_matching_replacement_is_not_owned_by_the_failed_transaction(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, existing_installation: bool
) -> None:
    context = HarnessContext(home_dir=tmp_path / "home", workspace_dir=None, guard_home=tmp_path / "guard-home")
    if existing_installation:
        harness_support.install("codex", context)
    config_path = codex_paths(context).config
    replacement: bytes | None = None
    replacement_identity = None

    def matching_replacement(rendered: bytes) -> None:
        nonlocal replacement, replacement_identity
        replacement = rendered
        atomic_write_text(config_path, rendered.decode("utf-8"), mode=0o600)
        replacement_identity = config_path.stat().st_ino

    _interrupt_config_write(monkeypatch, config_path, matching_replacement)
    with pytest.raises(CodexHookIntegrityError, match="Codex publication needs recovery"):
        harness_support.install("codex", context)
    assert replacement is not None
    assert config_path.read_bytes() == replacement
    assert config_path.stat().st_ino == replacement_identity


@pytest.mark.parametrize("existing_installation", [False, True])
def test_matching_replacement_after_completed_write_is_preserved(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, existing_installation: bool
) -> None:
    context = HarnessContext(home_dir=tmp_path / "home", workspace_dir=None, guard_home=tmp_path / "guard-home")
    if existing_installation:
        harness_support.install("codex", context)
    config_path = codex_paths(context).config
    use_stepwise_publication(monkeypatch)
    replacement: bytes | None = None
    replacement_identity = None

    def replaced_readback(_context: HarnessContext) -> dict[str, object]:
        nonlocal replacement, replacement_identity
        replacement = config_path.read_bytes()
        previous_identity = config_path.stat().st_ino
        atomic_write_text(config_path, replacement.decode("utf-8"), mode=0o600)
        replacement_identity = config_path.stat().st_ino
        assert replacement_identity != previous_identity
        raise OSError("injected readback failure after a matching external replacement")

    monkeypatch.setattr(publication_steps, "readback", replaced_readback)
    with pytest.raises(CodexHookIntegrityError, match="Codex publication needs recovery"):
        harness_support.install("codex", context)
    assert replacement is not None
    assert config_path.read_bytes() == replacement
    assert config_path.stat().st_ino == replacement_identity


def test_invalid_utf8_snapshot_is_rejected_before_manifest_or_secret_writes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    context = HarnessContext(home_dir=tmp_path / "home", workspace_dir=None, guard_home=tmp_path / "guard-home")
    harness_support.install("codex", context)
    config_path = codex_paths(context).config
    manifest_path = hook_manifest_path(context.guard_home, config_path)
    secret_path = hook_secret_path(context.guard_home)
    manifest_before, secret_before = manifest_path.read_bytes(), secret_path.read_bytes()
    config_path.write_bytes(b"\xff")

    with pytest.raises(RuntimeError, match="codex_hook_config_invalid"):
        publication_helpers.write_authenticated_hook_config(
            context, config_path=config_path, payload={}, previous_manifest=None
        )
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


def test_substituted_target_during_snapshot_is_reported_as_invalid_not_conflict(tmp_path: Path) -> None:
    """The native target snapshot refuses a config another file links to."""
    context = HarnessContext(home_dir=tmp_path / "home", workspace_dir=None, guard_home=tmp_path / "guard-home")
    harness_support.install("codex", context)
    config_path = codex_paths(context).config
    target = config_path.parent / "other-owner.toml"
    target.write_bytes(b'owner = "other-writer"\n')
    config_path.unlink()
    os.link(target, config_path)
    with pytest.raises(RuntimeError, match="codex_hook_config_invalid"):
        publication_helpers.write_authenticated_hook_config(
            context, config_path=config_path, payload={}, previous_manifest=None
        )
    assert config_path.stat().st_ino == target.stat().st_ino
    assert config_path.stat().st_nlink == 2
    assert target.read_bytes() == b'owner = "other-writer"\n'
