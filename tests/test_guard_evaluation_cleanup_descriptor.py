from __future__ import annotations

import os
import signal
import stat
from contextlib import contextmanager
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import evaluation_cleanup as cleanup_module
from codex_plugin_scanner.guard import evaluation_preflight as preflight_module
from codex_plugin_scanner.guard.evaluation_contracts import EvaluationContractError
from codex_plugin_scanner.guard.evaluation_preflight import (
    cleanup_interrupted_evaluation_setup,
    setup_evaluation,
)
from tests.test_guard_evaluation_preflight import _artifact, _artifact_paths, _fake_host, _profile

pytestmark = pytest.mark.skipif(os.name != "posix", reason="descriptor-bound cleanup requires POSIX")


def test_nested_cleanup_finishes_reading_entries_before_removing_them(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(preflight_module, "check_host_version", lambda *_args, **_kwargs: (True, "host_version_match"))
    _, setup = _setup(tmp_path)
    nested = setup.root_path / "nested"
    nested.mkdir()
    (nested / "first.bin").write_bytes(b"first")
    (nested / "second.bin").write_bytes(b"second")
    identity = nested.stat().st_dev, nested.stat().st_ino
    original_scandir = cleanup_module.os.scandir

    @contextmanager
    def mutation_sensitive_scandir(descriptor):
        with original_scandir(descriptor) as entries:
            details = os.fstat(descriptor)
            if (details.st_dev, details.st_ino) == identity:
                first = next(entries)

                def remaining_entries():
                    yield first
                    # Model a filesystem iterator which skips later entries
                    # when its directory changes during the read.
                    if (nested / first.name).exists():
                        yield from entries

                yield remaining_entries()
            else:
                yield entries

    with monkeypatch.context() as patch:
        patch.setattr(cleanup_module.os, "scandir", mutation_sensitive_scandir)
        assert setup.cleanup() is True
    assert not setup.root_path.exists()


def _setup(tmp_path: Path):
    executable = _fake_host(tmp_path)
    artifact = _artifact(tmp_path)
    profile = _profile(tmp_path, executable)
    setup = setup_evaluation(
        profile,
        artifact_paths=_artifact_paths(artifact),
        parent_dir=tmp_path,
        allow_host_execution=True,
    )
    assert setup.report.status == "passed"
    assert setup.root_path is not None and setup.marker_token is not None
    assert setup.root_identity is not None
    return profile, setup


def _foreign_directory(tmp_path: Path) -> tuple[Path, bytes]:
    foreign = tmp_path / "unrelated-state"
    foreign.mkdir(mode=0o700)
    sentinel = foreign / "user-config.json"
    content = b"preserve-this-unrelated-configuration"
    sentinel.write_bytes(content)
    sentinel.chmod(0o600)
    return foreign, content


def _swap_at_final_root_stat(
    tmp_path: Path,
    root: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[Path, Path, bytes]:
    foreign, content = _foreign_directory(tmp_path)
    held = root.with_name("held-owned-root")
    original_stat = preflight_module.os.stat
    swapped = False

    def swap_before_final_stat(path: object, *args: object, **kwargs: object):
        nonlocal swapped
        if (
            not swapped
            and path == root.name
            and kwargs.get("dir_fd") is not None
            and kwargs.get("follow_symlinks") is False
        ):
            root.rename(held)
            foreign.rename(root)
            swapped = True
        return original_stat(path, *args, **kwargs)

    monkeypatch.setattr(preflight_module.os, "stat", swap_before_final_stat)
    return held, root, content


def _swap_at_final_root_rmdir(
    tmp_path: Path,
    root: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[Path, Path, bytes]:
    foreign, content = _foreign_directory(tmp_path)
    held = root.with_name("held-owned-root")
    original_rmdir = preflight_module.os.rmdir
    swapped = False

    def swap_before_final_rmdir(path: object, *args: object, **kwargs: object):
        nonlocal swapped
        if not swapped and path == root.name and kwargs.get("dir_fd") is not None:
            root.rename(held)
            foreign.rename(root)
            swapped = True
        return original_rmdir(path, *args, **kwargs)

    monkeypatch.setattr(preflight_module.os, "rmdir", swap_before_final_rmdir)
    return held, root, content


def test_normal_cleanup_is_descriptor_bound_and_idempotent(tmp_path: Path) -> None:
    _profile_data, setup = _setup(tmp_path)
    assert setup.root_path is not None
    foreign_directory, foreign_content = _foreign_directory(tmp_path)
    link = setup.root_path / "foreign-link"
    link.symlink_to(foreign_directory, target_is_directory=True)
    nested = setup.root_path / "workspace" / "nested"
    nested.mkdir()
    (nested / "result.bin").write_bytes(b"owned-result")
    unrelated = tmp_path / "unrelated-config.json"
    unrelated_bytes = b"leave-this-byte-sequence-alone"
    unrelated.write_bytes(unrelated_bytes)

    assert setup.cleanup() is True
    assert not setup.root_path.exists()
    assert unrelated.read_bytes() == unrelated_bytes
    assert (foreign_directory / "user-config.json").read_bytes() == foreign_content
    assert setup.cleanup() is False


def test_cleanup_allows_owned_root_permission_change(tmp_path: Path) -> None:
    _profile_data, setup = _setup(tmp_path)
    assert setup.root_path is not None
    setup.root_path.chmod(0o755)

    assert setup.cleanup() is True


@pytest.mark.parametrize("special_mode", (stat.S_ISUID, stat.S_ISGID, stat.S_ISVTX))
def test_cleanup_rejects_special_mode_bits_on_owned_root(tmp_path: Path, special_mode: int) -> None:
    _profile_data, setup = _setup(tmp_path)
    assert setup.root_path is not None
    setup.root_path.chmod(0o700 | special_mode)

    with pytest.raises(EvaluationContractError, match="unsafe permission bits"):
        setup.cleanup()

    setup.root_path.chmod(0o700)
    assert setup.cleanup() is True


@pytest.mark.parametrize("special_mode", (stat.S_ISUID, stat.S_ISGID, stat.S_ISVTX))
def test_cleanup_rejects_special_mode_bits_on_ownership_marker(tmp_path: Path, special_mode: int) -> None:
    _profile_data, setup = _setup(tmp_path)
    assert setup.root_path is not None
    marker = setup.root_path / cleanup_module.MARKER_NAME
    marker.chmod(0o600 | special_mode)

    with pytest.raises(EvaluationContractError, match="ownership marker is unsafe"):
        setup.cleanup()

    marker.chmod(0o600)
    assert setup.cleanup() is True


def test_cleanup_keeps_marker_until_owned_entries_are_removed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _profile_data, setup = _setup(tmp_path)
    assert setup.root_path is not None and setup.marker_token is not None
    marker = setup.root_path / ".hol-guard-evaluation-owned"
    original_remove = cleanup_module._remove_descriptor_tree

    def fail_before_owned_entry_removal(directory_descriptor: int, entry_name: str) -> None:
        if entry_name == "guard-home":
            raise ValueError("synthetic cleanup failure")
        original_remove(directory_descriptor, entry_name)

    monkeypatch.setattr(cleanup_module, "_remove_descriptor_tree", fail_before_owned_entry_removal)
    with pytest.raises(ValueError, match="unable to clean up evaluation setup"):
        setup.cleanup()

    assert marker.read_text(encoding="utf-8") == setup.marker_token
    monkeypatch.undo()
    assert setup.cleanup() is True


def test_live_cleanup_rejects_root_replacement_before_marker_validation(tmp_path: Path) -> None:
    _profile_data, setup = _setup(tmp_path)
    assert setup.root_path is not None
    root = setup.root_path
    held = root.with_name("held-owned-root")
    foreign, content = _foreign_directory(tmp_path)
    root.rename(held)
    foreign.rename(root)

    with pytest.raises(ValueError, match="changed before cleanup"):
        setup.cleanup()

    assert (root / "user-config.json").read_bytes() == content
    assert held.joinpath(".hol-guard-evaluation-owned").read_text(encoding="utf-8") == setup.marker_token


def test_live_cleanup_rejects_replacement_at_final_destructive_boundary(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _profile_data, setup = _setup(tmp_path)
    assert setup.root_path is not None
    held, replacement, content = _swap_at_final_root_stat(tmp_path, setup.root_path, monkeypatch)

    with pytest.raises(ValueError, match="changed during cleanup"):
        setup.cleanup()

    assert (replacement / "user-config.json").read_bytes() == content
    assert held.is_dir()


def test_live_cleanup_preserves_nonempty_replacement_at_unavoidable_final_name_race(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _profile_data, setup = _setup(tmp_path)
    assert setup.root_path is not None
    held, replacement, content = _swap_at_final_root_rmdir(tmp_path, setup.root_path, monkeypatch)

    with pytest.raises(ValueError, match="unable to clean up evaluation setup"):
        setup.cleanup()

    assert (replacement / "user-config.json").read_bytes() == content
    assert held.is_dir()


def test_interrupted_cleanup_uses_the_same_root_descriptor_boundary(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    profile, setup = _setup(tmp_path)
    assert setup.root_path is not None and setup.marker_token is not None
    root = setup.root_path
    token = setup.marker_token
    held, replacement, content = _swap_at_final_root_stat(tmp_path, root, monkeypatch)

    with pytest.raises(ValueError, match="changed during cleanup"):
        cleanup_interrupted_evaluation_setup(profile, owned_root=root, marker_token=token)

    assert (replacement / "user-config.json").read_bytes() == content
    assert held.is_dir()


def test_interrupted_cleanup_rejects_replacement_before_root_open(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    profile, setup = _setup(tmp_path)
    assert setup.root_path is not None and setup.marker_token is not None
    root = setup.root_path
    token = setup.marker_token
    held = root.with_name(f"{cleanup_module.OWNED_ROOT_PREFIX}held")
    replacement, content = _foreign_directory(tmp_path)
    marker = replacement / cleanup_module.MARKER_NAME
    marker.write_text(token, encoding="utf-8")
    marker.chmod(0o600)
    original_open = cleanup_module.os.open
    swapped = False

    def swap_before_root_open(path: object, *args: object, **kwargs: object):
        nonlocal swapped
        if not swapped and path == root.name and kwargs.get("dir_fd") is not None:
            root.rename(held)
            replacement.rename(root)
            swapped = True
        return original_open(path, *args, **kwargs)

    monkeypatch.setattr(cleanup_module.os, "open", swap_before_root_open)
    with pytest.raises(ValueError, match="changed before cleanup"):
        cleanup_interrupted_evaluation_setup(profile, owned_root=root, marker_token=token)

    assert (root / "user-config.json").read_bytes() == content
    assert held.is_dir()
    monkeypatch.undo()
    assert cleanup_module.remove_owned_root(held, token, expected_root_identity=setup.root_identity) is True


def test_cleanup_rejects_marker_fifo_swap_without_blocking(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _profile_data, setup = _setup(tmp_path)
    assert setup.root_path is not None
    root = setup.root_path
    marker = root / ".hol-guard-evaluation-owned"
    held_marker = root / ".held-marker"
    foreign = tmp_path / "unrelated-state"
    foreign.mkdir(mode=0o700)
    sentinel = foreign / "user-config.json"
    sentinel.write_bytes(b"preserve-during-marker-race")
    original_open = preflight_module.os.open
    observed_flags: list[int] = []
    swapped = False

    def swap_marker_before_open(path: object, flags: int, *args: object, **kwargs: object):
        nonlocal swapped
        if path == ".hol-guard-evaluation-owned" and not swapped and kwargs.get("dir_fd") is not None:
            observed_flags.append(flags)
            marker.rename(held_marker)
            os.mkfifo(marker, mode=0o600)
            swapped = True
        return original_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(preflight_module.os, "open", swap_marker_before_open)
    previous_handler = signal.getsignal(signal.SIGALRM)

    def fail_if_blocked(_signum: int, _frame: object) -> None:
        raise AssertionError("marker FIFO open blocked")

    signal.signal(signal.SIGALRM, fail_if_blocked)
    signal.setitimer(signal.ITIMER_REAL, 1.0)
    try:
        with pytest.raises(ValueError, match="ownership marker changed during cleanup"):
            setup.cleanup()
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous_handler)
        marker.unlink()
        held_marker.rename(marker)
        monkeypatch.undo()

    assert swapped
    assert observed_flags and observed_flags[0] & os.O_NONBLOCK
    assert stat.S_ISREG(marker.stat().st_mode)
    assert sentinel.read_bytes() == b"preserve-during-marker-race"
    assert setup.cleanup() is True


def test_recovery_rejects_symlink_missing_marker_and_foreign_parent(tmp_path: Path) -> None:
    unrelated = tmp_path / "unrelated"
    unrelated.mkdir(mode=0o700)
    sentinel = unrelated / "user-config.json"
    sentinel.write_bytes(b"preserve")
    link = tmp_path / "hol-guard-eval-link"
    link.symlink_to(unrelated, target_is_directory=True)
    with pytest.raises(ValueError, match="must not be a symlink"):
        cleanup_interrupted_evaluation_setup(_profile(tmp_path), owned_root=link, marker_token="a" * 32)
    assert sentinel.read_bytes() == b"preserve"

    missing_marker = tmp_path / "hol-guard-eval-missing-marker"
    missing_marker.mkdir(mode=0o700)
    with pytest.raises(ValueError, match="ownership marker is missing"):
        cleanup_interrupted_evaluation_setup(_profile(tmp_path), owned_root=missing_marker, marker_token="a" * 32)
    assert missing_marker.is_dir()
    missing_marker.rmdir()

    _profile_data, setup = _setup(tmp_path)
    assert setup.root_path is not None and setup.marker_token is not None
    other_parent = tmp_path / "other-private-parent"
    other_parent.mkdir(mode=0o700)
    other_profile = _profile(tmp_path)
    scope = other_profile["targetScope"]
    assert isinstance(scope, dict)
    scope["rootPath"] = str(other_parent)
    scope["allowedPaths"] = [str(other_parent)]
    with pytest.raises(ValueError, match="outside the profile target scope"):
        cleanup_interrupted_evaluation_setup(
            other_profile,
            owned_root=setup.root_path,
            marker_token=setup.marker_token,
        )
    assert setup.root_path.is_dir()
    assert setup.cleanup() is True


def test_cleanup_blocks_when_descriptor_support_is_unavailable(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _profile_data, setup = _setup(tmp_path)
    assert setup.root_path is not None
    monkeypatch.setattr(preflight_module.os, "name", "nt")

    with pytest.raises(ValueError, match="descriptor-bound evaluation cleanup is unavailable"):
        setup.cleanup()
    assert setup.root_path.is_dir()


def test_setup_blocks_before_allocation_when_descriptor_support_is_unavailable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    executable = _fake_host(tmp_path)
    artifact = _artifact(tmp_path)
    profile = _profile(tmp_path, executable)
    monkeypatch.setattr(cleanup_module, "descriptor_cleanup_supported", lambda: False)

    setup = setup_evaluation(
        profile,
        artifact_paths=_artifact_paths(artifact),
        parent_dir=tmp_path,
        allow_host_execution=True,
    )

    assert setup.report.status == "blocked_environment"
    assert setup.report.reason == "descriptor_cleanup_unavailable"
    assert setup.report.checks[-1] == {
        "name": "setup_cleanup",
        "status": "blocked_environment",
        "reason": "descriptor_cleanup_unavailable",
    }
    assert setup.root_path is None
    assert setup.marker_token is None
    assert not list(tmp_path.glob("hol-guard-eval-*"))
