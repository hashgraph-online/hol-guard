"""Recovery from an interrupted `ai-tools configure --apply`.

The AI tool's settings file must end either as it was or recoverable with
`ai-tools restore`, never changed with no copy to go back to.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.cli import cloud_actions_host_apply
from codex_plugin_scanner.guard.cli.cloud_actions_host_apply import apply_host_config, backups_dir, restore_host_config
from codex_plugin_scanner.guard.cli.cloud_actions_host_config import plan_host_config
from tests.cloud_actions_pairing_support import URL, entry

CODEX_SETTINGS = '# Hand-written; keep this comment.\nmodel = "gpt-5"\n'


def _seed(home: Path) -> Path:
    path = home / ".codex" / "config.toml"
    path.parent.mkdir(parents=True)
    path.write_text(CODEX_SETTINGS, encoding="utf-8")
    return path


def _strays(directory: Path) -> list[str]:
    return sorted(path.name for path in directory.iterdir() if ".guard-tmp" in path.name)


def test_an_interrupt_before_the_move_changes_nothing(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = _seed(tmp_path)
    before = path.read_bytes()
    guard_home = tmp_path / "guard"
    plan = plan_host_config("codex", path=path, entry=entry("codex"), url=URL)
    real = cloud_actions_host_apply.replace_file

    def interrupted(source: Path, destination: Path) -> None:
        if destination == path:
            raise KeyboardInterrupt
        real(source, destination)

    monkeypatch.setattr(cloud_actions_host_apply, "replace_file", interrupted)
    with pytest.raises(KeyboardInterrupt):
        _ = apply_host_config(plan, guard_home=guard_home)

    assert path.read_bytes() == before
    assert _strays(path.parent) == []
    assert list(backups_dir(guard_home, "codex").glob("*")) == []

    # Running the same command again works.
    monkeypatch.setattr(cloud_actions_host_apply, "replace_file", real)
    _ = apply_host_config(plan, guard_home=guard_home)
    assert path.read_bytes() == plan.after


def test_an_interrupt_right_after_the_move_puts_the_earlier_file_back(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = _seed(tmp_path)
    before = path.read_bytes()
    guard_home = tmp_path / "guard"
    plan = plan_host_config("codex", path=path, entry=entry("codex"), url=URL)
    real = cloud_actions_host_apply.replace_file
    interrupted = False

    def moved_then_interrupted(source: Path, destination: Path) -> None:
        nonlocal interrupted
        real(source, destination)
        # The move has landed, but Guard has not yet noted it.
        if destination == path and not interrupted:
            interrupted = True
            raise KeyboardInterrupt

    monkeypatch.setattr(cloud_actions_host_apply, "replace_file", moved_then_interrupted)
    with pytest.raises(KeyboardInterrupt):
        _ = apply_host_config(plan, guard_home=guard_home)

    assert path.read_bytes() == before
    assert _strays(path.parent) == []
    assert list(backups_dir(guard_home, "codex").glob("*")) == []


def test_an_edit_after_an_interrupted_move_is_kept_and_restore_stays_available(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = _seed(tmp_path)
    guard_home = tmp_path / "guard"
    plan = plan_host_config("codex", path=path, entry=entry("codex"), url=URL)
    real = cloud_actions_host_apply.replace_file
    edited = b"# The AI tool wrote this after Guard.\n" + (plan.after or b"")

    def moved_edited_then_interrupted(source: Path, destination: Path) -> None:
        real(source, destination)
        if destination == path:
            destination.write_bytes(edited)
            raise KeyboardInterrupt

    monkeypatch.setattr(cloud_actions_host_apply, "replace_file", moved_edited_then_interrupted)
    with pytest.raises(KeyboardInterrupt):
        _ = apply_host_config(plan, guard_home=guard_home)

    # Guard does not overwrite an edit it did not make, and keeps its copy.
    assert path.read_bytes() == edited
    assert _strays(path.parent) == []
    assert list(backups_dir(guard_home, "codex").glob("*.json"))

    # Restoring removes only Guard's entry; the later edit stays.
    monkeypatch.setattr(cloud_actions_host_apply, "replace_file", real)
    restored = restore_host_config("codex", path=path, guard_home=guard_home)
    assert restored is not None and restored.scope == "entry"
    after_restore = path.read_text(encoding="utf-8")
    assert "# The AI tool wrote this after Guard." in after_restore
    assert "# Hand-written; keep this comment." in after_restore
    assert "cloud-actions" not in after_restore


def test_an_interrupt_before_the_move_leaves_another_writers_settings_alone(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = _seed(tmp_path)
    guard_home = tmp_path / "guard"
    plan = plan_host_config("codex", path=path, entry=entry("codex"), url=URL)
    assert plan.after is not None
    real = cloud_actions_host_apply.replace_file

    def written_elsewhere_then_interrupted(source: Path, destination: Path) -> None:
        if destination != path:
            real(source, destination)
            return
        # Another apply wrote the same settings; this one never moved its file.
        destination.write_bytes(plan.after or b"")
        raise KeyboardInterrupt

    monkeypatch.setattr(cloud_actions_host_apply, "replace_file", written_elsewhere_then_interrupted)
    with pytest.raises(KeyboardInterrupt):
        _ = apply_host_config(plan, guard_home=guard_home)

    assert path.read_bytes() == plan.after
    assert _strays(path.parent) == []
    assert list(backups_dir(guard_home, "codex").glob("*")) == []


def test_an_edit_made_while_guard_prepares_the_put_back_is_kept(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = _seed(tmp_path)
    before = path.read_bytes()
    guard_home = tmp_path / "guard"
    plan = plan_host_config("codex", path=path, entry=entry("codex"), url=URL)
    real_replace = cloud_actions_host_apply.replace_file
    real_temporary = cloud_actions_host_apply._write_temporary
    edited = b"# The AI tool wrote this while Guard was putting its file back.\n" + (plan.after or b"")
    interrupted = False

    def moved_then_interrupted(source: Path, destination: Path) -> None:
        nonlocal interrupted
        real_replace(source, destination)
        if destination == path and not interrupted:
            interrupted = True
            raise KeyboardInterrupt

    def edited_during_put_back(target: Path, payload: bytes, mode: int) -> Path:
        temporary = real_temporary(target, payload, mode)
        if target == path and payload == before and interrupted:
            path.write_bytes(edited)
        return temporary

    monkeypatch.setattr(cloud_actions_host_apply, "replace_file", moved_then_interrupted)
    monkeypatch.setattr(cloud_actions_host_apply, "_write_temporary", edited_during_put_back)
    with pytest.raises(KeyboardInterrupt):
        _ = apply_host_config(plan, guard_home=guard_home)

    assert path.read_bytes() == edited
    assert _strays(path.parent) == []
    assert list(backups_dir(guard_home, "codex").glob("*.json"))


def test_an_unknown_move_result_with_the_file_unchanged_keeps_no_copy(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = _seed(tmp_path)
    before = path.read_bytes()
    guard_home = tmp_path / "guard"
    plan = plan_host_config("codex", path=path, entry=entry("codex"), url=URL)
    real = cloud_actions_host_apply.replace_file

    def interrupted(source: Path, destination: Path) -> None:
        if destination == path:
            raise KeyboardInterrupt
        real(source, destination)

    monkeypatch.setattr(cloud_actions_host_apply, "replace_file", interrupted)
    # Guard cannot tell whether its file was moved (for example, the check itself failed).
    monkeypatch.setattr(cloud_actions_host_apply, "_moved", lambda *_args, **_kwargs: None)
    with pytest.raises(KeyboardInterrupt):
        _ = apply_host_config(plan, guard_home=guard_home)

    assert path.read_bytes() == before
    assert list(backups_dir(guard_home, "codex").glob("*")) == []
    monkeypatch.setattr(cloud_actions_host_apply, "replace_file", real)
    assert restore_host_config("codex", path=path, guard_home=guard_home) is None


@pytest.mark.skipif(os.name == "nt", reason="POSIX directory permissions")
def test_a_settings_folder_guard_cannot_write_is_left_alone(tmp_path: Path) -> None:
    path = _seed(tmp_path)
    before = path.read_bytes()
    guard_home = tmp_path / "guard"
    plan = plan_host_config("codex", path=path, entry=entry("codex"), url=URL)
    path.parent.chmod(0o500)
    try:
        if os.access(path.parent, os.W_OK):
            pytest.skip("running with permission to write anywhere")
        with pytest.raises(cloud_actions_host_apply.HostConfigWriteError) as error:
            _ = apply_host_config(plan, guard_home=guard_home)
    finally:
        path.parent.chmod(0o700)

    assert error.value.reason == "write_failed"
    assert path.read_bytes() == before
    assert list(backups_dir(guard_home, "codex").glob("*")) == []
