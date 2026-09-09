"""Native readback, concurrent writes and display-only settings validation."""

from __future__ import annotations

import argparse
import errno
import io
import json
import multiprocessing
import os
import time
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import config as config_module
from codex_plugin_scanner.guard import settings_write_lock as lock_module
from codex_plugin_scanner.guard.cli.commands_dispatch_desktop import _run_guard_desktop_command
from codex_plugin_scanner.guard.config import load_guard_config, update_guard_settings
from codex_plugin_scanner.guard.settings_write_lock import atomic_write_settings, settings_write_lock


def _competing_writer(home: str, start, ready, outcomes) -> None:
    original_read = config_module._read_toml

    def slow_read(path):
        result = original_read(path)
        time.sleep(0.1)
        return result

    config_module._read_toml = slow_read
    ready.put(True)
    if not start.wait(20):
        outcomes.put("start-timeout")
        return
    try:
        updated = update_guard_settings(
            Path(home), {"presentation_mode": "technical", "presentation_revision": 0}, skip_approval_gate=True
        )
        outcomes.put(("saved", updated.presentation_revision))
    except ValueError as error:
        outcomes.put(("conflict", str(error)))


def test_concurrent_processes_cannot_both_save_the_same_presentation_revision(tmp_path: Path) -> None:
    home = tmp_path / "guard"
    home.mkdir()
    context = multiprocessing.get_context("spawn")
    start = context.Event()
    ready = context.Queue()
    outcomes = context.Queue()
    processes = [context.Process(target=_competing_writer, args=(str(home), start, ready, outcomes)) for _ in range(2)]
    try:
        for process in processes:
            process.start()
        assert all(ready.get(timeout=20) for _ in processes)
        start.set()
        result = [outcomes.get(timeout=20) for _ in processes]
        assert sorted(item[0] for item in result) == ["conflict", "saved"]
        assert ("saved", 1) in result
        assert "another surface" in next(item[1] for item in result if item[0] == "conflict")
        resolved = load_guard_config(home)
        assert (resolved.presentation_mode, resolved.presentation_revision) == ("technical", 1)
    finally:
        start.set()
        for process in processes:
            process.join(timeout=10)
            if process.is_alive():
                process.terminate()
                process.join(timeout=5)
        ready.close()
        outcomes.close()


def test_desktop_get_reads_fresh_config_without_rewriting_it(tmp_path: Path) -> None:
    home = tmp_path / "guard"
    stale = load_guard_config(home)
    update_guard_settings(home, {"presentation_mode": "technical"}, skip_approval_gate=True)
    path = home / "config.toml"
    before = (path.read_bytes(), path.stat().st_mtime_ns)
    stream = io.StringIO()
    args = argparse.Namespace(desktop_command="presentation-get", guard_home=home, json=True)
    assert _run_guard_desktop_command(args, config=stale, output_stream=stream) == 0
    payload = json.loads(stream.getvalue())
    assert payload == {
        "mode": "technical",
        "source": "local-explicit",
        "explicit": True,
        "canWrite": True,
        "schemaVersion": 1,
        "revision": 1,
        "diagnostic": None,
    }
    assert (path.read_bytes(), path.stat().st_mtime_ns) == before


def test_desktop_get_parser_accepts_native_read_command(tmp_path: Path) -> None:
    from codex_plugin_scanner.cli import _build_parser

    parser = _build_parser("hol-guard", program_mode="guard")
    args = parser.parse_args(["desktop", "presentation-get", "--guard-home", str(tmp_path), "--json"])
    assert args.desktop_command == "presentation-get"
    assert args.json is True


@pytest.mark.parametrize("revision", [None, True, False, 0.0, -1, "0", 2**53])
def test_presentation_revision_rejects_non_wire_integers(tmp_path: Path, revision: object) -> None:
    with pytest.raises(ValueError, match="non-negative safe integer"):
        update_guard_settings(
            tmp_path / "guard",
            {"presentation_mode": "technical", "presentation_revision": revision},
            skip_approval_gate=True,
        )
    assert load_guard_config(tmp_path / "guard").presentation_mode == "everyday"


@pytest.mark.parametrize("version", [True, 1.0, "1", None, 2])
def test_presentation_schema_rejects_non_exact_versions(tmp_path: Path, version: object) -> None:
    with pytest.raises(ValueError, match="Unsupported presentation schema"):
        update_guard_settings(
            tmp_path / "guard",
            {"presentation_mode": "technical", "presentation_schema_version": version},
            skip_approval_gate=True,
        )


def test_settings_lock_is_released_after_validation_failure(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="failed write"), settings_write_lock(tmp_path):
        raise ValueError("failed write")
    with settings_write_lock(tmp_path):
        assert (tmp_path / ".settings-write.lock").is_file()


def test_settings_lock_timeout_never_runs_the_writer(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def busy(_handle):
        raise BlockingIOError(errno.EAGAIN, "busy")

    monkeypatch.setattr(lock_module, "acquire_file_lock", busy)
    monkeypatch.setattr(lock_module, "_LOCK_TIMEOUT_SECONDS", 0.0)
    with pytest.raises(ValueError, match="still saving"), settings_write_lock(tmp_path):
        pytest.fail("a busy lock must not allow a write")


@pytest.mark.skipif(os.name == "nt", reason="POSIX link and mode validation")
def test_settings_lock_rejects_symlink_and_public_lock(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.write_bytes(b"unchanged")
    lock = tmp_path / ".settings-write.lock"
    lock.symlink_to(target)
    with pytest.raises((OSError, ValueError)), settings_write_lock(tmp_path):
        pytest.fail("a symlink lock must not allow a write")
    assert target.read_bytes() == b"unchanged"
    lock.unlink()
    lock.write_bytes(b"0")
    lock.chmod(0o644)
    with pytest.raises(ValueError, match="private regular file"), settings_write_lock(tmp_path):
        pytest.fail("a public lock must not allow a write")


def test_atomic_config_replace_failure_preserves_the_old_snapshot(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "config.toml"
    path.write_text('presentation_mode = "everyday"\n')
    previous = path.read_bytes()

    def fail_replace(_source, _destination):
        raise OSError("simulated replacement failure")

    monkeypatch.setattr(lock_module.os, "replace", fail_replace)
    with pytest.raises(OSError, match="replacement failure"):
        atomic_write_settings(path, 'presentation_mode = "technical"\n')
    assert path.read_bytes() == previous
    assert not list(tmp_path.glob(".config-*"))


def test_exhausted_presentation_revision_never_writes_an_unreadable_wire_value(tmp_path: Path) -> None:
    path = tmp_path / "config.toml"
    path.write_text(
        'presentation_mode = "everyday"\npresentation_mode_explicit = true\npresentation_revision = 9007199254740991\n'
    )
    before = path.read_bytes()
    with pytest.raises(ValueError, match="revision is exhausted"):
        update_guard_settings(
            tmp_path, {"presentation_mode": "technical", "presentation_revision": 2**53 - 1}, skip_approval_gate=True
        )
    assert path.read_bytes() == before


def test_unsupported_presentation_schema_rejects_an_actual_mode_change(tmp_path: Path) -> None:
    path = tmp_path / "config.toml"
    path.write_text('presentation_mode = "everyday"\npresentation_schema_version = 2\n')
    before = path.read_bytes()
    with pytest.raises(ValueError, match="newer schema"):
        update_guard_settings(
            tmp_path, {"presentation_mode": "technical", "presentation_mode_explicit": True}, skip_approval_gate=True
        )
    assert path.read_bytes() == before
