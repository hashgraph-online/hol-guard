"""Races must not turn a checked file into an unbounded or foreign input."""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.secrets import secret_repository_scanner as repository
from codex_plugin_scanner.guard.secrets.cli import main as secrets_main
from codex_plugin_scanner.path_support import FileChangedDuringReadError, read_bytes_file_within_root


def mutate_before_open(monkeypatch, victim, mutation):
    """Intervene at either binary-open API, after its caller's path checks."""
    original_path_open, original_os_open = Path.open, os.open
    triggered = []

    def mutate(path, readable):
        if isinstance(path, (str, Path)) and Path(path) == victim and readable and not triggered:
            triggered.append(True)
            mutation()

    def path_open(path, *args, **kwargs):
        mutate(path, kwargs.get("mode", args[0] if args else "r") == "rb")
        return original_path_open(path, *args, **kwargs)

    def os_open(path, flags, *args, **kwargs):
        mutate(path, flags & os.O_ACCMODE == os.O_RDONLY)
        return original_os_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(Path, "open", path_open)
    monkeypatch.setattr(os, "open", os_open)
    return triggered


@pytest.mark.parametrize("mutation", ["symlink", "replacement", "growth"])
def test_checked_file_mutation_is_explicitly_incomplete(monkeypatch, tmp_path, mutation):
    root = tmp_path / "repository"
    root.mkdir()
    victim = root / "input.ts"
    victim.write_bytes(b"initial")
    outside = tmp_path / "outside.ts"
    outside.write_bytes(b"outside-owned-test-fixture")

    def change():
        if mutation == "growth":
            victim.write_bytes(b"X" * 128)
        else:
            victim.unlink()
            if mutation == "symlink":
                victim.symlink_to(outside)
            else:
                victim.write_bytes(b"replacement")

    triggered = mutate_before_open(monkeypatch, victim, change)
    result = repository.scan_repository_secrets(root, max_file_bytes=32)
    assert triggered == [True]
    assert result.truncated and result.errors == ("working_tree_file_changed",)
    assert result.files_scanned == result.bytes_scanned == 0
    assert result.findings == ()


def test_changed_input_cli_exits_two_and_preserves_other_findings(monkeypatch, tmp_path, capsys):
    victim = tmp_path / "a-changed.ts"
    victim.write_bytes(b"initial")
    token = "ghp_" + "7tH3mZ5qP9vC2xL4nR6sB8wF1jK0dE5uA7iY"
    (tmp_path / "b-observed.ts").write_text(f'GITHUB_TOKEN="{token}"\n')
    triggered = mutate_before_open(monkeypatch, victim, lambda: victim.write_bytes(b"X" * 2048))
    exit_code = secrets_main(["scan", str(tmp_path), "--json", "--max-file-bytes", "1024", "--fail-on-findings"])
    captured = capsys.readouterr()
    public = json.loads(captured.out)
    assert triggered == [True]
    assert exit_code == 2
    assert public["truncated"] and public["errors"] == ["working_tree_file_changed"]
    assert public["finding_count"] == 1 and public["files_scanned"] == 1
    assert token not in captured.out + captured.err


@pytest.mark.parametrize("mutation", ["same-size-content", "growth", "path-replacement"])
def test_mutation_during_descriptor_read_is_rejected(monkeypatch, tmp_path, mutation):
    victim = tmp_path / "input.ts"
    victim.write_bytes(b"initial")
    original_fdopen = os.fdopen
    triggered, observed_fds = [], []

    class MutatingReader:
        def __init__(self, handle):
            self.handle = handle

        def __enter__(self):
            self.handle.__enter__()
            return self

        def __exit__(self, *args):
            return self.handle.__exit__(*args)

        def read(self, limit):
            triggered.append(True)
            if mutation == "path-replacement":
                victim.unlink()
                victim.write_bytes(b"changed")
            elif mutation == "growth":
                victim.write_bytes(b"X" * 128)
            else:
                victim.write_bytes(b"changed")
            return self.handle.read(limit)

    def fdopen(fd, *args, **kwargs):
        observed_fds.append(fd)
        return MutatingReader(original_fdopen(fd, *args, **kwargs))

    monkeypatch.setattr(os, "fdopen", fdopen)
    with pytest.raises(FileChangedDuringReadError):
        read_bytes_file_within_root(tmp_path, victim, max_bytes=32)
    assert triggered == [True]
    assert len(observed_fds) == 1
    with pytest.raises(OSError):
        os.fstat(observed_fds[0])


def test_stable_boundaries_and_hardlinks_remain_readable(tmp_path):
    victim = tmp_path / "input.ts"
    victim.write_bytes(b"A" * 32)
    alias = tmp_path / "alias.ts"
    os.link(victim, alias)
    assert read_bytes_file_within_root(tmp_path, victim, max_bytes=32) == b"A" * 32
    assert read_bytes_file_within_root(tmp_path, alias, max_bytes=32) == b"A" * 32
    with pytest.raises(OSError, match="exceeds"):
        read_bytes_file_within_root(tmp_path, victim, max_bytes=31)
    victim.write_bytes(b"")
    assert read_bytes_file_within_root(tmp_path, victim, max_bytes=32) == b""
