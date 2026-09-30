"""The one-time baseline converter cannot overwrite unrelated or edited work."""

from __future__ import annotations

import runpy
from pathlib import Path

import pytest

TOOL = runpy.run_path(str(Path(__file__).parents[1] / "scripts/migrate_command_extension_sources.py"))


def test_migration_publication_is_idempotent_and_preserves_modified_files(tmp_path: Path) -> None:
    output = tmp_path / "output"
    files = {"command.example.json": b'{"source":true}\n'}
    TOOL["publish"](output, files, {"baseline": "reviewed"})
    before = {path.name: (path.read_bytes(), path.stat().st_mtime_ns) for path in output.iterdir()}
    TOOL["publish"](output, files, {"baseline": "reviewed"})
    assert {path.name: (path.read_bytes(), path.stat().st_mtime_ns) for path in output.iterdir()} == before
    (output / "command.example.json").write_bytes(b"user edit")
    with pytest.raises(ValueError, match="modified output"):
        TOOL["publish"](output, files, {"baseline": "reviewed"})
    assert (output / "command.example.json").read_bytes() == b"user edit"


def test_migration_refuses_unowned_files_symlinks_and_escaping_names(tmp_path: Path) -> None:
    output = tmp_path / "output"
    output.mkdir()
    unrelated = output / "notes.txt"
    unrelated.write_text("preserve")
    with pytest.raises(ValueError, match="unrelated"):
        TOOL["publish"](output, {"command.example.json": b"{}"}, {})
    assert list(output.iterdir()) == [unrelated]
    link = tmp_path / "link"
    link.symlink_to(output, target_is_directory=True)
    with pytest.raises(ValueError, match="symlink"):
        TOOL["publish"](link, {"command.example.json": b"{}"}, {})
    with pytest.raises(ValueError, match="unsafe output name"):
        TOOL["publish"](tmp_path / "fresh", {"../escape.json": b"{}"}, {})
    assert not (tmp_path / "escape.json").exists()


def test_failed_publication_rolls_back_only_files_created_by_this_call(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original_open = Path.open

    def fail_second(path: Path, *args: object, **kwargs: object):
        if path.name == "command.second.json":
            raise OSError("simulated disk failure")
        return original_open(path, *args, **kwargs)

    monkeypatch.setattr(Path, "open", fail_second)
    output = tmp_path / "output"
    with pytest.raises(OSError, match="disk failure"):
        TOOL["publish"](output, {"command.first.json": b"{}", "command.second.json": b"{}"}, {})
    assert list(output.iterdir()) == []


def test_baseline_identity_and_duplicate_json_are_checked_before_conversion(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="identity mismatch"):
        TOOL["convert"]({"identity": {"program_digest": "expected"}}, {"program_digest": "other"}, {}, {})
    path = tmp_path / "duplicate.json"
    path.write_text('{"catalog":[],"catalog":[]}')
    with pytest.raises(ValueError, match="duplicate JSON key"):
        TOOL["load"](path)
