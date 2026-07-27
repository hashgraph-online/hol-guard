from __future__ import annotations

from pathlib import Path

from codex_plugin_scanner.guard.runtime.local_temp_paths import trusted_temporary_root_for_path


def test_trusted_temporary_root_accepts_regular_temp_path(tmp_path: Path) -> None:
    candidate = tmp_path / "payload.json"
    _ = candidate.write_text("{}", encoding="utf-8")

    root = trusted_temporary_root_for_path(candidate)

    assert root is not None
    assert candidate.resolve().is_relative_to(root)


def test_trusted_temporary_root_rejects_parent_traversal(tmp_path: Path) -> None:
    nested = tmp_path / "nested"
    nested.mkdir()
    candidate = nested / ".." / "payload.json"
    _ = (tmp_path / "payload.json").write_text("{}", encoding="utf-8")

    assert trusted_temporary_root_for_path(candidate) is None


def test_trusted_temporary_root_rejects_relative_path() -> None:
    assert trusted_temporary_root_for_path(Path("payload.json")) is None


def test_trusted_temporary_root_rejects_symlink_escape(tmp_path: Path) -> None:
    candidate = tmp_path / "payload-link"
    candidate.symlink_to(Path.home(), target_is_directory=True)

    assert trusted_temporary_root_for_path(candidate) is None
