from __future__ import annotations

import sys
import tempfile
from pathlib import Path

import pytest

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


@pytest.mark.skipif(sys.platform != "darwin", reason="Darwin temporary-path alias")
def test_trusted_temporary_root_accepts_resolved_private_tmp_path() -> None:
    with tempfile.TemporaryDirectory(dir="/tmp") as temp_dir:
        candidate = Path(temp_dir, "payload.json")
        _ = candidate.write_text("{}", encoding="utf-8")
        resolved = candidate.resolve()

        assert resolved.is_relative_to(Path("/private/tmp"))
        assert trusted_temporary_root_for_path(resolved) == Path("/private/tmp")


def test_trusted_temporary_root_rejects_symlink_escape(tmp_path: Path) -> None:
    candidate = tmp_path / "payload-link"
    candidate.symlink_to(Path.home(), target_is_directory=True)

    assert trusted_temporary_root_for_path(candidate) is None
