"""Tests for submission artifact generation."""

from pathlib import Path

from codex_plugin_scanner.quality_artifact import _digest_plugin


def test_digest_plugin_ignores_internal_git_state(tmp_path: Path):
    (tmp_path / "plugin.json").write_text(
        '{"name":"demo-plugin","version":"1.0.0","description":"demo"}',
        encoding="utf-8",
    )
    (tmp_path / ".git").mkdir()
    (tmp_path / ".git" / "HEAD").write_text("ref: refs/heads/main\n", encoding="utf-8")

    first = _digest_plugin(tmp_path)

    (tmp_path / ".git" / "HEAD").write_text("ref: refs/heads/feature\n", encoding="utf-8")
    second = _digest_plugin(tmp_path)

    assert first["value"] == second["value"]
    assert first["included_files"] == 1
    assert second["included_files"] == 1
