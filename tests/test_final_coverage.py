"""Final coverage tests for remaining best_practices branches."""

import tempfile
from pathlib import Path
from unittest.mock import patch

FIXTURES = Path(__file__).parent / "fixtures"


def test_skill_frontmatter_empty_skills_dir():
    """Skills dir exists but contains no SKILL.md files (covers line 92)."""
    from codex_plugin_scanner.checks.best_practices import check_skill_frontmatter

    with tempfile.TemporaryDirectory() as tmpdir:
        d = Path(tmpdir)
        m = d / ".codex-plugin"
        m.mkdir()
        (m / "plugin.json").write_text('{"name":"t","version":"1.0.0","description":"t","skills":"skills"}')
        (d / "skills").mkdir()
        r = check_skill_frontmatter(d)
        assert r.passed
        assert "No SKILL.md files found" in r.message


def test_skill_frontmatter_oserror_in_loop():
    """OSError when reading SKILL.md inside the for loop (covers lines 104-105)."""
    from codex_plugin_scanner.checks.best_practices import check_skill_frontmatter

    with tempfile.TemporaryDirectory() as tmpdir:
        d = Path(tmpdir)
        m = d / ".codex-plugin"
        m.mkdir()
        (m / "plugin.json").write_text('{"name":"t","version":"1.0.0","description":"t","skills":"skills"}')
        s = d / "skills" / "bad"
        s.mkdir(parents=True)
        (s / "SKILL.md").write_text("---\nname: test\n---\ncontent")

        # First call to read_text (glob results) succeeds, second (file content) fails
        call_count = 0
        original_read_text = Path.read_text

        def mock_read_text(self, *args, **kwargs):
            nonlocal call_count
            call_count += 1
            # Let glob work normally but fail on SKILL.md read
            if self.name == "SKILL.md":
                raise OSError("mock permission denied")
            return original_read_text(self, *args, **kwargs)

        with patch.object(Path, "read_text", mock_read_text):
            r = check_skill_frontmatter(d)
            assert r.passed  # OSError is caught, file is skipped
