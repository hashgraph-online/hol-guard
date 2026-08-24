"""Regression tests for scanner false positives reported by downstream users."""

import tempfile
from pathlib import Path

from codex_plugin_scanner.checks.security import check_no_hardcoded_secrets


def test_openai_secret_prefix_does_not_match_inside_hyphenated_identifier():
    with tempfile.TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        (root / "state.ts").write_text(
            "const marker = 'task-base-untracked-guard';\n",
            encoding="utf-8",
        )

        result = check_no_hardcoded_secrets(root)

        assert result.passed is True
        assert result.points == 7


def test_openai_secret_prefix_still_detects_a_standalone_token():
    with tempfile.TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        token = "".join(("sk-proj-", "A1b2C3d4", "E5f6G7h8", "I9j0K1l2"))
        (root / "config.ts").write_text(
            f"const apiKey = '{token}';\n",
            encoding="utf-8",
        )

        result = check_no_hardcoded_secrets(root)

        assert result.passed is False
        assert result.points == 0
        assert result.findings[0].file_path == "config.ts"
