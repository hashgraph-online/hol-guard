"""Tests for best practices checks."""

import tempfile
from pathlib import Path

from codex_plugin_scanner.checks.best_practices import (
    check_codexignore,
    check_no_env_files,
    check_readme,
    check_skill_frontmatter,
    check_skills_directory,
    run_best_practice_checks,
)

FIXTURES = Path(__file__).parent / "fixtures"


class TestCheckReadme:
    def test_passes_when_found(self):
        r = check_readme(FIXTURES / "good-plugin")
        assert r.passed and r.points == 3

    def test_fails_when_missing(self):
        r = check_readme(FIXTURES / "minimal-plugin")
        assert not r.passed and r.points == 0


class TestCheckSkillsDirectory:
    def test_passes_when_exists(self):
        r = check_skills_directory(FIXTURES / "good-plugin")
        assert r.passed and r.points == 3

    def test_passes_when_no_skills_field(self):
        r = check_skills_directory(FIXTURES / "minimal-plugin")
        assert r.passed and r.points == 0
        assert not r.applicable

    def test_fails_when_declared_but_missing(self):
        r = check_skills_directory(FIXTURES / "skills-missing-dir")
        assert not r.passed and r.points == 0
        assert "nonexistent-skills" in r.message

    def test_passes_when_manifest_unreadable(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            r = check_skills_directory(Path(tmpdir))
            assert r.passed and r.points == 0
            assert not r.applicable


class TestCheckSkillFrontmatter:
    def test_passes_with_valid_frontmatter(self):
        r = check_skill_frontmatter(FIXTURES / "good-plugin")
        assert r.passed and r.points == 3

    def test_passes_when_no_skills_field(self):
        r = check_skill_frontmatter(FIXTURES / "minimal-plugin")
        assert r.passed and r.points == 0
        assert not r.applicable

    def test_fails_with_missing_frontmatter(self):
        r = check_skill_frontmatter(FIXTURES / "skills-no-frontmatter")
        assert not r.passed and r.points == 0

    def test_passes_when_skills_dir_missing(self):
        r = check_skill_frontmatter(FIXTURES / "skills-missing-dir")
        assert r.passed and r.points == 0
        assert not r.applicable


class TestCheckNoEnvFiles:
    def test_passes_when_clean(self):
        r = check_no_env_files(FIXTURES / "good-plugin")
        assert r.passed and r.points == 3

    def test_fails_when_env_found(self):
        r = check_no_env_files(FIXTURES / "bad-plugin")
        assert not r.passed and r.points == 0


class TestCheckCodexignore:
    def test_passes_when_found(self):
        r = check_codexignore(FIXTURES / "good-plugin")
        assert r.passed and r.points == 3

    def test_fails_when_missing(self):
        r = check_codexignore(FIXTURES / "minimal-plugin")
        assert not r.passed and r.points == 0


class TestRunBestPracticeChecks:
    def test_good_plugin_gets_15(self):
        results = run_best_practice_checks(FIXTURES / "good-plugin")
        assert sum(c.points for c in results) == 15
        assert sum(c.max_points for c in results) == 15

    def test_minimal_plugin_gets_3(self):
        results = run_best_practice_checks(FIXTURES / "minimal-plugin")
        assert sum(c.points for c in results) == 3
        assert sum(c.max_points for c in results) == 9

    def test_bad_plugin_gets_0(self):
        results = run_best_practice_checks(FIXTURES / "bad-plugin")
        assert sum(c.points for c in results) == 0
        assert sum(c.max_points for c in results) == 9

    def test_returns_tuple_of_correct_length(self):
        results = run_best_practice_checks(FIXTURES / "good-plugin")
        assert isinstance(results, tuple)
        assert len(results) == 5
