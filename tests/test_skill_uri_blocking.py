"""Tests for skill:// URI handling in target_is_known_skill_doc_path."""

from codex_plugin_scanner.guard.runtime.false_positive_rules import (
    target_is_known_skill_doc_path,
)


def test_skill_uri_existing():
    assert target_is_known_skill_doc_path("skill://guard-dev-testing") is True


def test_skill_uri_nonexistent():
    assert target_is_known_skill_doc_path("skill://nonexistent-skill-xyz") is False


def test_skill_uri_empty():
    assert target_is_known_skill_doc_path("skill://") is False


def test_skill_uri_path_traversal():
    assert target_is_known_skill_doc_path("skill://../../etc/passwd") is False


def test_skill_uri_parent_dir():
    assert target_is_known_skill_doc_path("skill://..") is False


def test_skill_uri_dot():
    assert target_is_known_skill_doc_path("skill://.") is False


def test_resolved_claude_skill_path():
    """Filesystem path to a symlinked skill dir is blocked by the symlink check.

    The skill:// URI path is the correct way to read skills — it uses realpath
    containment. Direct filesystem paths go through the stricter symlink check.
    """
    assert target_is_known_skill_doc_path("~/.claude/skills/guard-dev-testing") is False


def test_resolved_skill_md_path():
    """Filesystem path through a symlinked skill dir is also blocked."""
    assert target_is_known_skill_doc_path("~/.claude/skills/guard-dev-testing/SKILL.md") is False


def test_skill_uri_absolute_path():
    """skill:///etc/passwd must be rejected."""
    assert target_is_known_skill_doc_path("skill:///etc/passwd") is False


def test_skill_uri_root():
    """skill:/// must be rejected."""
    assert target_is_known_skill_doc_path("skill:///") is False


def test_skill_uri_nonexistent_skill():
    """A directory without SKILL.md must not be accepted."""
    assert target_is_known_skill_doc_path("skill://nonexistent-skill-xyz") is False


def test_skill_uri_skill_md_symlink_escape(tmp_path):
    """SKILL.md symlinked to a file outside the skill dir must be rejected."""
    home = tmp_path / "home"
    skills_root = home / ".claude" / "skills" / "evil-skill"
    skills_root.mkdir(parents=True)
    secret_file = tmp_path / "secret.txt"
    secret_file.write_text("SECRET=abc123\n")
    # SKILL.md is a symlink pointing outside the skill dir
    (skills_root / "SKILL.md").symlink_to(secret_file)
    assert target_is_known_skill_doc_path("skill://evil-skill", home_dir=home) is False


def test_skill_uri_symlinked_dir_without_skill_md(tmp_path):
    """A symlinked directory without SKILL.md must not be accepted."""
    home = tmp_path / "home"
    skills_root = home / ".claude" / "skills"
    skills_root.mkdir(parents=True)
    target_dir = tmp_path / "some-dir"
    target_dir.mkdir()
    (skills_root / "link").symlink_to(target_dir, target_is_directory=True)
    assert target_is_known_skill_doc_path("skill://link", home_dir=home) is False


def test_skill_uri_legitimate_symlinked_dir(tmp_path):
    """A symlinked skill dir with a real SKILL.md inside should pass."""
    home = tmp_path / "home"
    skills_root = home / ".claude" / "skills"
    skills_root.mkdir(parents=True)
    real_skill = tmp_path / "real-skill"
    real_skill.mkdir()
    (real_skill / "SKILL.md").write_text("---\nname: test\n---\n")
    (skills_root / "link").symlink_to(real_skill, target_is_directory=True)
    assert target_is_known_skill_doc_path("skill://link", home_dir=home) is True


def test_non_skill_path():
    assert target_is_known_skill_doc_path("/etc/passwd") is False


def test_codex_skills_root():
    assert target_is_known_skill_doc_path("~/.codex/skills") is True


def test_agents_skills_root():
    assert target_is_known_skill_doc_path("~/.agents/skills") is True
