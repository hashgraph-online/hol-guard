"""Tests for skill:// URI handling in target_is_known_skill_doc_path."""

from codex_plugin_scanner.guard.runtime.false_positive_rules import (
    target_is_known_skill_doc_path,
)
from codex_plugin_scanner.guard.runtime.secret_file_requests import (
    is_explicitly_benign_native_file_read_request,
)
from codex_plugin_scanner.guard.runtime.source_paths import source_path_is_allowed


def test_skill_uri_existing(tmp_path):
    home = tmp_path / "home"
    skills_root = home / ".claude" / "skills"
    skills_root.mkdir(parents=True)
    real_skill = tmp_path / "guard-dev-testing"
    real_skill.mkdir()
    (real_skill / "SKILL.md").write_text("---\nname: guard-dev-testing\n---\n")
    (skills_root / "guard-dev-testing").symlink_to(real_skill, target_is_directory=True)

    assert target_is_known_skill_doc_path("skill://guard-dev-testing", home_dir=home) is True


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


def test_resolved_claude_skill_path(tmp_path):
    """Filesystem path to a symlinked skill dir is blocked by the symlink check.

    The skill:// URI path is the correct way to read skills — it uses realpath
    containment. Direct filesystem paths go through the stricter symlink check.
    """
    home = tmp_path / "home"
    skills_root = home / ".claude" / "skills"
    skills_root.mkdir(parents=True)
    real_skill = tmp_path / "guard-dev-testing"
    real_skill.mkdir()
    (real_skill / "SKILL.md").write_text("---\nname: guard-dev-testing\n---\n")
    (skills_root / "guard-dev-testing").symlink_to(real_skill, target_is_directory=True)

    assert target_is_known_skill_doc_path("~/.claude/skills/guard-dev-testing", home_dir=home) is False


def test_resolved_skill_md_path(tmp_path):
    """The exact skill document may use a harness-managed directory link."""
    home = tmp_path / "home"
    skills_root = home / ".claude" / "skills"
    skills_root.mkdir(parents=True)
    real_skill = tmp_path / "guard-dev-testing"
    real_skill.mkdir()
    (real_skill / "SKILL.md").write_text("---\nname: guard-dev-testing\n---\n")
    (skills_root / "guard-dev-testing").symlink_to(real_skill, target_is_directory=True)

    assert target_is_known_skill_doc_path("~/.claude/skills/guard-dev-testing/SKILL.md", home_dir=home) is True


def test_native_read_allows_one_existing_workspace_source(tmp_path):
    workspace = tmp_path / "workspace"
    source = workspace / "src" / "service.py"
    source.parent.mkdir(parents=True)
    source.write_text("value = 1\n")

    assert is_explicitly_benign_native_file_read_request(
        "Read",
        {"file_path": str(source)},
        cwd=workspace,
        home_dir=tmp_path,
    )


def test_native_read_allows_exact_symlinked_skill_document(tmp_path):
    home = tmp_path / "home"
    skills_root = home / ".claude" / "skills"
    skills_root.mkdir(parents=True)
    real_skill = tmp_path / "guard-dev-testing"
    real_skill.mkdir()
    skill_doc = real_skill / "SKILL.md"
    skill_doc.write_text("# Test skill\n")
    linked_skill = skills_root / "guard-dev-testing"
    linked_skill.symlink_to(real_skill, target_is_directory=True)

    assert is_explicitly_benign_native_file_read_request(
        "Read",
        {"file_path": str(linked_skill / "SKILL.md")},
        cwd=tmp_path / "workspace",
        home_dir=home,
    )


def test_native_read_rejects_ambiguous_missing_and_sensitive_targets(tmp_path):
    workspace = tmp_path / "workspace"
    source = workspace / "src" / "service.py"
    source.parent.mkdir(parents=True)
    source.write_text("value = 1\n")
    sensitive = workspace / ".env"
    sensitive.write_text("SECRET=value\n")

    assert not is_explicitly_benign_native_file_read_request(
        "Read",
        {"paths": [str(source), str(sensitive)]},
        cwd=workspace,
        home_dir=tmp_path,
    )
    assert not is_explicitly_benign_native_file_read_request(
        "Read",
        {"file_path": str(workspace / "src" / "missing.py")},
        cwd=workspace,
        home_dir=tmp_path,
    )
    assert not is_explicitly_benign_native_file_read_request(
        "Read",
        {"file_path": str(sensitive)},
        cwd=workspace,
        home_dir=tmp_path,
    )
    assert not is_explicitly_benign_native_file_read_request(
        "Write",
        {"file_path": str(source)},
        cwd=workspace,
        home_dir=tmp_path,
    )
    assert not is_explicitly_benign_native_file_read_request(
        "Read",
        {"metadata": [str(source)], "target": str(sensitive)},
        cwd=workspace,
        home_dir=tmp_path,
    )


def test_known_skill_paths_reject_sensitive_glob_and_traversal_targets(tmp_path):
    home = tmp_path / "home"
    skill = home / ".claude" / "skills" / "safe"
    skill.mkdir(parents=True)
    (skill / "SKILL.md").write_text("# Safe\n")
    (skill / ".env").write_text("SECRET=value\n")
    (skill / "notes.md").write_text("notes\n")

    for target in (
        "~/.claude/skills/safe/.env",
        "~/.claude/skills/safe/*.md",
        "~/.claude/skills/safe/../secret.py",
    ):
        decision = source_path_is_allowed(target, cwd=tmp_path / "workspace", home_dir=home)
        assert not decision.allowed


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
