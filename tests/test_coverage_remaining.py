"""Tests to reach 100% coverage on remaining branches."""

import tempfile
from pathlib import Path

FIXTURES = Path(__file__).parent / "fixtures"


def test_incomplete_frontmatter_delimiters():
    """Skill file with one --- but no second (incomplete frontmatter)."""
    from codex_plugin_scanner.checks.best_practices import check_skill_frontmatter

    with tempfile.TemporaryDirectory() as tmpdir:
        d = Path(tmpdir)
        manifest_dir = d / ".codex-plugin"
        manifest_dir.mkdir()
        (manifest_dir / "plugin.json").write_text('{"name":"t","version":"1.0.0","description":"t","skills":"skills"}')
        skills_dir = d / "skills" / "partial"
        skills_dir.mkdir(parents=True)
        (skills_dir / "SKILL.md").write_text("---\nname: test\nno second delimiter")
        r = check_skill_frontmatter(d)
        assert not r.passed


def test_frontmatter_missing_only_name():
    """Frontmatter has description: but not name:."""
    from codex_plugin_scanner.checks.best_practices import check_skill_frontmatter

    with tempfile.TemporaryDirectory() as tmpdir:
        d = Path(tmpdir)
        manifest_dir = d / ".codex-plugin"
        manifest_dir.mkdir()
        (manifest_dir / "plugin.json").write_text('{"name":"t","version":"1.0.0","description":"t","skills":"skills"}')
        skills_dir = d / "skills" / "partial"
        skills_dir.mkdir(parents=True)
        (skills_dir / "SKILL.md").write_text("---\ndescription: test\n---\ncontent")
        r = check_skill_frontmatter(d)
        assert not r.passed
        assert "partial" in r.message


def test_frontmatter_missing_only_description():
    """Frontmatter has name: but not description:."""
    from codex_plugin_scanner.checks.best_practices import check_skill_frontmatter

    with tempfile.TemporaryDirectory() as tmpdir:
        d = Path(tmpdir)
        manifest_dir = d / ".codex-plugin"
        manifest_dir.mkdir()
        (manifest_dir / "plugin.json").write_text('{"name":"t","version":"1.0.0","description":"t","skills":"skills"}')
        skills_dir = d / "skills" / "partial"
        skills_dir.mkdir(parents=True)
        (skills_dir / "SKILL.md").write_text("---\nname: test\n---\ncontent")
        r = check_skill_frontmatter(d)
        assert not r.passed


def test_secret_scan_excluded_dir():
    """File inside excluded dir should be skipped."""
    from codex_plugin_scanner.checks.security import check_no_hardcoded_secrets

    with tempfile.TemporaryDirectory() as tmpdir:
        d = Path(tmpdir)
        node_dir = d / "node_modules" / "pkg"
        node_dir.mkdir(parents=True)
        (node_dir / "secret.txt").write_text('password = "longsecretvalue12345"')
        r = check_no_hardcoded_secrets(d)
        assert r.passed


def test_secret_scan_binary_ext():
    """File with binary extension should be skipped."""
    from codex_plugin_scanner.checks.security import check_no_hardcoded_secrets

    with tempfile.TemporaryDirectory() as tmpdir:
        d = Path(tmpdir)
        (d / "image.png").write_bytes(b"password = longsecretvalue12345" + b"\x00" * 100)
        r = check_no_hardcoded_secrets(d)
        assert r.passed


def test_mit_license_branch():
    """Test the MIT license detection path (Apache not matched first)."""
    from codex_plugin_scanner.checks.security import check_license

    with tempfile.TemporaryDirectory() as tmpdir:
        d = Path(tmpdir)
        mit_text = """MIT License

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files.
"""
        (d / "LICENSE").write_text(mit_text)
        r = check_license(d)
        assert r.passed
        assert "MIT" in r.message


def test_cli_main_entrypoint():
    """Test the __main__ block path."""
    from codex_plugin_scanner.cli import main

    rc = main([str(FIXTURES / "good-plugin")])
    assert rc == 0


def test_main_output_to_file_and_json_together():
    """Test --output takes precedence (--json is implied)."""
    from codex_plugin_scanner.cli import main

    with tempfile.TemporaryDirectory() as tmpdir:
        out_file = Path(tmpdir) / "report.json"
        rc = main([str(FIXTURES / "good-plugin"), "--json", "--output", str(out_file)])
        assert rc == 0
        content = out_file.read_text()
        import json

        assert json.loads(content)["score"] == 100


def test_skills_field_empty_string():
    """Skills field is empty string."""
    from codex_plugin_scanner.checks.best_practices import check_skills_directory

    with tempfile.TemporaryDirectory() as tmpdir:
        d = Path(tmpdir)
        manifest_dir = d / ".codex-plugin"
        manifest_dir.mkdir()
        (manifest_dir / "plugin.json").write_text('{"name":"t","version":"1.0.0","description":"t","skills":""}')
        r = check_skills_directory(d)
        assert r.passed  # empty string is falsy, skips check


def test_skills_dir_exists_but_empty():
    """Skills dir exists but contains no SKILL.md files."""
    from codex_plugin_scanner.checks.best_practices import check_skill_frontmatter

    with tempfile.TemporaryDirectory() as tmpdir:
        d = Path(tmpdir)
        manifest_dir = d / ".codex-plugin"
        manifest_dir.mkdir()
        (manifest_dir / "plugin.json").write_text('{"name":"t","version":"1.0.0","description":"t","skills":"skills"}')
        (d / "skills").mkdir()  # empty skills dir
        r = check_skill_frontmatter(d)
        assert r.passed
        assert "No SKILL.md files found" in r.message
