"""Regression coverage for plugin-scanner license filename detection."""

from pathlib import Path

import pytest

from codex_plugin_scanner.checks.security import check_license, run_security_checks
from codex_plugin_scanner.lint_fixes import apply_safe_autofixes

MIT_LICENSE = "MIT License\n\nPermission is hereby granted, free of charge, to any person.\n"


@pytest.mark.parametrize(
    "filename",
    ["LICENSE.md", "LICENSE.txt", "LICENSE.rst", "LICENCE.md", "COPYING", "license.md"],
)
def test_recognizes_common_root_license_filenames(tmp_path: Path, filename: str) -> None:
    (tmp_path / filename).write_text(MIT_LICENSE, encoding="utf-8")

    result = check_license(tmp_path)

    assert result.passed
    assert result.points == 3
    assert result.message == "LICENSE found (MIT)"
    assert not result.findings


def test_markdown_license_has_no_missing_finding_in_security_pipeline(tmp_path: Path) -> None:
    (tmp_path / "LICENSE.md").write_text(MIT_LICENSE, encoding="utf-8")

    results = run_security_checks(tmp_path)

    assert not any(f.rule_id == "LICENSE_MISSING" for result in results for f in result.findings)


@pytest.mark.parametrize("filename", ["LICENSE.template", "NOT_LICENSE.md", "docs/LICENSE.md"])
def test_does_not_accept_lookalikes_or_nested_license(tmp_path: Path, filename: str) -> None:
    candidate = tmp_path / filename
    candidate.parent.mkdir(parents=True, exist_ok=True)
    candidate.write_text(MIT_LICENSE, encoding="utf-8")

    result = check_license(tmp_path)

    assert not result.passed
    assert any(f.rule_id == "LICENSE_MISSING" for f in result.findings)


def test_does_not_accept_directory_as_license(tmp_path: Path) -> None:
    (tmp_path / "LICENSE.md").mkdir()

    result = check_license(tmp_path)

    assert not result.passed
    assert "could not be read" in result.message


def test_does_not_follow_markdown_license_symlink_outside_scan_root(tmp_path: Path) -> None:
    outside = tmp_path.parent / f"{tmp_path.name}-external-license"
    outside.write_text(MIT_LICENSE, encoding="utf-8")
    try:
        (tmp_path / "LICENSE.md").symlink_to(outside)
    except (NotImplementedError, OSError):
        pytest.skip("symlinks unavailable")

    result = check_license(tmp_path)

    assert not result.passed
    assert "could not be read" in result.message


def test_unreadable_canonical_license_does_not_fall_back_to_markdown(tmp_path: Path) -> None:
    outside = tmp_path.parent / f"{tmp_path.name}-external-license"
    outside.write_text(MIT_LICENSE, encoding="utf-8")
    try:
        (tmp_path / "LICENSE").symlink_to(outside)
    except (NotImplementedError, OSError):
        pytest.skip("symlinks unavailable")
    (tmp_path / "LICENSE.md").write_text(MIT_LICENSE, encoding="utf-8")

    result = check_license(tmp_path)

    assert not result.passed
    assert "could not be read" in result.message


@pytest.mark.parametrize("filename", ["LICENSE.md", "LICENCE.txt", "COPYING", "license.md"])
def test_autofix_does_not_create_conflicting_license(tmp_path: Path, filename: str) -> None:
    original = "Apache License, Version 2.0\n"
    (tmp_path / filename).write_text(original, encoding="utf-8")

    changes = apply_safe_autofixes(tmp_path)

    assert not (tmp_path / "LICENSE").exists()
    assert (tmp_path / filename).read_text(encoding="utf-8") == original
    assert "created LICENSE" not in changes


def test_autofix_still_creates_license_when_absent(tmp_path: Path) -> None:
    changes = apply_safe_autofixes(tmp_path)

    assert (tmp_path / "LICENSE").is_file()
    assert "created LICENSE" in changes


def test_autofix_does_not_treat_license_template_as_real_license(tmp_path: Path) -> None:
    (tmp_path / "LICENSE.template").write_text(MIT_LICENSE, encoding="utf-8")

    changes = apply_safe_autofixes(tmp_path)

    assert (tmp_path / "LICENSE").exists()
    assert "created LICENSE" in changes
