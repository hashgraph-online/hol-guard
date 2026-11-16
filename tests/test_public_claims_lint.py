from __future__ import annotations

from pathlib import Path

from scripts.ci import public_claims_lint as gate

REPO_ROOT = Path(__file__).resolve().parents[1]


def test_repository_public_claims_are_bounded() -> None:
    assert gate.run(REPO_ROOT) == []


def test_unbounded_antivirus_paragraph_is_reported() -> None:
    findings = gate.check_text("x.md", "Intro.\n\nGuard is antivirus for every AI agent.\n")
    assert [finding.line for finding in findings] == [3]


def test_limit_in_the_same_paragraph_bounds_the_claim() -> None:
    text = "Guard is antivirus for AI agents.\nIt only sees events a supported harness sends.\n"
    assert gate.check_text("x.md", text) == []


def test_limit_in_another_paragraph_does_not_bound_the_claim() -> None:
    text = "Guard is universal protection.\n\nIt does not scan files.\n"
    assert [finding.line for finding in gate.check_text("x.md", text)] == [1]


def test_table_row_needs_its_own_limit() -> None:
    text = "| Claim | Note |\n| --- | --- |\n| Universal coverage | yes |\n| Other | not covered |\n"
    assert [finding.line for finding in gate.check_text("x.md", text)] == [3]


def test_heading_is_bounded_by_its_section() -> None:
    bounded = "# Guard: Antivirus for AI Agents\n\nIt only sees hook events.\n"
    unbounded = "# Guard: Antivirus for AI Agents\n\nIt is great.\n\n## Next\n\nIt does not scan files.\n"
    assert gate.check_text("x.md", bounded) == []
    assert [finding.line for finding in gate.check_text("x.md", unbounded)] == [1]


def test_packaging_terms_are_not_claims() -> None:
    text = "| Wheel | universal wheel (py3-none-any) |\n\nBuild a universal2 binary.\n"
    assert gate.check_text("x.md", text) == []


def test_fenced_code_is_ignored() -> None:
    assert gate.check_text("x.md", "```\necho universal antivirus\n```\n") == []


def test_missing_listed_file_fails(tmp_path: Path) -> None:
    problems = gate.run(tmp_path)
    assert any("README.md: listed public claim file is missing" in problem for problem in problems)
