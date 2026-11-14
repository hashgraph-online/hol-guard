from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
_SPEC = importlib.util.spec_from_file_location("check_public_claims", REPO_ROOT / "scripts/check_public_claims.py")
assert _SPEC is not None and _SPEC.loader is not None
public_claims = importlib.util.module_from_spec(_SPEC)
sys.modules[_SPEC.name] = public_claims
_SPEC.loader.exec_module(public_claims)


def test_the_repository_bounds_every_broad_protection_claim():
    assert [str(finding) for finding in public_claims.check_repository(REPO_ROOT)] == []


def test_the_public_pages_include_the_readme_and_skip_working_documents():
    pages = {page.relative_to(REPO_ROOT).as_posix() for page in public_claims.public_markdown(REPO_ROOT)}

    assert "README.md" in pages
    assert "docs/guard/harness-support.md" in pages
    assert not any(public_claims.WORKING_DOCUMENT.search(Path(page).stem) for page in pages if page != "README.md")


def test_an_unbounded_antivirus_headline_is_reported():
    text = "# Synthetic: Antivirus for AI Agents\n\nIt reviews actions.\n\nIt blocks risky commands.\n"

    findings = public_claims.check_markdown("synthetic.md", text)

    assert [(finding.line, finding.claim) for finding in findings] == [(1, "Antivirus")]


def test_a_limit_in_the_claim_paragraph_bounds_it():
    text = "Guard is antivirus for agents. It does not cover actions outside its hooks.\n"

    assert public_claims.check_markdown("synthetic.md", text) == []


def test_a_limit_two_prose_paragraphs_later_bounds_a_headline_but_not_three():
    head = "# Antivirus for agents\n\n[![Badge](https://example.invalid/b.svg)](https://example.invalid)\n\n"
    limit = "See the [matrix](docs/guard/harness-support.md).\n"
    bounded = f"{head}First paragraph.\n\n{limit}"
    too_far = f"{head}First.\n\nSecond.\n\n{limit}"

    assert public_claims.check_markdown("synthetic.md", bounded) == []
    assert len(public_claims.check_markdown("synthetic.md", too_far)) == 1


def test_a_limit_in_the_next_section_does_not_bound_a_claim():
    text = "## One\n\nGuard gives complete protection.\n\n## Two\n\nIt does not cover background sessions.\n"

    findings = public_claims.check_markdown("synthetic.md", text)

    assert [(finding.line, finding.claim) for finding in findings] == [(3, "complete protection")]


def test_negated_and_fenced_claims_are_not_claims():
    text = (
        "Guard does not claim universal prevention of social engineering.\n\n"
        "Never disable antivirus for a release gate.\n\n"
        "```text\nuniversal protection\n```\n"
    )

    assert public_claims.check_markdown("synthetic.md", text) == []


def test_the_package_description_must_carry_its_own_limit():
    unbounded = 'name = "x"\ndescription = "Open-source antivirus for AI agents."\n'
    bounded = 'description = "Open-source antivirus for AI agents. It does not cover actions outside its hooks."\n'

    findings = public_claims.check_package_description("pyproject.toml", unbounded)

    assert [(finding.line, finding.claim) for finding in findings] == [(2, "antivirus")]
    assert public_claims.check_package_description("pyproject.toml", bounded) == []
