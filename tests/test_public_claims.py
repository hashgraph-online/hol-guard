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


def test_an_html_badge_line_is_not_prose_but_html_with_trailing_text_is():
    badge = '<a href="https://example.invalid"><img src="https://example.invalid/b.svg" alt="Badge" height="20"></a>'
    limit = "See the [matrix](docs/guard/harness-support.md).\n"
    bare = f"# Antivirus for agents\n\n{badge}\n\nFirst paragraph.\n\n{limit}"
    with_text = f"# Antivirus for agents\n\n{badge} Trailing words.\n\nFirst paragraph.\n\n{limit}"

    assert public_claims.check_markdown("synthetic.md", bare) == []
    assert len(public_claims.check_markdown("synthetic.md", with_text)) == 1


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
    unbounded = '[project]\nname = "x"\ndescription = "Open-source antivirus for AI agents."\n'
    single_quoted = "[project]\ndescription = 'Open-source antivirus for AI agents.'  # tagline\n"
    bounded = (
        '[project]\ndescription = "Open-source antivirus for AI agents. It does not cover actions outside its hooks."\n'
    )

    findings = public_claims.check_package_description("pyproject.toml", unbounded)

    assert [(finding.line, finding.claim) for finding in findings] == [(3, "antivirus")]
    assert [f.claim for f in public_claims.check_package_description("pyproject.toml", single_quoted)] == ["antivirus"]
    assert public_claims.check_package_description("pyproject.toml", bounded) == []


def test_catalog_pages_and_nested_guides_are_public():
    pages = {page.relative_to(REPO_ROOT).as_posix() for page in public_claims.public_markdown(REPO_ROOT)}

    assert "docs/guard/catalog-discovery-preparation.md" in pages
    assert "docs/guard/extensions/README.md" in pages
    assert public_claims.WORKING_DOCUMENT.search("release-log")
    assert not public_claims.WORKING_DOCUMENT.search("catalog-discovery-preparation")
    assert not any(page.startswith(("docs/guard/adr/", "docs/guard/audits/")) for page in pages)


def test_a_heading_claim_cannot_borrow_a_limit_from_a_sibling_section():
    sibling = (
        "## Antivirus for agents\n\nIt reviews actions.\n\n## Other topic\n\nIt does not cover background sessions.\n"
    )
    child = "## Antivirus for agents\n\n### Limits\n\nIt does not cover background sessions.\n"

    assert [f.claim for f in public_claims.check_markdown("synthetic.md", sibling)] == ["Antivirus"]
    assert public_claims.check_markdown("synthetic.md", child) == []


def test_html_comments_neither_claim_nor_bound():
    hidden_limit = "Guard gives complete protection.\n<!-- limitations -->\n"
    hidden_claim = "<!-- antivirus -->\n\nGuard reviews actions.\n"

    assert [f.claim for f in public_claims.check_markdown("synthetic.md", hidden_limit)] == ["complete protection"]
    assert public_claims.check_markdown("synthetic.md", hidden_claim) == []


def test_an_unrelated_negation_does_not_hide_a_claim():
    text = "Guard needs no account and provides complete protection.\n"

    assert [f.claim for f in public_claims.check_markdown("synthetic.md", text)] == ["complete protection"]


def test_a_claim_wrapped_across_lines_is_still_a_claim():
    text = "Intro.\n\nGuard provides complete\nprotection for agents.\n"

    findings = public_claims.check_markdown("synthetic.md", text)

    assert [(finding.line, finding.claim) for finding in findings] == [(3, "complete\nprotection")]


def test_denying_a_limit_is_not_a_limit():
    markdown = "Guard provides full protection with no blind spots.\n\nIt has no known limitations.\n"
    description = '[project]\ndescription = "Open-source antivirus for AI agents, without limitations."\n'

    assert [f.claim for f in public_claims.check_markdown("synthetic.md", markdown)] == ["full protection"]
    assert [f.claim for f in public_claims.check_package_description("pyproject.toml", description)] == ["antivirus"]


def test_a_negation_must_govern_the_claim():
    markdown = "Guard needs no setup for complete protection.\n"
    description = '[project]\ndescription = "Needs no setup for complete protection."\n'

    assert [f.claim for f in public_claims.check_markdown("synthetic.md", markdown)] == ["complete protection"]
    assert [f.claim for f in public_claims.check_package_description("pyproject.toml", description)] == [
        "complete protection"
    ]


def test_a_shorter_fence_inside_a_longer_one_does_not_close_it():
    text = "````markdown\n```\nuniversal protection\n````\n\nGuard provides complete protection.\n"

    findings = public_claims.check_markdown("synthetic.md", text)

    assert [(finding.line, finding.claim) for finding in findings] == [(6, "complete protection")]


def test_a_negation_wrapped_onto_the_previous_line_still_governs_the_claim():
    text = "Guard does not\nprovide complete protection.\n"

    assert public_claims.check_markdown("synthetic.md", text) == []


def test_a_limit_wrapped_across_lines_still_bounds_the_claim():
    text = "Guard offers complete protection for shell tools. It does\nnot cover hosted agents.\n"

    assert public_claims.check_markdown("synthetic.md", text) == []


def test_a_list_item_ends_the_sentence_a_negation_sits_in():
    text = "Guard does not\n- complete protection\n"

    assert [f.claim for f in public_claims.check_markdown("synthetic.md", text)] == ["complete protection"]


def test_a_negation_wrapped_inside_a_blockquote_still_governs_the_claim():
    text = "> Guard does not\n> provide complete protection.\n"

    assert public_claims.check_markdown("synthetic.md", text) == []


def test_agent_skill_text_and_the_answers_page_are_public():
    pages = {page.relative_to(REPO_ROOT).as_posix() for page in public_claims.public_markdown(REPO_ROOT)}
    assert {
        "HOL_GUARD_ANSWERS.md",
        ".factory/skills/hol-guard/SKILL.md",
        ".factory/droids/hol-guard-runner.md",
    } <= pages
