"""Pin what the plugin scanner finds on a synthetic evasion corpus.

Each case in ``fixtures/scanner-evasion-corpus/corpus.json`` is an inert skill
that tries one known evasion technique. The expected outcome is what the
scanner reports today, misses included, so a change in coverage fails here and
the corpus and its public summary are updated together.
"""

import json
from pathlib import Path

import pytest

from codex_plugin_scanner.models import ScanOptions, Severity
from codex_plugin_scanner.scanner import scan_plugin

PROJECT_ROOT = Path(__file__).resolve().parents[1]
CORPUS = PROJECT_ROOT / "tests" / "fixtures" / "scanner-evasion-corpus" / "corpus.json"
SUMMARY = PROJECT_ROOT / "docs" / "trust" / "scanner-evasion-corpus.md"
REPORTED = {Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM}
OUTCOMES = {"detected", "missed", "clean"}
# Findings that mean the scan did not finish. They must never count as a detection.
INCOMPLETE_ANALYSIS_RULES = {"SCAN_INPUT_UNREADABLE", "SCAN_RESOURCE_BUDGET_EXCEEDED"}

CORPUS_DATA = json.loads(CORPUS.read_text(encoding="utf-8"))
CASES = CORPUS_DATA["cases"]


def _materialize(case: dict, destination: Path) -> Path:
    if destination.resolve().is_relative_to(PROJECT_ROOT):
        raise ValueError("Corpus fixtures must be materialized outside the repository")
    (destination / ".codex-plugin").mkdir(parents=True)
    (destination / ".codex-plugin" / "plugin.json").write_text(
        json.dumps(
            {
                "name": "evasion-fixture",
                "version": "1.0.0",
                "description": "Synthetic scanner evasion fixture.",
                "skills": "./skills/",
            }
        ),
        encoding="utf-8",
    )
    for relative, content in case["files"].items():
        path = destination / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    return destination


def _outcome(case: dict, plugin_dir: Path) -> str:
    result = scan_plugin(plugin_dir, ScanOptions(cisco_skill_scan=CORPUS_DATA["scan"]["options"]["cisco_skill_scan"]))
    case_files = set(case["files"])
    findings = [finding for category in result.categories for check in category.checks for finding in check.findings]
    incomplete = sorted({finding.rule_id for finding in findings if finding.rule_id in INCOMPLETE_ANALYSIS_RULES})
    assert not incomplete, f"{case['id']}: scan did not complete ({', '.join(incomplete)})"
    flagged = any(finding.severity in REPORTED and finding.file_path in case_files for finding in findings)
    if case["expected"] == "clean":
        return "flagged" if flagged else "clean"
    return "detected" if flagged else "missed"


def test_corpus_cases_are_well_formed():
    ids = [case["id"] for case in CASES]
    assert len(ids) == len(set(ids))
    for case in CASES:
        assert case["expected"] in OUTCOMES
        assert case["files"], case["id"]
        for relative, content in case["files"].items():
            assert not Path(relative).is_absolute() and ".." not in Path(relative).parts
            assert "http" not in content or ".example" in content or ".invalid" in content, case["id"]


@pytest.mark.parametrize("case", CASES, ids=[case["id"] for case in CASES])
def test_scanner_outcome_matches_corpus(case, tmp_path):
    plugin_dir = _materialize(case, tmp_path / "plugin")
    assert _outcome(case, plugin_dir) == case["expected"]


def test_summary_lists_every_case_with_its_outcome():
    summary = SUMMARY.read_text(encoding="utf-8")
    for case in CASES:
        assert f"| `{case['id']}` | {case['class']} | {case['expected']} |" in summary, case["id"]
    detected = sum(case["expected"] == "detected" for case in CASES)
    missed = sum(case["expected"] == "missed" for case in CASES)
    assert f"{detected} detected, {missed} missed" in summary
