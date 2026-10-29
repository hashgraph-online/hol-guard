"""Native behavior of the command.secret-blast-radius source.

The canonical source and portable fixture are builder-managed, so a later
authoring kit can prove ownership of their bytes. Supplementary cases live
here and run against the managed fixture's own build.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.extension_builder.native_source_compiler import run_source_compiler
from tests.extension_builder_support import use_built_native_source_compiler

ROOT = Path(__file__).resolve().parents[1]
_FIXTURE_PATH = ROOT / "tests/fixtures/command-source-secret-blast-radius.v1.json"
_EXTENSION_ID = "command.secret-blast-radius"
_ROOT_RULE = "command.secret-blast-radius.op-75eb278d6a9fb4cf"
_UNCLASSIFIED_RULE = "command.secret-blast-radius.unclassified"

# Reviewed literal invocations: offline, and they write nothing. The root rule
# and the unclassified fallback both carry them as safe variants, so neither
# leaves an effective segment; the action stays at the review floor.
REVIEWED_LITERAL_COMMANDS: tuple[str, ...] = (
    "secret-blast-radius --harden",
    "secret-blast-radius --help",
    "secret-blast-radius --json",
    "secret-blast-radius --list-incidents",
    "secret-blast-radius --no-exec",
    "secret-blast-radius --runbook",
    "secret-blast-radius --sarif",
    "secret-blast-radius --version",
)

# --osv sends lockfile package names and versions to api.osv.dev, and the
# *-file options write a report to a chosen path, alone or after a safe flag.
ROOT_REVIEW_COMMANDS: tuple[str, ...] = (
    "secret-blast-radius --osv",
    "secret-blast-radius --sarif-file report.sarif",
    "secret-blast-radius --runbook-file runbook.md",
    "secret-blast-radius --json --osv",
    "secret-blast-radius --sarif --sarif-file out.sarif",
    "secret-blast-radius --runbook --runbook-file runbook.md",
)


def _case(case_id: str, command: str, rule_id: str, segments: list[int]) -> dict[str, object]:
    return {
        "command": command,
        "disabled_permissions": [],
        "enabled_extensions": [_EXTENSION_ID],
        "expected_action": "review",
        "expected_effective_segments": segments,
        "id": case_id,
        "rule_id": rule_id,
    }


def _supplementary_cases() -> list[dict[str, object]]:
    cases: list[dict[str, object]] = []
    for index, command in enumerate(REVIEWED_LITERAL_COMMANDS):
        cases.append(_case(f"literal-{index}-root", command, _ROOT_RULE, []))
        cases.append(_case(f"literal-{index}-unclassified", command, _UNCLASSIFIED_RULE, []))
    for index, command in enumerate(ROOT_REVIEW_COMMANDS):
        cases.append(_case(f"review-{index}-root", command, _ROOT_RULE, [0]))
        cases.append(_case(f"review-{index}-unclassified", command, _UNCLASSIFIED_RULE, [0]))
    return cases


def test_supplementary_cases_pass_against_the_native_evaluator(monkeypatch: pytest.MonkeyPatch) -> None:
    use_built_native_source_compiler(monkeypatch)
    fixture = json.loads(_FIXTURE_PATH.read_text(encoding="utf-8"))
    fixture["cases"] = _supplementary_cases()
    result = run_source_compiler("test", fixture)
    assert result["ok"] is True, result
    assert result["target_commands_executed"] == 0
    cases = result["cases"]
    assert isinstance(cases, list)
    assert len(cases) == len(fixture["cases"])
    failures = [case for case in cases if not case["passed"]]
    assert failures == []
