"""The approval-row converter must keep the replayed action and drop identifying text."""

from __future__ import annotations

import importlib.util
from pathlib import Path

_SPEC = importlib.util.spec_from_file_location(
    "approval_rows_to_gate_cases", Path(__file__).parents[1] / "scripts" / "approval_rows_to_gate_cases.py"
)
assert _SPEC is not None and _SPEC.loader is not None
converter = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(converter)


def test_project_paths_keep_the_file_inside_the_checkout() -> None:
    assert converter.scrub("cat /Users/alice/proj/src/a.ts", []) == "cat ${WORKTREE}/src/a.ts"
    assert converter.scrub("git -C /home/u/proj status", []) == "git -C ${WORKTREE} status"


def test_repository_owners_are_replaced_without_an_owner_flag() -> None:
    assert converter.scrub("gh api repos/acme/secret/pulls/3", []) == "gh api repos/o/r/pulls/3"
    assert converter.scrub("gh pr view 3 --repo acme/secret", []) == "gh pr view 3 --repo o/r"
    assert converter.scrub("git clone git@github.com:acme/secret.git", []) == "git clone git@github.com:o/r.git"


def test_rows_with_string_input_are_skipped_and_reasons_are_scrubbed() -> None:
    assert converter.to_case({"tool_name": "bash", "tool_input": '"ls"'}, []) is None
    case = converter.to_case(
        {"tool_name": "bash", "tool_input": {"command": "ls"}, "reason_code": "review /Users/alice/proj"}, []
    )
    assert case is not None and case["observed_reason_code"] == "review ${WORKTREE}"
