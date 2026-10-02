"""Every input hashed into maintained evidence must schedule its regeneration."""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/workflows/extension-artifact-regen.yml"
# Same lower bound as the evidence report contract; the exact count grows.
MIN_REPORT_INPUTS = 40


def _triggers(workflow: dict) -> dict:
    """Accept YAML 1.1 and 1.2 loaders without accepting ambiguous event keys."""
    assert not ("on" in workflow and True in workflow), "Ambiguous workflow event keys"
    triggers = workflow.get("on", workflow.get(True))
    assert isinstance(triggers, dict), "Workflow events must be a mapping"
    return triggers


def _matches(path: str, pattern: str) -> bool:
    """Match only positive * and terminal ** patterns used by this workflow.

    Fail explicitly for other glob syntax rather than silently approximating
    negation, character classes, or zero-directory **/ matching.
    """
    assert not any(token in pattern for token in ("!", "?", "[", "]", "+", "**/")), (
        "Unsupported regeneration trigger pattern: " + pattern
    )
    expression = re.escape(pattern).replace(r"\*\*", ".*").replace(r"\*", "[^/]*")
    return re.fullmatch(expression, path) is not None


@pytest.mark.parametrize(
    "path,pattern,expected",
    [
        ("rust/crates/example/src/lib.rs", "rust/**", True),
        ("tests/guard_command_corpus_native.py", "tests/guard_command_corpus*.py", True),
        ("tests/nested/guard_command_corpus.py", "tests/guard_command_corpus*.py", False),
        ("other/tests/guard_command_corpus.py", "tests/guard_command_corpus*.py", False),
        ("src/runtime/deep/module.py", "src/runtime/*.py", False),
        ("tests/fixture.json", "tests/fixture.json", True),
        ("tests/fixtureXjson", "tests/fixture.json", False),
    ],
)
def test_trigger_matcher_preserves_path_boundaries(path: str, pattern: str, expected: bool) -> None:
    """Keep single-star matching within one path segment."""
    assert _matches(path, pattern) is expected


def test_regen_trigger_covers_every_decision_diff_input() -> None:
    """Require every bound report input to schedule regeneration."""
    from tests.guard_command_decision_diff import (
        _EVIDENCE_SOURCE_PATHS,
        KNOWN_GAPS_PATH,
        MANIFEST_PATH,
        NATIVE_CONTRACT_PATH,
        PAIRS_PATH,
        REPO_ROOT,
    )

    workflow = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    # PyYAML's YAML 1.1 parser reads the Actions "on" key as True.
    patterns = _triggers(workflow)["push"]["paths"]
    inputs = {
        path.relative_to(REPO_ROOT).as_posix()
        for path in (*_EVIDENCE_SOURCE_PATHS, KNOWN_GAPS_PATH, MANIFEST_PATH, PAIRS_PATH, NATIVE_CONTRACT_PATH)
    }
    # Native-contract inputs affect the report indirectly and must be watched
    # independently of whether the broad rust/** pattern remains in place.
    native_contract = json.loads(NATIVE_CONTRACT_PATH.read_text(encoding="utf-8"))
    inputs.update(native_contract["inherited_source_identities"]["sources"])
    inputs.update(native_contract["immutable_input_sha256"])
    assert len(inputs) >= MIN_REPORT_INPUTS
    missing = sorted(path for path in inputs if not any(_matches(path, pattern) for pattern in patterns))
    assert not missing, "Report inputs missing from the regeneration trigger:\n" + "\n".join(missing)


def test_regen_keeps_main_scope_and_reviewed_publication() -> None:
    """Retain main-only publication through a normally reviewed pull request."""
    workflow = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    assert _triggers(workflow)["push"]["branches"] == ["main"]
    assert "workflow_dispatch" in _triggers(workflow)
    assert "pull_request" not in _triggers(workflow)
    assert workflow["concurrency"]["cancel-in-progress"] is False
    steps = workflow["jobs"]["regen"]["steps"]
    publish = next((step for step in steps if step.get("name") == "Regenerate and publish refreshed artifacts"), None)
    assert publish is not None, "Missing reviewed artifact publication step"
    assert "gh pr create" in publish["run"]
    assert 'gh pr merge --repo "${GH_REPO}" --auto --squash' in publish["run"]
    assert "--admin" not in publish["run"]
    assert "continue-on-error" not in publish


@pytest.mark.parametrize("key", ["on", True])
def test_event_keys_support_both_yaml_versions(key: object) -> None:
    """Accept the event mapping produced by either YAML version."""
    events = {"push": {"branches": ["main"]}}
    assert _triggers({key: events}) == events


@pytest.mark.parametrize("workflow", [{}, {"on": None}, {"on": {}, True: {}}])
def test_invalid_or_ambiguous_event_keys_fail_explicitly(workflow: dict) -> None:
    """Reject missing, malformed, or ambiguous workflow events."""
    with pytest.raises(AssertionError):
        _triggers(workflow)


@pytest.mark.parametrize("pattern", ["!src/**", "tests/test?.py", "tests/[ab].py", "tests/a+.py", "**/test.py"])
def test_unsupported_glob_syntax_fails_explicitly(pattern: str) -> None:
    """Refuse glob syntax this deliberately narrow matcher cannot interpret."""
    with pytest.raises(AssertionError, match="Unsupported regeneration trigger pattern"):
        _matches("tests/test.py", pattern)
