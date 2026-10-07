"""Publish changed product inputs, not independently reviewed test expectations."""

from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/workflows/extension-artifact-regen.yml"


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


def test_regen_trigger_covers_product_inputs_not_per_run_evidence() -> None:
    """Verify regen trigger covers product inputs not per run evidence."""
    workflow = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    patterns = _triggers(workflow)["push"]["paths"]
    inputs = {
        "rust/Cargo.toml",
        "rust/Cargo.lock",
        "rust/build_support/command_identity.rs",
        "rust/crates/guard-command/build.rs",
        "contracts/extensions/trust-class-map.v1.json",
        "contributions/command-sources/command.future.json",
        "contributions/mcp-servers/mcp.future.json",
        "contributions/extension-listings/command.future.json",
        "contracts/mcp-servers/contribution.v1.schema.json",
        "scripts/build_native_command_program.py",
        "scripts/export_extension_directory.py",
        "scripts/render_command_extension_directory.py",
        "scripts/prepare_extension_contribution.py",
    }
    assert all(any(_matches(path, pattern) for pattern in patterns) for path in inputs)
    for evidence in (
        "tests/fixtures/command-source-demo.v1.json",
        "tests/fixtures/extension-controls/catalog-baseline.v1.json",
        "tests/fixtures/guard-command-corpus/decision-diff-report.json",
        "tests/guard_command_decision_diff.py",
        "build/guard-evidence/decision-diff-report.json",
    ):
        assert not any(_matches(evidence, pattern) for pattern in patterns), evidence


def test_regen_keeps_main_scope_and_verified_snapshot_publication() -> None:
    """Publish verified main snapshots without creating generated-file PRs."""
    workflow = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    assert _triggers(workflow)["push"]["branches"] == ["main"]
    assert "workflow_dispatch" in _triggers(workflow)
    assert "pull_request" not in _triggers(workflow)
    assert workflow["concurrency"]["cancel-in-progress"] is False
    steps = workflow["jobs"]["regen"]["steps"]
    publish = next((step for step in steps if step.get("name") == "Publish immutable public snapshot"), None)
    assert publish is not None, "Missing verified snapshot publication step"
    assert "scripts/publish_extension_snapshot.py" in publish["run"]
    assert "gh pr create" not in publish["run"]
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
