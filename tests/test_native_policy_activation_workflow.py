"""Exercise the hosted evidence validator without claiming native execution."""

import textwrap
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

EXPECTED = (
    "test_first_action_after_publish_uses_the_signed_default[1]",
    "test_first_action_after_publish_uses_the_signed_default[2]",
    "test_signed_exact_policy_is_consumed_by_actual_resident[canonical]",
    "test_signed_exact_policy_is_consumed_by_actual_resident[memory]",
)
WORKFLOW = Path(__file__).resolve().parents[1] / ".github/workflows/mdm-cloud-integration-lab.yml"


def _accepted(names: tuple[str, ...], outcome: str | None = None) -> bool:
    """Execute the exact bounded XML predicate embedded in the workflow."""
    workflow = WORKFLOW.read_text()
    start = workflow.index("          expected = {")
    end = workflow.index("          clean = subprocess.run(", start)
    cases = [ET.Element("testcase", name=name) for name in names]
    if outcome is not None:
        ET.SubElement(cases[-1], outcome)
    namespace = {"cases": cases}
    exec(compile(textwrap.dedent(workflow[start:end]), str(WORKFLOW), "exec"), namespace)
    return namespace["passed"]


def test_four_exact_native_assertions_are_required() -> None:
    assert _accepted(EXPECTED)
    assert not _accepted(EXPECTED[:2])
    assert not _accepted(EXPECTED[:-1])
    assert not _accepted((*EXPECTED, EXPECTED[-1]))
    assert not _accepted((*EXPECTED[:-1], EXPECTED[0]))
    assert not _accepted((*EXPECTED[:-1], "unrelated_assertion"))


@pytest.mark.parametrize("outcome", ["skipped", "failure", "error"])
def test_any_nonpass_outcome_rejects_native_evidence(outcome: str) -> None:
    assert not _accepted(EXPECTED, outcome)


def test_both_actual_native_test_files_are_selected() -> None:
    workflow = WORKFLOW.read_text()
    start = workflow.index("          uv run --no-sync pytest -q -m slow")
    end = workflow.index("      - name: Validate bounded native assertion evidence", start)
    invocation = workflow[start:end]
    assert "tests/test_native_cloud_policy_resident.py" in invocation
    assert "tests/test_native_scoped_policy_resident.py" in invocation
    assert "test-only; production advertisement not evaluated" in workflow
