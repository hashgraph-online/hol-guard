"""Which approval-retry and connector-setup cases each harness lane drives."""

from __future__ import annotations

import pytest

from ci.gauntlet.approval_retry import CATALOG as APPROVAL_RETRY_CATALOG
from ci.gauntlet.approval_retry_bash import BASH_LIFECYCLE_CASES
from ci.gauntlet.approval_retry_suite import lane_scenarios
from ci.gauntlet.catalog import CONNECTOR_CATALOG, load_catalog


@pytest.mark.parametrize("harness", ["omp", "pi"])
def test_a_native_bash_owner_lane_drives_every_case(harness: str):
    catalog = load_catalog(APPROVAL_RETRY_CATALOG)
    assert lane_scenarios(catalog, harness) == catalog


@pytest.mark.parametrize(
    ("harness", "no_tool"),
    [
        ("codex", {"approved-retry-identical-file-read"}),
        ("claude-code", set()),
        ("cursor", set()),
    ],
)
def test_a_lane_skips_only_the_cases_it_cannot_drive(harness: str, no_tool: set[str]):
    # Guard contains an approved script on these harnesses instead of binding its
    # content to the run, so the grant-and-journal oracle can never hold there. Codex
    # has no file-read tool, so the case that pins a read through it cannot bind.
    catalog = load_catalog(APPROVAL_RETRY_CATALOG)
    lane = lane_scenarios(catalog, harness)
    skipped = BASH_LIFECYCLE_CASES | no_tool
    assert {scenario.id for scenario in catalog} - {scenario.id for scenario in lane} == skipped
    assert [scenario for scenario in catalog if scenario.id not in skipped] == list(lane)


@pytest.mark.parametrize("harness", ["omp", "pi", "codex", "claude-code", "cursor"])
def test_every_lane_drives_the_connector_mcp_cases(harness: str):
    # An MCP tool comes from the server the case configures, not from the harness,
    # so no lane may drop a connector case for naming one.
    catalog = load_catalog(CONNECTOR_CATALOG)
    mcp_cases = [s for s in catalog if any(t.startswith("mcp__") for t in s.required_tools)]
    assert mcp_cases
    lane = lane_scenarios(catalog, harness)
    assert all(case in lane for case in mcp_cases)
