"""Keep the consolidated required gate equivalent to its two former aggregates."""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text())
CONFIGURED_SHARDS = str(WORKFLOW["env"]["CI_PYTEST_COVERAGE_SHARDS"])
ALWAYS_ON = {
    "plan",
    "native-workspace",
    "native-command-evaluators",
    "native-offline-previous",
    "native-offline-upgrade",
    "native-gates",
    "quality",
}
LANE_GATED = {
    "coverage",
    "compatibility",
    "scheduling-sensitive",
    "dashboard",
    "dashboard-integration-wheel",
    "dashboard-integration",
    "cisco-full",
    "pi-exact-continuation",
    "cross-platform",
    "windows-native-runtime",
    "windows-shim-admin",
    "windows-packaged-daemon",
    "macos-native-runtime",
    "macos-skill-identity",
    "macos-gates",
}
PYTHON_PROVIDERS = {
    "NATIVE_WORKSPACE_RESULT": "native-workspace",
    "QUALITY_RESULT": "quality",
    "NATIVE_PRODUCER_RESULT": "native-command-evaluators",
    "COVERAGE_RESULT": "coverage",
    "COMPATIBILITY_RESULT": "compatibility",
    "SCHEDULING_SENSITIVE_RESULT": "scheduling-sensitive",
}
pytestmark = pytest.mark.skipif(os.name == "nt", reason="The aggregate runs on Ubuntu with Bash")


@pytest.fixture(scope="module")
def gate() -> dict:
    return WORKFLOW["jobs"]["required"]


def _results(data_only: bool) -> dict:
    return {
        job: {"result": "skipped" if data_only and job in LANE_GATED else "success"} for job in ALWAYS_ON | LANE_GATED
    }


def _passes(gate: dict, needs: dict, data_only: bool, **overrides: str) -> bool:
    env = {
        **os.environ,
        "PATH": str(Path(sys.executable).parent) + os.pathsep + os.environ["PATH"],
        "RESULTS": json.dumps(needs),
        "EVENT_NAME": "pull_request",
        "PLAN_DATA_ONLY": str(data_only).lower(),
        "PLAN_LANES": "[]",
        "PLAN_SHARD_COUNT": CONFIGURED_SHARDS,
        "EXPECTED_SHARDS": CONFIGURED_SHARDS,
        **{name: needs.get(job, {}).get("result", "") for name, job in PYTHON_PROVIDERS.items()},
        **overrides,
    }
    for step in gate["steps"][:2]:
        result = subprocess.run(
            ["bash", "-e", "-o", "pipefail", "-c", step["run"]],
            env=env,
            capture_output=True,
            check=False,
            timeout=5,
        )
        if result.returncode:
            return False
    return True


def _former_combined_passes(needs: dict, data_only: bool) -> bool:
    """Model the former shell gate AND required evaluator, including malformed results."""
    allowed = {"success", "skipped"} if data_only else {"success"}
    python_gate = all(needs.get(job, {}).get("result", "") in allowed for job in PYTHON_PROVIDERS.values())
    return (
        python_gate
        and needs.keys() >= ALWAYS_ON | LANE_GATED
        and all(needs[job].get("result") == "success" for job in ALWAYS_ON)
        and not any(needs[job].get("result") in {"failure", "cancelled"} for job in LANE_GATED)
        and (data_only or not any(needs[job].get("result") == "skipped" for job in LANE_GATED))
    )


def test_only_the_duplicate_aggregate_is_retired_and_its_step_is_literal(gate: dict) -> None:
    jobs = WORKFLOW["jobs"]
    assert "ci-python-312" not in jobs
    assert set(gate["needs"]) == ALWAYS_ON | LANE_GATED
    assert gate["name"] == "hol-guard / required" and gate["if"] == "always()"
    assert gate["permissions"] == {"contents": "read", "statuses": "read"}
    assert [step["name"] for step in gate["steps"][:3]] == [
        "Evaluate planned required results",
        "Verify Python CI dependencies",
        "Check out the merge freeze policy from the base revision",
    ]
    moved = gate["steps"][1]
    # Digest of the complete former step (name, env and run), before consolidation.
    assert hashlib.sha256(json.dumps(moved, sort_keys=True).encode()).hexdigest() == (
        "3d283983fa0f2fa60a8b4cb65fcaf62561318b652891b4c0f5ef98f561b94e66"
    )
    for name, job in PYTHON_PROVIDERS.items():
        assert moved["env"][name] == "${{ needs." + job + ".result }}"
    assert "if" not in moved and "continue-on-error" not in moved
    expressions = re.findall(r"needs\.([\w-]+)\.", "\n".join(moved["env"].values()))
    assert set(expressions) <= set(gate["needs"])


@pytest.mark.parametrize("data_only", [False, True], ids=["full", "data-only"])
@pytest.mark.parametrize("provider", sorted(PYTHON_PROVIDERS.values()))
@pytest.mark.parametrize(
    "result",
    ["success", "failure", "cancelled", "skipped", "", "unknown", "timed_out", "missing", "missing-result"],
)
def test_six_provider_results_match_the_former_combined_checks(
    gate: dict,
    data_only: bool,
    provider: str,
    result: str,
) -> None:
    needs = _results(data_only)
    if result == "missing":
        del needs[provider]
    else:
        needs[provider] = {} if result == "missing-result" else {"result": result}
    expected = result == "success" or (data_only and provider in LANE_GATED and result == "skipped")
    assert _former_combined_passes(needs, data_only) == expected
    assert _passes(gate, needs, data_only) == expected


@pytest.mark.parametrize("data_only", [False, True])
@pytest.mark.parametrize("provider", sorted(ALWAYS_ON))
@pytest.mark.parametrize("result", ["failure", "cancelled", "skipped", "missing"])
def test_native_and_planner_failures_remain_closed(gate: dict, data_only: bool, provider: str, result: str) -> None:
    needs = _results(data_only)
    if result == "missing":
        del needs[provider]
    else:
        needs[provider]["result"] = result
    assert not _passes(gate, needs, data_only)


@pytest.mark.parametrize("count", ["", "0", "unknown", str(int(CONFIGURED_SHARDS) + 1)])
def test_full_plan_requires_the_configured_matrix_cardinality(gate: dict, count: str) -> None:
    assert not _passes(gate, _results(False), False, PLAN_SHARD_COUNT=count)


@pytest.mark.parametrize("event", ["push", "merge_group", "workflow_dispatch"])
def test_a_skipped_off_pr_planner_still_allows_successful_providers(gate: dict, event: str) -> None:
    needs = _results(False)
    needs["plan"]["result"] = "skipped"
    assert _passes(gate, needs, False, EVENT_NAME=event)
