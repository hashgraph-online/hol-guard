"""Native CI sharding must retain every test and propagate every failure."""

from __future__ import annotations

import copy
import hashlib
import importlib.util
from pathlib import Path

import pytest
import yaml

from tests.support.ci_workflow import expand_ci_job_actions

ROOT = Path(__file__).resolve().parents[1]


def _load(name: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts/ci" / f"{name}.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


SHARD = _load("native_regression_shard")
VERIFY = _load("verify_native_regression_shards")


def _reports(count: int = 4) -> list[dict[str, object]]:
    nodes = [f"tests/test_example.py::test_{index:04}" for index in range(37)]
    digest = hashlib.sha256("\n".join(sorted(nodes)).encode()).hexdigest()
    return [
        {
            "schema": "hol-guard.native-regression-shard.v1",
            "platform": platform,
            "shard_index": index,
            "shard_count": count,
            "collected_count": len(nodes),
            "inventory_sha256": digest,
            "selected": SHARD.select_nodes(nodes, index, count),
            "exit_code": 0,
        }
        for platform in sorted(VERIFY.PLATFORMS)
        for index in range(count)
    ]


@pytest.mark.parametrize("size", [16, 37, 1252])
def test_shards_cover_non_divisible_inventories_exactly_once(size: int) -> None:
    nodes = [f"test_{i}" for i in range(size)]
    shards = [SHARD.select_nodes(nodes, index, 16) for index in range(16)]
    assert sorted(node for shard in shards for node in shard) == sorted(nodes)
    assert all(shards)
    assert len({node for shard in shards for node in shard}) == size
    assert SHARD.select_nodes(list(reversed(nodes)), 0, 16) == shards[0]


@pytest.mark.parametrize(
    "nodes,index,count", [([], 0, 1), (["a"], 0, 0), (["a"], -1, 1), (["a"], 1, 1), (["a"], 0, 2), (["a", "a"], 0, 1)]
)
def test_invalid_shards_fail_closed(nodes: list[str], index: int, count: int) -> None:
    with pytest.raises(ValueError):
        SHARD.select_nodes(nodes, index, count)


def test_all_platforms_reconcile_the_full_inventory() -> None:
    assert VERIFY.verify_reports(_reports(), 4) == {platform: 37 for platform in VERIFY.PLATFORMS}


@pytest.mark.parametrize(
    "field,value",
    [
        ("schema", "wrong"),
        ("platform", "unknown"),
        ("shard_index", -1),
        ("shard_index", True),
        ("shard_count", 3),
        ("collected_count", 36),
        ("inventory_sha256", "wrong"),
        ("selected", []),
        ("selected", ["unknown"]),
        ("exit_code", 1),
        ("exit_code", False),
    ],
)
def test_bad_or_failed_shard_cannot_pass(field: str, value: object) -> None:
    reports = _reports()
    reports[0][field] = value
    with pytest.raises(ValueError):
        VERIFY.verify_reports(reports, 4)


def test_missing_extra_and_duplicate_reports_fail() -> None:
    for reports in [_reports()[:-1], [*_reports(), _reports()[0]], [_reports()[0]] * 16]:
        with pytest.raises(ValueError):
            VERIFY.verify_reports(reports, 4)


def test_duplicate_test_cannot_replace_a_missing_test() -> None:
    reports = _reports()
    reports[0]["selected"] = copy.deepcopy(reports[1]["selected"])
    with pytest.raises(ValueError):
        VERIFY.verify_reports(reports, 4)


def test_platform_gates_require_complete_inventory_and_all_native_proofs() -> None:
    """Verify platform gates require complete inventory and all native proofs."""
    jobs = expand_ci_job_actions(yaml.safe_load((ROOT / ".github/workflows/native-wheel-ci.yml").read_text()))["jobs"]
    for name in ["linux-x64", "windows-x64", "macos"]:
        job = jobs[name]
        assert job["if"] == "always()"
        assert "native-regression-complete" in job["needs"]
        assert "test -n" in job["steps"][0]["run"]
        assert 'test "$result" = success || exit 1' in job["steps"][0]["run"]
    for platform in ["linux", "windows", "macos"]:
        regression = jobs[f"{platform}-regression"]
        assert regression["needs"] == f"{platform}-build"
        assert regression["strategy"]["matrix"]["shard"] == list(range(8))
        assert regression["strategy"]["fail-fast"] is False
        assert "if" not in regression
        assert "continue-on-error" not in regression
        proof = jobs[f"{platform}-proof"]
        assert proof["needs"] == f"{platform}-build"
        assert all("regression-tests.txt" not in step.get("run", "") for step in proof["steps"])
    assert {item["target"] for item in jobs["macos-regression"]["strategy"]["matrix"]["include"]} == {
        "aarch64-apple-darwin",
        "x86_64-apple-darwin",
    }


def test_regression_action_installs_only_the_same_run_wheel() -> None:
    """Verify regression action installs only the same run wheel."""
    action = expand_ci_job_actions(yaml.safe_load((ROOT / ".github/actions/native-regression/action.yml").read_text()))
    steps = action["runs"]["steps"]
    download = next(step for step in steps if step.get("uses", "").startswith("actions/download-artifact@"))
    assert download["with"] == {"name": "${{ inputs.artifact-name }}"}
    commands = "\n".join(step.get("run", "") for step in steps)
    assert "--frozen --no-dev --group ci-test --no-install-project" in commands
    assert "native-dist/*.whl" in commands
    assert "native_regression_shard.py" in commands
    tolerated = [step for step in steps if step.get("continue-on-error")]
    assert len(tolerated) == 1 and tolerated[0]["id"] == "setup-uv-primary"
    retry = next(step for step in steps if step.get("name") == "Retry uv setup after a transient download failure")
    assert retry["if"] == "steps.setup-uv-primary.outcome == 'failure'"
    assert not retry.get("continue-on-error")


def test_required_status_aggregators_run_after_cancellation() -> None:
    """Verify required status aggregators run after cancellation."""
    for filename, names in {
        "ci.yml": ["ci-python-312"],
        "native-wheel-ci.yml": ["linux-x64", "windows-x64", "macos", "native-regression-complete"],
    }.items():
        workflow = expand_ci_job_actions(yaml.safe_load((ROOT / ".github/workflows" / filename).read_text()))
        assert workflow["concurrency"]["cancel-in-progress"] is True
        for name in names:
            gate = workflow["jobs"][name]
            assert gate["if"] == "always()"
            assert gate["needs"]
            assert any("success" in step.get("run", "") for step in gate["steps"])


def test_every_native_runner_and_reconciler_use_the_same_shard_count() -> None:
    """Verify every native runner and reconciler use the same shard count."""
    jobs = expand_ci_job_actions(yaml.safe_load((ROOT / ".github/workflows/native-wheel-ci.yml").read_text()))["jobs"]
    for platform in ("linux", "windows", "macos"):
        job = jobs[f"{platform}-regression"]
        count = len(job["strategy"]["matrix"]["shard"])
        action = next(step for step in job["steps"] if step.get("uses") == "./.github/actions/native-regression")
        assert int(action["with"]["shard-count"]) == count == 8
    assert any("--shard-count 8" in step.get("run", "") for step in jobs["native-regression-complete"]["steps"])


@pytest.mark.parametrize("count", [None, True, 0, 3, "37"])
def test_invalid_inventory_count_identifies_the_platform(count: object) -> None:
    reports = _reports()
    reports[0]["collected_count"] = count
    platform = reports[0]["platform"]
    with pytest.raises(ValueError, match=f"invalid native inventory count: {platform}"):
        VERIFY.verify_reports(reports, 4)


@pytest.mark.parametrize("count", [0, -1, -16])
def test_nonpositive_shard_counts_have_a_clear_error(count: int) -> None:
    with pytest.raises(ValueError, match="shard count must be positive"):
        SHARD.select_nodes(["test_example"], 0, count)
    with pytest.raises(ValueError, match="shard count must be positive"):
        VERIFY.verify_reports([], count)


@pytest.mark.parametrize("platform", sorted(VERIFY.PLATFORMS))
def test_inventory_count_errors_identify_the_platform(platform: str) -> None:
    reports = _reports()
    report = next(report for report in reports if report["platform"] == platform)
    report["collected_count"] = 0
    with pytest.raises(ValueError, match=f"invalid native inventory count: {platform}"):
        VERIFY.verify_reports(reports, 4)


@pytest.mark.parametrize("platform", sorted(VERIFY.PLATFORMS))
def test_failed_shard_errors_identify_platform_and_index(platform: str) -> None:
    reports = _reports()
    report = next(report for report in reports if report["platform"] == platform and report["shard_index"] == 2)
    report["exit_code"] = 1
    with pytest.raises(ValueError, match=f"{platform}, shard=2"):
        VERIFY.verify_reports(reports, 4)


def test_missing_report_error_identifies_expected_and_actual_counts() -> None:
    with pytest.raises(ValueError, match="expected 16, got 15"):
        VERIFY.verify_reports(_reports()[:-1], 4)
