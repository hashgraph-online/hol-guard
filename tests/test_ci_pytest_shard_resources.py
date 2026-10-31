"""Deadline isolation retains the complete traced inventory on existing hosts."""

from __future__ import annotations

import ast
import hashlib
import json
import re
import shlex
import subprocess
import sys
import time
from pathlib import Path

import pytest

from scripts.ci import run_projection_shard as runner
from scripts.ci.build_pytest_shard_plan import (
    FIXTURE_GROUP_FUNCTIONS,
    build_affinity_node_shards,
    build_coverage_node_shards,
    write_shard_plan,
)
from scripts.ci.pytest_duration_manifest import node_id_digest
from scripts.ci.pytest_shard_resources import (
    DEADLINE_FAMILIES,
    coverage_worker_count,
    deadline_counts,
    deadline_family,
    resource_metadata,
)
from scripts.ci.test_inventory import build_inventory
from tests.support.ci_workflow import load_ci_workflow

ROOT = Path(__file__).resolve().parents[1]


def _deadline_nodes() -> list[str]:
    return [
        DEADLINE_FAMILIES[0],
        *[f"{DEADLINE_FAMILIES[1]}[{a}-{b}]" for a in (False, True) for b in (False, True)],
        *[f"{DEADLINE_FAMILIES[2]}[{expired}]" for expired in (False, True)],
    ]


def _nodes() -> list[str]:
    return _deadline_nodes() + [f"tests/test_control_{i}.py::test_control" for i in range(256)]


def _plan(tmp_path: Path) -> tuple[Path, Path]:
    shards, loads = build_coverage_node_shards(_nodes(), 128, {})
    write_shard_plan(tmp_path, shards=shards, estimated_loads=loads, manifest_used=False, deadline_isolation=True)
    return tmp_path / "shard-000.txt", tmp_path / "shard-127.txt"


@pytest.mark.parametrize("measured", [False, True])
def test_all_128_shards_preserve_nodes_markers_and_exactly_once_ownership(measured: bool) -> None:
    nodes = _nodes()
    durations = {node_id_digest(node): 2.0 for node in nodes} if measured else {}
    baseline, _ = build_affinity_node_shards(nodes, 128, durations)
    shards, _ = build_coverage_node_shards(nodes, 128, durations)
    before = [node for shard in baseline for node in shard]
    after = [node for shard in shards for node in shard]
    markers = {node: ("native_route_unpinned", "parametrize") if "[" in node else ("unit",) for node in nodes}
    assert len(shards) == 128 and all(shards)
    assert sorted(after) == sorted(before) == sorted(nodes)
    assert len(after) == len(set(after))
    assert build_inventory(before, markers) == build_inventory(after, markers)
    assert shards[127] == sorted(_deadline_nodes())
    assert deadline_counts(shards[127]) == dict(zip(DEADLINE_FAMILIES, (1, 4, 2), strict=True))
    assert not any(deadline_family(node) for shard in shards[:127] for node in shard)


def test_selector_matching_is_exact_and_missing_families_are_errors() -> None:
    for family in DEADLINE_FAMILIES:
        assert deadline_family(family) == family
        assert deadline_family(family + "[parameter]") == family
        assert deadline_family(family + "_followup") is None
        with pytest.raises(ValueError, match="every deadline-sensitive"):
            build_coverage_node_shards([n for n in _nodes() if deadline_family(n) != family], 128, {})
        path, function = family.split("::")
        source = ast.parse((ROOT / path).read_text())
        assert any(isinstance(node, ast.FunctionDef) and node.name == function for node in source.body)
    with pytest.raises(ValueError, match="at least three"):
        build_coverage_node_shards(_nodes(), 2, {})
    with pytest.raises(ValueError, match="unique"):
        build_coverage_node_shards([*_nodes(), DEADLINE_FAMILIES[0]], 128, {})
    with pytest.raises(ValueError, match="invalid pytest node"):
        build_coverage_node_shards([*_nodes(), DEADLINE_FAMILIES[0] + "[bad\ninjected]"], 128, {})


def test_protected_offline_and_single_process_affinities_remain_intact() -> None:
    offline = "tests/test_native_offline_cache.py"
    fixture_functions = sorted(FIXTURE_GROUP_FUNCTIONS[offline])
    shared = [f"{offline}::{name}[{index}]" for name in fixture_functions for index in range(2)]
    rest = [f"{offline}::test_other_{i}" for i in range(8)]
    corpus = [f"tests/test_guard_command_decision_diff.py::test_report[{i}]" for i in range(16)]
    nodes = _nodes() + shared + rest + corpus
    durations = {node_id_digest(node): 100.0 for node in shared + rest}
    durations.update({node_id_digest(node): 10.0 for node in corpus})
    baseline, _ = build_affinity_node_shards(nodes, 128, durations)
    shards, _ = build_coverage_node_shards(nodes, 128, durations)
    for expected in (shared, rest, corpus):
        owners = [i for i, shard in enumerate(shards) if set(shard) & set(expected)]
        old_owners = [i for i, shard in enumerate(baseline) if set(shard) & set(expected)]
        assert len(owners) == len(old_owners) == 1
        assert owners == old_owners
        assert set(expected) <= set(shards[owners[0]])
    assert set(shared + rest) <= set(shards[0] + shards[1])


@pytest.mark.parametrize("isolated", [False, True])
@pytest.mark.parametrize("traced", [False, True])
def test_runner_executes_one_owned_invocation_with_policy_workers_and_coverage(tmp_path, monkeypatch, isolated, traced):
    ordinary, serial = _plan(tmp_path)
    path = serial if isolated else ordinary
    flags = ["@" + str(path), "--dist", "loadfile", "--max-worker-restart", "0"]
    if traced:
        flags += ["--cov", "--cov-branch", "--cov-report="]
    monkeypatch.delenv("HOL_GUARD_NATIVE_SOURCE_COMPILER", raising=False)
    calls = []

    def execute(command, **kwargs):
        calls.append(command)
        return subprocess.CompletedProcess(command, 0)

    monkeypatch.setattr(runner.subprocess, "run", execute)
    assert runner.main(["--coverage-resources", str(path), "--", *flags]) == 0
    assert calls == [[sys.executable, "-m", "pytest", "-n", "1" if isolated else "4", *flags]]


@pytest.mark.parametrize(
    "extra",
    [
        ["-n", "4"],
        ["-n8"],
        ["--numprocesses=2"],
        ["--dist", "each"],
        ["-k", "missing"],
        ["-m", "slow"],
        ["@other.txt"],
        ["/extra/tests.py"],
        ["--deselect", DEADLINE_FAMILIES[0]],
        ["--deselect=tests/test_desktop_native_qualification.py"],
        ["--deselect", "tests/test_desktop_native"],
        ["--deselect", "tests/test_business_policy_dashboard_recovery.py::test_inspection"],
        ["--deselect", "@other.txt"],
    ],
)
def test_policy_rejects_worker_overrides_filters_and_extra_selectors_before_launch(tmp_path, monkeypatch, extra):
    _, path = _plan(tmp_path)
    monkeypatch.setattr(runner.subprocess, "run", lambda *a, **k: pytest.fail("invalid policy started a child"))
    with pytest.raises(ValueError):
        runner.main(["--coverage-resources", str(path), "--", "@" + str(path), *extra])


@pytest.mark.parametrize("option", ["--deselect", "--deselect="])
def test_runner_rejects_owned_response_file_consumed_as_option_value(tmp_path, monkeypatch, option):
    _, path = _plan(tmp_path)
    reference = "@" + str(path)
    flags = [option + reference] if option.endswith("=") else [option, reference]
    monkeypatch.setattr(runner.subprocess, "run", lambda *a, **k: pytest.fail("invalid policy started a child"))
    with pytest.raises(ValueError):
        runner.main(["--coverage-resources", str(path), "--", *flags])


def test_policy_rejects_missing_plan_tampering_and_rehashed_illegal_companions(tmp_path):
    ordinary, serial = _plan(tmp_path)
    assert coverage_worker_count(ordinary, ["@" + str(ordinary)]) == 4
    assert coverage_worker_count(serial, ["@" + str(serial)]) == 1
    metadata_path = tmp_path / "plan.json"
    metadata = json.loads(metadata_path.read_text())
    serial.write_text(serial.read_text() + "tests/test_probe.py::test_busy\n")
    with pytest.raises(ValueError, match="response file"):
        coverage_worker_count(serial, ["@" + str(serial)])
    metadata["execution_policy"]["shard_sha256"][127] = hashlib.sha256(serial.read_bytes()).hexdigest()
    metadata_path.write_text(json.dumps(metadata))
    with pytest.raises(ValueError, match="companions"):
        coverage_worker_count(serial, ["@" + str(serial)])
    metadata.pop("execution_policy")
    metadata_path.write_text(json.dumps(metadata))
    with pytest.raises(ValueError, match="missing or invalid"):
        coverage_worker_count(ordinary, ["@" + str(ordinary)])
    with pytest.raises(ValueError, match="no companions"):
        resource_metadata(
            [
                ["tests/test_a.py::test_a"],
                ["tests/test_b.py::test_b"],
                [*_deadline_nodes(), "tests/test_extra.py::test_extra"],
            ]
        )


def test_workflow_keeps_all_coverage_artifacts_provenance_and_required_ownership():
    workflow = load_ci_workflow()
    job = workflow["jobs"]["coverage"]
    command = next(s["run"] for s in job["steps"] if s.get("name", "").startswith("Run coverage shard"))
    tokens = shlex.split(command)
    assert "--coverage-resources" in tokens
    assert "-n" not in tokens and "4" not in tokens
    assert workflow["env"]["CI_PYTEST_COVERAGE_SHARDS"] == "128"
    assert (
        job["strategy"]["matrix"]["shard-index"]
        == "${{ fromJSON(needs.native-command-evaluators.outputs.shard-indices) }}"
    )
    assert "coverage_args=(--cov --cov-branch --cov-report=)" in command
    assert "GUARD_PYTEST_DURATION_OUTPUT=pytest-durations.json" in command
    assert "coverage" in workflow["jobs"]["required"]["needs"]
    assert job["timeout-minutes"] == 15
    assert sum(s.get("name") == "Upload pytest coverage data artifact" for s in job["steps"]) == 1
    assert sum(s.get("name") == "Upload pytest duration artifact" for s in job["steps"]) == 1


@pytest.mark.parametrize("traced", [False, True])
def test_actual_workflow_arguments_pass_the_resource_gate_for_every_shard(tmp_path, traced):
    _plan(tmp_path)
    job = load_ci_workflow()["jobs"]["coverage"]
    command = next(s["run"] for s in job["steps"] if s.get("name", "").startswith("Run coverage shard"))
    match = re.search(
        r'run_projection_shard.py --coverage-resources "\$shard_file" -- (.*)', command.replace("\\\n", " "), re.S
    )
    assert match is not None
    raw = shlex.split(match[1])
    for index in range(128):
        path = tmp_path / f"shard-{index:03d}.txt"
        args = []
        for arg in raw:
            if arg == "${coverage_args[@]}":
                args.extend(["--cov", "--cov-branch", "--cov-report="] if traced else [])
            else:
                args.append("@" + str(path) if arg == "@$shard_file" else arg)
        assert coverage_worker_count(path, args) == (1 if index == 127 else 4)


def test_original_deadlines_are_unchanged_and_a_slow_child_still_times_out(tmp_path):
    from codex_plugin_scanner.guard.codex_hook_launch_runtime import run_isolated_hook_process

    desktop = ast.parse((ROOT / "tests/test_desktop_native_qualification.py").read_text())
    function = next(
        n for n in desktop.body if isinstance(n, ast.FunctionDef) and n.name == DEADLINE_FAMILIES[0].split("::")[1]
    )
    budgets = [
        n.value.value
        for n in ast.walk(function)
        if isinstance(n, ast.Assign)
        and any(isinstance(t, ast.Name) and t.id == "budget" for t in n.targets)
        and isinstance(n.value, ast.Constant)
    ]
    assert budgets == [30]
    surface = ast.parse((ROOT / "tests/test_guard_mcp_policy_daemon.py").read_text())
    helper = next(n for n in ast.walk(surface) if isinstance(n, ast.FunctionDef) and n.name == "_read_response")
    timeouts = [
        kw.value.value
        for n in ast.walk(helper)
        if isinstance(n, ast.Call)
        for kw in n.keywords
        if kw.arg == "timeout" and isinstance(kw.value, ast.Constant)
    ]
    assert timeouts == [5]
    # Exercise the same real containment primitive with a short injected
    # deadline; the source contracts above retain the actual 30s/5s budgets.
    result = run_isolated_hook_process(
        [sys.executable, "-c", "import time; time.sleep(2)"],
        input_text="",
        cwd=tmp_path,
        environment={},
        deadline_monotonic=time.monotonic() + 0.1,
    )
    assert result.timed_out and not result.containment_failed
