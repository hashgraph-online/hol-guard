"""Independent publication lanes retain complete target and trust gates."""

from __future__ import annotations

import copy
import json
import os
import re
import shlex
import subprocess
import sys

import pytest

from tests.release_workflow_helpers import (
    NATIVE_WHEEL_LANES,
    NATIVE_WHEEL_WORKFLOW,
    PREPARED_WHEEL_LANES,
    PUBLISH_WORKFLOW,
    ROOT,
    load_workflow,
    native_target_matrix,
    native_wheel_job,
)

TARGETS = (
    "x86_64-unknown-linux-musl",
    "x86_64-apple-darwin",
    "aarch64-apple-darwin",
    "x86_64-pc-windows-msvc",
    "aarch64-pc-windows-msvc",
    "aarch64-unknown-linux-musl",
)
PREPARED_TARGETS = TARGETS[:5]
PREPARE = ROOT / ".github/workflows/release-native-prepare.yml"


def test_quality_lints_and_formats_all_changed_contracts_without_dropping_existing_paths() -> None:
    required = {
        "src/",
        "tests/test_guard_durable_io.py",
        "tests/test_guard_managed_install_context.py",
        "tests/test_guard_private_file_io.py",
        "tests/release_workflow_helpers.py",
        "tests/test_alpha_fast_native_release.py",
        "tests/test_ci_speed_contracts.py",
        "tests/test_installed_canary_workflow.py",
        "tests/test_pr_testpypi_canary_workflow.py",
        "tests/test_publish_target_lanes.py",
        "tests/test_release_compiler_cache.py",
        "tests/test_release_critical_path.py",
        "tests/test_release_native_binary_cache.py",
        "tests/test_release_please_workflow.py",
        "tests/test_release_publication_workflow.py",
        "tests/test_release_train_workflow.py",
        "tests/test_unpublished_alpha_reservation.py",
        "scripts/ci/native_approval_contract_gate.py",
        "tests/test_ci_native_approval_workflow.py",
    }
    steps = load_workflow(ROOT / ".github/actions/ci-job-quality/action.yml")["runs"]["steps"]
    for name in ("Lint production sources", "Check formatting for production sources"):
        step = next(step for step in steps if step.get("name") == name)
        assert required <= set(shlex.split(step["run"]))


def _assert_graph(jobs: dict) -> None:
    wheel_ids = [f"build-native-guard-wheel-{lane}" for lane in NATIVE_WHEEL_LANES]
    assert {key for key in jobs if key.startswith("build-native-guard-wheel")} == set(wheel_ids)
    assert {key for key in jobs if key.startswith("precompile-native")} == {
        f"precompile-native-{lane}" for lane in PREPARED_WHEEL_LANES
    }
    conditions = []
    for lane, target in zip(NATIVE_WHEEL_LANES, TARGETS, strict=True):
        if lane not in PREPARED_WHEEL_LANES:
            continue
        prepare_id = f"precompile-native-{lane}"
        prepare = jobs[prepare_id]
        wheel = jobs[f"build-native-guard-wheel-{lane}"]
        assert prepare["uses"] == "./.github/workflows/release-native-prepare.yml"
        assert prepare["needs"] == ["authorize-release", "resolve-alpha-version", "resolve-canary-version"]
        assert prepare["with"]["target"] == target
        assert wheel["uses"] == "./.github/workflows/release-native-wheel.yml"
        assert wheel["needs"] == ["build", prepare_id]
        assert wheel["with"] == {
            "target": target,
            "source_sha": "${{ needs.build.outputs.source_sha }}",
            "version": "${{ needs.build.outputs.version }}",
            "channel": "${{ needs.build.outputs.channel }}",
            "precompiled": f"${{{{ needs.{prepare_id}.result == 'success' }}}}",
            "release_repair": "${{ needs.build.outputs.release_repair == 'true' }}",
        }
        assert prepare["permissions"] == {"contents": "read", "actions": "read"}
        assert wheel["permissions"] == {"contents": "read"}
        assert "secrets" not in prepare and "secrets" not in wheel
        condition = " ".join(wheel["if"].split())
        assert condition.startswith("always() && !cancelled() && needs.build.result == 'success' &&")
        assert set(re.findall(r"needs\.(precompile-native-[\w-]+)\.result", condition)) == {prepare_id}
        selected = f"contains(fromJSON(needs.build.outputs.native_wheel_targets || '[]'), '{target}')"
        assert selected in condition
        assert f"needs.{prepare_id}.result == 'success' || needs.{prepare_id}.result == 'skipped'" in condition
        assert f"needs.{prepare_id}.result == 'failure'" not in condition
        assert f"needs.{prepare_id}.result == 'cancelled'" not in condition
        assert "github.event.pull_request.head.repo.full_name == github.repository" in condition
        assert "publish-testpypi-canary" in condition
        assert "github.run_attempt == 1" in condition
        conditions.append(condition.replace(prepare_id, "prepare").replace(selected, "selected"))
    assert len(set(conditions)) == 1
    prepared = "(needs.prepare.result == 'success' || needs.prepare.result == 'skipped') && "
    for lane, target in zip(NATIVE_WHEEL_LANES, TARGETS, strict=True):
        if lane in PREPARED_WHEEL_LANES:
            continue
        wheel = jobs[f"build-native-guard-wheel-{lane}"]
        assert wheel["uses"] == "./.github/workflows/release-native-wheel.yml"
        assert wheel["needs"] == ["build"]
        assert wheel["with"] == {
            "target": target,
            "source_sha": "${{ needs.build.outputs.source_sha }}",
            "version": "${{ needs.build.outputs.version }}",
            "channel": "${{ needs.build.outputs.channel }}",
            "precompiled": False,
            "release_repair": "${{ needs.build.outputs.release_repair == 'true' }}",
        }
        assert wheel["permissions"] == {"contents": "read"}
        assert "secrets" not in wheel
        selected = f"contains(fromJSON(needs.build.outputs.native_wheel_targets || '[]'), '{target}')"
        condition = " ".join(wheel["if"].split()).replace(selected, "selected")
        assert condition == conditions[0].replace(prepared, "")
    assemble = jobs["assemble-native-guard-distributions"]
    assert assemble["needs"] == ["build", *wheel_ids, "publish-installed-bundle-assets"]
    assert assemble["runs-on"] == "ubuntu-latest"
    assert "needs.build.result == 'success'" in assemble["if"]
    assert "needs.publish-installed-bundle-assets.result == 'success'" in assemble["if"]


def test_each_wheel_waits_only_for_build_and_its_own_preparation() -> None:
    _assert_graph(load_workflow(PUBLISH_WORKFLOW)["jobs"])


@pytest.mark.parametrize("lane", PREPARED_WHEEL_LANES)
def test_every_preparation_caller_must_authorize_artifact_reads(lane):
    jobs = copy.deepcopy(load_workflow(PUBLISH_WORKFLOW)["jobs"])
    del jobs[f"precompile-native-{lane}"]["permissions"]["actions"]
    with pytest.raises(AssertionError):
        _assert_graph(jobs)


@pytest.mark.parametrize(
    "prepared,allowed", [("success", True), ("skipped", True), ("failure", False), ("cancelled", False)]
)
def test_failed_preparation_cannot_be_hidden_by_in_job_wheel_compilation(prepared, allowed):
    expression = load_workflow(PUBLISH_WORKFLOW)["jobs"]["build-native-guard-wheel-linux-x64"]["if"]
    values = {
        "always()": True,
        "cancelled()": False,
        "needs.build.result": "success",
        "needs.precompile-native-linux-x64.result": prepared,
        "contains(fromJSON(needs.build.outputs.native_wheel_targets || '[]'), 'x86_64-unknown-linux-musl')": True,
        "contains(github.event.pull_request.labels.*.name, 'publish-testpypi-canary')": False,
        "format('refs/tags/v{0}', github.event.inputs.release_version)": "refs/tags/v1.2.3",
        "needs.build.outputs.channel": "stable",
        "github.event.pull_request.head.repo.full_name": "owner/repo",
        "github.repository": "owner/repo",
        "github.event_name": "workflow_dispatch",
        "github.run_attempt": 1,
        "github.event.inputs.release_channel": "stable",
        "github.event.inputs.release_train": "main",
        "github.ref": "refs/tags/v1.2.3",
    }
    for key in sorted(values, key=len, reverse=True):
        expression = expression.replace(key, repr(values[key]))
    expression = expression.replace("&&", " and ").replace("||", " or ").replace("!", " not ")
    assert eval(" ".join(expression.split()), {"__builtins__": {}}) is allowed


@pytest.mark.parametrize("broken", ["missing", "other-target", "wrong-target-input"])
def test_graph_contract_rejects_missing_or_mismatched_target_edges(broken: str) -> None:
    jobs = copy.deepcopy(load_workflow(PUBLISH_WORKFLOW)["jobs"])
    wheel = jobs["build-native-guard-wheel-linux-x64"]
    if broken == "missing":
        wheel["needs"] = ["build"]
    elif broken == "other-target":
        wheel["needs"] = ["build", "precompile-native-macos-x64"]
    else:
        wheel["with"]["target"] = TARGETS[1]
    with pytest.raises(AssertionError):
        _assert_graph(jobs)


def test_prepare_default_is_five_targets_and_each_selector_is_exactly_one() -> None:
    workflow = load_workflow(PREPARE)
    assert workflow["permissions"] == {"contents": "read", "actions": "read"}
    assert workflow[True]["workflow_call"]["inputs"]["target"] == {
        "description": "One approved Rust target; empty retains the five-target main warmer.",
        "required": False,
        "type": "string",
        "default": "",
    }
    table = native_target_matrix(workflow["jobs"]["compile"])
    assert list(table) == ["", *PREPARED_TARGETS]
    assert table[""] == [table[target][0] for target in PREPARED_TARGETS]
    for target in PREPARED_TARGETS:
        assert len(table[target]) == 1
        assert table[target][0]["target"] == target
    assert "arbitrary-target" not in table
    assert "all" not in table
    assert "inputs.target || 'all'" in workflow["concurrency"]["group"]
    assert workflow["concurrency"]["cancel-in-progress"] == "${{ github.event_name == 'push' }}"
    assert workflow["jobs"]["compile"]["concurrency"]["queue"] == "max"


def test_single_wheel_callee_retains_all_fixed_native_hardware_tuples() -> None:
    workflow = load_workflow(NATIVE_WHEEL_WORKFLOW)
    assert set(workflow[True]) == {"workflow_call"}
    assert set(workflow["jobs"]) == {"wheel"}
    assert workflow["permissions"] == {"contents": "read"}
    inputs = workflow[True]["workflow_call"]["inputs"]
    assert {name: value["type"] for name, value in inputs.items()} == {
        "target": "string",
        "source_sha": "string",
        "version": "string",
        "channel": "string",
        "precompiled": "boolean",
        "release_repair": "boolean",
    }
    assert "secrets" not in workflow[True]["workflow_call"]
    table = native_target_matrix(native_wheel_job())
    assert list(table) == list(TARGETS)
    rows = [table[target][0] for target in TARGETS]
    assert [row["runner"] for row in rows] == [
        "ubuntu-latest",
        "macos-15-intel",
        "macos-15",
        "windows-latest",
        "windows-11-arm",
        "ubuntu-24.04-arm",
    ]
    selector = _selector_step()
    assert rows == json.loads(selector["env"]["NATIVE_WHEEL_MATRIX"])


@pytest.mark.parametrize("channel,old_source,count", [("stable", False, 6), ("canary", False, 4), ("stable", True, 4)])
def test_actual_selection_script_keeps_same_canary_and_old_source_omissions(tmp_path, channel, old_source, count):
    selector = _selector_step()
    source = (
        "0" * 40 if old_source else subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    )
    output = tmp_path / "outputs"
    result = subprocess.run(
        ["bash", "-c", selector["run"]],
        cwd=ROOT,
        text=True,
        capture_output=True,
        env={
            **os.environ,
            "CHANNEL": channel,
            "SOURCE_SHA": source,
            "NATIVE_WHEEL_MATRIX": selector["env"]["NATIVE_WHEEL_MATRIX"],
            "GITHUB_OUTPUT": str(output),
        },
    )
    assert result.returncode == 0, result.stderr
    values = dict(line.split("=", 1) for line in output.read_text().splitlines())
    assert json.loads(values["targets"]) == [row["target"] for row in json.loads(values["matrix"])]
    assert len(json.loads(values["targets"])) == count
    assert (TARGETS[-1] in json.loads(values["targets"])) is (count == 6)


def _assembly_condition_allows(selected: tuple[str, ...], outcomes: dict[str, str]) -> bool:
    expression = load_workflow(PUBLISH_WORKFLOW)["jobs"]["assemble-native-guard-distributions"]["if"]
    expression = expression.replace("always()", "True").replace("cancelled()", "False")
    for lane, target in zip(NATIVE_WHEEL_LANES, TARGETS, strict=True):
        expression = expression.replace(
            f"contains(fromJSON(needs.build.outputs.native_wheel_targets || '[]'), '{target}')",
            repr(target in selected),
        )
        expression = expression.replace(f"needs.build-native-guard-wheel-{lane}.result", repr(outcomes[lane]))
    expression = expression.replace("needs.build.result", "'success'")
    expression = expression.replace("needs.publish-installed-bundle-assets.result", "'success'")
    expression = expression.replace("&&", " and ").replace("||", " or ").replace("!", " not ")
    return eval(" ".join(expression.split()), {"__builtins__": {}})


def _assembly_allowed(selected: tuple[str, ...], outcomes: dict[str, str]) -> bool:
    condition = _assembly_condition_allows(selected, outcomes)
    rows = _matrix_rows()
    matrix = [row for row in rows if row["target"] in selected]
    source = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    return condition and _inventory_result(json.dumps(selected), json.dumps(matrix), ROOT, source).returncode == 0


@pytest.mark.parametrize("missing_lane", NATIVE_WHEEL_LANES)
@pytest.mark.parametrize("result", ["skipped", "failure", "cancelled"])
def test_assembly_rejects_every_selected_target_that_did_not_succeed(missing_lane, result):
    outcomes = dict.fromkeys(NATIVE_WHEEL_LANES, "success")
    assert _assembly_allowed(TARGETS, outcomes)
    outcomes[missing_lane] = result
    assert not _assembly_allowed(TARGETS, outcomes)


@pytest.mark.parametrize("unselected", ["windows-arm64", "linux-arm64"])
def test_assembly_allows_only_intentionally_unselected_target_to_skip(unselected: str) -> None:
    outcomes = dict.fromkeys(NATIVE_WHEEL_LANES, "success")
    outcomes["windows-arm64"] = outcomes["linux-arm64"] = "skipped"
    assert _assembly_condition_allows(TARGETS[:4], outcomes)
    source = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    assert (
        _inventory_result(json.dumps(TARGETS[:4]), json.dumps(_matrix_rows()[:4]), ROOT, source, "canary").returncode
        == 0
    )
    for result in ("failure", "cancelled", "success"):
        outcomes[unselected] = result
        assert not _assembly_condition_allows(TARGETS[:4], outcomes)


def _selector_step():
    steps = load_workflow(PUBLISH_WORKFLOW)["jobs"]["build"]["steps"]
    return next(step for step in steps if step.get("id") == "native_wheel_matrix")


def _matrix_rows():
    selector = _selector_step()
    return json.loads(selector["env"]["NATIVE_WHEEL_MATRIX"])


def _inventory_step():
    steps = load_workflow(PUBLISH_WORKFLOW)["jobs"]["assemble-native-guard-distributions"]["steps"]
    return next(step for step in steps if step.get("name") == "Validate source-bound native wheel inventory")


def _inventory_result(selected, matrix, root, source, channel="stable"):
    env = {**os.environ, "SOURCE_SHA": source, "CHANNEL": channel}
    for key, value in [("NATIVE_WHEEL_TARGETS", selected), ("NATIVE_WHEEL_MATRIX", matrix)]:
        env.pop(key, None)
        if value is not None:
            env[key] = value
    return subprocess.run(
        [sys.executable, "-c", _inventory_step()["run"]], cwd=root, env=env, text=True, capture_output=True, check=False
    )


@pytest.fixture(scope="module")
def qualified_sources(tmp_path_factory):
    sources = {}
    # False predates GitHub-only wheels, "manifest" predates the Linux ARM64 wheel, True carries both.
    for capable in (False, "manifest", True):
        root = tmp_path_factory.mktemp(f"source-{capable}")
        (root / "marker").write_text("qualified source\n")
        if capable:
            manifest = root / "scripts/embed_native_wheel_manifest.py"
            manifest.parent.mkdir()
            manifest.write_text("# source capability fixture\n")
        if capable is True:
            (root / "scripts/release_artifact_sets.py").write_text('GITHUB_ONLY = {"manylinux_2_17_aarch64"}\n')
        env = {**os.environ, "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1"}
        subprocess.run(["git", "init", "--quiet"], cwd=root, env=env, check=True)
        subprocess.run(["git", "add", "."], cwd=root, env=env, check=True)
        subprocess.run(
            [
                "git",
                "-c",
                "user.name=Fixture",
                "-c",
                "user.email=fixture@example.invalid",
                "-c",
                "commit.gpgsign=false",
                "commit",
                "--quiet",
                "-m",
                "qualified source fixture",
            ],
            cwd=root,
            env=env,
            check=True,
        )
        sources[capable] = (
            root,
            subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, env=env, text=True).strip(),
        )
    return sources


def _expected_rows(capable, channel):
    rows = _matrix_rows()
    if channel == "canary" or not capable:
        return rows[:4]
    return rows if capable is True else rows[:5]


@pytest.mark.parametrize("channel", ["stable", "alpha", "canary"])
@pytest.mark.parametrize("capable", [False, "manifest", True])
def test_inventory_gate_preserves_original_source_capability_and_channel_routes(qualified_sources, capable, channel):
    root, source = qualified_sources[capable]
    rows = _expected_rows(capable, channel)
    targets = [row["target"] for row in rows]
    result = _inventory_result(json.dumps(targets), json.dumps(rows), root, source, channel)
    assert result.returncode == 0, result.stderr
    if channel != "canary" and capable:
        # A source that ships the Linux ARM64 wheel cannot assemble without it, and an older one cannot add it.
        other = _matrix_rows()[:5] if capable is True else _matrix_rows()
        other_targets = json.dumps([row["target"] for row in other])
        assert _inventory_result(other_targets, json.dumps(other), root, source, channel).returncode != 0


@pytest.mark.parametrize("channel", ["stable", "alpha", "canary"])
@pytest.mark.parametrize("capable", [False, "manifest", True])
def test_platform_selection_matches_the_inventory_gate_for_each_source(qualified_sources, tmp_path, capable, channel):
    root, source = qualified_sources[capable]
    selector = _selector_step()
    output = tmp_path / "outputs"
    env = {"CHANNEL": channel, "SOURCE_SHA": source, "GITHUB_OUTPUT": str(output)}
    env["NATIVE_WHEEL_MATRIX"] = selector["env"]["NATIVE_WHEEL_MATRIX"]
    result = subprocess.run(
        ["bash", "-c", selector["run"]], cwd=root, text=True, capture_output=True, env={**os.environ, **env}
    )
    assert result.returncode == 0, result.stderr
    values = dict(line.split("=", 1) for line in output.read_text().splitlines())
    assert json.loads(values["matrix"]) == _expected_rows(capable, channel)


@pytest.mark.parametrize(
    "invalid",
    [
        "missing-targets",
        "missing-matrix",
        "malformed-targets",
        "malformed-matrix",
        "empty-targets",
        "empty-matrix",
        "object-targets",
        "object-matrix",
        "duplicate-target",
        "duplicate-row",
        "unknown-target",
        "unknown-row",
        "mismatch",
        "supported-stable-missing-one",
        "wrong-source",
        "unknown-channel",
        "canary-extra-target",
    ],
)
def test_inventory_gate_rejects_missing_or_corrupt_outputs_without_publish_escape(qualified_sources, invalid):
    root, source = qualified_sources[True]
    rows, targets = _matrix_rows(), list(TARGETS)
    channel = "canary" if invalid == "canary-extra-target" else "stable"
    if invalid == "duplicate-target":
        targets.append(targets[0])
    elif invalid == "duplicate-row":
        rows.append(copy.deepcopy(rows[0]))
    elif invalid == "unknown-target":
        targets[0] = "unapproved-target"
    elif invalid == "unknown-row":
        rows[0]["target"] = "unapproved-target"
    elif invalid == "mismatch":
        targets.pop()
    elif invalid == "supported-stable-missing-one":
        targets.pop()
        rows.pop()
    elif invalid == "wrong-source":
        source = "0" * 40
    elif invalid == "unknown-channel":
        channel = "unknown"
    selected, matrix = json.dumps(targets), json.dumps(rows)
    if invalid == "missing-targets":
        selected = None
    elif invalid == "missing-matrix":
        matrix = None
    if invalid.endswith("targets"):
        selected = {"malformed-targets": "[", "empty-targets": "[]", "object-targets": "{}"}.get(invalid, selected)
    if invalid.endswith("matrix"):
        matrix = {"malformed-matrix": "[", "empty-matrix": "[]", "object-matrix": "{}"}.get(invalid, matrix)
    result = _inventory_result(selected, matrix, root, source, channel)
    assert result.returncode != 0, (invalid, result.stdout)
    assert all(
        "needs.assemble-native-guard-distributions.result == 'success'" in job["if"]
        for job in load_workflow(PUBLISH_WORKFLOW)["jobs"].values()
        if "assemble-native-guard-distributions" in job.get("needs", [])
    )


@pytest.mark.parametrize("field", ["runner", "platform_tag", "runtime", "source_compiler", "rustflags", "extra"])
def test_inventory_gate_rejects_changed_target_tuple(qualified_sources, field):
    root, source = qualified_sources[True]
    rows = _matrix_rows()
    rows[0][field] = "unapproved-value"
    result = _inventory_result(json.dumps(TARGETS), json.dumps(rows), root, source)
    assert result.returncode != 0, result.stdout


def test_inventory_gate_is_mandatory_before_artifacts_and_empty_selection_cannot_assemble():
    job = load_workflow(PUBLISH_WORKFLOW)["jobs"]["assemble-native-guard-distributions"]
    step = _inventory_step()
    assert "if" not in step and "continue-on-error" not in step and "continue-on-error" not in job
    assert all(
        job["steps"].index(step) < index
        for index, item in enumerate(job["steps"])
        if "actions/download-artifact@" in item.get("uses", "")
    )
    assert not _assembly_allowed((), dict.fromkeys(NATIVE_WHEEL_LANES, "skipped"))
