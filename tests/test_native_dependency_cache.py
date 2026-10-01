"""Preserve lock-bound native dependency wheels without reusing tested artifacts."""

from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]


def _configuration() -> tuple[dict, dict]:
    action = yaml.safe_load((ROOT / ".github/actions/native-regression/action.yml").read_text())
    workflow = yaml.safe_load((ROOT / ".github/workflows/native-wheel-ci.yml").read_text())
    return action, workflow


def test_each_native_platform_has_one_regression_cache_writer() -> None:
    """Both setup paths use shard zero, while other shards remain read-only."""
    action, workflow = _configuration()
    setup_steps = [
        step for step in action["runs"]["steps"] if step.get("uses", "").startswith("astral-sh/setup-uv@")
    ]
    assert len(setup_steps) == 2
    for step in setup_steps:
        options = step["with"]
        assert options["enable-cache"] is True
        assert options["save-cache"] == "${{ inputs.shard-index == '0' }}"
        assert options["prune-cache"] is False
        assert options["cache-suffix"] == "native-ci-v1"
        assert options["cache-dependency-glob"].splitlines() == ["pyproject.toml", "uv.lock"]
    assert setup_steps[0]["with"] == setup_steps[1]["with"]
    for name in ("linux-regression", "macos-regression", "windows-regression"):
        job = workflow["jobs"][name]
        assert job["strategy"]["matrix"]["shard"] == list(range(8))
        shard = next(step for step in job["steps"] if step.get("uses") == "./.github/actions/native-regression")
        assert shard["with"]["shard-index"] == "${{ matrix.shard }}"
        assert shard["with"]["shard-count"] == "8"


def test_macos_proofs_restore_the_same_lock_bound_cache_without_writing() -> None:
    """Proof consumers use the regression producer's full cache on matching runners."""
    action, workflow = _configuration()
    producer = next(step for step in action["runs"]["steps"] if step.get("id") == "setup-uv-primary")
    proof = workflow["jobs"]["macos-proof"]
    consumer = next(step for step in proof["steps"] if step.get("uses", "").startswith("astral-sh/setup-uv@"))
    for key in ("version", "enable-cache", "cache-suffix", "cache-dependency-glob", "prune-cache"):
        assert consumer["with"][key] == producer["with"][key]
    assert consumer["with"]["save-cache"] is False
    assert proof["strategy"]["matrix"]["runner"] == ["macos-15-intel", "macos-15"]
    assert proof["strategy"]["matrix"]["proof"] == ["default", "pi", "extensions", "performance"]
    action_python = next(
        step for step in action["runs"]["steps"] if step.get("uses", "").startswith("actions/setup-python@")
    )
    proof_python = next(
        step for step in proof["steps"] if step.get("uses", "").startswith("actions/setup-python@")
    )
    assert proof_python["with"]["python-version"] == action_python["with"]["python-version"] == "3.12"


def test_dependency_cache_does_not_replace_same_run_wheel_or_full_regression_manifest() -> None:
    """Every run still installs and tests its own artifact with frozen dependencies."""
    action, workflow = _configuration()
    steps = action["runs"]["steps"]
    commands = "\n".join(step.get("run", "") for step in steps)
    assert "uv sync --frozen --no-dev --group ci-test --no-install-project --python 3.12" in commands
    assert 'uv pip install --python "$interpreter" --no-deps native-dist/*.whl' in commands
    download = next(step for step in steps if step.get("uses", "").startswith("actions/download-artifact@"))
    assert download["with"] == {"name": "${{ inputs.artifact-name }}"}
    run = next(step for step in steps if step.get("name") == "Run the complete manifest's assigned shard")
    assert run["env"]["HOL_GUARD_NATIVE_REGRESSION"] == "1"
    assert run["env"]["HOL_GUARD_TEST_USE_INSTALLED"] == "1"
    assert "scripts/ci/native_regression_shard.py" in run["run"]
    assert not run.get("continue-on-error", False)
    assert "native-regression-complete" in workflow["jobs"]["linux-x64"]["needs"]
    assert "native-regression-complete" in workflow["jobs"]["windows-x64"]["needs"]
