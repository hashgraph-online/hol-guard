from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from scripts.ci.mutation_targets import TARGETS, render_mutmut_config
from scripts.ci.run_mutation_target import prepare_workspace

ROOT = Path(__file__).resolve().parents[1]
SCRIPT_PATH = ROOT / "scripts" / "ci" / "mutation_gate.py"
SPEC = importlib.util.spec_from_file_location("mutation_gate", SCRIPT_PATH)
assert SPEC is not None and SPEC.loader is not None
mutation_gate = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = mutation_gate
SPEC.loader.exec_module(mutation_gate)


def _counts(**overrides: int) -> dict[str, int]:
    counts = {
        "killed": 382,
        "survived": 206,
        "total": 588,
        "no_tests": 0,
        "skipped": 0,
        "suspicious": 0,
        "timeout": 0,
        "segfault": 0,
        "check_was_interrupted_by_user": 0,
    }
    counts.update(overrides)
    return counts


def test_mutation_score_uses_all_evaluated_mutants() -> None:
    assert mutation_gate.mutation_score(_counts()) == pytest.approx(64.965986)


def test_mutation_gate_supports_direct_script_execution(tmp_path: Path) -> None:
    summary = tmp_path / "summary.json"
    summary.write_text(json.dumps(_counts()), encoding="utf-8")
    # Model installed generator metadata without requiring the optional mutation extra.
    metadata_root = tmp_path / "installed-metadata"
    for package, version in mutation_gate.BASELINES["command-model"].tool_versions:
        distribution = metadata_root / f"{package}-{version}.dist-info"
        distribution.mkdir(parents=True)
        (distribution / "METADATA").write_text(f"Name: {package}\nVersion: {version}\n", encoding="utf-8")
    environment = {
        **os.environ,
        "PYTHONPATH": os.pathsep.join((str(metadata_root), os.environ.get("PYTHONPATH", ""))),
    }

    result = subprocess.run(
        [
            sys.executable,
            str(SCRIPT_PATH),
            "--target",
            "command-model",
            "--summary",
            str(summary),
        ],
        cwd=tmp_path,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)["target"] == "command-model"


def test_mutation_gate_accepts_measured_parser_baseline_and_target_contracts(tmp_path: Path) -> None:
    baseline = mutation_gate.BASELINES["command-model"]
    assert mutation_gate.validation_errors(baseline, _counts()) == ()
    assert set(TARGETS) == {
        "command-model",
        "secret-flow",
        "hook-output",
        "approval-reuse",
        "package-intent",
        "package-policy",
        "recovery",
    }
    assert len({target.source_path for target in TARGETS.values()}) == len(TARGETS)
    for target in TARGETS.values():
        assert (ROOT / target.source_path).is_file(), target.source_path
        for test_path in target.test_selection:
            assert (ROOT / test_path.partition("::")[0]).is_file(), test_path
        config = render_mutmut_config(target)
        assert 'source_paths = ["src"]' in config
        assert f'only_mutate = ["{target.source_path}"]' in config

    output = tmp_path / "pyproject.toml"
    result = subprocess.run(
        [sys.executable, "scripts/ci/mutation_targets.py", "--target", "secret-flow", "--output", str(output)],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    assert output.read_text(encoding="utf-8") == render_mutmut_config(TARGETS["secret-flow"])
    workspace = tmp_path / "workspace"
    config_path = prepare_workspace(ROOT, TARGETS["secret-flow"], workspace)
    assert (workspace / "src").is_symlink()
    assert (workspace / "tests").is_symlink()
    assert config_path.read_text(encoding="utf-8") == render_mutmut_config(TARGETS["secret-flow"])
    runner_result = subprocess.run(
        [sys.executable, "scripts/ci/run_mutation_target.py", "--target", "secret-flow", "--dry-run"],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    assert runner_result.returncode == 0, runner_result.stderr
    assert '"target": "secret-flow"' in runner_result.stdout


def test_mutation_gate_reports_every_failed_constraint() -> None:
    baseline = mutation_gate.BASELINES["command-model"]
    errors = mutation_gate.validation_errors(
        baseline,
        _counts(killed=300, survived=300, total=600, timeout=1, suspicious=1),
    )

    assert errors == (
        "expected 588 mutants, found 600",
        "mutation score 50.00% is below 64.00%",
        "suspicious must be zero, found 1",
        "timeout must be zero, found 1",
    )


def test_load_counts_rejects_invalid_or_inconsistent_summaries(tmp_path: Path) -> None:
    path = tmp_path / "summary.json"
    path.write_text(json.dumps(_counts(total=611)), encoding="utf-8")

    with pytest.raises(ValueError, match="total"):
        mutation_gate.load_counts(path)
