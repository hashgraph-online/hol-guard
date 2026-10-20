"""Guard the fast artifact producer without weakening native replay coverage."""

from __future__ import annotations

from pathlib import Path

import yaml

from tests.support.ci_workflow import expand_ci_job_actions

ROOT = Path(__file__).resolve().parents[1]


def _jobs() -> dict:
    document = yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8"))
    return expand_ci_job_actions(document)["jobs"]


def test_native_evaluator_produces_verified_artifacts_before_python_gates() -> None:
    jobs = _jobs()
    producer = jobs["native-command-evaluators"]["steps"]
    names = [step.get("name") for step in producer]
    assert "Build native command evaluators once for pytest shards" in names
    assert "Verify generated native command catalogs before pytest fan-out" in names
    assert names.index("Verify generated native command catalogs before pytest fan-out") < names.index(
        "Upload native command evaluators"
    )
    assert "Upload matching native command projections" in names

    # Public catalogs must be regenerated from the staged trust bindings before
    # they are uploaded. All consumers must receive the same verified artifacts.
    assert sum(step.get("uses") == "./.github/actions/setup-ci-python" for step in producer) == 1
    generation = names.index("Prepare current public directory before pytest collection")
    uploaded = names.index("Upload matching native command projections")
    assert names.index("Verify generated native command catalogs before pytest fan-out") < generation < uploaded
    generated = producer[generation]["run"]
    assert "prepare_extension_directory.py" in generated
    assert "--compiler rust/target/release/guard-command-source --check" in generated

    # Native contract checks and replay cases do not delay the artifact producer.
    assert not any("uv run --no-sync pytest" in step.get("run", "") for step in producer)
    assert not any("Benign false-positive and Gauntlet replay gates" in str(name) for name in names)


def test_native_replay_shards_are_complete_and_required() -> None:
    jobs = _jobs()
    job = jobs["native-gates"]
    assert job["needs"] == "native-command-evaluators"
    assert job["strategy"]["fail-fast"] is False
    assert job["strategy"]["matrix"]["shard-index"] == list(range(8))
    assert job["timeout-minutes"] == 5
    steps = job["steps"]
    assert any(step.get("uses") == "./.github/actions/setup-ci-python" for step in steps)

    downloads = [
        step.get("with", {}).get("name")
        for step in steps
        if step.get("uses", "").startswith("actions/download-artifact@")
    ]
    assert "pytest-native-command-evaluators" in downloads
    assert any(step.get("uses") == "./.github/actions/restore-command-projections" for step in steps)

    contracts = next(
        step for step in steps if step.get("name") == "Check native contract groups after artifact fan-out"
    )
    assert contracts["if"] == "matrix.shard-index == 0"
    assert "test_native_contract_validates_every_authored_signature" in contracts["run"]
    assert "test_install_writes_managed_extension_that_denies_on_hook_errors" in contracts["run"]
    assert "test_managed_extension_fails_safe_on_ambiguous_success_payloads" in contracts["run"]

    replay = next(
        step
        for step in steps
        if step.get("name") == "Benign false-positive and Gauntlet replay gates (model-free, native path)"
    )
    assert replay["env"]["SHARD_COUNT"] == 8
    assert "set -o pipefail" in replay["run"]
    assert "pytest --collect-only -q" in replay["run"]
    assert "sort gate-nodes.txt | awk" in replay["run"]
    assert "(NR - 1) % n == i" in replay["run"]
    assert "test -s gate-shard.txt" in replay["run"]
    assert "-n 4 --dist load --max-worker-restart 0" in replay["run"]
    for gate_file in (
        "tests/test_guard_benign_false_positive_gate.py",
        "tests/test_guard_gauntlet_replay_gate.py",
        "tests/test_guard_command_corpus_benign_allow.py",
    ):
        assert gate_file in replay["run"]

    required = jobs["required"]
    assert "native-gates" in required["needs"]
    assert '"native-gates"' in required["steps"][0]["run"]
