from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from scripts import qualify_guard_native


def test_paired_driver_preserves_alternating_environments_and_rejects_unqualified_samples(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    baseline, candidate = tmp_path / "baseline-python", tmp_path / "candidate-python"
    baseline.symlink_to(sys.executable)
    candidate.symlink_to(sys.executable)
    calls: list[str] = []

    def run(argv: tuple[str, ...], **_kwargs: object) -> SimpleNamespace:
        arm = "baseline" if argv[0] == str(baseline) else "candidate"
        assert argv[argv.index("--receipt-profile") + 1] == ("baseline_2e672d2" if arm == "baseline" else "candidate")
        calls.append(arm)
        raw_file = Path(argv[argv.index("--raw-file") + 1])
        raw_file.write_text("{}")
        report = {
            "schema": "hol-guard.native-qualification-block.v1",
            "runtime": {"runtime_sha256": arm, "package_record_sha256": arm, "python_version": "3.12.14"},
            "corpus_digest": "same-corpus",
            "hardware": {"platform": "linux-x64", "cpu_model": "same-cpu"},
            "resources": {"sample_minimum_met": False},
            "measurements": {
                "DAEMON_INGRESS.claude-code.PostToolUse": {
                    "count": 2,
                    "p95_ms": 10 if arm == "baseline" else 7,
                    "p99_ms": 12,
                }
            },
        }
        return SimpleNamespace(
            returncode=0,
            timed_out=False,
            containment_failed=False,
            output_limit_exceeded=False,
            stdout=json.dumps(report),
        )

    monkeypatch.setattr(qualify_guard_native, "run_isolated_hook_process", run)
    args = argparse.Namespace(
        baseline_python=baseline,
        candidate_python=candidate,
        baseline_artifact=None,
        candidate_artifact=None,
        runs=3,
        mode="smoke",
        output_dir=tmp_path / "reports",
        block_timeout_seconds=10,
    )
    result = qualify_guard_native._run_pair(args)
    assert calls == ["baseline", "candidate", "candidate", "baseline", "baseline", "candidate"]
    assert result["qualification_complete"] is False
    assert result["sampling_passed"] is False
    assert (args.output_dir / "aggregate" / "comparison.json").is_file()
    assert len(list((args.output_dir / "private_samples").iterdir())) == 6


def test_paired_failure_prints_the_same_sanitized_evidence_as_its_artifact(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    failure = {
        "schema": "hol-guard.native-qualification-failure.v1",
        "category": "AttributeError",
        "reason": "qualification_fixture.unclassified_failure",
        "origin": "native_slo_faults.__enter__",
        "line": 74,
    }
    completed = SimpleNamespace(
        returncode=1,
        timed_out=False,
        containment_failed=False,
        output_limit_exceeded=False,
        stdout=json.dumps(failure),
        stderr="private runtime output must never be printed",
    )
    monkeypatch.setattr(qualify_guard_native, "run_isolated_hook_process", lambda *_args, **_kwargs: completed)
    args = argparse.Namespace(
        baseline_python=tmp_path / "baseline-python",
        candidate_python=tmp_path / "candidate-python",
        baseline_artifact=None,
        candidate_artifact=None,
        runs=1,
        mode="smoke",
        output_dir=tmp_path / "reports",
        block_timeout_seconds=10,
    )
    with pytest.raises(RuntimeError, match="paired block failed"):
        qualify_guard_native._run_pair(args)
    printed = capsys.readouterr().err
    artifact = args.output_dir / "aggregate" / "00-baseline-failure.json"
    lines = [json.loads(line) for line in printed.splitlines()]
    assert lines[0] == json.loads(artifact.read_text())
    assert lines[0]["origin"] == "native_slo_faults.__enter__"
    assert [item["arm"] for item in lines] == ["baseline", "candidate"]
    incomplete = json.loads((args.output_dir / "aggregate" / "incomplete-pair.json").read_text())
    assert incomplete["qualification_complete"] is False
    assert incomplete["attempted_blocks"] == 2
    assert incomplete["completed_blocks"] == {"baseline": 0, "candidate": 0}
    assert incomplete["failures"] == lines
    assert completed.stderr not in printed


def test_failed_baseline_retains_successful_candidate_without_comparing_or_resampling(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls = []

    def run(argv: tuple[str, ...], **_kwargs: object) -> SimpleNamespace:
        arm = Path(argv[0]).name
        calls.append(arm)
        failed = arm == "baseline"
        report = {"schema": "hol-guard.native-qualification-block.v1"}
        if not failed:
            Path(argv[argv.index("--raw-file") + 1]).write_text("{}")
        return SimpleNamespace(
            returncode=1 if failed else 0,
            timed_out=failed,
            containment_failed=False,
            output_limit_exceeded=False,
            stdout="" if failed else json.dumps(report),
        )

    monkeypatch.setattr(qualify_guard_native, "run_isolated_hook_process", run)
    args = argparse.Namespace(
        baseline_python=tmp_path / "baseline",
        candidate_python=tmp_path / "candidate",
        baseline_artifact=None,
        candidate_artifact=None,
        runs=3,
        mode="smoke",
        output_dir=tmp_path / "reports",
        block_timeout_seconds=10,
    )
    with pytest.raises(RuntimeError, match="both arms retained"):
        qualify_guard_native._run_pair(args)
    public = args.output_dir / "aggregate"
    assert calls == ["baseline", "candidate"]
    assert json.loads((public / "00-candidate.json").read_text())["schema"] == "hol-guard.native-qualification-block.v1"
    assert not (public / "comparison.json").exists()
    incomplete = json.loads((public / "incomplete-pair.json").read_text())
    assert incomplete["completed_blocks"] == {"baseline": 0, "candidate": 1}
    assert incomplete["attempted_blocks"] == 2
    assert incomplete["unattempted_blocks"] == 4
    assert incomplete["comparison_available"] is incomplete["qualification_complete"] is False
    assert incomplete["failures"][0]["timed_out"] is True
