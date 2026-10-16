from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from scripts import bench_guard_native_installed_slo as benchmark
from scripts.native_slo_failure_reason import annotate_failure_reason, contract_failure_reason


def test_contract_failure_names_the_failed_check_in_report_and_stderr(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    runtime = tmp_path / "fixture-runtime"
    runtime.write_bytes(b"fixture")
    output = tmp_path / "failed.json"

    def fail_run(*_args: object, **_kwargs: object) -> dict[str, object]:
        raise RuntimeError("native_installed_slo_failed: hook scheduler capacity was not steady after prewarm")

    monkeypatch.setattr(benchmark, "run_slo", fail_run)
    monkeypatch.setattr(sys, "argv", ["bench", "--runtime", str(runtime), "--json", str(output)])

    assert benchmark.main() == 1
    label = "hook_scheduler_capacity_was_not_steady_after_prewarm"
    parsed = json.loads(output.read_text(encoding="utf-8"))
    assert parsed["failure"]["category"] == "benchmark_contract"
    assert parsed["failure"]["reason"] == label
    captured = capsys.readouterr()
    assert json.loads(captured.out)["failure"]["reason"] == label
    assert f"benchmark aborted ({label})" in captured.err


def test_wrapped_contract_failure_is_found_through_the_cause_chain() -> None:
    try:
        try:
            raise RuntimeError("native_installed_slo_failed: resident stream pool burst returned request errors")
        except RuntimeError as inner:
            raise ValueError("wrapper") from inner
    except ValueError as error:
        assert contract_failure_reason(error) == "resident_stream_pool_burst_returned_request_errors"


@pytest.mark.parametrize(
    "error",
    [
        RuntimeError("fixture exception with /fixture/request"),
        RuntimeError("native_installed_slo_failed: " + "x" * 300),
        RuntimeError("native_installed_slo_failed:", "extra"),
        type("CustomError", (RuntimeError,), {})("native_installed_slo_failed: custom formatter"),
        OSError("native_installed_slo_failed: not a benchmark check"),
        RuntimeError("native_installed_slo_failed: read /fixture/home/.ssh failed"),
        RuntimeError("native_installed_slo_failed: read C:\\fixture failed"),
        RuntimeError("native_installed_slo_failed: read ~fixture failed"),
    ],
)
def test_other_exception_text_is_never_reported(error: BaseException) -> None:
    result: dict[str, object] = {"failure": {"category": "benchmark_internal_failure"}}
    assert annotate_failure_reason(result, error) is None
    assert result == {"failure": {"category": "benchmark_internal_failure"}}


@pytest.mark.parametrize(
    ("message", "label"),
    [
        ("native_installed_slo_failed: api token was rejected", "redacted"),
        (
            "native_installed_slo_failed: native/test override remained in proof environment",
            "native_test_override_remained_in_proof_environment",
        ),
        ("native_installed_slo_failed: recovery sample 3 failed", "recovery_sample_3_failed"),
        ("native_installed_slo_failed: " + "a b " * 40, ("a_b_" * 24).rstrip("_")),
    ],
)
def test_reason_labels_stay_bounded_and_privacy_safe(message: str, label: str) -> None:
    result: dict[str, object] = {"failure": {"category": "benchmark_contract"}}
    assert annotate_failure_reason(result, RuntimeError(message)) == label
    assert len(label) <= 96
