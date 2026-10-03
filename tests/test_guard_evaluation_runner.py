"""Focused checks for the bounded built-in synthetic evaluation runner."""

from __future__ import annotations

import json
import os
import time
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import evaluation_cli_run as cli_run
from codex_plugin_scanner.guard import evaluation_runner as runner
from codex_plugin_scanner.guard.adapters.hook_python_subprocess import ProbeResult
from codex_plugin_scanner.guard.evaluation_cli import main
from codex_plugin_scanner.guard.evaluation_contracts import EvaluationContractError, EvaluationProfile
from codex_plugin_scanner.guard.evaluation_preflight import EvaluationSetup, setup_evaluation
from codex_plugin_scanner.guard.evaluation_witness import FileWitnessPair

from .evaluation_cli_fixtures import _profile


def _write_runner_profile(tmp_path: Path, case_ids: tuple[str, ...]) -> tuple[Path, dict[str, object]]:
    executable = tmp_path / "unused-host"
    executable.write_text("#!/bin/sh\nexit 64\n", encoding="utf-8")
    executable.chmod(0o755)
    profile = _profile(tmp_path, executable)
    profile["expectedCapabilities"] = [{"capabilityId": case_id, "expectedAction": "block"} for case_id in case_ids]
    profile_path = tmp_path / "runner-profile.json"
    profile_path.write_text(json.dumps(profile), encoding="utf-8")
    return profile_path, profile


def _run_payload(capsys, profile_path: Path, *extra: str) -> tuple[int, dict[str, object]]:
    code = main(["run", "--profile", str(profile_path), *extra])
    payload = json.loads(capsys.readouterr().out)
    return code, payload


@pytest.mark.skipif(os.name == "nt", reason="CLI recovery storage requires POSIX ownership checks")
def test_run_rejects_profile_capability_outside_builtin_cases(tmp_path: Path, capsys) -> None:
    profile_path, _ = _write_runner_profile(tmp_path, ("synthetic.read",))

    code, payload = _run_payload(capsys, profile_path)

    assert code == 2
    assert payload["status"] == "not_run"
    assert payload["error"]["code"] == "case_not_supported"


@pytest.mark.skipif(os.name == "nt", reason="CLI recovery storage requires POSIX ownership checks")
def test_run_rejects_partial_case_selection(tmp_path: Path, capsys) -> None:
    profile_path, _ = _write_runner_profile(
        tmp_path,
        (runner.SHELL_CASE_ID, runner.EGRESS_CASE_ID),
    )

    code, payload = _run_payload(capsys, profile_path, "--case", runner.SHELL_CASE_ID)

    assert code == 2
    assert payload["status"] == "not_run"
    assert payload["error"]["code"] == "case_coverage_invalid"


@pytest.mark.skipif(os.name == "nt", reason="CLI recovery storage requires POSIX ownership checks")
def test_run_reports_timeout_and_cleans_owned_setup(monkeypatch, tmp_path: Path, capsys) -> None:
    profile_path, _ = _write_runner_profile(tmp_path, (runner.SHELL_CASE_ID,))

    def timeout(*_args, **_kwargs):
        raise runner.EvaluationRunnerError("run_timeout", "deadline", status="blocked_environment")

    monkeypatch.setattr(runner, "_run_case", timeout)
    code, payload = _run_payload(capsys, profile_path)

    assert code == 2
    assert payload["status"] == "blocked_environment"
    assert payload["run"]["cases"][0]["errorCode"] == "run_timeout"
    assert payload["cleanup"] == {"removed": True, "recoveryTokenRetained": False}
    assert not list(tmp_path.glob("hol-guard-eval-*"))


@pytest.mark.parametrize(
    ("patch_name", "error_code"),
    (
        ("check_network_ready", "receiver_not_ready"),
        ("_fixed_network_control", "control_failed"),
    ),
)
@pytest.mark.skipif(os.name == "nt", reason="CLI recovery storage requires POSIX ownership checks")
def test_run_reports_receiver_and_control_failures(
    monkeypatch,
    tmp_path: Path,
    capsys,
    patch_name: str,
    error_code: str,
) -> None:
    profile_path, _ = _write_runner_profile(tmp_path, (runner.EGRESS_CASE_ID,))
    if patch_name == "check_network_ready":
        monkeypatch.setattr(runner.LocalSideEffectWitness, patch_name, lambda _self, **_kwargs: False)
    else:
        monkeypatch.setattr(
            runner,
            patch_name,
            lambda *_args, **_kwargs: (_ for _ in ()).throw(
                runner.EvaluationRunnerError(error_code, "control", status="failed")
            ),
        )

    code, payload = _run_payload(capsys, profile_path)

    assert code == 2
    assert payload["run"]["cases"][0]["errorCode"] == error_code
    assert payload["cleanup"]["removed"] is True
    assert not list(tmp_path.glob("hol-guard-eval-*"))


@pytest.mark.skipif(os.name == "nt", reason="CLI recovery storage requires POSIX ownership checks")
def test_run_reports_witness_operation_failure_per_case(monkeypatch, tmp_path: Path, capsys) -> None:
    profile_path, _ = _write_runner_profile(tmp_path, (runner.SHELL_CASE_ID,))
    monkeypatch.setattr(
        runner.LocalSideEffectWitness,
        "new_file_pair",
        lambda _self: (_ for _ in ()).throw(RuntimeError("fixture unavailable")),
    )

    code, payload = _run_payload(capsys, profile_path)

    assert code == 2
    assert payload["run"]["cases"][0]["errorCode"] == "witness_failed"
    assert payload["cleanup"]["removed"] is True


@pytest.mark.skipif(os.name == "nt", reason="CLI recovery storage requires POSIX ownership checks")
def test_network_readiness_uses_remaining_run_deadline(monkeypatch, tmp_path: Path, capsys) -> None:
    profile_path, profile_data = _write_runner_profile(tmp_path, (runner.EGRESS_CASE_ID,))
    profile_data["resourceLimits"]["maxDurationSeconds"] = 1  # type: ignore[index]
    profile_path.write_text(json.dumps(profile_data), encoding="utf-8")
    observed: list[float] = []

    def not_ready(_self, **kwargs):
        observed.append(kwargs["timeout_seconds"])
        return False

    monkeypatch.setattr(runner.LocalSideEffectWitness, "check_network_ready", not_ready)
    _run_payload(capsys, profile_path)

    assert observed and 0 < observed[0] <= 1


def test_summary_counts_unknown_status_as_failed() -> None:
    assert runner._summary([{"status": "unexpected"}, {}]) == {
        "passed": 0,
        "failed": 2,
        "blockedEnvironment": 0,
        "unsupported": 0,
        "notRun": 0,
    }


@pytest.mark.skipif(os.name == "nt", reason="CLI recovery storage requires POSIX ownership checks")
def test_run_preserves_unrelated_bytes_and_never_invokes_host(tmp_path: Path, capsys) -> None:
    profile_path, profile = _write_runner_profile(
        tmp_path,
        (runner.SHELL_CASE_ID, runner.EGRESS_CASE_ID),
    )
    unrelated = tmp_path / "unrelated.txt"
    unrelated.write_bytes(b"keep me")
    host_path = Path(str(profile["hostIdentity"]["executable"]))  # type: ignore[index]
    marker = tmp_path / "host-ran"
    host_path.write_text(
        f"#!/bin/sh\ntouch '{marker}'\nexit 0\n",
        encoding="utf-8",
    )
    host_path.chmod(0o755)

    code, payload = _run_payload(capsys, profile_path)
    encoded = json.dumps(payload)

    assert code == 2
    assert payload["status"] == "blocked_environment"
    assert payload["run"]["proofBoundary"] == "synthetic_adapter_test"
    assert all(case["proofType"] == "synthetic_adapter_test" for case in payload["run"]["cases"])
    assert all(case["observedAction"] is None for case in payload["run"]["cases"])
    assert all(case["hostEventBound"] is False for case in payload["run"]["cases"])
    assert unrelated.read_bytes() == b"keep me"
    assert not marker.exists()
    assert str(tmp_path) not in encoded
    assert not list(tmp_path.glob("hol-guard-eval-*"))


def test_synthetic_setup_skips_host_probe_and_artifacts(tmp_path: Path) -> None:
    profile_path, profile_data = _write_runner_profile(tmp_path, (runner.SHELL_CASE_ID,))
    del profile_path
    profile = EvaluationProfile.from_dict(profile_data)

    setup = setup_evaluation(profile, execution_mode="synthetic_adapter")
    try:
        assert setup.report.status == "passed"
        assert {check["reason"] for check in setup.report.checks if check["name"] == "host_version"} == {
            "synthetic_adapter_mode"
        }
    finally:
        assert setup.cleanup() is True


@pytest.mark.skipif(os.name == "nt", reason="CLI recovery storage requires POSIX ownership checks")
def test_run_hides_unexpected_runner_error_and_cleans_owned_setup(monkeypatch, tmp_path: Path, capsys) -> None:
    profile_path, _ = _write_runner_profile(tmp_path, (runner.SHELL_CASE_ID,))

    def fail_runner(*_args, **_kwargs):
        raise RuntimeError("private-diagnostic-marker")

    monkeypatch.setattr(cli_run, "run_synthetic_cases", fail_runner)
    code, payload = _run_payload(capsys, profile_path)

    assert code == 2
    assert payload["status"] == "blocked_environment"
    assert payload["error"]["code"] == "runner_failed"
    assert payload["cleanup"] == {"removed": True, "recoveryTokenRetained": False}
    assert "private-diagnostic-marker" not in json.dumps(payload)
    assert not list(tmp_path.glob("hol-guard-eval-*"))
    assert not list(tmp_path.glob(".hol-guard-evaluation-recovery-*.token"))


@pytest.mark.skipif(os.name == "nt", reason="CLI recovery storage requires POSIX ownership checks")
def test_run_fails_closed_when_witness_setup_fails(monkeypatch, tmp_path: Path, capsys) -> None:
    profile_path, _ = _write_runner_profile(tmp_path, (runner.SHELL_CASE_ID,))

    def fail_setup(_self):
        raise RuntimeError("private-witness-marker")

    monkeypatch.setattr(runner.LocalSideEffectWitness, "__enter__", fail_setup)
    code, payload = _run_payload(capsys, profile_path)

    assert code == 2
    assert payload["status"] == "blocked_environment"
    assert payload["error"]["code"] == "witness_setup_failed"
    assert payload["run"]["cases"] == []
    assert "private-witness-marker" not in json.dumps(payload)
    assert payload["cleanup"] == {"removed": True, "recoveryTokenRetained": False}
    assert not list(tmp_path.glob("hol-guard-eval-*"))


@pytest.mark.skipif(os.name == "nt", reason="CLI recovery storage requires POSIX ownership checks")
def test_run_cleans_setup_when_recovery_token_cannot_be_written(monkeypatch, tmp_path: Path, capsys) -> None:
    profile_path, _ = _write_runner_profile(tmp_path, (runner.SHELL_CASE_ID,))

    def fail_token_write(*_args, **_kwargs):
        raise cli_run._CliError(
            "cleanup_token_unavailable",
            "recovery token could not be written",
            status="blocked_environment",
        )

    monkeypatch.setattr(cli_run, "_write_recovery_token", fail_token_write)
    code, payload = _run_payload(capsys, profile_path)

    assert code == 2
    assert payload["status"] == "blocked_environment"
    assert payload["error"]["code"] == "cleanup_token_unavailable"
    assert payload["cleanup"] == {"removed": True, "recoveryTokenRetained": False}
    assert not list(tmp_path.glob("hol-guard-eval-*"))
    assert not list(tmp_path.glob(".hol-guard-evaluation-recovery-*.token"))


@pytest.mark.skipif(os.name == "nt", reason="CLI recovery storage requires POSIX ownership checks")
def test_run_retains_recovery_token_when_cleanup_is_uncertain(monkeypatch, tmp_path: Path, capsys) -> None:
    profile_path, _ = _write_runner_profile(tmp_path, (runner.SHELL_CASE_ID,))
    original_cleanup = EvaluationSetup.cleanup

    def uncertain_cleanup(self):
        assert original_cleanup(self) is True
        raise EvaluationContractError("cleanup outcome uncertain")

    monkeypatch.setattr(EvaluationSetup, "cleanup", uncertain_cleanup)
    code, payload = _run_payload(capsys, profile_path)

    assert code == 2
    assert payload["status"] == "blocked_environment"
    assert payload["error"]["code"] == "cleanup_failed"
    assert payload["cleanup"] == {
        "removed": False,
        "recoveryTokenRetained": True,
        "reason": "cleanup_failed",
    }
    assert not list(tmp_path.glob("hol-guard-eval-*"))
    assert len(list(tmp_path.glob(".hol-guard-evaluation-recovery-*.token"))) == 1


def test_synthetic_runner_rejects_an_installed_mode_adapter(tmp_path: Path) -> None:
    _, profile_data = _write_runner_profile(tmp_path, (runner.SHELL_CASE_ID,))
    profile = EvaluationProfile.from_dict(profile_data)
    setup = setup_evaluation(profile, execution_mode="synthetic_adapter")

    class InstalledAdapter:
        mode = "installed"
        proof_type = "installed_host"

        def run_case(self, *_args, **_kwargs):
            pytest.fail("installed adapter must not run in synthetic mode")

    try:
        with pytest.raises(runner.EvaluationRunnerError) as error:
            runner.run_synthetic_cases(profile, setup, adapter=InstalledAdapter())
        assert error.value.code == "adapter_rejected"
        assert error.value.status == "not_run"
    finally:
        assert setup.cleanup() is True


@pytest.mark.parametrize(
    ("timed_out", "overflow", "incomplete", "returncode", "expected_code"),
    (
        (True, False, False, 0, "run_timeout"),
        (False, True, False, 0, "output_limit_exceeded"),
        (False, False, True, 0, "control_capture_incomplete"),
        (False, False, False, 1, "control_failed"),
    ),
)
def test_file_control_never_accepts_incomplete_or_failed_execution(
    monkeypatch,
    tmp_path: Path,
    timed_out: bool,
    overflow: bool,
    incomplete: bool,
    returncode: int,
    expected_code: str,
) -> None:
    pair = FileWitnessPair(tmp_path / "denied", tmp_path / "allowed")
    result = ProbeResult(
        returncode=returncode,
        stdout=b"",
        stderr=b"",
        timed_out=timed_out,
        output_overflow=overflow,
        capture_incomplete=incomplete,
    )
    monkeypatch.setattr(runner, "run_probe", lambda *_args, **_kwargs: result)
    ctx = runner.EvaluationRunContext(deadline=time.monotonic() + 5, output_limit_bytes=1024)

    with pytest.raises(runner.EvaluationRunnerError) as error:
        runner._fixed_file_control(pair, ctx=ctx)

    assert error.value.code == expected_code
    assert not pair.allowed_target.exists()


@pytest.mark.parametrize(
    "url",
    (
        "https://127.0.0.1:8080/probe/allowed",
        "http://localhost:8080/probe/allowed",
        "http://127.0.0.1:8080/outside",
        "http://127.0.0.1:invalid/probe/allowed",
    ),
)
def test_network_control_rejects_non_loopback_witness_routes(monkeypatch, url: str) -> None:
    monkeypatch.setattr(runner, "managed_urlopen", lambda *_args, **_kwargs: pytest.fail("unexpected network call"))
    ctx = runner.EvaluationRunContext(deadline=time.monotonic() + 5, output_limit_bytes=1024)

    with pytest.raises(runner.EvaluationRunnerError) as error:
        runner._fixed_network_control(url, ctx=ctx)

    assert error.value.code == "fixture_rejected"
