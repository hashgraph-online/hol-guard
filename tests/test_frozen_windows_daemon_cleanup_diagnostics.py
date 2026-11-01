"""Pure failure-path coverage; actual frozen Windows execution stays in its CI lane."""

from __future__ import annotations

import subprocess
from types import SimpleNamespace

import pytest

from tests import test_frozen_windows_daemon_bootstrap as harness


def test_cleanup_failure_preserves_result_and_bounds_redacted_evidence(tmp_path, capsys):
    secret = "PRIVATE_SENTINEL"
    phase = "native_resident_phase phase=client_authenticate status=start elapsed_ms=1"
    directory = tmp_path / secret
    directory.mkdir()
    (directory / "managed-resident-phases.v1.log").write_text(
        "\n".join([phase] * 100 + [f"{phase} {secret}", f"native_resident_phase phase={secret}"])
    )
    sampler = SimpleNamespace(report=lambda: f"12:34:56.789 add {secret}\n{secret}")
    result = subprocess.CompletedProcess([secret], 4, stdout="original-out", stderr="original-err")

    with pytest.raises(AssertionError) as caught:
        harness._assert_cleanup_succeeded(result, {"HOL_GUARD_HOME": str(tmp_path), "SECRET": secret}, sampler)

    assert "stdout='original-out'" in str(caught.value)
    assert "stderr='original-err'" in str(caught.value)
    evidence = capsys.readouterr().out
    assert "resident_state 12:34:56.789 add" in evidence
    assert phase in evidence
    assert secret not in evidence
    assert str(tmp_path) not in evidence
    assert len(evidence) <= 4097
    assert result.returncode == 4


def test_cleanup_diagnostic_exception_cannot_replace_original_failure(tmp_path, capsys):
    def broken_report():
        raise RuntimeError("PRIVATE_EXCEPTION")

    result = subprocess.CompletedProcess([], 4, stdout="original-out", stderr="original-err")
    with pytest.raises(AssertionError, match="original-out"):
        harness._assert_cleanup_succeeded(
            result, {"HOL_GUARD_HOME": str(tmp_path)}, SimpleNamespace(report=broken_report)
        )
    assert capsys.readouterr().out == "Packaged cleanup resident diagnostics: unavailable\n"


def test_successful_cleanup_does_not_collect_diagnostics(capsys):
    def unexpected_report():
        pytest.fail("successful cleanup must not collect evidence")

    harness._assert_cleanup_succeeded(
        subprocess.CompletedProcess([], 0, stdout="", stderr=""), {}, SimpleNamespace(report=unexpected_report)
    )
    assert capsys.readouterr().out == ""


def test_cleanup_diagnostic_output_failure_preserves_original_assertion(tmp_path, monkeypatch):
    def broken_print(*_args, **_kwargs):
        raise RuntimeError("PRIVATE_OUTPUT_EXCEPTION")

    monkeypatch.setattr(harness, "print", broken_print, raising=False)
    result = subprocess.CompletedProcess([], 4, stdout="original-out", stderr="original-err")
    with pytest.raises(AssertionError, match="original-out"):
        harness._assert_cleanup_succeeded(result, {"HOL_GUARD_HOME": str(tmp_path)}, SimpleNamespace(report=lambda: ""))
