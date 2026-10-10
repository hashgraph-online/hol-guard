"""Native-runtime unavailability is reported as a runtime error, not a usage error."""

from __future__ import annotations

import argparse

import pytest

from codex_plugin_scanner import cli_native_errors as cli


def test_native_unavailable_prints_real_code_without_usage(capsys: pytest.CaptureFixture[str]) -> None:
    parser = argparse.ArgumentParser(prog="hol-guard")
    code = cli.report_native_unavailable(
        parser,
        ValueError("native_mcp_descriptor_digest_unavailable:native_resident_runtime_identity_mismatch"),
    )
    err = capsys.readouterr().err
    assert code == 1
    assert "hol-guard: error: native_mcp_descriptor_digest_unavailable:native_resident_runtime_identity_mismatch" in err
    assert "usage:" not in err
    assert "hol-guard daemon repair" in err


def test_other_value_errors_keep_the_parser_error_path() -> None:
    parser = argparse.ArgumentParser(prog="hol-guard")
    assert cli.report_native_unavailable(parser, ValueError("bad --flag")) is None


def test_transport_failure_details_are_reported_as_runtime_errors(capsys: pytest.CaptureFixture[str]) -> None:
    parser = argparse.ArgumentParser(prog="hol-guard")
    message = (
        "native_mcp_descriptor_digest_unavailable:"
        "native_client_timed_out[pipe,2 attempt(s),allowance=none,budget=3.50s]"
    )
    assert cli.report_native_unavailable(parser, ValueError(message)) == 1
    err = capsys.readouterr().err
    assert f"hol-guard: error: {message}" in err
    assert "usage:" not in err


def test_value_error_exit_falls_back_to_usage_error() -> None:
    parser = argparse.ArgumentParser(prog="hol-guard")
    with pytest.raises(SystemExit) as raised:
        cli.guard_value_error_exit(parser, ValueError("bad --flag"))
    assert raised.value.code == 2
