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


@pytest.mark.parametrize("supported", [True, False])
def test_missing_runtime_explains_available_installation_path(
    supported: bool, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Missing runtimes name either in-place repair or unsupported-platform guidance."""
    from codex_plugin_scanner.guard.cli import update_native_wheel

    monkeypatch.setattr(update_native_wheel, "bundled_native_runtime_missing", lambda: True)
    monkeypatch.setattr(update_native_wheel, "native_platform_supported", lambda: supported)
    monkeypatch.setattr(cli.sysconfig, "get_platform", lambda: "linux-aarch64")
    parser = argparse.ArgumentParser(prog="hol-guard")

    assert cli.guard_value_error_exit(parser, ValueError("native_guard_config_unavailable")) == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "native_guard_config_unavailable" in captured.err
    assert "usage:" not in captured.err
    if supported:
        assert "Run `hol-guard update` to repair this installation" in captured.err
        assert "matching native wheel for this Guard version" in captured.err
        assert "same Python environment" in captured.err
        assert "https://github.com/hashgraph-online/hol-guard/releases" in captured.err
        assert "No published" not in captured.err
    else:
        assert "hol-guard update" not in captured.err
        assert "No published HOL Guard native wheel matches this Python platform (linux-aarch64)" in captured.err
        assert "universal Python wheel cannot provide protection" in captured.err
        assert "get-started.md#platform-support" in captured.err


def test_existing_unhealthy_runtime_does_not_report_missing_platform_support(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """An installed but unhealthy runtime must not be described as absent."""
    from codex_plugin_scanner.guard.cli import update_native_wheel

    monkeypatch.setattr(update_native_wheel, "bundled_native_runtime_missing", lambda: False)

    def unexpected_platform_probe() -> bool:
        """Reject platform probing when the bundled runtime already exists."""
        pytest.fail("An existing runtime failure is not evidence of an unsupported platform")

    monkeypatch.setattr(update_native_wheel, "native_platform_supported", unexpected_platform_probe)
    parser = argparse.ArgumentParser(prog="hol-guard")
    assert cli.guard_value_error_exit(parser, ValueError("native_guard_config_unavailable")) == 1
    assert capsys.readouterr().err == "hol-guard: error: native_guard_config_unavailable\n"
