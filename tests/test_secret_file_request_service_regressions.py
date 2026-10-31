"""Regression tests for request-classification service boundaries."""

from pathlib import Path

from codex_plugin_scanner.guard.runtime.secret_file_requests import extract_sensitive_tool_action_request


def test_python_inline_pytest_scan_skips_option_values(tmp_path: Path) -> None:
    command = 'python -W ignore -c "import pytest; pytest.main()"'

    match = extract_sensitive_tool_action_request("Bash", {"command": command}, cwd=tmp_path)

    assert match is not None
    assert match.reason_code == "pytest_restricted_profile_required"
