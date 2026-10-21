"""Regression tests for request-classification service boundaries."""

from pathlib import Path

from codex_plugin_scanner.guard.runtime.secret_file_request_services.developer_inspection import (
    _find_args_use_write_or_unsafe_exec_action,
    _read_only_lookup_find_args_are_safe,
)
from codex_plugin_scanner.guard.runtime.secret_file_requests import extract_sensitive_tool_action_request


def test_find_read_only_validation_checks_every_leading_path(tmp_path: Path) -> None:
    assert not _read_only_lookup_find_args_are_safe([".", "~/.ssh", "-type", "f"], home_dir=tmp_path)


def test_find_exec_allows_only_literal_ls_over_discovered_paths() -> None:
    assert not _find_args_use_write_or_unsafe_exec_action([".", "-exec", "ls", "-ld", "{}", ";"])
    assert _find_args_use_write_or_unsafe_exec_action([".", "-exec", "./ls", "-ld", "{}", ";"])
    assert _find_args_use_write_or_unsafe_exec_action([".", "-exec", "ls", "-ld", "{}", ".env", ";"])
    assert _find_args_use_write_or_unsafe_exec_action([".", "-exec", "ls", "--", "-private", "{}", ";"])
    assert _find_args_use_write_or_unsafe_exec_action([".", "-exec", "sh", "-c", "ls -ld {}", ";"])


def test_python_inline_pytest_scan_skips_option_values(tmp_path: Path) -> None:
    command = 'python -W ignore -c "import pytest; pytest.main()"'

    match = extract_sensitive_tool_action_request("Bash", {"command": command}, cwd=tmp_path)

    assert match is not None
    assert match.reason_code == "pytest_restricted_profile_required"
