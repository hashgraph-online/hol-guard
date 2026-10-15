"""Regression tests for request-classification service boundaries."""

import os
from pathlib import Path

from codex_plugin_scanner.guard.runtime.secret_file_request_services.developer_inspection import (
    _find_args_use_write_or_unsafe_exec_action,
    _read_only_lookup_find_args_are_safe,
)
from codex_plugin_scanner.guard.runtime.secret_file_request_services.local_read_operands import (
    _local_read_operands_resolve_safely,
    _ripgrep_args_expand_hidden_files,
)
from codex_plugin_scanner.guard.runtime.secret_file_request_services.pytest_target_detection import (
    _python_inline_script_runs_pytest,
)
from codex_plugin_scanner.guard.runtime.secret_file_request_services.read_only_filters import (
    _read_only_lookup_filter_grep_args_are_safe,
)


def test_find_read_only_validation_checks_every_leading_path(tmp_path: Path) -> None:
    assert not _read_only_lookup_find_args_are_safe([".", "~/.ssh", "-type", "f"], home_dir=tmp_path)


def test_find_exec_allows_only_literal_ls_over_discovered_paths() -> None:
    assert not _find_args_use_write_or_unsafe_exec_action([".", "-exec", "ls", "-ld", "{}", ";"])
    assert _find_args_use_write_or_unsafe_exec_action([".", "-exec", "./ls", "-ld", "{}", ";"])
    assert _find_args_use_write_or_unsafe_exec_action([".", "-exec", "ls", "-ld", "{}", ".env", ";"])
    assert _find_args_use_write_or_unsafe_exec_action([".", "-exec", "ls", "--", "-private", "{}", ";"])
    assert _find_args_use_write_or_unsafe_exec_action([".", "-exec", "sh", "-c", "ls -ld {}", ";"])


def test_local_read_rejects_missing_containment_root(tmp_path: Path) -> None:
    target = tmp_path / "target.txt"
    target.write_text("safe", encoding="utf-8")
    assert not _local_read_operands_resolve_safely(
        "cat",
        [str(target)],
        cwd=tmp_path,
        root=tmp_path / "missing",
    )


def test_ripgrep_hidden_mode_parser_handles_clusters_and_option_values() -> None:
    assert _ripgrep_args_expand_hidden_files(["-Fu", "API_KEY", "."])
    assert _ripgrep_args_expand_hidden_files(["-.F", "API_KEY", "."])
    assert not _ripgrep_args_expand_hidden_files(["-g*.ts", "API_KEY", "."])
    assert not _ripgrep_args_expand_hidden_files(["-g", "-u", "API_KEY", "."])
    assert not _ripgrep_args_expand_hidden_files(["--", "-u", "."])


def test_python_inline_pytest_scan_skips_option_values() -> None:
    assert _python_inline_script_runs_pytest(["-W", "ignore", "-c", "import pytest; pytest.main()"])


def test_grep_filter_rejects_dangling_value_options() -> None:
    assert not _read_only_lookup_filter_grep_args_are_safe(["-f"])
    assert not _read_only_lookup_filter_grep_args_are_safe(["-e"])


def test_local_read_rejects_symlink_loop_root(tmp_path: Path) -> None:
    loop = tmp_path / "loop"
    os.symlink(loop.name, loop)

    assert not _local_read_operands_resolve_safely("cat", ["target.txt"], cwd=tmp_path, root=loop)
