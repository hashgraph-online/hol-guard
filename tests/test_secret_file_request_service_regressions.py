"""Regression tests for request-classification service boundaries."""

import os
import tempfile
from pathlib import Path
from unittest.mock import patch

from codex_plugin_scanner.guard.runtime.secret_file_request_services import credential_exfiltration
from codex_plugin_scanner.guard.runtime.secret_file_request_services.developer_inspection import (
    _find_args_use_write_or_unsafe_exec_action,
    _read_only_lookup_find_args_are_safe,
)
from codex_plugin_scanner.guard.runtime.secret_file_request_services.encoded_payloads import (
    _looks_destructive_shell_command,
)
from codex_plugin_scanner.guard.runtime.secret_file_request_services.interpreter_observers import (
    _python_args_use_module_mode,
    _read_only_lookup_segments,
    _shell_env_assignment_key,
)
from codex_plugin_scanner.guard.runtime.secret_file_request_services.local_read_operands import (
    _local_read_operands_resolve_safely,
)
from codex_plugin_scanner.guard.runtime.secret_file_request_services.node_heredoc_safety import (
    _looks_like_safe_node_generated_file_heredoc,
)
from codex_plugin_scanner.guard.runtime.secret_file_request_services.pytest_target_detection import (
    _python_inline_script_runs_pytest,
)
from codex_plugin_scanner.guard.runtime.secret_file_request_services.read_only_filters import (
    _read_only_lookup_filter_grep_args_are_safe,
)
from codex_plugin_scanner.guard.runtime.secret_file_request_services.sensitive_read_pipeline import (
    _wget_segment_consumes_stdin,
)
from codex_plugin_scanner.guard.runtime.secret_file_request_services.upload_arguments import (
    _wget_segment_uses_file_upload,
)


def test_find_read_only_validation_checks_every_leading_path(tmp_path: Path) -> None:
    assert not _read_only_lookup_find_args_are_safe([".", "~/.ssh", "-type", "f"], home_dir=tmp_path)


def test_find_exec_allows_only_literal_ls_over_discovered_paths() -> None:
    assert not _find_args_use_write_or_unsafe_exec_action([".", "-exec", "ls", "-ld", "{}", ";"])
    assert _find_args_use_write_or_unsafe_exec_action([".", "-exec", "./ls", "-ld", "{}", ";"])
    assert _find_args_use_write_or_unsafe_exec_action([".", "-exec", "ls", "-ld", "{}", ".env", ";"])
    assert _find_args_use_write_or_unsafe_exec_action([".", "-exec", "sh", "-c", "ls -ld {}", ";"])


def test_read_only_segments_reject_non_stderr_redirection() -> None:
    assert not _read_only_lookup_segments(["cat", "-n>report.txt"])
    assert not _read_only_lookup_segments(["grep", "pattern", "--color=always>report.txt"])


def test_environment_append_marker_must_precede_assignment() -> None:
    assert _shell_env_assignment_key("SAFE=value+=suffix") == "SAFE"
    assert _shell_env_assignment_key("SAFE+=suffix") == "SAFE"


def test_python_module_mode_recognizes_clustered_flags() -> None:
    assert _python_args_use_module_mode(["-Sm", "pytest"])
    assert _python_args_use_module_mode(["-Bmhttp.server"])


def test_local_read_rejects_missing_containment_root(tmp_path: Path) -> None:
    target = tmp_path / "target.txt"
    target.write_text("safe", encoding="utf-8")
    assert not _local_read_operands_resolve_safely(
        "cat",
        [str(target)],
        cwd=tmp_path,
        root=tmp_path / "missing",
    )


def test_generated_node_workflow_requires_quoted_heredoc() -> None:
    command = "node - <<NODE\nconst fs = require('fs');\nfs.writeFileSync('/tmp/output.json', '{}');\nNODE"
    script = "const fs = require('fs');\nfs.writeFileSync('/tmp/output.json', '{}');"
    assert not _looks_like_safe_node_generated_file_heredoc(command, script)


def test_python_inline_pytest_scan_skips_option_values() -> None:
    assert _python_inline_script_runs_pytest(["-W", "ignore", "-c", "import pytest; pytest.main()"])


def test_grep_filter_rejects_dangling_value_options() -> None:
    assert not _read_only_lookup_filter_grep_args_are_safe(["-f"])
    assert not _read_only_lookup_filter_grep_args_are_safe(["-e"])


def test_wget_stdin_detection_scans_all_upload_flags() -> None:
    assert _wget_segment_consumes_stdin(["--body-file", "payload.txt", "--post-file", "-"])
    assert _wget_segment_consumes_stdin(["--body-file=payload.txt", "--post-file=-"])


def test_wget_upload_uses_pipeline_stdin_state() -> None:
    assert _wget_segment_uses_file_upload(["--post-file", "-"], stdin_uses_local_file=True)
    assert _wget_segment_uses_file_upload(["--body-file=-"], stdin_uses_local_file=True)


def test_runtime_text_decode_failure_does_not_close_transferred_descriptor_twice(
    tmp_path: Path,
) -> None:
    target = tmp_path / "invalid.txt"
    target.write_bytes(b"\xff")
    raw_close_calls: list[int] = []

    with patch.object(credential_exfiltration.os, "close", side_effect=raw_close_calls.append):
        assert credential_exfiltration._read_small_runtime_text_file(target, allowed_roots=(tmp_path,)) is None
    assert raw_close_calls == []


def test_destructive_shell_recursion_is_bounded() -> None:
    command = "echo " + "$(echo " * 8 + "safe" + ")" * 8

    assert _looks_destructive_shell_command(command)


def test_routine_non_overwriting_move_is_not_destructive(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / ".next").mkdir()
    assert not _looks_destructive_shell_command("mv .next guard-next-cache", cwd=workspace, home_dir=tmp_path)


def test_routine_move_supports_static_workspace_paths(tmp_path: Path) -> None:
    source = tmp_path / "app" / ".next"
    destination = tmp_path / "app" / "guard-next-cache"
    source.mkdir(parents=True)
    assert not _looks_destructive_shell_command(f"mv {source} {destination}", cwd=tmp_path / "app", home_dir=tmp_path)


def test_routine_generated_directory_move_to_temporary_storage_is_not_destructive(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    source = workspace / ".next"
    source.mkdir(parents=True)
    destination = Path(tempfile.gettempdir()) / f"guard-next-cache-{tmp_path.name}"
    assert not _looks_destructive_shell_command(f"mv {source} {destination}", cwd=workspace, home_dir=tmp_path)


def test_routine_move_remains_destructive_when_destination_exists(tmp_path: Path) -> None:
    source = tmp_path / "source"
    destination = tmp_path / "destination"
    source.mkdir()
    destination.mkdir()
    assert _looks_destructive_shell_command("mv source destination", cwd=tmp_path, home_dir=tmp_path)


def test_routine_move_remains_destructive_for_unsafe_shapes(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "source").mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    commands = (
        "mv -f source destination",
        "mv source other destination",
        "mv source* destination",
        "mv source $DESTINATION",
        "LD_PRELOAD=./payload.so mv source destination",
        f"mv source {outside / 'destination'}",
        "mv source destination && echo moved",
    )
    for command in commands:
        assert _looks_destructive_shell_command(command, cwd=workspace, home_dir=tmp_path), command


def test_routine_move_remains_destructive_for_dangling_destination_symlink(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    destination = tmp_path / "destination"
    destination.symlink_to(tmp_path / "missing-target")

    assert _looks_destructive_shell_command("mv source destination", cwd=tmp_path, home_dir=tmp_path)


def test_routine_move_remains_destructive_for_sensitive_home_path(tmp_path: Path) -> None:
    ssh_dir = tmp_path / ".ssh"
    ssh_dir.mkdir()
    assert _looks_destructive_shell_command("mv ~/.ssh ~/.ssh-backup", cwd=tmp_path, home_dir=tmp_path)


def test_local_read_rejects_symlink_loop_root(tmp_path: Path) -> None:
    loop = tmp_path / "loop"
    os.symlink(loop.name, loop)

    assert not _local_read_operands_resolve_safely("cat", ["target.txt"], cwd=tmp_path, root=loop)
