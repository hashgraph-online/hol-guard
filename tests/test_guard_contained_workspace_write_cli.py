from __future__ import annotations

import argparse
import io
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.cli import commands_contained_write as cli_module
from codex_plugin_scanner.guard.cli.commands_parser import add_guard_root_parser
from codex_plugin_scanner.guard.contained_workspace_write_execution import (
    ContainedWorkspaceWriteResult,
    ContainedWriteOperation,
    try_execute_contained_workspace_write,
)
from tests.test_guard_contained_workspace_write_execution import (
    prepare_contained_write_test,
    write_contained_test_file,
)


def test_cli_parser_and_json_output_expose_no_paths_or_content(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace, guard_home = prepare_contained_write_test(tmp_path, monkeypatch, b"output\n")
    write_contained_test_file(workspace / "in.json", "input\n")
    write_contained_test_file(workspace / "out.json", "old\n")
    executed = try_execute_contained_workspace_write(
        "copy-generated",
        workspace=workspace,
        guard_home=guard_home,
        source="in.json",
        target="out.json",
    )
    assert executed is not None
    result = ContainedWorkspaceWriteResult(
        executed.exit_code,
        "private-content",
        executed.stderr,
        executed.proof,
        executed.decision,
        executed.operation_id,
        executed.output_digest,
    )
    parser = argparse.ArgumentParser()
    add_guard_root_parser(parser)
    args = parser.parse_args(
        ("contained-write", "--workspace", str(workspace), "copy", "in.json", "out.json", "--json")
    )

    def execute_write(
        _operation: ContainedWriteOperation,
        *,
        workspace: Path,
        guard_home: Path,
        source: str,
        target: str | None = None,
        environment: dict[str, str] | None = None,
        timeout_seconds: float = 120.0,
    ) -> ContainedWorkspaceWriteResult:
        del workspace, guard_home, source, target, environment, timeout_seconds
        return result

    monkeypatch.setattr(cli_module, "try_execute_contained_workspace_write", execute_write)
    output = io.StringIO()
    status = cli_module._run_guard_contained_write_command(
        args,
        guard_home=guard_home,
        workspace=workspace,
        output_stream=output,
    )

    assert status == 0
    payload = output.getvalue()
    assert "private-content" not in payload
    assert str(tmp_path) not in payload
    assert '"decision":"silent-contained"' in payload
