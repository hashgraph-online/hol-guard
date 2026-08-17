from __future__ import annotations

import io
import json
import sys
from pathlib import Path

from codex_plugin_scanner.cli import main
from codex_plugin_scanner.guard.redaction import redact_text
from codex_plugin_scanner.guard.runtime.command_inspection import inspect_command
from codex_plugin_scanner.guard.runtime.secret_file_requests import extract_sensitive_tool_action_request

_ACTION = "process environment secret read"


def _match(command: str, *, cwd: Path | None = None, home_dir: Path | None = None):
    workspace = cwd or Path("/tmp")
    return extract_sensitive_tool_action_request(
        "run_terminal_command",
        {"command": command},
        cwd=workspace,
        home_dir=home_dir or workspace,
    )


def test_printenv_without_args_is_process_environment_secret_read() -> None:
    match = _match("printenv")
    assert match is not None
    assert match.action_class == _ACTION


def test_printenv_named_secret_is_process_environment_secret_read() -> None:
    match = _match("printenv AWS_SECRET_ACCESS_KEY")
    assert match is not None
    assert match.action_class == _ACTION


def test_printenv_path_is_not_secret_read() -> None:
    assert _match("printenv PATH") is None


def test_python_print_environ_is_process_environment_secret_read() -> None:
    match = _match("python3 -c 'import os; print(os.environ)'")
    assert match is not None
    assert match.action_class == _ACTION


def test_python_getenv_secret_is_process_environment_secret_read() -> None:
    match = _match("python3 -c \"import os; print(os.getenv('GOOGLE_CLOUD_PRIVATE_KEY'))\"")
    assert match is not None
    assert match.action_class == _ACTION


def test_python_getenv_path_is_not_secret_read() -> None:
    assert _match("python3 -c \"import os; print(os.getenv('PATH'))\"") is None


def test_node_process_env_dump_is_process_environment_secret_read() -> None:
    match = _match("node -e 'console.log(process.env)'")
    assert match is not None
    assert match.action_class == _ACTION


def test_echo_secret_env_expansion_is_process_environment_secret_read() -> None:
    match = _match("echo $AWS_SECRET_ACCESS_KEY")
    assert match is not None
    assert match.action_class == _ACTION


def test_python_script_file_that_prints_environ_is_secret_read(tmp_path: Path) -> None:
    script = tmp_path / "dump_env.py"
    script.write_text("import os\nprint(os.environ)\n", encoding="utf-8")
    match = _match("python3 dump_env.py", cwd=tmp_path, home_dir=tmp_path)
    assert match is not None
    assert match.action_class == _ACTION


def test_inspect_command_reviews_python_environ_dump() -> None:
    payload = inspect_command("python3 -c 'import os; print(os.environ)'")
    assert payload["status"] == "review"
    assert payload["classification"]["action_class"] == _ACTION
    assert "local_secret_read" in payload["risk_classes"]


def test_grok_pretool_denies_python_environ_dump(tmp_path: Path, monkeypatch, capsys) -> None:
    home_dir = tmp_path / "home"
    guard_home = tmp_path / "guard-home"
    workspace_dir = tmp_path / "workspace"
    home_dir.mkdir()
    guard_home.mkdir()
    workspace_dir.mkdir()
    (guard_home / "config.toml").write_text("approval_wait_timeout_seconds = 0\n", encoding="utf-8")
    event = {
        "hook_event_name": "PreToolUse",
        "tool_name": "run_terminal_command",
        "toolInput": {"command": "python3 -c 'import os; print(os.environ)'"},
        "cwd": str(workspace_dir),
    }
    monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps(event)))

    rc = main(
        [
            "guard",
            "hook",
            "--home",
            str(home_dir),
            "--guard-home",
            str(guard_home),
            "--workspace",
            str(workspace_dir),
            "--harness",
            "grok",
        ]
    )
    payload = json.loads(capsys.readouterr().out)

    assert rc == 2
    assert payload["decision"] == "deny"
    assert "environment" in str(payload.get("reason", "")).lower() or "secret" in str(payload.get("reason", "")).lower()


def test_redact_text_masks_aws_secret_in_mapping() -> None:
    text = (
        "{'AWS_ACCESS_KEY_ID': 'AKIAIOSFODNN7EXAMPLE', "
        "'AWS_SECRET_ACCESS_KEY': 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'}"
    )
    result = redact_text(text)
    assert "AKIAIOSFODNN7EXAMPLE" not in result.text
    assert "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" not in result.text
    assert "aws-secret-access-key" in result.classifiers
