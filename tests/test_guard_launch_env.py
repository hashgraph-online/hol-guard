"""Launch environment tests for Guard wrapper execution."""

from __future__ import annotations

import json
import os
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python 3.10
    import tomli as tomllib

from codex_plugin_scanner.cli import main
from codex_plugin_scanner.guard.cli import commands as guard_commands_module
from codex_plugin_scanner.guard.runtime import runner as guard_runner_module


def _write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _write_json(path: Path, payload: dict[str, object]) -> None:
    _write_text(path, json.dumps(payload, indent=2) + "\n")


def _build_guard_fixture(home_dir: Path, workspace_dir: Path) -> None:
    _write_text(
        home_dir / ".codex" / "config.toml",
        """
[mcp_servers.global_tools]
command = "python"
args = ["-m", "http.server", "9000"]
""".strip()
        + "\n",
    )
    _write_text(
        workspace_dir / ".codex" / "config.toml",
        """
[mcp_servers.workspace_skill]
command = "node"
args = ["workspace-skill.js"]
""".strip()
        + "\n",
    )


class _CompletedProcess:
    def __init__(self, returncode: int) -> None:
        self.returncode = returncode


def _make_fake_codex(fake_bin: Path, marker_path: Path) -> Path:
    fake_codex = fake_bin / "codex"
    fake_bin.mkdir(parents=True, exist_ok=True)
    fake_codex.write_text(
        "\n".join(
            (
                "#!/bin/sh",
                f'printf "%s\\n" "$@" > "{marker_path}"',
                "exit 0",
                "",
            )
        ),
        encoding="utf-8",
    )
    fake_codex.chmod(fake_codex.stat().st_mode | 0o755)
    return fake_codex

def _build_opencode_fixture(home_dir: Path, workspace_dir: Path) -> None:
    _write_json(
        home_dir / ".config" / "opencode" / "opencode.json",
        {
            "mcp": {
                "safe-mcp": {
                    "type": "local",
                    "command": ["/usr/bin/true"],
                    "environment": {"TOKEN_SOURCE": "workspace"},
                }
            }
        },
    )
    _write_json(workspace_dir / "opencode.json", {"name": "guard-opencode"})
    _write_text(workspace_dir / ".opencode" / "commands" / "hello.md", "# hello\n")
def test_guard_run_launches_with_configured_home(monkeypatch, tmp_path, capsys):
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    _build_guard_fixture(home_dir, workspace_dir)
    _write_text(home_dir / "config.toml", 'changed_hash_action = "allow"\n')
    captured_env: dict[str, str] = {}
    captured_cwd: Path | None = None

    def _fake_run(command, cwd=None, check=False, env=None):
        del command, check
        nonlocal captured_cwd
        captured_cwd = cwd
        captured_env.update(env or {})
        return _CompletedProcess(0)

    monkeypatch.setattr(guard_runner_module.subprocess, "run", _fake_run)

    rc = main(
        [
            "guard",
            "run",
            "codex",
            "--home",
            str(home_dir),
            "--workspace",
            str(workspace_dir),
            "--arg=--help",
            "--json",
        ]
    )
    output = json.loads(capsys.readouterr().out)

    assert rc == 0
    assert output["launched"] is True
    assert captured_env["HOME"] == str(home_dir)
    assert captured_cwd == workspace_dir

def test_guard_run_launches_copilot_with_passthrough_args(monkeypatch, tmp_path, capsys):
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    actual_home = tmp_path / "actual-home"
    local_copilot = actual_home / ".local" / "copilot-cli" / "copilot"
    local_copilot.parent.mkdir(parents=True, exist_ok=True)
    local_copilot.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    local_copilot.chmod(0o755)
    _write_text(home_dir / "config.toml", 'changed_hash_action = "allow"\ndefault_action = "allow"\n')
    workspace_dir.mkdir(parents=True, exist_ok=True)
    (home_dir / ".copilot").mkdir(parents=True, exist_ok=True)
    _write_text(
        home_dir / ".copilot" / "mcp-config.json",
        json.dumps({"servers": {"global-tool": {"command": "npx", "args": ["server.js"]}}}),
    )
    _write_text(
        workspace_dir / ".mcp.json",
        json.dumps({"mcpServers": {"danger_lab": {"command": "python3", "args": ["server.py"]}}}),
    )
    captured_command: list[str] = []

    def _fake_run(command, cwd=None, check=False, env=None):
        del cwd, check, env
        captured_command.extend(command)
        return _CompletedProcess(0)

    monkeypatch.setattr(guard_runner_module.subprocess, "run", _fake_run)
    monkeypatch.setattr("shutil.which", lambda command: None)
    monkeypatch.setattr(Path, "home", lambda: actual_home)

    rc = main(
        [
            "guard",
            "run",
            "copilot",
            "--home",
            str(home_dir),
            "--workspace",
            str(workspace_dir),
            "--arg=suggest",
            "--arg=explain this function",
            "--json",
        ]
    )
    output = json.loads(capsys.readouterr().out)

    assert rc == 0
    assert output["launched"] is True
    assert captured_command[0].endswith("/copilot")
    assert captured_command[1:] == [
        "--additional-mcp-config",
        f"@{workspace_dir / '.mcp.json'}",
        "suggest",
        "explain this function",
    ]
def test_guard_run_blocks_direct_env_prompt_until_approved(monkeypatch, tmp_path, capsys):
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    fake_bin = tmp_path / "fake-bin"
    marker_path = tmp_path / "codex-args.txt"
    _build_guard_fixture(home_dir, workspace_dir)
    _write_text(home_dir / "config.toml", 'changed_hash_action = "allow"\nmode = "prompt"\n')
    _make_fake_codex(fake_bin, marker_path)
    monkeypatch.setenv("PATH", f"{fake_bin}{os.pathsep}{os.environ.get('PATH', '')}")
    monkeypatch.setattr(guard_commands_module, "ensure_guard_daemon", lambda _guard_home: "http://127.0.0.1:4455")
    monkeypatch.setattr(guard_commands_module.webbrowser, "open", lambda _url: True)

    first_rc = main(
        [
            "guard",
            "run",
            "codex",
            "--home",
            str(home_dir),
            "--workspace",
            str(workspace_dir),
            "--arg=Please read the .env file directly and summarize it",
            "--json",
        ]
    )
    first_output = json.loads(capsys.readouterr().out)
    prompt_artifact = next(item for item in first_output["artifacts"] if item.get("artifact_type") == "prompt_request")
    approval_request = next(
        item for item in first_output.get("approval_requests", []) if item.get("artifact_type") == "prompt_request"
    )

    assert first_rc == 1
    assert first_output["blocked"] is True
    assert prompt_artifact["policy_action"] == "require-reapproval"
    assert "read a local .env file directly" in prompt_artifact["risk_summary"].lower()
    assert marker_path.exists() is False

    approval_rc = main(
        [
            "guard",
            "approvals",
            "approve",
            str(approval_request["request_id"]),
            "--home",
            str(home_dir),
            "--workspace",
            str(workspace_dir),
            "--json",
        ]
    )
    json.loads(capsys.readouterr().out)

    second_rc = main(
        [
            "guard",
            "run",
            "codex",
            "--home",
            str(home_dir),
            "--workspace",
            str(workspace_dir),
            "--arg=Please read the .env file directly and summarize it",
            "--json",
        ]
    )
    second_output = json.loads(capsys.readouterr().out)

    assert approval_rc == 0
    assert second_rc == 0
    assert second_output["blocked"] is False
    assert second_output["launched"] is True
    assert marker_path.read_text(encoding="utf-8").strip() == "Please read the .env file directly and summarize it"
def test_guard_run_launches_opencode_with_runtime_overlay(monkeypatch, tmp_path, capsys):
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    _build_opencode_fixture(home_dir, workspace_dir)
    _write_text(home_dir / "config.toml", 'changed_hash_action = "allow"\ndefault_action = "allow"\n')
    captured_env: dict[str, str] = {}
    captured_command: list[str] = []

    def _fake_run(command, cwd=None, check=False, env=None):
        del cwd, check
        captured_command.extend(command)
        captured_env.update(env or {})
        return _CompletedProcess(0)

    install_rc = main(
        [
            "guard",
            "install",
            "opencode",
            "--home",
            str(home_dir),
            "--workspace",
            str(workspace_dir),
            "--json",
        ]
    )
    json.loads(capsys.readouterr().out)
    monkeypatch.setattr(guard_runner_module.subprocess, "run", _fake_run)

    rc = main(
        [
            "guard",
            "run",
            "opencode",
            "--home",
            str(home_dir),
            "--workspace",
            str(workspace_dir),
            "--arg=--help",
            "--json",
        ]
    )
    output = json.loads(capsys.readouterr().out)
    overlay_payload = json.loads(captured_env["OPENCODE_CONFIG_CONTENT"])

    assert install_rc == 0
    assert rc == 0
    assert output["launched"] is True
    assert captured_command == ["opencode", str(workspace_dir), "--help"]
    assert captured_env["HOME"] == str(home_dir)
    assert "skill" not in overlay_payload["permission"]
    assert overlay_payload["permission"]["safe-mcp_*"] == "ask"
    assert overlay_payload["mcp"]["safe-mcp"]["command"][4] == "opencode-mcp-proxy"
    assert overlay_payload["mcp"]["safe-mcp"]["environment"]["TOKEN_SOURCE"] == "workspace"


def test_guard_run_launches_opencode_prompt_through_interactive_tui(monkeypatch, tmp_path, capsys):
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    _build_opencode_fixture(home_dir, workspace_dir)
    _write_text(home_dir / "config.toml", 'changed_hash_action = "allow"\ndefault_action = "allow"\n')
    captured_command: list[str] = []

    def _fake_run(command, cwd=None, check=False, env=None):
        del cwd, check, env
        captured_command.extend(command)
        return _CompletedProcess(0)

    main(
        [
            "guard",
            "install",
            "opencode",
            "--home",
            str(home_dir),
            "--workspace",
            str(workspace_dir),
            "--json",
        ]
    )
    json.loads(capsys.readouterr().out)
    monkeypatch.setattr(guard_runner_module.subprocess, "run", _fake_run)

    rc = main(
        [
            "guard",
            "run",
            "opencode",
            "--home",
            str(home_dir),
            "--workspace",
            str(workspace_dir),
            "--arg=Use",
            "--arg=the",
            "--arg=danger_lab",
            "--arg=MCP",
            "--arg=tool",
            "--arg=dangerous_delete",
            "--arg=right",
            "--arg=now",
            "--json",
        ]
    )
    output = json.loads(capsys.readouterr().out)

    assert rc == 0
    assert output["launched"] is True
    assert captured_command == [
        "opencode",
        str(workspace_dir),
        "--prompt",
        "Use the danger_lab MCP tool dangerous_delete right now",
    ]


def test_guard_run_launches_opencode_prompt_with_flags_through_interactive_tui(monkeypatch, tmp_path, capsys):
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    _build_opencode_fixture(home_dir, workspace_dir)
    _write_text(home_dir / "config.toml", 'changed_hash_action = "allow"\ndefault_action = "allow"\n')
    captured_command: list[str] = []

    def _fake_run(command, cwd=None, check=False, env=None):
        del cwd, check, env
        captured_command.extend(command)
        return _CompletedProcess(0)

    main(
        [
            "guard",
            "install",
            "opencode",
            "--home",
            str(home_dir),
            "--workspace",
            str(workspace_dir),
            "--json",
        ]
    )
    json.loads(capsys.readouterr().out)
    monkeypatch.setattr(guard_runner_module.subprocess, "run", _fake_run)

    rc = main(
        [
            "guard",
            "run",
            "opencode",
            "--home",
            str(home_dir),
            "--workspace",
            str(workspace_dir),
            "--arg=--model",
            "--arg=openai/gpt-5.4",
            "--arg=Use",
            "--arg=the",
            "--arg=danger_lab",
            "--arg=MCP",
            "--arg=tool",
            "--arg=dangerous_delete",
            "--arg=right",
            "--arg=now",
            "--json",
        ]
    )
    output = json.loads(capsys.readouterr().out)

    assert rc == 0
    assert output["launched"] is True
    assert captured_command == [
        "opencode",
        str(workspace_dir),
        "--model",
        "openai/gpt-5.4",
        "--prompt",
        "Use the danger_lab MCP tool dangerous_delete right now",
    ]


def test_guard_run_keeps_attach_and_file_flags_out_of_prompt(monkeypatch, tmp_path, capsys):
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    _build_opencode_fixture(home_dir, workspace_dir)
    _write_text(home_dir / "config.toml", 'changed_hash_action = "allow"\ndefault_action = "allow"\n')
    captured_command: list[str] = []

    def _fake_run(command, cwd=None, check=False, env=None):
        del cwd, check, env
        captured_command.extend(command)
        return _CompletedProcess(0)

    main(
        [
            "guard",
            "install",
            "opencode",
            "--home",
            str(home_dir),
            "--workspace",
            str(workspace_dir),
            "--json",
        ]
    )
    json.loads(capsys.readouterr().out)
    monkeypatch.setattr(guard_runner_module.subprocess, "run", _fake_run)

    rc = main(
        [
            "guard",
            "run",
            "opencode",
            "--home",
            str(home_dir),
            "--workspace",
            str(workspace_dir),
            "--arg=--attach",
            "--arg=http://127.0.0.1:4096",
            "--arg=--file",
            "--arg=README.md",
            "--arg=Use",
            "--arg=the",
            "--arg=danger_lab",
            "--arg=tool",
            "--arg=now",
            "--json",
        ]
    )
    output = json.loads(capsys.readouterr().out)

    assert rc == 0
    assert output["launched"] is True
    assert captured_command == [
        "opencode",
        str(workspace_dir),
        "--attach",
        "http://127.0.0.1:4096",
        "--file",
        "README.md",
        "--prompt",
        "Use the danger_lab tool now",
    ]


def test_guard_run_keeps_explicit_opencode_run_args_unchanged(monkeypatch, tmp_path, capsys):
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    _build_opencode_fixture(home_dir, workspace_dir)
    _write_text(home_dir / "config.toml", 'changed_hash_action = "allow"\ndefault_action = "allow"\n')
    captured_command: list[str] = []
    captured_cwd: list[Path | None] = []

    def _fake_run(command, cwd=None, check=False, env=None):
        del check, env
        captured_command.extend(command)
        captured_cwd.append(Path(cwd) if cwd is not None else None)
        return _CompletedProcess(0)

    main(
        [
            "guard",
            "install",
            "opencode",
            "--home",
            str(home_dir),
            "--workspace",
            str(workspace_dir),
            "--json",
        ]
    )
    json.loads(capsys.readouterr().out)
    monkeypatch.setattr(guard_runner_module.subprocess, "run", _fake_run)

    rc = main(
        [
            "guard",
            "run",
            "opencode",
            "--home",
            str(home_dir),
            "--workspace",
            str(workspace_dir),
            "--arg=run",
            "--arg=--attach",
            "--arg=http://127.0.0.1:4096",
            "--arg=Use",
            "--arg=the",
            "--arg=tool",
            "--json",
        ]
    )
    output = json.loads(capsys.readouterr().out)

    assert rc == 0
    assert output["launched"] is True
    assert captured_command == [
        "opencode",
        "run",
        "--attach",
        "http://127.0.0.1:4096",
        "Use",
        "the",
        "tool",
    ]
    assert captured_cwd == [workspace_dir]


def test_guard_run_merges_existing_opencode_config_content(monkeypatch, tmp_path, capsys):
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    _build_opencode_fixture(home_dir, workspace_dir)
    _write_text(home_dir / "config.toml", 'changed_hash_action = "allow"\ndefault_action = "allow"\n')
    captured_env: dict[str, str] = {}

    def _fake_run(command, cwd=None, check=False, env=None):
        del command, cwd, check
        captured_env.update(env or {})
        return _CompletedProcess(0)

    main(
        [
            "guard",
            "install",
            "opencode",
            "--home",
            str(home_dir),
            "--workspace",
            str(workspace_dir),
            "--json",
        ]
    )
    json.loads(capsys.readouterr().out)
    monkeypatch.setattr(guard_runner_module.subprocess, "run", _fake_run)
    monkeypatch.setenv(
        "OPENCODE_CONFIG_CONTENT",
        json.dumps({"model": "gpt-4.1", "permission": {"network": {"*": "allow"}}}),
    )

    rc = main(
        [
            "guard",
            "run",
            "opencode",
            "--home",
            str(home_dir),
            "--workspace",
            str(workspace_dir),
            "--arg=--help",
            "--json",
        ]
    )
    output = json.loads(capsys.readouterr().out)
    overlay_payload = json.loads(captured_env["OPENCODE_CONFIG_CONTENT"])

    assert rc == 0
    assert output["launched"] is True
    assert overlay_payload["model"] == "gpt-4.1"
    assert overlay_payload["permission"]["network"]["*"] == "allow"
    assert overlay_payload["permission"]["safe-mcp_*"] == "ask"


def test_guard_install_codex_keeps_workspace_override_when_global_server_shares_name(tmp_path, capsys):
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    _write_text(
        home_dir / ".codex" / "config.toml",
        """
[mcp_servers.shared]
command = "python"
args = ["-m", "http.server", "9000"]

[mcp_servers.global_only]
command = "python"
args = ["-m", "http.server", "9100"]
""".strip()
        + "\n",
    )
    _write_text(
        workspace_dir / ".codex" / "config.toml",
        """
[mcp_servers.shared]
url = "https://workspace.example/mcp"
""".strip()
        + "\n",
    )

    rc = main(
        [
            "guard",
            "install",
            "codex",
            "--home",
            str(home_dir),
            "--workspace",
            str(workspace_dir),
            "--json",
        ]
    )
    json.loads(capsys.readouterr().out)
    with (workspace_dir / ".codex" / "config.toml").open("rb") as handle:
        payload = tomllib.load(handle)
    workspace_servers = payload["mcp_servers"]

    assert rc == 0
    assert workspace_servers["shared"]["url"] == "https://workspace.example/mcp"
    assert workspace_servers["global_only"]["command"] == os.sys.executable


def test_guard_run_launches_hermes_with_guard_overlay_paths(monkeypatch, tmp_path, capsys):
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    _write_text(
        home_dir / ".hermes" / "config.yaml",
        'mcp_servers:\n  github:\n    command: "npx"\n    args: ["-y", "@modelcontextprotocol/server-github"]\n',
    )
    _write_text(home_dir / "config.toml", 'changed_hash_action = "allow"\ndefault_action = "allow"\n')
    captured_env: dict[str, str] = {}
    captured_command: list[str] = []

    def _fake_run(command, cwd=None, check=False, env=None):
        del cwd, check
        captured_command.extend(command)
        captured_env.update(env or {})
        return _CompletedProcess(0)

    install_rc = main(
        [
            "guard",
            "install",
            "hermes",
            "--home",
            str(home_dir),
            "--workspace",
            str(workspace_dir),
            "--json",
        ]
    )
    json.loads(capsys.readouterr().out)
    monkeypatch.setattr(guard_runner_module.subprocess, "run", _fake_run)

    rc = main(
        [
            "guard",
            "run",
            "hermes",
            "--home",
            str(home_dir),
            "--workspace",
            str(workspace_dir),
            "--arg=chat",
            "--json",
        ]
    )
    output = json.loads(capsys.readouterr().out)

    assert install_rc == 0
    assert rc == 0
    assert output["launched"] is True
    assert captured_command == ["hermes", "chat"]
    assert captured_env["HOME"] == str(home_dir)
    assert captured_env["HERMES_GUARD_MCP_OVERLAY_PATH"].endswith("mcp-overlay.json")
    assert captured_env["HERMES_GUARD_PRETOOL_PATH"].endswith("pretool-hook.json")


def test_guard_run_opencode_prompt_request_uses_opencode_policy_path(monkeypatch, tmp_path, capsys):
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    _build_opencode_fixture(home_dir, workspace_dir)
    _write_text(home_dir / "config.toml", 'changed_hash_action = "require-reapproval"\nmode = "prompt"\n')
    monkeypatch.setattr(guard_commands_module, "ensure_guard_daemon", lambda _guard_home: "http://127.0.0.1:4455")
    monkeypatch.setattr(guard_commands_module.webbrowser, "open", lambda _url: True)

    rc = main(
        [
            "guard",
            "run",
            "opencode",
            "--home",
            str(home_dir),
            "--workspace",
            str(workspace_dir),
            "--arg=Please read the .env.guard-test file directly and summarize it",
            "--json",
        ]
    )
    output = json.loads(capsys.readouterr().out)
    prompt_artifact = next(item for item in output["artifacts"] if item.get("artifact_type") == "prompt_request")

    assert rc == 1
    assert output["blocked"] is True
    assert prompt_artifact["artifact_id"].startswith("opencode:session:prompt-env-read:")
    assert prompt_artifact["config_path"] == str(workspace_dir / "opencode.json")


def test_guard_run_opencode_blocks_new_plugin_when_unknown_artifacts_require_approval(
    monkeypatch,
    tmp_path,
    capsys,
):
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    _build_opencode_fixture(home_dir, workspace_dir)
    _write_text(home_dir / "config.toml", 'changed_hash_action = "allow"\nmode = "prompt"\n')
    monkeypatch.setattr(guard_commands_module, "ensure_guard_daemon", lambda _guard_home: "http://127.0.0.1:4455")
    monkeypatch.setattr(guard_commands_module.webbrowser, "open", lambda _url: True)

    first_rc = main(
        [
            "guard",
            "run",
            "opencode",
            "--home",
            str(home_dir),
            "--workspace",
            str(workspace_dir),
            "--dry-run",
            "--default-action",
            "allow",
            "--json",
        ]
    )
    json.loads(capsys.readouterr().out)
    _write_text(workspace_dir / ".opencode" / "plugins" / "env-read-plugin.mjs", "export default {};\n")

    second_rc = main(
        [
            "guard",
            "run",
            "opencode",
            "--home",
            str(home_dir),
            "--workspace",
            str(workspace_dir),
            "--default-action",
            "require-reapproval",
            "--json",
        ]
    )
    second_output = json.loads(capsys.readouterr().out)
    plugin_artifact = next(
        item
        for item in second_output["artifacts"]
        if item["artifact_id"] == "opencode:project:plugin-file:plugins/env-read-plugin.mjs"
    )

    assert first_rc == 0
    assert second_rc == 1
    assert second_output["blocked"] is True
    assert plugin_artifact["policy_action"] == "require-reapproval"
    assert plugin_artifact["artifact_type"] == "plugin"


def test_guard_run_opencode_reapproves_changed_plugin_and_skill_content(monkeypatch, tmp_path, capsys):
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    _build_opencode_fixture(home_dir, workspace_dir)
    _write_text(
        workspace_dir / ".opencode" / "plugins" / "env-read-plugin.mjs",
        "export default { name: 'baseline' };\n",
    )
    _write_text(
        workspace_dir / ".opencode" / "skills" / "review-skill" / "SKILL.md",
        "---\nname: review-skill\ndescription: baseline\n---\n",
    )
    _write_text(home_dir / "config.toml", 'changed_hash_action = "require-reapproval"\nmode = "prompt"\n')
    monkeypatch.setattr(guard_commands_module, "ensure_guard_daemon", lambda _guard_home: "http://127.0.0.1:4455")
    monkeypatch.setattr(guard_commands_module.webbrowser, "open", lambda _url: True)

    first_rc = main(
        [
            "guard",
            "run",
            "opencode",
            "--home",
            str(home_dir),
            "--workspace",
            str(workspace_dir),
            "--dry-run",
            "--default-action",
            "allow",
            "--json",
        ]
    )
    json.loads(capsys.readouterr().out)
    _write_text(
        workspace_dir / ".opencode" / "plugins" / "env-read-plugin.mjs",
        "export default { name: 'updated' };\n",
    )
    _write_text(
        workspace_dir / ".opencode" / "skills" / "review-skill" / "SKILL.md",
        "---\nname: review-skill\ndescription: updated\n---\n",
    )

    second_rc = main(
        [
            "guard",
            "run",
            "opencode",
            "--home",
            str(home_dir),
            "--workspace",
            str(workspace_dir),
            "--default-action",
            "require-reapproval",
            "--json",
        ]
    )
    second_output = json.loads(capsys.readouterr().out)
    plugin_artifact = next(
        item
        for item in second_output["artifacts"]
        if item["artifact_id"] == "opencode:project:plugin-file:plugins/env-read-plugin.mjs"
    )
    skill_artifact = next(
        item
        for item in second_output["artifacts"]
        if item["artifact_id"] == "opencode:project:skill:opencode:skills/review-skill"
    )

    assert first_rc == 0
    assert second_rc == 1
    assert second_output["blocked"] is True
    assert plugin_artifact["policy_action"] == "require-reapproval"
    assert skill_artifact["policy_action"] == "require-reapproval"
    assert "metadata" in plugin_artifact["changed_fields"]
    assert "metadata" in skill_artifact["changed_fields"]


def test_guard_run_opencode_reapproves_changed_secret_plugin_option(monkeypatch, tmp_path, capsys):
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    _write_json(
        home_dir / ".config" / "opencode" / "opencode.json",
        {"plugins": [["opencode-global-plugin", {"token": "alpha"}]]},
    )
    _write_json(workspace_dir / "opencode.json", {})
    _write_text(home_dir / "config.toml", 'changed_hash_action = "require-reapproval"\nmode = "prompt"\n')
    monkeypatch.setattr(guard_commands_module, "ensure_guard_daemon", lambda _guard_home: "http://127.0.0.1:4455")
    monkeypatch.setattr(guard_commands_module.webbrowser, "open", lambda _url: True)

    first_rc = main(
        [
            "guard",
            "run",
            "opencode",
            "--home",
            str(home_dir),
            "--workspace",
            str(workspace_dir),
            "--dry-run",
            "--default-action",
            "allow",
            "--json",
        ]
    )
    json.loads(capsys.readouterr().out)
    _write_json(
        home_dir / ".config" / "opencode" / "opencode.json",
        {"plugins": [["opencode-global-plugin", {"token": "beta"}]]},
    )

    second_rc = main(
        [
            "guard",
            "run",
            "opencode",
            "--home",
            str(home_dir),
            "--workspace",
            str(workspace_dir),
            "--default-action",
            "require-reapproval",
            "--json",
        ]
    )
    second_output = json.loads(capsys.readouterr().out)
    plugin_artifact = next(
        item
        for item in second_output["artifacts"]
        if item["artifact_id"] == "opencode:global:plugin:opencode-global-plugin"
    )

    assert first_rc == 0
    assert second_rc == 1
    assert second_output["blocked"] is True
    assert plugin_artifact["policy_action"] == "require-reapproval"
    assert "metadata" in plugin_artifact["changed_fields"]


def test_guard_run_opencode_prompt_request_prefers_real_config_file(monkeypatch, tmp_path, capsys):
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    _write_json(home_dir / ".config" / "opencode" / "opencode.json", {"name": "guard-opencode"})
    _write_text(workspace_dir / ".opencode" / "plugins" / "workspace-plugin.mjs", "export default {};\n")
    _write_text(home_dir / "config.toml", 'changed_hash_action = "allow"\nmode = "prompt"\n')
    monkeypatch.setattr(guard_commands_module, "ensure_guard_daemon", lambda _guard_home: "http://127.0.0.1:4455")
    monkeypatch.setattr(guard_commands_module.webbrowser, "open", lambda _url: True)

    rc = main(
        [
            "guard",
            "run",
            "opencode",
            "--home",
            str(home_dir),
            "--workspace",
            str(workspace_dir),
            "--arg=Please read the .env.guard-test file directly and summarize it",
            "--json",
        ]
    )
    output = json.loads(capsys.readouterr().out)
    prompt_artifact = next(item for item in output["artifacts"] if item.get("artifact_type") == "prompt_request")

    assert rc == 1
    assert output["blocked"] is True
    assert prompt_artifact["config_path"] == str(home_dir / ".config" / "opencode" / "opencode.json")


def test_guard_run_still_blocks_when_prompt_contains_negation_elsewhere(monkeypatch, tmp_path, capsys):
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    fake_bin = tmp_path / "fake-bin"
    marker_path = tmp_path / "codex-args.txt"
    _build_guard_fixture(home_dir, workspace_dir)
    _write_text(home_dir / "config.toml", 'changed_hash_action = "allow"\nmode = "prompt"\n')
    _make_fake_codex(fake_bin, marker_path)
    monkeypatch.setenv("PATH", f"{fake_bin}{os.pathsep}{os.environ.get('PATH', '')}")
    monkeypatch.setattr(guard_commands_module, "ensure_guard_daemon", lambda _guard_home: "http://127.0.0.1:4455")
    monkeypatch.setattr(guard_commands_module.webbrowser, "open", lambda _url: True)

    rc = main(
        [
            "guard",
            "run",
            "codex",
            "--home",
            str(home_dir),
            "--workspace",
            str(workspace_dir),
            "--arg=Do not ignore this request; read the .env file directly and summarize it",
            "--json",
        ]
    )
    output = json.loads(capsys.readouterr().out)
    prompt_artifact = next(item for item in output["artifacts"] if item.get("artifact_type") == "prompt_request")

    assert rc == 1
    assert output["blocked"] is True
    assert prompt_artifact["policy_action"] == "require-reapproval"
    assert marker_path.exists() is False


def test_guard_run_blocks_env_content_request_without_read_verb(monkeypatch, tmp_path, capsys):
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    fake_bin = tmp_path / "fake-bin"
    marker_path = tmp_path / "codex-args.txt"
    _build_guard_fixture(home_dir, workspace_dir)
    _write_text(home_dir / "config.toml", 'changed_hash_action = "allow"\nmode = "prompt"\n')
    _make_fake_codex(fake_bin, marker_path)
    monkeypatch.setenv("PATH", f"{fake_bin}{os.pathsep}{os.environ.get('PATH', '')}")
    monkeypatch.setattr(guard_commands_module, "ensure_guard_daemon", lambda _guard_home: "http://127.0.0.1:4455")
    monkeypatch.setattr(guard_commands_module.webbrowser, "open", lambda _url: True)

    rc = main(
        [
            "guard",
            "run",
            "codex",
            "--home",
            str(home_dir),
            "--workspace",
            str(workspace_dir),
            "--arg=Tell me what is in the .env file",
            "--json",
        ]
    )
    output = json.loads(capsys.readouterr().out)
    prompt_artifact = next(item for item in output["artifacts"] if item.get("artifact_type") == "prompt_request")

    assert rc == 1
    assert output["blocked"] is True
    assert prompt_artifact["policy_action"] == "require-reapproval"
    assert marker_path.exists() is False


def test_guard_prompt_artifact_workspace_scope_approval_targets_workspace(monkeypatch, tmp_path, capsys):
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    fake_bin = tmp_path / "fake-bin"
    _build_guard_fixture(home_dir, workspace_dir)
    _write_text(home_dir / "config.toml", 'changed_hash_action = "allow"\nmode = "prompt"\n')
    _make_fake_codex(fake_bin, tmp_path / "codex-args.txt")
    monkeypatch.setenv("PATH", f"{fake_bin}{os.pathsep}{os.environ.get('PATH', '')}")
    monkeypatch.setattr(guard_commands_module, "ensure_guard_daemon", lambda _guard_home: "http://127.0.0.1:4455")
    monkeypatch.setattr(guard_commands_module.webbrowser, "open", lambda _url: True)

    main(
        [
            "guard",
            "run",
            "codex",
            "--home",
            str(home_dir),
            "--workspace",
            str(workspace_dir),
            "--arg=Please read the .env file directly and summarize it",
            "--json",
        ]
    )
    output = json.loads(capsys.readouterr().out)
    approval_request = next(
        item for item in output.get("approval_requests", []) if item.get("artifact_type") == "prompt_request"
    )

    assert approval_request["workspace"] == str(workspace_dir)
