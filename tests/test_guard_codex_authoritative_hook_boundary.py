"""Security regressions for the authoritative Codex shell-hook boundary."""

from __future__ import annotations

import base64
import io
import json
import shlex
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
import tomllib

from codex_plugin_scanner.cli import main
from codex_plugin_scanner.guard import codex_harness_client as codex_adapter
from codex_plugin_scanner.guard import native_harness_ops as harness_ops
from codex_plugin_scanner.guard.harness_context import HarnessContext
from codex_plugin_scanner.guard.store import GuardStore
from tests import codex_install_flow_support as flow
from tests import codex_plan_segments as segments
from tests import harness_ops_support as harness_support
from tests.codex_publication_steps import use_stepwise_publication
from tests.codex_toml_support import dump_toml, read_toml_payload
from tests.conftest import guard_commands_module

SHELL_GUARD_BEGIN = "# >>> HOL Guard Codex shell guard >>>"
SHELL_GUARD_END = "# <<< HOL Guard Codex shell guard <<<"


def _write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _install_codex(home_dir: Path, workspace_dir: Path, capsys: pytest.CaptureFixture[str]) -> dict[str, object]:
    _write_text(
        home_dir / ".codex" / "config.toml",
        '[mcp_servers.example]\ncommand = "python"\nargs = ["-m", "http.server"]\n',
    )
    _write_text(workspace_dir / ".codex" / "config.toml", 'approval_policy = "never"\n')
    result = main(
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
    output = json.loads(capsys.readouterr().out)
    assert result == 0
    return output


def _managed_shell_block(body: str) -> str:
    return "\n".join(
        (
            SHELL_GUARD_BEGIN,
            body,
            SHELL_GUARD_END,
        )
    )


def test_install_migrates_legacy_shell_controls_without_changing_user_bytes(tmp_path, capsys):
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    guard_root = home_dir / "managed" / "codex"
    user_prefix = "export KEEP_BEFORE=1\n"
    user_suffix = "export KEEP_AFTER=2\n\n"
    legacy_profile = f"{user_prefix}\n{_managed_shell_block('source /old/guard')}\n{user_suffix}"

    for startup_name in (".zshenv", ".bashrc", ".bash_profile", ".bash_login", ".profile"):
        _write_text(home_dir / startup_name, legacy_profile)
    fish_conf = home_dir / ".config" / "fish" / "conf.d" / "hol-guard-codex.fish"
    _write_text(fish_conf, f"{user_prefix}\n{_managed_shell_block('source /old/fish-guard')}\n{user_suffix}")
    for guard_name in (
        "codex-zshenv-guard.zsh",
        "codex-bashenv-guard.bash",
        "codex-fish-guard.fish",
    ):
        _write_text(guard_root / guard_name, "legacy Guard-owned shell control\n")

    output = _install_codex(home_dir, workspace_dir, capsys)
    manifest = output["managed_install"]["manifest"]

    assert manifest["enforcement_boundary"] == "codex-native-hooks"
    assert "managed_shell_guard_path" not in manifest
    assert "managed_shell_guard_paths" not in manifest
    for startup_name in (".zshenv", ".bashrc", ".bash_profile", ".bash_login", ".profile"):
        assert (home_dir / startup_name).read_text(encoding="utf-8") == f"{user_prefix}{user_suffix}"
    assert fish_conf.read_text(encoding="utf-8") == f"{user_prefix}{user_suffix}"
    assert not any(
        (guard_root / guard_name).exists()
        for guard_name in (
            "codex-zshenv-guard.zsh",
            "codex-bashenv-guard.bash",
            "codex-fish-guard.fish",
        )
    )


def test_legacy_shell_cleanup_preserves_crlf_non_utf8_and_unmatched_markers(tmp_path) -> None:
    begin = SHELL_GUARD_BEGIN.encode("ascii")
    end = SHELL_GUARD_END.encode("ascii")
    context = HarnessContext(home_dir=tmp_path / "home", workspace_dir=None, guard_home=tmp_path / "guard-home")
    context.home_dir.mkdir()
    unterminated = b"KEEP\n" + begin + b"\nunterminated\n"
    (context.home_dir / ".zshenv").write_bytes(
        b"\xffKEEP\r\n\r\n" + begin + b"\r\nlegacy\r\n" + end + b"\r\nAFTER\xfe\r\n"
    )
    (context.home_dir / ".bashrc").write_bytes(unterminated)

    planned = {change.path.name: change.after for change in segments.prepare_codex_shell_cleanup(context)}

    assert planned[".zshenv"] == b"\xffKEEP\r\nAFTER\xfe\r\n"
    assert planned[".bashrc"] == unterminated


def test_codex_launch_fails_closed_without_authoritative_native_hooks(tmp_path):
    context = HarnessContext(
        home_dir=tmp_path / "home",
        workspace_dir=tmp_path / "workspace",
        guard_home=tmp_path / "guard-home",
    )
    context.workspace_dir.mkdir(parents=True)

    with pytest.raises(RuntimeError, match="codex_authoritative_hook_unavailable"):
        harness_ops.preview_launch_commands("codex", context, ["Fix it."])


def test_codex_launch_fails_closed_when_native_hooks_are_disabled_after_install(tmp_path, capsys):
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    _install_codex(home_dir, workspace_dir, capsys)
    config_path = home_dir / ".codex" / "config.toml"
    config_text = config_path.read_text(encoding="utf-8")
    assert "hooks = true" in config_text
    config_path.write_text(config_text.replace("hooks = true", "hooks = false", 1), encoding="utf-8")
    context = HarnessContext(
        home_dir=home_dir,
        workspace_dir=workspace_dir,
        guard_home=home_dir,
        home_override_explicit=True,
    )

    with pytest.raises(RuntimeError, match="codex_authoritative_hook_unavailable"):
        harness_ops.launch_command("codex", context, ["Fix it."])


@pytest.mark.parametrize("tamper_target", ("matcher", "command"))
def test_codex_launch_fails_closed_when_authoritative_hook_is_tampered(
    tamper_target,
    tmp_path,
    capsys,
):
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    _install_codex(home_dir, workspace_dir, capsys)
    config_path = home_dir / ".codex" / "config.toml"
    payload = read_toml_payload(config_path)
    hooks = payload["hooks"]
    assert isinstance(hooks, dict)
    pre_tool_groups = hooks["PreToolUse"]
    assert isinstance(pre_tool_groups, list)
    pre_tool_group = pre_tool_groups[-1]
    assert isinstance(pre_tool_group, dict)
    if tamper_target == "matcher":
        pre_tool_group["matcher"] = "Read"
    else:
        entries = pre_tool_group["hooks"]
        assert isinstance(entries, list)
        entry = entries[0]
        assert isinstance(entry, dict)
        entry["command"] = f"{entry['command']} --tampered"
    config_path.write_text(dump_toml(payload), encoding="utf-8")
    context = HarnessContext(home_dir=home_dir, workspace_dir=workspace_dir, guard_home=home_dir)

    with pytest.raises(RuntimeError, match="codex_authoritative_hook_unavailable"):
        harness_ops.preview_launch_commands("codex", context, ["Fix it."])


def test_codex_launch_rejects_hook_bound_to_opposite_home_mode(
    tmp_path,
    capsys,
    monkeypatch,
):
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    _install_codex(home_dir, workspace_dir, capsys)
    context = HarnessContext(
        home_dir=home_dir,
        workspace_dir=workspace_dir,
        guard_home=home_dir,
        home_override_explicit=True,
    )
    config_path = home_dir / ".codex" / "config.toml"
    payload = read_toml_payload(config_path)
    hooks = payload["hooks"]
    assert isinstance(hooks, dict)
    pre_tool_groups = hooks["PreToolUse"]
    assert isinstance(pre_tool_groups, list)
    pre_tool_group = pre_tool_groups[-1]
    assert isinstance(pre_tool_group, dict)
    entries = pre_tool_group["hooks"]
    assert isinstance(entries, list)
    entry = entries[0]
    assert isinstance(entry, dict)
    monkeypatch.setattr(codex_adapter.Path, "home", lambda: home_dir)
    opposite_home_command = codex_adapter._hook_command_parts_for_home_mode(
        context,
        home_is_current=True,
    )
    entry["command"] = shlex.join(opposite_home_command)
    config_path.write_text(dump_toml(payload), encoding="utf-8")

    with pytest.raises(RuntimeError, match="codex_authoritative_hook_unavailable"):
        harness_ops.preview_launch_commands("codex", context, ["Fix it."])


def test_codex_install_fails_closed_if_native_hook_reconciliation_is_unavailable(
    tmp_path,
    capsys,
    monkeypatch,
):
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    _write_text(workspace_dir / ".codex" / "config.toml", 'approval_policy = "never"\n')
    real_ask = flow.ask

    def _strip_hooks(encoded):
        payload = tomllib.loads(base64.b64decode(encoded).decode("utf-8"))
        payload.pop("hooks", None)
        return base64.b64encode(dump_toml(payload).encode("utf-8")).decode("ascii")

    def _without_hooks(op, *args, **kwargs):
        # The planned config loses its Guard hooks, as if the native plan
        # could not reconcile them; publication must refuse it.
        answer = real_ask(op, *args, **kwargs)
        if op == "install_plan" and "files" in answer:
            # The plan leads with authority, manifest, receipt and config.
            config = answer["files"][3]
            config["after"] = _strip_hooks(config["after"])
        return answer

    # Publish stepwise so the plan answer reaches the publication.
    use_stepwise_publication(monkeypatch)
    monkeypatch.setattr(flow, "ask", _without_hooks)

    context = HarnessContext(
        home_dir=home_dir,
        workspace_dir=workspace_dir,
        guard_home=home_dir,
        home_override_explicit=True,
    )
    with pytest.raises(RuntimeError, match="codex_authoritative_hook_unavailable"):
        harness_support.install("codex", context)

    assert (home_dir / "bin" / "guard-codex").exists() is False


@pytest.mark.parametrize(
    "command_template",
    (
        "trap - DEBUG; cat .env > {marker}",
        "trap ':' DEBUG; cat .env > {marker}",
        "set +T; cat .env > {marker}",
        "function __hol_guard_codex_bash_debug_trap() {{ :; }}; cat .env > {marker}",
        "BASH_ENV=/dev/null bash -c 'cat .env' > {marker}",
        ". /dev/null; cat .env > {marker}",
        "{{ cat .env; }} > {marker}",
        "(cat .env) > {marker}",
        "bash -c 'cat .env' > {marker}",
        "cat <(cat .env) > {marker}",
        "cat .env | tee {marker}",
        'printf %s "$(cat .env)" > {marker}',
        "cat <<EOF > {marker}\n$(cat .env)\nEOF",
    ),
    ids=(
        "remove-debug-trap",
        "replace-debug-trap",
        "disable-functrace",
        "replace-guard-function",
        "replace-bash-env",
        "source-clean-startup",
        "group-outer-redirection",
        "subshell-outer-redirection",
        "nested-bash-c-outer-redirection",
        "process-substitution",
        "pipeline",
        "command-substitution",
        "heredoc-command-substitution",
    ),
)
@pytest.mark.usefixtures("native_hook_force")
def test_native_pretool_checks_complete_command_before_shell_mutation_can_run(
    command_template,
    tmp_path,
    capsys,
    monkeypatch,
    native_hook_force: Path,
):
    bash_path = shutil.which("bash")
    if bash_path is None:
        pytest.skip("bash is required for the marker-file security reproduction")
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    _install_codex(home_dir, workspace_dir, capsys)
    _write_text(home_dir / "config.toml", "approval_wait_timeout_seconds = 0\n")
    _write_text(workspace_dir / ".env", "P25_FAKE_SECRET=marker-only-test-value\n")
    marker_path = workspace_dir / "guard-p25-bypass-marker"
    command = command_template.format(marker=shlex.quote(str(marker_path)))
    event = {
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": command},
        "source_scope": "project",
        "cwd": str(workspace_dir),
    }
    monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps(event)))
    monkeypatch.setattr(
        guard_commands_module,
        "ensure_guard_daemon",
        lambda _guard_home: "http://127.0.0.1:4455",
    )

    result = main(
        [
            "guard",
            "hook",
            "--home",
            str(home_dir),
            "--workspace",
            str(workspace_dir),
            "--harness",
            "codex",
        ]
    )
    captured = capsys.readouterr()
    response = json.loads(captured.out) if captured.out else {}
    denied = response.get("hookSpecificOutput", {}).get("permissionDecision") == "deny"
    if not denied:
        subprocess.run(
            [bash_path, "-c", command],
            cwd=workspace_dir,
            env={"HOME": str(home_dir), "PATH": str(Path(bash_path).parent)},
            check=False,
            capture_output=True,
            text=True,
            timeout=5,
        )

    assert result == 0
    assert denied is True
    assert marker_path.exists() is False
    assert len(GuardStore(home_dir).list_approval_requests(limit=10)) <= 1


@pytest.mark.usefixtures("native_hook_force")
def test_native_pretool_keeps_ordinary_safe_command_prompt_free(
    tmp_path,
    capsys,
    monkeypatch,
    native_hook_force: Path,
):
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    _install_codex(home_dir, workspace_dir, capsys)
    command = "git status --short"
    event = {
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": command},
        "source_scope": "project",
        "cwd": str(workspace_dir),
    }
    monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps(event)))

    result = main(
        [
            "guard",
            "hook",
            "--home",
            str(home_dir),
            "--workspace",
            str(workspace_dir),
            "--harness",
            "codex",
        ]
    )

    assert result == 0
    output = json.loads(capsys.readouterr().out)
    assert output["hookSpecificOutput"]["permissionDecision"] == "allow"
    assert output["continue"] is True
    assert GuardStore(home_dir).list_approval_requests(limit=10) == []
