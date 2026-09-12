"""Regression coverage for direct reads, scripts and immutable review floors."""

from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard.runtime.command_evaluation import evaluate_command
from codex_plugin_scanner.guard.runtime.secret_file_requests import (
    build_tool_action_request_artifact,
    extract_sensitive_tool_action_request,
    is_explicitly_benign_tool_action_request,
)
from codex_plugin_scanner.guard.runtime.shell_secret_reads import assess_shell_reads


@pytest.mark.parametrize(
    "command",
    (
        "cat .env",
        "head -n 10 .env.local",
        "tail --lines=2 .env.production",
        "sed -n '1,3p' .env",
        "grep API_KEY .env",
        "rg -n TOKEN .env",
        "cat < .env",
        "read value < .env",
        "source .env",
        ". .env",
        "/bin/cat .env",
        "command cat .env",
        "command -p cat .env",
        "command -- cat .env",
        "exec cat .env",
        "exec -- cat .env",
        "exec -a reader cat .env",
        "bash -c 'cat .env'",
        "ksh -c 'cat .env'",
        "ash -c 'cat .env'",
        "cat .env | head -n 1",
        "python3 -c 'print(open(\".env\").read())'",
        "python3.11 -c 'print(open(\".env\").read())'",
        "python3.12 -c 'print(open(\".env\").read())'",
        'node -e \'console.log(require("fs").readFileSync(".env", "utf8"))\'',
    ),
)
def test_secret_reads_have_an_explicit_floor(command: str, tmp_path: Path) -> None:
    evaluation = evaluate_command(command, cwd=tmp_path, home_dir=tmp_path)
    assert evaluation.minimum_action in {"review", "block"}
    assert evaluation.decision_plane.action in {"require-reapproval", "block"}
    assert "local_secret_read" in evaluation.risk_classes
    request = extract_sensitive_tool_action_request("Bash", {"command": command}, cwd=tmp_path, home_dir=tmp_path)
    assert request is not None
    assert not is_explicitly_benign_tool_action_request("Bash", {"command": command}, cwd=tmp_path, home_dir=tmp_path)


@pytest.mark.parametrize(
    "command",
    (
        "echo .env",
        "printf '%s' .env",
        "rg '.env' src",
        "grep -e .env README.md",
        "cat docs/environment.md",
        "test -e .env && echo exists || echo absent",
        "command -v cat",
        "command -V cat",
        "bunx vitest run __tests__/guard-extension-public-promotions.test.ts --reporter=dot",
    ),
)
def test_mentions_and_test_arguments_are_not_secret_reads(command: str, tmp_path: Path) -> None:
    result = assess_shell_reads(command, cwd=tmp_path, home_dir=tmp_path)
    assert not result.requires_review
    assert not result.sensitive_paths


@pytest.mark.parametrize(
    "launch",
    (
        "bash scripts/check.sh",
        "sh scripts/check.sh",
        "ash scripts/check.sh",
        "./scripts/check.sh",
        "source scripts/check.sh",
        "command bash scripts/check.sh",
        "exec bash scripts/check.sh",
    ),
)
def test_local_script_reads_are_found_without_a_network_sink(launch: str, tmp_path: Path) -> None:
    script = tmp_path / "scripts/check.sh"
    script.parent.mkdir()
    script.write_text("cat .env\n")
    result = assess_shell_reads(launch, cwd=tmp_path, home_dir=tmp_path)
    assert result.sensitive_paths == (str(tmp_path / ".env"),)
    assert result.script_sources
    request = extract_sensitive_tool_action_request("Bash", {"command": launch}, cwd=tmp_path, home_dir=tmp_path)
    assert request is not None
    assert request.guard_default_action == "require-reapproval"
    assert request.action_class == "local secret read shell command"


def test_nested_script_keeps_the_callers_working_directory(tmp_path: Path) -> None:
    (tmp_path / "scripts").mkdir()
    (tmp_path / "scripts/parent.sh").write_text("sh child.sh\n")
    (tmp_path / "child.sh").write_text("cat .env\n")
    result = assess_shell_reads("sh scripts/parent.sh", cwd=tmp_path, home_dir=tmp_path)
    assert result.sensitive_paths == (str(tmp_path / ".env"),)
    assert len(result.script_sources) == 2


@pytest.mark.parametrize("source", ("echo harmless\n", 'p=.en; cat "${p}v"\n'))
def test_no_detected_secret_does_not_authorize_arbitrary_scripts(source: str, tmp_path: Path) -> None:
    (tmp_path / "check.sh").write_text(source)
    result = evaluate_command("bash check.sh", cwd=tmp_path, home_dir=tmp_path)
    assert result.minimum_action == "review"
    assert result.decision_plane.action == "require-reapproval"


def test_shell_command_strings_retain_review_and_are_scanned(tmp_path: Path) -> None:
    harmless = evaluate_command("ksh -c 'echo harmless'", cwd=tmp_path, home_dir=tmp_path)
    assert harmless.minimum_action == "review"
    secret = assess_shell_reads("ksh -c 'cat .env'", cwd=tmp_path, home_dir=tmp_path)
    assert secret.sensitive_paths == (str(tmp_path / ".env"),)
    oversized = "echo x; " * 1200 + "cat .env"
    result = assess_shell_reads(f"bash -c {oversized!r}", cwd=tmp_path, home_dir=tmp_path)
    assert result.requires_review
    assert result.sensitive_paths == (str(tmp_path / ".env"),)


def test_python_flags_before_script_do_not_hide_local_execution(tmp_path: Path) -> None:
    script = tmp_path / "check.py"
    script.write_text('open(".env").read()\n')
    for command in ("python3 -s check.py", "python3 -I check.py"):
        assessment = assess_shell_reads(command, cwd=tmp_path, home_dir=tmp_path)
        assert assessment.script_requested
        assert assessment.sensitive_paths == (str(tmp_path / ".env"),)
        assert evaluate_command(command, cwd=tmp_path, home_dir=tmp_path).minimum_action == "review"


@pytest.mark.parametrize(
    ("command", "filename"),
    (
        ("python3 - < payload.py", "payload.py"),
        ("node - < payload.js", "payload.js"),
    ),
)
def test_interpreter_stdin_requires_local_execution_review(command: str, filename: str, tmp_path: Path) -> None:
    (tmp_path / filename).write_text("print('synthetic input')\n", encoding="utf-8")
    assessment = assess_shell_reads(command, cwd=tmp_path, home_dir=tmp_path)
    assert assessment.script_requested
    assert assessment.incomplete
    assert assessment.requires_review
    evaluation = evaluate_command(command, cwd=tmp_path, home_dir=tmp_path)
    assert evaluation.minimum_action == "review"
    assert evaluation.decision_plane.action == "require-reapproval"


def test_python_module_mode_is_mutable_local_execution(tmp_path: Path) -> None:
    (tmp_path / "reader.py").write_text('open(".env").read()\n')
    assessment = assess_shell_reads("python3 -I -m reader", cwd=tmp_path, home_dir=tmp_path)
    assert assessment.script_requested
    assert assessment.incomplete
    assert assessment.requires_review
    evaluation = evaluate_command("python3 -I -m reader", cwd=tmp_path, home_dir=tmp_path)
    assert evaluation.minimum_action == "review"
    assert evaluation.decision_plane.action == "require-reapproval"


def test_extensionless_local_executable_requires_review(tmp_path: Path) -> None:
    script = tmp_path / "check"
    script.write_text("#!/bin/sh\ncat .env\n")
    script.chmod(0o755)
    assessment = assess_shell_reads("./check", cwd=tmp_path, home_dir=tmp_path)
    assert assessment.script_requested
    assert assessment.requires_review
    assert evaluate_command("./check", cwd=tmp_path, home_dir=tmp_path).minimum_action == "review"


def test_ambiguous_execution_builtin_fails_closed(tmp_path: Path) -> None:
    assessment = assess_shell_reads("command --unknown cat .env", cwd=tmp_path, home_dir=tmp_path)
    assert assessment.script_requested
    assert assessment.incomplete
    assert assessment.requires_review


def test_post_cd_reads_use_the_execution_directory(tmp_path: Path) -> None:
    ssh_dir = tmp_path / ".ssh"
    ssh_dir.mkdir()
    (ssh_dir / "config").write_text("Host example\n")
    result = assess_shell_reads("cd .ssh && cat config", cwd=tmp_path, home_dir=tmp_path)
    assert result.sensitive_paths == (str(ssh_dir / "config"),)

    subdir = tmp_path / "subdir"
    subdir.mkdir()
    (tmp_path / ".env").write_text("FAKE_TEST_SECRET=synthetic\n")
    (subdir / "notes.txt").symlink_to(tmp_path / ".env")
    alias = assess_shell_reads("cd subdir && cat notes.txt", cwd=tmp_path, home_dir=tmp_path)
    assert alias.sensitive_paths == (str(tmp_path / ".env"),)


def test_unresolved_cwd_input_redirect_fails_closed(tmp_path: Path) -> None:
    assessment = assess_shell_reads('cd "$DIR" && read value < .env', cwd=tmp_path, home_dir=tmp_path)
    assert assessment.script_requested
    assert assessment.incomplete
    assert assessment.requires_review


def test_script_changes_change_the_request_identity(tmp_path: Path) -> None:
    script = tmp_path / "check.sh"
    identities = []
    for source in ("cat .env\n", "head -n 1 .env\n"):
        script.write_text(source)
        request = extract_sensitive_tool_action_request(
            "Bash", {"command": "bash check.sh"}, cwd=tmp_path, home_dir=tmp_path
        )
        assert request is not None
        artifact = build_tool_action_request_artifact(
            harness="claude-code", request=request, config_path=str(tmp_path / "policy.json"), source_scope="project"
        )
        assert "local_secret_read" in artifact.metadata["risk_classes"]
        identities.append(artifact.artifact_id)
    assert identities[0] != identities[1]


@pytest.mark.parametrize("case", ("missing", "oversized", "cycle", "symlink"))
def test_uninspectable_scripts_still_require_review(case: str, tmp_path: Path) -> None:
    script = tmp_path / "check.sh"
    if case == "oversized":
        script.write_text("#" * (33 * 1024))
    elif case == "cycle":
        script.write_text("bash check.sh\n")
    elif case == "symlink":
        target = tmp_path / "other.sh"
        target.write_text("echo harmless\n")
        script.symlink_to(target)
    assessment = assess_shell_reads("bash check.sh", cwd=tmp_path, home_dir=tmp_path)
    assert assessment.requires_review
    assert assessment.incomplete
    assert (
        evaluate_command("bash check.sh", cwd=tmp_path, home_dir=tmp_path).decision_plane.action == "require-reapproval"
    )


def test_innocent_path_alias_cannot_hide_a_secret_read(tmp_path: Path) -> None:
    (tmp_path / ".env").write_text("FAKE_TEST_SECRET=synthetic\n")
    (tmp_path / "notes.txt").symlink_to(tmp_path / ".env")
    result = assess_shell_reads("cat notes.txt", cwd=tmp_path, home_dir=tmp_path)
    assert result.sensitive_paths == (str(tmp_path / ".env"),)
    assert evaluate_command("cat notes.txt", cwd=tmp_path, home_dir=tmp_path).minimum_action == "review"


def test_path_object_construction_is_not_a_file_read(tmp_path: Path) -> None:
    command = "python3 -c 'from pathlib import Path; print(Path(\".env\"))'"
    assert not assess_shell_reads(command, cwd=tmp_path, home_dir=tmp_path).sensitive_paths
    command = "python3 -c 'from pathlib import Path; print(Path(\".env\").read_text())'"
    assert assess_shell_reads(command, cwd=tmp_path, home_dir=tmp_path).sensitive_paths
