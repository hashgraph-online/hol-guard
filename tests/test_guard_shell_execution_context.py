from __future__ import annotations

import os
import shlex
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.cli import commands_hook_runtime_eval as runtime_eval_module
from codex_plugin_scanner.guard.cli.commands_support_codex_reads import (
    _codex_command_is_read_only_source_inspection,
)
from codex_plugin_scanner.guard.cli.commands_support_codex_tool_output import (
    _codex_sensitive_local_source_matches,
)
from codex_plugin_scanner.guard.cli.commands_support_runtime_artifacts import (
    _codex_post_tool_output_artifact,
)
from codex_plugin_scanner.guard.cli.commands_support_runtime_policy import (
    _runtime_hook_approval_context_token,
)
from codex_plugin_scanner.guard.config import GuardConfig
from codex_plugin_scanner.guard.consumer import artifact_hash
from codex_plugin_scanner.guard.models import GuardArtifact
from codex_plugin_scanner.guard.runtime import secret_file_requests as secret_file_requests_module
from codex_plugin_scanner.guard.runtime.actions import GuardActionEnvelope
from codex_plugin_scanner.guard.runtime.package_intent import (
    build_package_request_artifact,
    parse_package_intent,
)
from codex_plugin_scanner.guard.runtime.secret_file_requests import (
    extract_sensitive_tool_action_request,
)
from codex_plugin_scanner.guard.runtime.shell_execution_context import (
    SHELL_CWD_AMBIGUOUS_STACK,
    SHELL_CWD_MISSING_DIRECTORY,
    SHELL_CWD_PATH_CHANGED,
    SHELL_CWD_STACK_LIMIT,
    SHELL_CWD_SYMLINK_ESCAPE,
    SHELL_CWD_UNREADABLE_DIRECTORY,
    SHELL_CWD_UNRESOLVED_CONTROL_FLOW,
    SHELL_CWD_UNRESOLVED_EXPRESSION,
    SHELL_CWD_UNRESOLVED_PARENT_SHELL,
    SHELL_CWD_WORKSPACE_ESCAPE,
    model_shell_execution_context,
    validate_shell_execution_segment,
)
from codex_plugin_scanner.guard.runtime.signals import GuardRiskSignalV3


def _write(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def _write_executable(path: Path) -> Path:
    _write(path, "#!/bin/sh\nexit 0\n")
    path.chmod(0o755)
    return path


def _approval_token(artifact: GuardArtifact, *, workspace: Path, config: GuardConfig) -> str:
    return _runtime_hook_approval_context_token(
        artifact=artifact,
        content_hash=artifact_hash(artifact),
        runtime_workspace=workspace,
        action_envelope=None,
        config=config,
        current_config_action="review",
        trusted_cli_action=None,
        untrusted_payload_action=None,
        package_action=None,
        data_flow_action=None,
        scanner_action=None,
        current_action="review",
        data_flow_signals=(),
        scanner_evidence=(),
    )


@pytest.mark.parametrize(
    "operand",
    [
        "project-b",
        "./project-b",
        "project-a/../project-b",
        "project with spaces",
        "prøject-雪",
    ],
)
def test_literal_cd_forms_resolve_against_the_prior_effective_cwd(tmp_path: Path, operand: str) -> None:
    destination = tmp_path / Path(operand).name
    if "../" in operand:
        destination = tmp_path / "project-b"
        (tmp_path / "project-a").mkdir()
    destination.mkdir()

    context = model_shell_execution_context(
        f"cd -- {shlex.quote(operand)} && pytest -q",
        cwd=tmp_path,
    )

    assert context.complete
    assert context.reason_code is None
    assert context.segments[1].effective_cwd == destination.resolve()
    assert context.segments[1].control_before == ("&&",)


def test_absolute_cd_and_newline_boundaries_preserve_full_command_identity(tmp_path: Path) -> None:
    destination = tmp_path / "project-b"
    destination.mkdir()
    command = f"cd {shlex.quote(str(destination))}\npytest -q"

    context = model_shell_execution_context(command, cwd=tmp_path)

    assert context.complete
    assert context.command_text == command
    assert context.segments[0].control_after == ("\n",)
    assert context.segments[1].effective_cwd == destination.resolve()


def test_nested_pushd_popd_tracks_a_bounded_explicit_stack(tmp_path: Path) -> None:
    nested = tmp_path / "services" / "auth"
    nested.mkdir(parents=True)

    context = model_shell_execution_context(
        "pushd services; pushd auth; ruff check .; popd; pytest -q; popd; pytest -q",
        cwd=tmp_path,
    )

    assert context.complete
    assert context.segments[2].effective_cwd == nested.resolve()
    assert context.segments[2].directory_stack == (tmp_path.resolve(), (tmp_path / "services").resolve())
    assert context.segments[4].effective_cwd == (tmp_path / "services").resolve()
    assert context.segments[6].effective_cwd == tmp_path.resolve()


def test_directory_stack_depth_is_bounded_and_fails_closed(tmp_path: Path) -> None:
    command = "; ".join((*(["pushd ."] * 33), "pytest -q"))

    context = model_shell_execution_context(command, cwd=tmp_path)

    assert not context.complete
    assert context.reason_code == SHELL_CWD_STACK_LIMIT
    assert context.segments[-1].effective_cwd is None


def test_subshell_group_restores_the_outer_working_directory(tmp_path: Path) -> None:
    destination = tmp_path / "project-b"
    destination.mkdir()

    context = model_shell_execution_context("(cd project-b && pytest -q); pytest -q", cwd=tmp_path)

    assert context.complete
    assert context.segments[1].effective_cwd == destination.resolve()
    assert context.segments[2].effective_cwd == tmp_path.resolve()
    assert context.segments[2].control_before == (
        ")",
        ";",
    )


def test_brace_group_keeps_the_changed_directory_and_accepts_required_separator(tmp_path: Path) -> None:
    destination = tmp_path / "project-b"
    destination.mkdir()

    context = model_shell_execution_context("{ cd project-b; pytest -q; }; ruff check .", cwd=tmp_path)

    assert context.complete
    assert context.segments[1].effective_cwd == destination.resolve()
    assert context.segments[2].effective_cwd == destination.resolve()
    assert context.segments[2].control_before == (";", "}", ";")


def test_trailing_list_separator_does_not_make_literal_cd_incomplete(tmp_path: Path) -> None:
    destination = tmp_path / "project-b"
    destination.mkdir()

    context = model_shell_execution_context("cd project-b;", cwd=tmp_path)

    assert context.complete
    assert context.reason_code is None


def test_fd_duplication_is_preserved_as_a_redirection_not_background_control(tmp_path: Path) -> None:
    destination = tmp_path / "project-b"
    destination.mkdir()

    context = model_shell_execution_context("cd project-b 2>&1 && pytest -q", cwd=tmp_path)

    assert context.complete
    assert context.segments[0].control_operator == "&&"
    assert context.segments[1].effective_cwd == destination.resolve()


def test_missing_directory_redirection_target_fails_closed(tmp_path: Path) -> None:
    (tmp_path / "project-b").mkdir()

    context = model_shell_execution_context("cd project-b > && pytest -q", cwd=tmp_path)

    assert not context.complete
    assert context.reason_code == SHELL_CWD_UNRESOLVED_EXPRESSION
    assert context.segments[1].effective_cwd is None


def test_pipeline_directory_change_does_not_leak_from_its_subprocess(tmp_path: Path) -> None:
    (tmp_path / "project-b").mkdir()

    context = model_shell_execution_context("cd project-b | pytest -q", cwd=tmp_path)

    assert context.complete
    assert context.segments[0].control_operator == "|"
    assert context.segments[1].effective_cwd == tmp_path.resolve()

    right_hand_change = model_shell_execution_context("echo ready | cd project-b && pytest -q", cwd=tmp_path)
    assert right_hand_change.complete
    assert right_hand_change.segments[-1].effective_cwd == tmp_path.resolve()


def test_conditionally_executed_directory_change_is_not_assumed(tmp_path: Path) -> None:
    (tmp_path / "project-b").mkdir()

    context = model_shell_execution_context("pytest -q && cd project-b; ruff check .", cwd=tmp_path)

    assert not context.complete
    assert context.reason_code == "shell_cwd_unresolved_control_flow"
    assert context.segments[-1].effective_cwd is None


@pytest.mark.parametrize(
    ("command", "reason_code"),
    [
        ("cd missing && pytest -q", SHELL_CWD_MISSING_DIRECTORY),
        ("cd $PROJECT && pytest -q", SHELL_CWD_UNRESOLVED_EXPRESSION),
        ("cd $(pwd) && pytest -q", SHELL_CWD_UNRESOLVED_EXPRESSION),
        ("cd project-* && pytest -q", SHELL_CWD_UNRESOLVED_EXPRESSION),
        ("popd; pytest -q", SHELL_CWD_AMBIGUOUS_STACK),
        ("pushd +1; pytest -q", SHELL_CWD_AMBIGUOUS_STACK),
        ("function cd; cd project-b && pytest -q", SHELL_CWD_UNRESOLVED_EXPRESSION),
        ("if cd project-b; then pytest -q; fi", SHELL_CWD_UNRESOLVED_CONTROL_FLOW),
    ],
)
def test_unresolved_directory_contexts_have_stable_fail_closed_reasons(
    tmp_path: Path,
    command: str,
    reason_code: str,
) -> None:
    context = model_shell_execution_context(command, cwd=tmp_path)

    assert not context.complete
    assert context.reason_code == reason_code
    assert context.segments[-1].effective_cwd is None
    request = extract_sensitive_tool_action_request("Bash", {"command": command}, cwd=tmp_path)
    assert request is not None
    assert request.action_class == "unresolved shell execution context"
    assert request.shell_execution_context_reason_code == reason_code


@pytest.mark.parametrize(
    "command",
    [
        "f() { cd project-b; }; f; pytest -q",
        "function f { cd project-b; }; f; pytest -q",
        "source setup.sh; pytest -q",
        ". setup.sh; pytest -q",
        'eval "cd project-b"; pytest -q',
        "trap 'cd project-b' DEBUG; pytest -q",
    ],
)
def test_parent_shell_cwd_effects_fail_closed_with_a_stable_reason(
    tmp_path: Path,
    command: str,
) -> None:
    (tmp_path / "project-b").mkdir()

    context = model_shell_execution_context(command, cwd=tmp_path)
    request = extract_sensitive_tool_action_request("Bash", {"command": command}, cwd=tmp_path)

    assert not context.complete
    assert context.reason_code == SHELL_CWD_UNRESOLVED_PARENT_SHELL
    assert all(segment.effective_cwd is None for segment in context.segments)
    assert request is not None
    assert request.action_class == "unresolved shell execution context"
    assert request.shell_execution_context_reason_code == SHELL_CWD_UNRESOLVED_PARENT_SHELL


def test_empty_debug_trap_does_not_poison_a_literal_directory_change(tmp_path: Path) -> None:
    destination = tmp_path / "project-b"
    destination.mkdir()

    context = model_shell_execution_context("trap '' DEBUG; cd project-b; pytest -q", cwd=tmp_path)

    assert context.complete
    assert context.segments[-1].effective_cwd == destination.resolve()


@pytest.mark.parametrize("wrapper", ["command", "time"])
def test_transparent_builtin_wrappers_preserve_literal_cd_context(tmp_path: Path, wrapper: str) -> None:
    destination = tmp_path / "project-b"
    destination.mkdir()

    context = model_shell_execution_context(f"{wrapper} cd project-b && pytest -q", cwd=tmp_path)

    assert context.complete
    assert context.segments[1].effective_cwd == destination.resolve()


def test_workspace_and_symlink_escapes_are_distinguished(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    outside = tmp_path / "outside"
    workspace.mkdir()
    outside.mkdir()
    symlink = workspace / "linked"
    try:
        symlink.symlink_to(outside, target_is_directory=True)
    except OSError:
        pytest.skip("directory symlinks are unavailable")

    lexical_escape = model_shell_execution_context("cd .. && pytest -q", cwd=workspace)
    symlink_escape = model_shell_execution_context("cd linked && pytest -q", cwd=workspace)

    assert lexical_escape.reason_code == SHELL_CWD_WORKSPACE_ESCAPE
    assert symlink_escape.reason_code == SHELL_CWD_SYMLINK_ESCAPE


def test_unreadable_directory_fails_closed_without_shell_execution(tmp_path: Path) -> None:
    destination = tmp_path / "unreadable"
    destination.mkdir()
    destination.chmod(0)
    try:
        context = model_shell_execution_context("cd unreadable && pytest -q", cwd=tmp_path)
    finally:
        destination.chmod(0o700)

    assert not context.complete
    assert context.reason_code == SHELL_CWD_UNREADABLE_DIRECTORY


@pytest.mark.parametrize("replacement", ["remove", "swap"])
def test_modeled_directory_is_revalidated_against_path_replacement(
    tmp_path: Path,
    replacement: str,
) -> None:
    destination = tmp_path / "project-b"
    destination.mkdir()
    context = model_shell_execution_context("cd project-b && pytest -q", cwd=tmp_path)
    command_segment = context.segments[1]
    destination.rmdir()
    if replacement == "swap":
        destination.mkdir()

    effective_cwd, reason = validate_shell_execution_segment(context, command_segment)

    assert effective_cwd is None
    assert reason == SHELL_CWD_PATH_CHANGED


def test_modeled_symlink_route_is_revalidated_against_retargeting(tmp_path: Path) -> None:
    first = tmp_path / "first"
    second = tmp_path / "second"
    first.mkdir()
    second.mkdir()
    link = tmp_path / "project"
    try:
        link.symlink_to(first, target_is_directory=True)
    except OSError:
        pytest.skip("directory symlinks are unavailable")
    context = model_shell_execution_context("cd project && pytest -q", cwd=tmp_path)
    command_segment = context.segments[1]
    link.unlink()
    link.symlink_to(second, target_is_directory=True)

    effective_cwd, reason = validate_shell_execution_segment(context, command_segment)

    assert effective_cwd is None
    assert reason == SHELL_CWD_PATH_CHANGED


def test_python_safety_checks_use_project_b_not_the_launch_project(tmp_path: Path) -> None:
    project_a = tmp_path / "project-a"
    project_b = project_a / "project-b"
    project_b.mkdir(parents=True)
    _write(project_a / "pytest.py", "raise SystemExit('project-a shadow')\n")

    safe_request = extract_sensitive_tool_action_request(
        "Bash",
        {"command": "cd project-b && python -m pytest -q"},
        cwd=project_a,
    )
    _write(project_b / "pytest.py", "raise SystemExit('project-b shadow')\n")
    unsafe_request = extract_sensitive_tool_action_request(
        "Bash",
        {"command": "cd project-b && python -m pytest -q"},
        cwd=project_a,
    )

    assert safe_request is not None
    assert safe_request.guard_default_action == "sandbox-required"
    assert safe_request.reason_code == "pytest_restricted_profile_required"
    assert safe_request.shell_execution_effective_cwds == (str(project_b.resolve()),)
    assert unsafe_request is not None
    assert unsafe_request.guard_default_action == "sandbox-required"
    assert unsafe_request.reason_code == "pytest_restricted_profile_required"
    assert unsafe_request.shell_execution_effective_cwds == (str(project_b.resolve()),)


def test_pytest_config_discovery_uses_the_effective_project(tmp_path: Path) -> None:
    project_a = tmp_path / "project-a"
    project_b = project_a / "project-b"
    project_b.mkdir(parents=True)
    _write(project_a / "pyproject.toml", '[tool.pytest.ini_options]\naddopts = "-q"\n')
    _write(project_b / "pyproject.toml", '[tool.pytest.ini_options]\naddopts = "-p evil"\n')

    request = extract_sensitive_tool_action_request(
        "Bash",
        {"command": "cd project-b && pytest -q"},
        cwd=project_a,
    )

    assert request is not None
    assert request.shell_execution_effective_cwds == (str(project_b.resolve()),)


def test_heredoc_does_not_make_an_earlier_project_use_the_last_effective_cwd(tmp_path: Path) -> None:
    project_a = tmp_path / "project-a"
    project_b = project_a / "project-b"
    project_b.mkdir(parents=True)
    _write(project_a / "pyproject.toml", '[tool.pytest.ini_options]\naddopts = "-p evil"\n')
    command = "python -m pytest -q; cd project-b && python - <<'PY'\nprint('safe')\nPY\n"

    request = extract_sensitive_tool_action_request("Bash", {"command": command}, cwd=project_a)

    assert request is not None
    assert request.shell_execution_effective_cwds == (
        str(project_a.resolve()),
        str(project_b.resolve()),
    )


def test_literal_pushd_and_ruff_remain_prompt_free_in_the_effective_project(tmp_path: Path) -> None:
    project = tmp_path / "services" / "auth"
    project.mkdir(parents=True)

    safe_request = extract_sensitive_tool_action_request(
        "Bash",
        {"command": "pushd services/auth && python -m ruff check ."},
        cwd=tmp_path,
    )
    _write(project / "ruff.py", "raise SystemExit('shadowed ruff')\n")
    unsafe_request = extract_sensitive_tool_action_request(
        "Bash",
        {"command": "pushd services/auth && python -m ruff check ."},
        cwd=tmp_path,
    )

    assert safe_request is None
    assert unsafe_request is not None
    assert unsafe_request.shell_execution_effective_cwds == (str(project.resolve()),)


def test_source_inspection_and_package_evidence_use_project_b(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project_a = tmp_path / "project-a"
    project_b = project_a / "project-b"
    _write(project_a / "package.json", '{"devDependencies":{"vitest":"^3.0.0"}}\n')
    _write(project_a / "package-lock.json", '{"packages":{"node_modules/vitest":{"version":"3.0.0"}}}\n')
    project_a_runner = _write_executable(project_a / "node_modules" / ".bin" / "vitest")
    _write(project_b / "src" / "safe.py", "SAFE = True\n")
    _write(project_b / "package.json", '{"devDependencies":{"vitest":"^4.0.0"}}\n')
    _write(project_b / "package-lock.json", '{"packages":{"node_modules/vitest":{"version":"4.0.0"}}}\n')
    local_runner = _write_executable(project_b / "node_modules" / ".bin" / "vitest")
    manager = _write_executable(tmp_path / "bin" / "npx")
    monkeypatch.setenv("PATH", str(manager.parent))

    assert _codex_command_is_read_only_source_inspection(
        "cd project-b && sed -n '1,20p' src/safe.py",
        cwd=project_a,
    )
    intent = parse_package_intent(
        "cd project-b && npx --no-install vitest --help",
        workspace=project_a,
    )

    assert intent is not None
    evidence = intent.local_executions[0]
    assert evidence.effective_cwd == str(project_b.resolve())
    assert evidence.local_executable is not None
    assert evidence.local_executable.resolved_path == str(local_runner.resolve())
    assert evidence.local_executable.resolved_path != str(project_a_runner.resolve())
    assert intent.manifest_paths == ("project-b/package.json",)


def test_secret_source_output_artifact_uses_the_effective_project(tmp_path: Path) -> None:
    project_a = tmp_path / "project-a"
    project_b = project_a / "project-b"
    _write(project_b / ".env", "API_KEY=project-b-secret\n")
    command = "cd project-b && cat .env"

    matches = _codex_sensitive_local_source_matches(command, cwd=project_a)
    artifact = _codex_post_tool_output_artifact(
        payload={
            "tool_name": "Bash",
            "tool_input": {"command": command},
            "tool_response": {"stdout": "API_KEY=project-b-secret\n"},
        },
        config_path=str(project_a / ".codex" / "config.toml"),
        source_scope="project",
        cwd=project_a,
    )

    assert matches
    assert matches[0].normalized_path == str((project_b / ".env").resolve())
    assert artifact is not None
    assert artifact.metadata["effective_cwd"] == str(project_b.resolve())


def test_approval_tokens_are_partitioned_by_effective_project(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    project_a = workspace / "project-a"
    project_b = workspace / "project-b"
    _write(project_a / "package.json", '{"dependencies":{"left-pad":"1.3.0"}}\n')
    _write(project_b / "package.json", '{"dependencies":{"left-pad":"1.1.0"}}\n')
    _write(project_a / "conftest.py", "PROJECT = 'a'\n")
    _write(project_b / "conftest.py", "PROJECT = 'b'\n")
    _write(project_a / "pyproject.toml", '[tool.pytest.ini_options]\naddopts = "-q"\n')
    _write(project_b / "pyproject.toml", '[tool.pytest.ini_options]\naddopts = "-ra"\n')
    config = GuardConfig(guard_home=tmp_path / "home", workspace=workspace)

    def token(project: str) -> str:
        intent = parse_package_intent(f"cd {project} && npm install left-pad", workspace=workspace)
        assert intent is not None
        artifact = build_package_request_artifact(
            "codex",
            intent,
            config_path=str(workspace / ".codex" / "config.toml"),
            source_scope="project",
        )
        return _approval_token(artifact, workspace=workspace, config=config)

    assert token("project-a") != token("project-b")


def test_approval_token_binds_executables_from_every_effective_project(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    project_a = workspace / "project-a"
    project_b = workspace / "project-b"
    runner_a = _write_executable(project_a / "runner")
    _write_executable(project_b / "runner")
    config = GuardConfig(guard_home=tmp_path / "home", workspace=workspace)
    artifact = GuardArtifact(
        artifact_id="codex:project:multi-cwd-runner",
        name="multi-cwd runner",
        harness="codex",
        artifact_type="tool_action_request",
        source_scope="project",
        config_path=str(workspace / ".codex" / "config.toml"),
        command="./runner",
        metadata={
            "shell_execution_context_hash": "stable-command-context",
            "shell_execution_context_complete": True,
            "shell_execution_effective_cwds": [str(project_a), str(project_b)],
        },
    )

    first = _approval_token(artifact, workspace=workspace, config=config)
    _write(runner_a, "#!/bin/sh\nexit 7\n")
    runner_a.chmod(0o755)
    second = _approval_token(artifact, workspace=workspace, config=config)

    assert first != second


def test_cisco_preflight_scans_every_distinct_effective_project(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project_a = tmp_path / "project-a"
    project_b = tmp_path / "project-b"
    project_a.mkdir()
    project_b.mkdir()
    calls: list[tuple[Path | None, tuple[Path, ...]]] = []
    signal = GuardRiskSignalV3(
        signal_id="cisco:test",
        source="cisco_skill",
        source_version="test",
        category="skill",
        severity="high",
        confidence="strong",
        title="fixture",
        plain_language_summary="fixture",
        technical_detail=None,
        evidence_ref=None,
        scanner_name="fixture",
        scanner_status="enabled",
        scanner_rule_id="fixture",
        redaction_level="summary",
        source_path=None,
        source_line=None,
        data_source=None,
        data_sink=None,
        recommended_action=None,
    )
    action = GuardActionEnvelope(
        schema_version=1,
        action_id="fixture",
        harness="codex",
        event_name="PreToolUse",
        action_type="file_write",
        workspace=str(tmp_path),
        workspace_hash="fixture",
        tool_name="Write",
        command=None,
        prompt_excerpt=None,
        prompt_text=None,
        target_paths=("skills/demo/SKILL.md",),
        network_hosts=(),
        mcp_server=None,
        mcp_tool=None,
        package_manager=None,
        package_name=None,
        script_name=None,
        raw_payload_redacted={},
    )

    def fake_scan(
        _action: GuardActionEnvelope,
        *,
        workspace: Path | str | None,
        approved_scan_roots: tuple[Path, ...],
    ) -> tuple[GuardRiskSignalV3, ...]:
        calls.append(
            (
                Path(workspace) if workspace is not None else None,
                approved_scan_roots,
            )
        )
        return (signal,)

    monkeypatch.setattr(runtime_eval_module, "scan_action_for_cisco_evidence", fake_scan)

    evidence = runtime_eval_module._runtime_cisco_scanner_evidence(
        action,
        runtime_workspace=tmp_path,
        raw_shell_cwds=[str(project_a), str(project_b), str(project_a), ""],
    )

    assert calls == [
        (project_a.resolve(), (project_a.resolve(), project_b.resolve())),
        (project_b.resolve(), (project_a.resolve(), project_b.resolve())),
    ]
    assert evidence == (signal,)


def test_unresolved_execution_context_cannot_reuse_an_approval_token(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    config = GuardConfig(guard_home=tmp_path / "home", workspace=workspace)
    intent = parse_package_intent("cd $PROJECT && npm install left-pad", workspace=workspace)
    assert intent is not None
    artifact = build_package_request_artifact(
        "codex",
        intent,
        config_path=str(workspace / ".codex" / "config.toml"),
        source_scope="project",
    )

    first = _approval_token(artifact, workspace=workspace, config=config)
    second = _approval_token(artifact, workspace=workspace, config=config)

    assert artifact.metadata["shell_execution_context_complete"] is False
    assert first != second


def test_missing_explicit_execution_context_completeness_cannot_reuse_token(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    config = GuardConfig(guard_home=tmp_path / "home", workspace=workspace)
    artifact = GuardArtifact(
        artifact_id="codex:project:legacy-shell-context",
        name="legacy shell context",
        harness="codex",
        artifact_type="tool_action_request",
        source_scope="project",
        config_path=str(workspace / ".codex" / "config.toml"),
        command="rm marker",
        metadata={
            "shell_execution_context_hash": "legacy-context-without-completeness",
            "shell_execution_effective_cwds": [str(workspace)],
        },
    )

    first = _approval_token(artifact, workspace=workspace, config=config)
    second = _approval_token(artifact, workspace=workspace, config=config)

    assert first != second


def test_destructive_shell_request_models_each_command_context_once(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project = tmp_path / "project"
    project.mkdir()
    original_model = secret_file_requests_module.model_shell_execution_context
    calls: list[str] = []

    def counting_model(
        command_text: str,
        *,
        cwd: Path | None = None,
        workspace_root: Path | None = None,
    ):
        calls.append(command_text)
        return original_model(command_text, cwd=cwd, workspace_root=workspace_root)

    monkeypatch.setattr(secret_file_requests_module, "model_shell_execution_context", counting_model)

    request = extract_sensitive_tool_action_request(
        "Bash",
        {"command": "cd project && rm marker"},
        cwd=tmp_path,
    )

    assert request is not None
    assert request.action_class == "destructive shell command"
    assert calls == ["cd project && rm marker"]


def test_path_hash_changes_when_effective_directory_identity_changes(tmp_path: Path) -> None:
    project = tmp_path / "project"
    project.mkdir()
    first = model_shell_execution_context("cd project && pytest -q", cwd=tmp_path)
    old = tmp_path / "old-project"
    project.rename(old)
    project.mkdir()
    second = model_shell_execution_context("cd project && pytest -q", cwd=tmp_path)

    assert first.context_hash != second.context_hash
    assert os.stat(old).st_ino != os.stat(project).st_ino
