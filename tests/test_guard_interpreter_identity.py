from __future__ import annotations

import os
import shlex
import sys
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.consumer.service import artifact_hash
from codex_plugin_scanner.guard.runtime.approval_context import (
    approval_context_validation_reason,
    build_approval_context_token,
    build_runtime_executable_identity,
)
from codex_plugin_scanner.guard.runtime.secret_file_requests import (
    build_tool_action_request_artifact,
    extract_sensitive_tool_action_request,
    is_explicitly_benign_tool_action_request,
)


def _write_interpreter(path: Path, body: bytes = b"#!/bin/sh\nexit 0\n", *, executable: bool = True) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(body)
    path.chmod(0o755 if executable else 0o644)


def _request(command: str, *, cwd: Path):
    return extract_sensitive_tool_action_request("Bash", {"command": command}, cwd=cwd, home_dir=Path.home())


def _interpreter_evidence(command: str, *, cwd: Path) -> dict[str, object]:
    request = _request(command, cwd=cwd)
    assert request is not None
    assert request.interpreter_executable_identities
    return request.interpreter_executable_identities[0]


@pytest.mark.parametrize(
    "command_builder",
    (
        lambda token: f"{token} -c \"print('fixture')\"",
        lambda token: f"{token} <<'PY'\nprint('fixture')\nPY",
    ),
)
def test_project_local_interpreter_never_inherits_python_basename_trust(
    tmp_path: Path,
    command_builder,
) -> None:
    workspace = tmp_path / "workspace"
    interpreter = workspace / "python"
    _write_interpreter(interpreter)
    command = command_builder("./python")

    request = _request(command, cwd=workspace)

    assert request is not None
    assert request.action_class == "untrusted Python interpreter"
    assert request.reason_code == "interpreter_identity_untrusted"
    evidence = request.interpreter_executable_identities[0]
    assert evidence["raw_token"] == "./python"
    assert evidence["normalized_name"] == "python"
    assert evidence["trust"] == "workspace_local"
    executable = evidence["executable"]
    assert isinstance(executable, dict)
    assert executable["launch_path"] == str(interpreter.absolute())
    assert executable["path"] == str(interpreter.resolve())
    assert executable["status"] == "verified"
    assert executable["mode"] == 0o755
    assert isinstance(executable["sha256"], str)
    assert executable["path_chain"]
    assert not is_explicitly_benign_tool_action_request(
        "Bash",
        {"command": command},
        cwd=workspace,
        home_dir=Path.home(),
    )


@pytest.mark.parametrize(
    "relative_token",
    ("./python", "subdir/python", "space ☃/python"),
)
def test_relative_and_unicode_interpreter_paths_bind_effective_cwd(
    tmp_path: Path,
    relative_token: str,
) -> None:
    workspace = tmp_path / "workspace"
    interpreter = workspace / relative_token
    _write_interpreter(interpreter)
    token = shlex.quote(relative_token)

    evidence = _interpreter_evidence(f"{token} -c \"print('fixture')\"", cwd=workspace)

    assert evidence["raw_token"] == relative_token
    assert evidence["effective_cwd"] == str(workspace.resolve())
    assert evidence["trust"] == "workspace_local"


def test_cd_and_env_chdir_resolve_interpreter_from_segment_cwd(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    nested = workspace / "nested"
    _write_interpreter(nested / "python")

    cd_evidence = _interpreter_evidence("cd nested && ./python -c 'print(1)'", cwd=workspace)
    env_evidence = _interpreter_evidence("env -C nested ./python -c 'print(1)'", cwd=workspace)

    assert cd_evidence["effective_cwd"] == str(nested.resolve())
    assert env_evidence["effective_cwd"] == str(nested.resolve())
    assert cd_evidence["executable"]["path"] == env_evidence["executable"]["path"]


def test_env_path_and_sudo_wrappers_preserve_bare_interpreter_resolution(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    bin_dir = workspace / "bin"
    _write_interpreter(bin_dir / "python")
    path_value = os.pathsep.join((str(bin_dir), os.defpath))

    env_evidence = _interpreter_evidence(
        f"env PATH={shlex.quote(path_value)} python -c 'print(1)'",
        cwd=workspace,
    )
    sudo_evidence = _interpreter_evidence(
        f"PATH={shlex.quote(path_value)} sudo -n python -c 'print(1)'",
        cwd=workspace,
    )

    assert env_evidence["raw_token"] == "python"
    assert env_evidence["trust"] == "workspace_local"
    assert env_evidence["executable"]["launch_path"] == str((bin_dir / "python").absolute())
    assert sudo_evidence["raw_token"] == "python"
    assert sudo_evidence["trust"] == "ambiguous"
    assert sudo_evidence["executable"]["resolution_reason"] == "sudo_path_resolution_unproven"


def test_shell_command_string_preserves_nested_interpreter_token(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    _write_interpreter(workspace / "python")
    nested = "./python -c \"print('fixture')\""

    evidence = _interpreter_evidence(f"/bin/sh -c {shlex.quote(nested)}", cwd=workspace)

    assert evidence["raw_token"] == "./python"
    assert evidence["trust"] == "workspace_local"


def test_exact_guard_interpreter_keeps_read_only_commands_prompt_free(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    token = shlex.quote(sys.executable)
    commands = (
        f"{token} -c \"print('fixture')\"",
        f"{token} <<'PY'\nprint('fixture')\nPY",
    )

    for command in commands:
        assert _request(command, cwd=workspace) is None
        assert is_explicitly_benign_tool_action_request(
            "Bash",
            {"command": command},
            cwd=workspace,
            home_dir=Path.home(),
        )


@pytest.mark.skipif(not Path("/usr/bin/python3").is_file(), reason="trusted system Python is unavailable")
def test_verified_system_interpreter_keeps_normal_read_only_path_prompt_free(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    command = "/usr/bin/python3 -c \"print('fixture')\""

    assert _request(command, cwd=workspace) is None


@pytest.mark.skipif(not Path("/usr/bin/python3").is_file(), reason="trusted system Python is unavailable")
def test_bare_interpreter_uses_effective_path_and_keeps_trusted_resolution_prompt_free(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    command = f"PATH=/usr/bin{os.pathsep}/bin python3 -c \"print('fixture')\""

    assert _request(command, cwd=workspace) is None
    assert is_explicitly_benign_tool_action_request(
        "Bash",
        {"command": command},
        cwd=workspace,
        home_dir=Path.home(),
    )


@pytest.mark.parametrize(
    "foreign_token",
    (
        r"C:\workspace\python.EXE",
        r"\\server\share\python3.exe",
    ),
)
def test_foreign_windows_paths_are_not_reduced_to_a_trusted_basename(
    tmp_path: Path,
    foreign_token: str,
) -> None:
    if os.name == "nt":
        pytest.skip("foreign-path behavior is exercised from POSIX")
    workspace = tmp_path / "workspace"
    workspace.mkdir()

    evidence = _interpreter_evidence(
        f"{shlex.quote(foreign_token)} -c \"print('fixture')\"",
        cwd=workspace,
    )

    assert evidence["raw_token"] == foreign_token
    assert evidence["normalized_name"] in {"python.exe", "python3.exe"}
    assert evidence["trust"] == "ambiguous"
    assert evidence["executable"]["status"] == "foreign_platform_path"


def test_missing_and_non_executable_interpreters_fail_closed(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    _write_interpreter(workspace / "python", executable=False)

    non_executable = _interpreter_evidence("./python -c 'print(1)'", cwd=workspace)
    missing = _interpreter_evidence("./missing/python -c 'print(1)'", cwd=workspace)

    assert non_executable["trust"] == "non_executable"
    assert non_executable["executable"]["status"] == "not_executable"
    assert missing["trust"] == "missing"
    assert missing["executable"]["status"] in {"path_unreadable", "unreadable"}
    assert "reuse_nonce" in missing["executable"]


def test_symlink_swap_changes_bound_interpreter_and_artifact_identity(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    first_target = workspace / "runtimes" / "python-v1"
    second_target = workspace / "runtimes" / "python-v2"
    _write_interpreter(first_target, b"#!/bin/sh\necho first\n")
    _write_interpreter(second_target, b"#!/bin/sh\necho other\n")
    link = workspace / "python"
    link.symlink_to(first_target.relative_to(workspace))
    command = "./python -c 'print(1)'"

    first_request = _request(command, cwd=workspace)
    assert first_request is not None
    first_evidence = first_request.interpreter_executable_identities[0]
    first_artifact = build_tool_action_request_artifact(
        "codex",
        first_request,
        config_path="hooks.json",
        source_scope="project",
    )

    link.unlink()
    link.symlink_to(second_target.relative_to(workspace))
    second_request = _request(command, cwd=workspace)
    assert second_request is not None
    second_evidence = second_request.interpreter_executable_identities[0]
    second_artifact = build_tool_action_request_artifact(
        "codex",
        second_request,
        config_path="hooks.json",
        source_scope="project",
    )

    assert first_evidence["raw_token"] == second_evidence["raw_token"] == "./python"
    assert first_evidence["executable"]["launch_path"] == second_evidence["executable"]["launch_path"]
    assert first_evidence["executable"]["path"] != second_evidence["executable"]["path"]
    assert first_evidence["executable"]["sha256"] != second_evidence["executable"]["sha256"]
    assert first_evidence["executable"]["path_chain"] != second_evidence["executable"]["path_chain"]
    assert first_artifact.artifact_id != second_artifact.artifact_id
    assert artifact_hash(first_artifact) != artifact_hash(second_artifact)


def test_same_python_basename_at_different_paths_cannot_collide(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    first = workspace / "first" / "python"
    second = workspace / "second" / "python"
    _write_interpreter(first, b"#!/bin/sh\necho first\n")
    _write_interpreter(second, b"#!/bin/sh\necho other\n")

    first_evidence = _interpreter_evidence("first/python -c 'print(1)'", cwd=workspace)
    second_evidence = _interpreter_evidence("second/python -c 'print(1)'", cwd=workspace)

    assert first_evidence["normalized_name"] == second_evidence["normalized_name"] == "python"
    assert first_evidence["raw_token"] != second_evidence["raw_token"]
    assert first_evidence["executable"]["path"] != second_evidence["executable"]["path"]
    assert first_evidence["executable"]["sha256"] != second_evidence["executable"]["sha256"]


def test_local_interpreter_cannot_reuse_trusted_interpreter_approval(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    local_interpreter = workspace / "python"
    _write_interpreter(local_interpreter)
    trusted_identity = build_runtime_executable_identity(sys.executable, cwd=workspace)
    local_identity = build_runtime_executable_identity("./python", cwd=workspace)
    shared_context = {
        "content": "same-inline-script",
        "capabilities": ["read-only-observer"],
        "policy": {"action": "review"},
        "sandbox": {"mode": "host"},
    }
    approved = build_approval_context_token(
        identity={"interpreter": trusted_identity},
        **shared_context,
    )

    reason = approval_context_validation_reason(
        approved,
        identity={"interpreter": local_identity},
        **shared_context,
    )

    assert trusted_identity["path"] != local_identity["path"]
    assert reason == "approval_reuse_identity_changed"


def test_same_path_same_bytes_replacement_changes_file_identity(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    interpreter = workspace / "python"
    content = b"#!/bin/sh\nexit 0\n"
    _write_interpreter(interpreter, content)
    first = build_runtime_executable_identity("./python", cwd=workspace)
    replacement = workspace / "replacement"
    _write_interpreter(replacement, content)

    os.replace(replacement, interpreter)
    second = build_runtime_executable_identity("./python", cwd=workspace)

    assert first["sha256"] == second["sha256"]
    assert (first["device"], first["inode"]) != (second["device"], second["inode"])
    assert first["path_chain"] != second["path_chain"]
    assert first != second
