"""P35 regressions for default-contained repository pytest execution."""

from __future__ import annotations

import json
import os
import socket
import sys
import tempfile
from pathlib import Path

import pytest

from codex_plugin_scanner.cli import main
from codex_plugin_scanner.guard.cli.commands_support_runtime_policy import _runtime_artifact_policy_action
from codex_plugin_scanner.guard.config import GuardConfig
from codex_plugin_scanner.guard.runtime import restricted_pytest as restricted_pytest_module
from codex_plugin_scanner.guard.runtime.restricted_pytest import (
    PYTEST_EXTERNAL_PYTHONPATH_REASON_CODE,
    PYTEST_INVALID_COMMAND_REASON_CODE,
    PYTEST_INVALID_WORKSPACE_REASON_CODE,
    PYTEST_RESTRICTED_PROFILE_VERSION,
    PYTEST_SANDBOX_UNAVAILABLE_REASON_CODE,
    RestrictedPytestError,
    _backend_argv,
    _macos_profile,
    prepare_restricted_pytest,
    run_restricted_pytest,
)
from codex_plugin_scanner.guard.runtime.secret_file_requests import (
    build_tool_action_request_artifact,
    extract_sensitive_tool_action_request,
)


def test_uncontained_pytest_is_repository_execution_requiring_sandbox(tmp_path: Path) -> None:
    for command in (
        "pytest -q",
        "py.test -q",
        "pytest.exe -q",
        "python3 -m pytest --collect-only",
        "pythonw -m pytest -q",
        "python.exe -m pytest -q",
        "./.venv/bin/python -m pytest tests/unit -q",
        "bash -c 'pytest -q'",
        "eval 'pytest -q'",
        "exec pytest -q",
        "builtin command pytest -q",
        "uv run python -m pytest -q",
        "uvx pytest -q",
        "poetry run pytest -q",
        "mise exec -- pytest -q",
        "direnv exec . pytest -q",
        "pipx run pytest -q",
        "xargs pytest",
        "find . -exec pytest -q {} +",
        "python -c 'import pytest; pytest.main()'",
        "python -c \"getattr(__import__('pytest'), 'main')()\"",
        "python -c \"exec('import pytest; pytest.main()')\"",
    ):
        match = extract_sensitive_tool_action_request("Bash", {"command": command}, cwd=tmp_path)

        assert match is not None, command
        assert match.guard_default_action == "sandbox-required", command
        assert match.reason_code == "pytest_restricted_profile_required", command


def test_pytest_text_in_nonexecuted_inline_literal_is_not_classified(tmp_path: Path) -> None:
    match = extract_sensitive_tool_action_request(
        "Bash",
        {"command": "python -c 'print(\"pytest.main()\")'"},
        cwd=tmp_path,
    )

    assert match is None


def test_contained_launcher_is_not_recursively_classified_as_uncontained(tmp_path: Path) -> None:
    match = extract_sensitive_tool_action_request(
        "Bash",
        {"command": (f"hol-guard pytest-contained --workspace {tmp_path} -- python3 -m pytest tests/unit -q")},
        cwd=tmp_path,
    )

    assert match is None


def test_pytest_artifact_carries_terminal_profile_and_reason(tmp_path: Path) -> None:
    match = extract_sensitive_tool_action_request(
        "Bash",
        {"command": "python3 -m pytest -q"},
        cwd=tmp_path,
    )
    assert match is not None

    artifact = build_tool_action_request_artifact(
        "codex",
        match,
        config_path="/dev/null",
        source_scope="project",
    )

    assert artifact.metadata["guard_default_action"] == "sandbox-required"
    assert artifact.metadata["reason_code"] == "pytest_restricted_profile_required"
    assert artifact.metadata["restricted_profile_version"] == PYTEST_RESTRICTED_PROFILE_VERSION
    assert artifact.metadata["restricted_capabilities"] == {
        "workspace": "read-write",
        "private_temporary_directory": "read-write",
        "host_home": "denied",
        "host_secret_environment": "denied",
        "network": "denied",
        "outside_writes": "denied",
        "process_execution": "approved-interpreter-runtime-only",
    }


def test_terminal_pytest_profile_cannot_be_downgraded_by_exact_allow(tmp_path: Path) -> None:
    match = extract_sensitive_tool_action_request(
        "Bash",
        {"command": "python3 -m pytest -q"},
        cwd=tmp_path,
    )
    assert match is not None
    artifact = build_tool_action_request_artifact(
        "codex",
        match,
        config_path="/dev/null",
        source_scope="project",
    )
    config = GuardConfig(
        guard_home=tmp_path,
        workspace=tmp_path,
        default_action="allow",
        harness_actions={"codex": "allow"},
        artifact_actions={artifact.artifact_id: "allow"},
    )

    assert _runtime_artifact_policy_action(config, artifact, "codex") == "sandbox-required"


def test_pytest_contained_cli_dispatches_exact_argv(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    observed: dict[str, object] = {}

    def fake_run_restricted_pytest(command, **kwargs):
        observed["command"] = command
        observed.update(kwargs)
        return 23

    monkeypatch.setattr(restricted_pytest_module, "run_restricted_pytest", fake_run_restricted_pytest)

    return_code = main(
        [
            "guard",
            "pytest-contained",
            "--workspace",
            str(tmp_path),
            "--cwd",
            str(tmp_path),
            "--timeout-seconds",
            "45",
            "--",
            sys.executable,
            "-m",
            "pytest",
            "-q",
        ]
    )

    assert return_code == 23
    assert observed == {
        "command": ["--", sys.executable, "-m", "pytest", "-q"],
        "workspace": tmp_path,
        "cwd": tmp_path,
        "timeout_seconds": 45,
    }


def test_prepare_restricted_pytest_binds_profile_workspace_and_capabilities(tmp_path: Path) -> None:
    executable = Path(sys.executable)
    workspace = Path.cwd().resolve()
    backend = Path("/usr/bin/true")
    plan = prepare_restricted_pytest(
        [str(executable), "-m", "pytest", "-q"],
        workspace=workspace,
        cwd=tmp_path if tmp_path.is_relative_to(workspace) else workspace,
        platform="darwin",
        backend_executable=backend,
    )

    evidence = plan.to_evidence()
    assert evidence["profile_version"] == PYTEST_RESTRICTED_PROFILE_VERSION
    assert evidence["network"] == "denied"
    assert evidence["host_home"] == "unmounted-or-denied"
    assert "write-outside-workspace-and-private-temp" in evidence["denied_capabilities"]


def test_prepare_restricted_pytest_does_not_trust_spoofed_home(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    workspace = Path.cwd().resolve()

    plan = prepare_restricted_pytest(
        [sys.executable, "-m", "pytest", "-q"],
        workspace=workspace,
        cwd=workspace,
        platform="darwin",
        backend_executable=Path("/usr/bin/true"),
    )

    assert plan.workspace == workspace


def test_linux_profile_unshares_network_and_does_not_mount_shell_toolchain() -> None:
    workspace = Path.cwd().resolve()
    private_root = Path("/tmp/hol-guard-pytest-test")
    plan = prepare_restricted_pytest(
        [sys.executable, "-m", "pytest", "-q"],
        workspace=workspace,
        cwd=workspace,
        platform="linux",
        backend_executable=Path("/usr/bin/true"),
    )

    argv = _backend_argv(plan, private_root=private_root)

    assert "--unshare-all" in argv
    assert "--unshare-net" in argv
    assert "--bind" in argv
    assert str(workspace) in argv
    assert "/bin" not in argv
    private_dir_index = argv.index("--dir")
    assert argv[private_dir_index : private_dir_index + 5] == [
        "--dir",
        str(private_root),
        "--bind",
        str(private_root),
        str(private_root),
    ]


def test_macos_profile_grants_only_root_metadata_and_bounded_runtime_reads(tmp_path: Path) -> None:
    workspace = Path.cwd().resolve()
    plan = prepare_restricted_pytest(
        [sys.executable, "-m", "pytest", "-q"],
        workspace=workspace,
        cwd=workspace,
        platform="darwin",
        backend_executable=Path("/usr/bin/true"),
    )

    profile = _macos_profile(plan, private_root=tmp_path)

    assert '(allow file-read-metadata (literal "/")' in profile
    assert "(allow file-read-metadata)" not in profile
    assert "(allow file-read*)" not in profile
    assert f'(subpath "{Path.home()}")' not in profile
    process_exec_rule = next(line for line in profile.splitlines() if line.startswith("(allow process-exec "))
    assert "(subpath " not in process_exec_rule


def test_prepare_restricted_pytest_rejects_non_pytest_command() -> None:
    with pytest.raises(RestrictedPytestError) as error:
        prepare_restricted_pytest(
            [sys.executable, "-c", "print('not pytest')"],
            workspace=Path.cwd(),
            platform="darwin",
            backend_executable=Path("/usr/bin/true"),
        )

    assert error.value.reason_code == PYTEST_INVALID_COMMAND_REASON_CODE


def test_prepare_restricted_pytest_rejects_cwd_outside_workspace(tmp_path: Path) -> None:
    with pytest.raises(RestrictedPytestError) as error:
        prepare_restricted_pytest(
            [sys.executable, "-m", "pytest"],
            workspace=tmp_path,
            cwd=Path.cwd(),
            platform="darwin",
            backend_executable=Path("/usr/bin/true"),
        )

    assert error.value.reason_code == PYTEST_INVALID_WORKSPACE_REASON_CODE


def test_prepare_restricted_pytest_rejects_broad_workspace_root() -> None:
    with pytest.raises(RestrictedPytestError) as error:
        prepare_restricted_pytest(
            [sys.executable, "-m", "pytest"],
            workspace=Path("/"),
            cwd=Path.cwd(),
            platform="darwin",
            backend_executable=Path("/usr/bin/true"),
        )

    assert error.value.reason_code == PYTEST_INVALID_WORKSPACE_REASON_CODE


def test_prepare_restricted_pytest_rejects_non_python_pytest_entrypoint() -> None:
    workspace = Path.cwd().resolve()
    with tempfile.TemporaryDirectory(prefix=".guard-p35-entrypoint-", dir=workspace) as project_text:
        entrypoint = Path(project_text) / "pytest"
        entrypoint.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        entrypoint.chmod(0o700)

        with pytest.raises(RestrictedPytestError) as error:
            prepare_restricted_pytest(
                [str(entrypoint), "-q"],
                workspace=workspace,
                cwd=workspace,
                platform="darwin",
                backend_executable=Path("/usr/bin/true"),
            )

    assert error.value.reason_code == PYTEST_INVALID_COMMAND_REASON_CODE


def test_prepare_restricted_pytest_rejects_unrecognized_external_python_runtime(tmp_path: Path) -> None:
    workspace = Path.cwd().resolve()
    external_python = tmp_path / "untrusted-runtime" / "bin" / "python"
    external_python.parent.mkdir(parents=True)
    external_python.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    external_python.chmod(0o700)
    with tempfile.TemporaryDirectory(prefix=".guard-p35-launcher-", dir=workspace) as project_text:
        workspace_python = Path(project_text) / "python"
        workspace_python.symlink_to(external_python)

        with pytest.raises(RestrictedPytestError) as error:
            prepare_restricted_pytest(
                [str(workspace_python), "-m", "pytest"],
                workspace=workspace,
                cwd=workspace,
                platform="darwin",
                backend_executable=Path("/usr/bin/true"),
            )

    assert error.value.reason_code == PYTEST_INVALID_COMMAND_REASON_CODE


def test_prepare_restricted_pytest_rejects_unapproved_intermediate_symlink_root(tmp_path: Path) -> None:
    workspace = Path.cwd().resolve()
    intermediate_python = tmp_path / "host-content" / "bin" / "python"
    intermediate_python.parent.mkdir(parents=True)
    intermediate_python.symlink_to(Path(sys.executable).resolve())
    with tempfile.TemporaryDirectory(prefix=".guard-p35-chain-", dir=workspace) as project_text:
        workspace_python = Path(project_text) / "python"
        workspace_python.symlink_to(intermediate_python)

        with pytest.raises(RestrictedPytestError) as error:
            prepare_restricted_pytest(
                [str(workspace_python), "-m", "pytest"],
                workspace=workspace,
                cwd=workspace,
                platform="darwin",
                backend_executable=Path("/usr/bin/true"),
            )

    assert error.value.reason_code == PYTEST_INVALID_COMMAND_REASON_CODE


def test_restricted_pytest_rejects_external_pythonpath_before_backend_runs(tmp_path: Path) -> None:
    workspace = Path.cwd().resolve()
    external = tmp_path.resolve()
    if external.is_relative_to(workspace):
        pytest.skip("pytest temporary directory unexpectedly lies inside the repository")
    with pytest.raises(RestrictedPytestError) as error:
        run_restricted_pytest(
            [sys.executable, "-m", "pytest", "-q"],
            workspace=workspace,
            cwd=workspace,
            env={"PATH": os.environ.get("PATH", ""), "PYTHONPATH": str(external)},
            platform="darwin",
            backend_executable=Path("/usr/bin/true"),
        )

    assert error.value.reason_code == PYTEST_EXTERNAL_PYTHONPATH_REASON_CODE


def test_restricted_pytest_fails_closed_without_platform_backend() -> None:
    with pytest.raises(RestrictedPytestError) as error:
        prepare_restricted_pytest(
            [sys.executable, "-m", "pytest", "-q"],
            workspace=Path.cwd(),
            platform="win32",
        )

    assert error.value.reason_code == PYTEST_SANDBOX_UNAVAILABLE_REASON_CODE


def test_restricted_pytest_fails_closed_when_supported_backend_is_missing(tmp_path: Path) -> None:
    with pytest.raises(RestrictedPytestError) as error:
        prepare_restricted_pytest(
            [sys.executable, "-m", "pytest", "-q"],
            workspace=Path.cwd(),
            platform="linux",
            backend_executable=tmp_path / "missing-bwrap",
        )

    assert error.value.reason_code == PYTEST_SANDBOX_UNAVAILABLE_REASON_CODE


@pytest.mark.skipif(sys.platform != "darwin", reason="requires the macOS Seatbelt backend")
@pytest.mark.parametrize("launch_style", ("module", "entrypoint"))
def test_real_restricted_pytest_blocks_host_sinks_and_preserves_harmless_suite(
    tmp_path: Path,
    launch_style: str,
) -> None:
    workspace = Path.cwd().resolve()
    outside_read_marker = tmp_path / "host-read-marker.txt"
    outside_write = tmp_path / "outside-write.txt"
    outside_read_marker.write_text("host-only-marker", encoding="utf-8")
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]
    try:
        with tempfile.TemporaryDirectory(prefix=".guard-p35-", dir=workspace) as project_text:
            project = Path(project_text)
            result_path = project / "containment-result.json"
            test_path = project / "test_containment_fixture.py"
            test_path.write_text(
                f"""
import json
import os
import socket
import subprocess
from pathlib import Path

OUTSIDE_READ_MARKER = Path({json.dumps(str(outside_read_marker))})
OUTSIDE_WRITE = Path({json.dumps(str(outside_write))})
LOOPBACK_PORT = {port}
RESULT_PATH = Path({json.dumps(str(result_path))})


def _blocked(operation):
    try:
        operation()
    except (OSError, subprocess.SubprocessError):
        return True
    return False


def test_repository_code_is_contained():
    result = {{
        "outside_read_blocked": _blocked(lambda: OUTSIDE_READ_MARKER.read_text()),
        "outside_write_blocked": _blocked(lambda: OUTSIDE_WRITE.write_text("escaped", encoding="utf-8")),
        "network_blocked": _blocked(
            lambda: socket.create_connection(("127.0.0.1", LOOPBACK_PORT), timeout=1)
        ),
        "subprocess_blocked": _blocked(
            lambda: subprocess.run(["/bin/sh", "-c", "true"], check=True)
        ),
        "host_credentials_absent": all(
            key not in os.environ
            for key in ("DEPLOY_ACCESS", "P35_HOST_CREDENTIAL", "AWS_ACCESS_KEY_ID", "DATABASE_URL", "LD_PRELOAD")
        ),
        "home_is_private": os.environ["HOME"].startswith(os.environ["TMPDIR"].rsplit("/tmp", 1)[0]),
    }}
    RESULT_PATH.write_text(json.dumps(result), encoding="utf-8")
    assert all(result.values())
""".lstrip(),
                encoding="utf-8",
            )
            launch_env = {
                **os.environ,
                "DEPLOY_ACCESS": "opaque-secret-without-a-sensitive-name",
                "P35_HOST_CREDENTIAL": "must-not-enter-sandbox",
                "AWS_ACCESS_KEY_ID": "must-not-enter-sandbox",
                "DATABASE_URL": "postgres://user:password@host/database",
                "LD_PRELOAD": "/private/tmp/must-not-load.dylib",
            }

            command = (
                [sys.executable, "-m", "pytest", str(test_path), "-q"]
                if launch_style == "module"
                else [str(Path(sys.executable).parent / "pytest"), str(test_path), "-q"]
            )
            return_code = run_restricted_pytest(
                command,
                workspace=workspace,
                cwd=project,
                env=launch_env,
                timeout_seconds=60,
            )

            assert return_code == 0
            assert json.loads(result_path.read_text(encoding="utf-8")) == {
                "outside_read_blocked": True,
                "outside_write_blocked": True,
                "network_blocked": True,
                "subprocess_blocked": True,
                "host_credentials_absent": True,
                "home_is_private": True,
            }
            assert not outside_write.exists()
    finally:
        listener.close()
