"""Windows contains only installed Python, and only for Claude Code's Git Bash sink."""

import hashlib
import json
import os
import sys
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import native_restricted_pytest as transport
from codex_plugin_scanner.guard import windows_paths
from codex_plugin_scanner.guard.adapters.zcode_contained_tests import contained_zcode_response, platform_contains
from codex_plugin_scanner.guard.runtime import contained_test_hook, restricted_inline_eval
from codex_plugin_scanner.guard.runtime.restricted_pytest_model import RestrictedPytestError

PYTHON = r"C:\Program Files\Python312\python.exe"
RUNTIME = r"C:\Program Files\HOL Guard\hol-guard-runtime.exe"


def _plan(tmp_path: Path, *, backend: str = "windows-appcontainer", profile: str = "python-eval-readonly-v1"):
    return {
        "profile_version": profile,
        "backend": backend,
        "backend_executable": RUNTIME,
        "workspace": str(tmp_path),
        "cwd": str(tmp_path),
        "command": [PYTHON, "test_calc.py"],
        "executable": PYTHON,
        "allowed_executables": [PYTHON],
        "denied_capabilities": ["network"],
    }


def _receipt(profile: str = "python-eval-readonly-v1") -> dict[str, object]:
    reasons = {
        "python-eval-readonly-v1": "native_python_eval_readonly_containment_required",
        "pytest-readonly-v2": "native_pytest_readonly_containment_required",
        "workspace-contained-v1": "native_workspace_containment_required",
    }
    return {
        "decision": "deny",
        "policy_action": "sandbox-required",
        "reason_code": reasons[profile],
        "required_execution_profile": profile,
    }


def test_windows_backend_decodes_only_for_python_on_windows(monkeypatch, tmp_path):
    monkeypatch.setattr(sys, "platform", "win32")
    plan = transport.decode_native_plan(_plan(tmp_path), ("python-eval-readonly-v1",))
    assert plan.backend == "windows-appcontainer"
    with pytest.raises(RestrictedPytestError):
        transport.decode_native_plan(_plan(tmp_path, profile="node-eval-readonly-v1"), ("node-eval-readonly-v1",))
    monkeypatch.setattr(sys, "platform", "darwin")
    with pytest.raises(RestrictedPytestError):
        transport.decode_native_plan(_plan(tmp_path), ("python-eval-readonly-v1",))


def test_windows_inline_eval_runs_through_the_native_runner(monkeypatch, tmp_path):
    monkeypatch.setattr(sys, "platform", "win32")
    plan = transport.decode_native_plan(_plan(tmp_path), ("python-eval-readonly-v1",))
    calls = []

    def run(argv, **kwargs):
        calls.append((argv, kwargs))
        return 0

    monkeypatch.setattr(restricted_inline_eval, "_run_backend_process", run)
    exit_code = restricted_inline_eval.run_restricted_inline_eval(
        plan, timeout_seconds=30, authorize_capability=lambda _argv: None
    )
    assert exit_code == 0
    argv, kwargs = calls[0]
    assert argv == [
        RUNTIME,
        "contained-readonly-windows",
        "--workspace",
        str(tmp_path),
        "--cwd",
        str(tmp_path),
        "--timeout-seconds",
        "30",
        "--",
        PYTHON,
        "test_calc.py",
    ]
    assert kwargs["timeout_seconds"] == 30


def test_windows_backend_never_reaches_posix_sandboxes(monkeypatch, tmp_path):
    monkeypatch.setattr(sys, "platform", "win32")
    plan = transport.decode_native_plan(_plan(tmp_path), ("python-eval-readonly-v1",))
    from codex_plugin_scanner.guard.runtime.restricted_pytest_sandbox import _backend_argv

    with pytest.raises(RestrictedPytestError):
        _backend_argv(plan, private_root=tmp_path)


def test_windows_contains_python_eval_only(monkeypatch):
    monkeypatch.setattr(sys, "platform", "win32")
    assert platform_contains(_receipt())
    assert not platform_contains(_receipt("pytest-readonly-v2"))
    assert not platform_contains(_receipt("workspace-contained-v1"))


@pytest.mark.parametrize(("harness", "routed"), [("claude-code", True), ("codex", False), ("zcode", False)])
def test_windows_routes_only_the_git_bash_harness(monkeypatch, tmp_path, harness, routed):
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setattr(windows_paths, "trusted_windows_local_temp", lambda: tmp_path)
    payload = {
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "cwd": str(tmp_path),
        "tool_input": {"command": "python3 test_calc.py"},
    }
    config = {
        "harness": harness,
        "python_executable": sys.executable,
        "package_root": str(tmp_path),
        "guard_home": str(tmp_path / "guard"),
    }
    result = contained_zcode_response(_receipt(), input_text=json.dumps(payload), config=config, cli_args=[])
    assert (result is not None) is routed


def test_windows_sink_finds_the_request_when_temp_differs(monkeypatch, tmp_path):
    """The hook and the harness shell can set TEMP differently; both use the profile's."""
    import shlex
    import tempfile

    profile_temp = (tmp_path / "profile-temp").resolve()
    profile_temp.mkdir()
    workspace = (tmp_path / "workspace").resolve()
    workspace.mkdir()
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setattr(windows_paths, "trusted_windows_local_temp", lambda: profile_temp)
    monkeypatch.setattr(contained_test_hook, "trusted_windows_local_temp", lambda: profile_temp)
    monkeypatch.setattr(tempfile, "tempdir", str(tmp_path))
    payload = {
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "cwd": str(workspace),
        "tool_input": {"command": "python3 test_calc.py"},
    }
    config = {
        "harness": "claude-code",
        "python_executable": sys.executable,
        "package_root": str(tmp_path),
        "guard_home": str(tmp_path / "guard"),
    }
    result = contained_zcode_response(_receipt(), input_text=json.dumps(payload), config=config, cli_args=[])
    assert result is not None
    argv = shlex.split(result["hookSpecificOutput"]["updatedInput"]["command"])
    request = Path(argv[argv.index("--request-file") + 1])
    assert request.parent.parent == profile_temp
    monkeypatch.setattr(tempfile, "tempdir", str(workspace))
    read = contained_test_hook._read_windows_request(
        request, argv[argv.index("--request-sha256") + 1], workspace=workspace
    )
    assert read["tool_input"] == {"command": "python3 test_calc.py"}


def _write_request(directory: Path, workspace: Path) -> tuple[Path, str]:
    directory.mkdir()
    raw = json.dumps(
        {
            "schema": "guard-contained-test-request.v1",
            "workspace": str(workspace),
            "payload": {
                "hook_event_name": "PreToolUse",
                "tool_name": "bash",
                "tool_input": {"command": "python3 test_calc.py"},
                "cwd": str(workspace),
            },
        }
    ).encode()
    request = directory / "request.json"
    request.write_bytes(raw)
    return request, hashlib.sha256(raw).hexdigest()


def test_windows_request_must_sit_directly_in_the_temporary_directory(monkeypatch, tmp_path):
    temporary = (tmp_path / "temp").resolve()
    temporary.mkdir()
    workspace = (tmp_path / "workspace").resolve()
    workspace.mkdir()
    monkeypatch.setattr(contained_test_hook, "trusted_windows_local_temp", lambda: temporary)
    request, digest = _write_request(temporary / "hol-guard-contained-test-a", workspace)
    payload = contained_test_hook._read_windows_request(request, digest, workspace=workspace)
    assert payload["tool_input"] == {"command": "python3 test_calc.py"}
    with pytest.raises(RestrictedPytestError):
        contained_test_hook._read_windows_request(request, "0" * 64, workspace=workspace)
    nested, nested_digest = _write_request(
        temporary / "hol-guard-contained-test-a" / "hol-guard-contained-test-b", workspace
    )
    with pytest.raises(RestrictedPytestError):
        contained_test_hook._read_windows_request(nested, nested_digest, workspace=workspace)


def test_windows_request_rejects_linked_files(monkeypatch, tmp_path):
    temporary = (tmp_path / "temp").resolve()
    temporary.mkdir()
    workspace = (tmp_path / "workspace").resolve()
    workspace.mkdir()
    monkeypatch.setattr(contained_test_hook, "trusted_windows_local_temp", lambda: temporary)
    request, digest = _write_request(temporary / "hol-guard-contained-test-a", workspace)
    os.link(request, tmp_path / "second-name")
    with pytest.raises(RestrictedPytestError):
        contained_test_hook._read_windows_request(request, digest, workspace=workspace)
    linked = temporary / "hol-guard-contained-test-b"
    linked.symlink_to(request.parent, target_is_directory=True)
    (tmp_path / "second-name").unlink()
    with pytest.raises(RestrictedPytestError):
        contained_test_hook._read_windows_request(linked / "request.json", digest, workspace=workspace)
