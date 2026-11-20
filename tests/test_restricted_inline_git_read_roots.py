"""An inline program that runs Git from a linked worktree reads that worktree's shared metadata."""

from dataclasses import replace
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import native_restricted_pytest as transport
from codex_plugin_scanner.guard.runtime import restricted_pytest_sandbox as sandbox
from codex_plugin_scanner.guard.runtime.restricted_pytest_model import RestrictedPytestError


def _plan(tmp_path: Path, profile: str, **extra: object) -> dict[str, object]:
    return {
        "profile_version": profile,
        "backend": "macos-seatbelt",
        "backend_executable": "/usr/bin/sandbox-exec",
        "workspace": str(tmp_path / "linked"),
        "cwd": str(tmp_path / "linked"),
        "command": ["/usr/bin/python3", "-c", "import subprocess; subprocess.run(['git', 'status'])"],
        "executable": "/usr/bin/python3",
        "allowed_executables": ["/usr/bin/python3", "/usr/local/bin/git"],
        "denied_capabilities": ["network"],
        **extra,
    }


@pytest.mark.parametrize("profile", ["python-eval-readonly-v1", "node-eval-readonly-v1"])
def test_an_inline_plan_carries_the_metadata_roots_its_git_reads(tmp_path: Path, monkeypatch, profile: str) -> None:
    metadata = str(tmp_path / "main" / ".git")
    plan = transport.decode_native_plan(_plan(tmp_path, profile, read_only_roots=[metadata]), (profile,))
    assert plan.read_only_roots == (Path(metadata),)
    monkeypatch.setattr(sandbox, "_macos_profile", lambda plan, **_: "(version 1)")
    argv = sandbox._backend_argv(plan, private_root=tmp_path / "private")
    assert argv[:3] == ["/usr/bin/sandbox-exec", "-p", "(version 1)"]


def test_an_inline_plan_without_git_needs_no_roots(tmp_path: Path) -> None:
    plan = transport.decode_native_plan(_plan(tmp_path, "python-eval-readonly-v1"), ("python-eval-readonly-v1",))
    assert plan.read_only_roots == ()


def test_other_profiles_still_refuse_extra_read_roots(tmp_path: Path) -> None:
    roots = [str(tmp_path / "main" / ".git")]
    with pytest.raises(RestrictedPytestError):
        transport.decode_native_plan(
            _plan(tmp_path, "pytest-readonly-v2", read_only_roots=roots), ("pytest-readonly-v2",)
        )
    plan = transport.decode_native_plan(_plan(tmp_path, "pytest-readonly-v2"), ("pytest-readonly-v2",))
    with pytest.raises(RestrictedPytestError, match="Unexpected extra read grants"):
        sandbox._backend_argv(
            replace(plan, read_only_roots=(Path(roots[0]),)),
            private_root=tmp_path / "private",
        )
