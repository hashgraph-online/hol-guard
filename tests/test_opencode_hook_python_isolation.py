"""Security regressions for isolated OpenCode hook-interpreter attestation."""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.adapters import hook_python
from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.adapters.hook_python_subprocess import ProbeResult


def _context(tmp_path: Path, *, workspace: Path | None = None) -> HarnessContext:
    return HarnessContext(
        home_dir=tmp_path / "home",
        workspace_dir=workspace,
        guard_home=tmp_path / "Guard home with spaces",
    )


def test_probe_environment_drops_python_virtualenv_and_loader_controls(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    hostile = {
        "PATH": str(tmp_path / "fake-bin"),
        "PYTHONPATH": str(tmp_path / "fake-package"),
        "PYTHONHOME": str(tmp_path / "fake-home"),
        "PYTHONSTARTUP": str(tmp_path / "startup.py"),
        "PYTHONINSPECT": "1",
        "PYTHONWARNINGS": "error",
        "PYTHONBREAKPOINT": "evil.breakpoint",
        "VIRTUAL_ENV": str(tmp_path / "workspace" / ".venv"),
        "UV_PROJECT_ENVIRONMENT": str(tmp_path / "uv-project"),
        "UV_PYTHON": str(tmp_path / "uv-python"),
        "CONDA_PREFIX": str(tmp_path / "conda"),
        "__PYVENV_LAUNCHER__": str(tmp_path / "launcher"),
        "LD_PRELOAD": str(tmp_path / "preload.so"),
        "DYLD_INSERT_LIBRARIES": str(tmp_path / "inject.dylib"),
    }
    for key, value in hostile.items():
        monkeypatch.setenv(key, value)

    neutral = tmp_path / "neutral"
    neutral.mkdir()
    env = hook_python._probe_environment(neutral)

    assert hostile.keys().isdisjoint(env)
    assert env["HOME"] == str(neutral)
    assert env["USERPROFILE"] == str(neutral)
    assert env["PYTHONNOUSERSITE"] == "1"
    assert env["PYTHONSAFEPATH"] == "1"


def test_workspace_shadow_modules_and_sitecustomize_never_execute(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    marker = tmp_path / "workspace-imported.marker"
    marker_literal = repr(str(marker))
    package = workspace / "codex_plugin_scanner"
    package.mkdir()
    (package / "__init__.py").write_text(
        f"from pathlib import Path\nPath({marker_literal}).write_text('package')\n",
        encoding="utf-8",
    )
    (workspace / "cryptography.py").write_text(
        f"from pathlib import Path\nPath({marker_literal}).write_text('cryptography')\n",
        encoding="utf-8",
    )
    (workspace / "sitecustomize.py").write_text(
        f"from pathlib import Path\nPath({marker_literal}).write_text('sitecustomize')\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("PYTHONPATH", str(workspace))
    monkeypatch.setenv("VIRTUAL_ENV", str(workspace / ".venv"))
    monkeypatch.chdir(workspace)

    resolved = hook_python.resolve_guard_hook_python(_context(tmp_path, workspace=workspace))

    assert resolved == Path(sys.executable).absolute()
    assert not marker.exists()


def test_candidates_ignore_path_collision_and_workspace_virtualenv(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace = tmp_path / "workspace"
    fake_bin = tmp_path / "fake-bin"
    fake_bin.mkdir()
    workspace_python = workspace / ".venv" / "bin" / "python"
    workspace_python.parent.mkdir(parents=True)
    workspace_python.write_text("#!/bin/sh\nexit 99\n", encoding="utf-8")
    workspace_python.chmod(0o755)
    for name in ("hol-guard", "plugin-guard"):
        collision = fake_bin / name
        collision.write_text("#!/bin/sh\nexit 99\n", encoding="utf-8")
        collision.chmod(0o755)
    monkeypatch.setenv("PATH", f"{fake_bin}{os.pathsep}{os.environ.get('PATH', '')}")

    candidates = hook_python._guard_hook_python_candidates(_context(tmp_path, workspace=workspace))

    assert candidates[0] == Path(sys.executable).absolute()
    assert workspace_python not in candidates
    assert all(candidate.parent != fake_bin for candidate in candidates)


def test_probe_rejects_noisy_stdout_before_parsing_identity(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        hook_python,
        "_run_probe",
        lambda *_args, **_kwargs: ProbeResult(
            returncode=0,
            stdout=b"noise\n{}\n",
            stderr=b"",
            timed_out=False,
            output_overflow=False,
        ),
    )

    with pytest.raises(RuntimeError, match="guard_hook_python_probe_output_invalid"):
        hook_python._attest_python(
            Path(sys.executable),
            neutral_cwd=tmp_path,
            expected_package_root=hook_python._active_package_root(),
        )


@pytest.mark.parametrize(
    ("result", "reason"),
    [
        (
            ProbeResult(1, b"", b"private path", True, False),
            "guard_hook_python_probe_timeout",
        ),
        (
            ProbeResult(1, b"", b"private path", False, True),
            "guard_hook_python_probe_output_limit",
        ),
        (
            ProbeResult(0, b'{"status":"ok"}\n', b"private path", False, False, True),
            "guard_hook_python_probe_capture_incomplete",
        ),
    ],
)
def test_probe_execution_failures_have_redacted_reason_codes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    result: ProbeResult,
    reason: str,
) -> None:
    monkeypatch.setattr(hook_python, "_run_probe", lambda *_args, **_kwargs: result)

    with pytest.raises(RuntimeError, match=reason) as error:
        hook_python._attest_python(
            Path(sys.executable),
            neutral_cwd=tmp_path,
            expected_package_root=hook_python._active_package_root(),
        )

    assert "private path" not in str(error.value)


def test_interpreter_symlink_identity_is_canonicalized_without_losing_invocation_path(tmp_path: Path) -> None:
    link = tmp_path / "python-link"
    try:
        link.symlink_to(Path(sys.executable).absolute())
    except (OSError, NotImplementedError):
        pytest.skip("symlinks unavailable")

    identity = hook_python._executable_identity(link)

    assert identity.invocation_path == link.absolute()
    assert identity.target_path == Path(sys.executable).resolve(strict=True)
    assert hook_python._identity_is_unchanged(identity)


def test_nonrunning_interpreter_is_rejected_with_stable_reason(tmp_path: Path) -> None:
    with pytest.raises(RuntimeError, match="guard_hook_python_not_running_interpreter"):
        hook_python._attest_python(
            tmp_path / "missing-python",
            neutral_cwd=tmp_path,
            expected_package_root=hook_python._active_package_root(),
        )


def test_moved_or_unexpected_package_root_is_rejected(tmp_path: Path) -> None:
    unexpected_root = tmp_path / "moved-package-root"
    unexpected_root.mkdir()

    with pytest.raises(RuntimeError, match="guard_hook_python_package_root_mismatch"):
        hook_python._attest_python(
            Path(sys.executable),
            neutral_cwd=tmp_path,
            expected_package_root=unexpected_root,
        )


def test_only_the_running_guard_interpreter_is_a_candidate(tmp_path: Path) -> None:
    context = _context(tmp_path)
    pipx_python = context.home_dir / ".local" / "pipx" / "venvs" / "hol-guard" / "bin" / "python"
    uv_python = context.home_dir / ".local" / "share" / "uv" / "tools" / "hol-guard" / "bin" / "python"
    for candidate in (pipx_python, uv_python):
        candidate.parent.mkdir(parents=True, exist_ok=True)
        candidate.write_text("placeholder", encoding="utf-8")

    candidates = hook_python._guard_hook_python_candidates(context)

    assert candidates == [Path(sys.executable).absolute()]
    assert pipx_python.absolute() not in candidates
    assert uv_python.absolute() not in candidates


def test_probe_uses_private_guard_owned_neutral_directory(tmp_path: Path) -> None:
    context = _context(tmp_path)

    neutral = hook_python._private_probe_cwd(context)

    assert neutral == (context.guard_home / "runtime" / "python-probe").resolve(strict=True)
    assert neutral.is_dir()
    if os.name != "nt":
        assert neutral.stat().st_mode & 0o077 == 0
