"""Security regressions for isolated OpenCode hook-interpreter attestation."""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.adapters import hook_python
from codex_plugin_scanner.guard.adapters.base import HarnessContext


def _context(tmp_path: Path, *, workspace: Path | None = None) -> HarnessContext:
    return HarnessContext(
        home_dir=tmp_path / "home",
        workspace_dir=workspace,
        guard_home=tmp_path / "Guard home with spaces",
    )


def test_preparation_attests_running_python_without_persistent_probe_state(tmp_path: Path) -> None:
    context = _context(tmp_path)
    probe: Path | None = None
    with pytest.raises(RuntimeError, match="preparation interrupted"), hook_python.disposable_guard_hook_probe():
        probe = Path(hook_python._attestation_probe(context)["scoped"])
        attestation = hook_python.attest_guard_hook_python(context)
        assert attestation.executable == Path(sys.executable).absolute()
        assert probe.is_dir()
        if os.name != "nt":
            assert probe.stat().st_mode & 0o077 == 0
        assert not context.guard_home.exists()
        raise RuntimeError("preparation interrupted")
    assert probe is not None
    assert not probe.exists()
    assert hook_python._PREPARATION_PROBE.get() is None
    assert not context.guard_home.exists()


def test_preparation_rejects_inherited_probe_scope(tmp_path: Path) -> None:
    context = _context(tmp_path)
    with hook_python.disposable_guard_hook_probe():
        probe = Path(hook_python._attestation_probe(context)["scoped"])
        token = hook_python._PREPARATION_PROBE.set((os.getpid() + 1, probe))
        try:
            with pytest.raises(RuntimeError, match="neutral_cwd_unavailable"):
                hook_python.attest_guard_hook_python(context)
        finally:
            hook_python._PREPARATION_PROBE.reset(token)
    assert not context.guard_home.exists()


@pytest.mark.skipif(os.name == "nt", reason="POSIX private directory modes")
def test_preparation_rejects_probe_that_loses_private_permissions(tmp_path: Path) -> None:
    with hook_python.disposable_guard_hook_probe():
        probe = Path(hook_python._attestation_probe(_context(tmp_path))["scoped"])
        probe.chmod(0o755)
        with pytest.raises(RuntimeError, match="neutral_cwd_unavailable"):
            hook_python.attest_guard_hook_python(_context(tmp_path))
    assert not probe.exists()


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
        hook_python._attest_python(tmp_path / "missing-python", probe={"scoped": str(tmp_path)})


def test_moved_or_unexpected_package_root_is_rejected(tmp_path: Path) -> None:
    unexpected_root = tmp_path / "moved-package-root"
    unexpected_root.mkdir()

    with pytest.raises(RuntimeError, match="guard_hook_python_package_root_mismatch"):
        hook_python._attest_python(
            Path(sys.executable),
            probe={"guard_home": str(tmp_path / "guard")},
            expected_package_root=unexpected_root,
        )


def test_probe_uses_private_guard_owned_neutral_directory(tmp_path: Path) -> None:
    context = _context(tmp_path)

    hook_python.attest_guard_hook_python(context)

    neutral = (context.guard_home / "runtime" / "python-probe").resolve(strict=True)
    assert neutral.is_dir()
    if os.name != "nt":
        assert neutral.stat().st_mode & 0o077 == 0
