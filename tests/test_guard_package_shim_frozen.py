"""Frozen Core package-shim generation and trusted-path checks."""

from __future__ import annotations

import ast
import shlex
import sys
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import shims as guard_shims_module
from codex_plugin_scanner.guard.adapters.base import HarnessContext


def test_frozen_package_shim_uses_direct_protect_command(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(guard_shims_module.sys, "frozen", True, raising=False)
    monkeypatch.setattr(
        guard_shims_module.sys,
        "executable",
        "/Applications/HOL Guard.app/Contents/MacOS/hol-guard",
    )
    context = HarnessContext(
        home_dir=tmp_path / "home",
        workspace_dir=tmp_path / "workspace",
        guard_home=tmp_path / "guard-home",
    )

    source = guard_shims_module._build_package_manager_python_shim(context, "npm")
    command_line = next(line for line in source.splitlines() if line.startswith("base_command = "))
    command = ast.literal_eval(command_line.split("=", 1)[1].strip())

    assert f"{guard_shims_module.FROZEN_PACKAGE_SHIM_SENTINEL} = True" in source
    assert command[0] == "/Applications/HOL Guard.app/Contents/MacOS/hol-guard"
    assert command[1:4] == ["protect", "--package-shim-ui", "--guard-home"]
    assert "-c" not in command
    assert "codex_plugin_scanner.cli" not in command


def test_frozen_package_shim_install_uses_quoted_shell_wrapper(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    frozen_exe = tmp_path / "HOL Guard.app" / "Contents" / "MacOS" / "hol-guard"
    frozen_exe.parent.mkdir(parents=True)
    frozen_exe.write_text("", encoding="utf-8")
    monkeypatch.setattr(guard_shims_module.sys, "frozen", True, raising=False)
    monkeypatch.setattr(guard_shims_module.sys, "executable", str(frozen_exe))
    context = HarnessContext(
        home_dir=tmp_path / "home",
        workspace_dir=tmp_path / "workspace",
        guard_home=tmp_path / "guard-home",
    )
    monkeypatch.setattr(
        guard_shims_module,
        "_detect_system_package_managers",
        lambda _context, path_env=None: (["npm"], []),
    )

    guard_shims_module.install_package_shims(context, managers=("npm",))

    wrapper_path = context.guard_home / "package-shims" / "bin" / "npm"
    python_path = context.guard_home / "package-shims" / "bin" / ".npm.py"
    wrapper = wrapper_path.read_text(encoding="utf-8")
    python_source = python_path.read_text(encoding="utf-8")

    assert wrapper.startswith("#!/bin/sh\n")
    assert "HOL Guard.app" in wrapper
    assert shlex.split(wrapper.splitlines()[1])[:3] == ["exec", str(frozen_exe), str(python_path)]
    assert f"{guard_shims_module.FROZEN_PACKAGE_SHIM_SENTINEL} = True" in python_source
    assert wrapper_path.stat().st_mode & 0o111


def test_frozen_package_shim_status_fails_when_sidecar_is_tampered(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    frozen_exe = tmp_path / "HOL Guard.app" / "Contents" / "MacOS" / "hol-guard"
    frozen_exe.parent.mkdir(parents=True)
    frozen_exe.write_text("", encoding="utf-8")
    monkeypatch.setattr(guard_shims_module.sys, "frozen", True, raising=False)
    monkeypatch.setattr(guard_shims_module.sys, "executable", str(frozen_exe))
    context = HarnessContext(
        home_dir=tmp_path / "home",
        workspace_dir=tmp_path / "workspace",
        guard_home=tmp_path / "guard-home",
    )
    monkeypatch.setattr(
        guard_shims_module,
        "_detect_system_package_managers",
        lambda _context, path_env=None: (["npm"], []),
    )

    guard_shims_module.install_package_shims(context, managers=("npm",))
    sidecar = context.guard_home / "package-shims" / "bin" / ".npm.py"
    sidecar.write_text("raise SystemExit(0)\n", encoding="utf-8")

    status = guard_shims_module.package_shim_status(context)
    details = next(item for item in status["manager_details"] if item["manager"] == "npm")

    assert details["integrity"] != "ok"


def test_frozen_package_shim_wrapper_uses_current_hol_guard_shim(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    core_dir = tmp_path / "core"
    versioned = core_dir / "versions" / "3.0.54" / "hol-guard"
    versioned.parent.mkdir(parents=True)
    versioned.write_text("", encoding="utf-8")
    shim = core_dir / "current-hol-guard"
    shim.write_text("", encoding="utf-8")
    monkeypatch.setattr(guard_shims_module.sys, "frozen", True, raising=False)
    monkeypatch.setattr(guard_shims_module.sys, "executable", str(versioned))
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.stable_guard_cli.MACOS_BUNDLED_HOL_GUARD",
        tmp_path / "missing-bundle",
    )
    context = HarnessContext(
        home_dir=tmp_path / "home",
        workspace_dir=tmp_path / "workspace",
        guard_home=tmp_path / "guard-home",
    )
    monkeypatch.setattr(
        guard_shims_module,
        "_detect_system_package_managers",
        lambda _context, path_env=None: (["npm"], []),
    )

    guard_shims_module.install_package_shims(context, managers=("npm",))

    wrapper = (context.guard_home / "package-shims" / "bin" / "npm").read_text(encoding="utf-8")
    sidecar = (context.guard_home / "package-shims" / "bin" / ".npm.py").read_text(encoding="utf-8")
    assert shlex.split(wrapper.splitlines()[1])[1] == str(shim)
    assert sidecar.splitlines()[0] == f"#!{shim}"
    command_line = next(line for line in sidecar.splitlines() if line.startswith("base_command = "))
    command = ast.literal_eval(command_line.split("=", 1)[1].strip())
    assert command[0] == str(shim)


def test_package_shim_status_stale_when_wrapper_interpreter_is_missing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    frozen_exe = tmp_path / "HOL Guard.app" / "Contents" / "MacOS" / "hol-guard"
    frozen_exe.parent.mkdir(parents=True)
    frozen_exe.write_text("", encoding="utf-8")
    monkeypatch.setattr(guard_shims_module.sys, "frozen", True, raising=False)
    monkeypatch.setattr(guard_shims_module.sys, "executable", str(frozen_exe))
    context = HarnessContext(
        home_dir=tmp_path / "home",
        workspace_dir=tmp_path / "workspace",
        guard_home=tmp_path / "guard-home",
    )
    monkeypatch.setattr(
        guard_shims_module,
        "_detect_system_package_managers",
        lambda _context, path_env=None: (["npm"], []),
    )
    guard_shims_module.install_package_shims(context, managers=("npm",))
    wrapper_path = context.guard_home / "package-shims" / "bin" / "npm"
    python_path = context.guard_home / "package-shims" / "bin" / ".npm.py"
    missing = tmp_path / "core" / "versions" / "3.0.54" / "hol-guard"
    wrapper_path.write_text(
        "\n".join(("#!/bin/sh", f"exec {shlex.quote(str(missing))} {shlex.quote(str(python_path))} \"$@\"", "")),
        encoding="utf-8",
    )

    status = guard_shims_module.package_shim_status(context)
    details = next(item for item in status["manager_details"] if item["manager"] == "npm")
    assert details["integrity"] == "stale"

    repaired = guard_shims_module.repair_package_shims(context, managers=("npm",))
    assert repaired["repaired"] == ["npm"]
    restored = wrapper_path.read_text(encoding="utf-8")
    assert shlex.split(restored.splitlines()[1])[1] == str(frozen_exe)


def test_resolve_frozen_package_shim_path_accepts_stable_launcher_shebang(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from codex_plugin_scanner.guard.package_shim_frozen import (
        FROZEN_PACKAGE_SHIM_SENTINEL,
        resolve_frozen_package_shim_path,
    )

    versioned = tmp_path / "core" / "versions" / "3.0.57" / "hol-guard"
    versioned.parent.mkdir(parents=True)
    versioned.write_text("", encoding="utf-8")
    shim = tmp_path / "core" / "current-hol-guard"
    shim.write_text("", encoding="utf-8")
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(sys, "executable", str(versioned))
    shim_dir = tmp_path / "package-shims" / "bin"
    shim_dir.mkdir(parents=True)
    sidecar = shim_dir / ".npm.py"
    sidecar.write_text(
        "\n".join(
            (
                f"#!{shim}",
                f"{FROZEN_PACKAGE_SHIM_SENTINEL} = True",
                "raise SystemExit(0)",
                "",
            )
        ),
        encoding="utf-8",
    )

    assert resolve_frozen_package_shim_path([str(sidecar)]) == sidecar.resolve()


def test_resolve_frozen_package_shim_path_rejects_untrusted_files(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake_exe = tmp_path / "hol-guard"
    fake_exe.write_text("", encoding="utf-8")
    monkeypatch.setattr(guard_shims_module.sys, "frozen", True, raising=False)
    monkeypatch.setattr(guard_shims_module.sys, "executable", str(fake_exe))
    outsider = tmp_path / "npm"
    outsider.write_text(
        "\n".join(
            (
                f"#!{fake_exe}",
                f"{guard_shims_module.FROZEN_PACKAGE_SHIM_SENTINEL} = True",
                "raise SystemExit(0)",
                "",
            )
        ),
        encoding="utf-8",
    )

    assert guard_shims_module.resolve_frozen_package_shim_path([str(outsider)]) is None


def test_package_shim_interpreter_runnable_rejects_non_executable_launcher(tmp_path: Path) -> None:
    from codex_plugin_scanner.guard.package_shim_frozen import package_shim_interpreter_runnable

    interpreter = tmp_path / "hol-guard"
    interpreter.write_text("", encoding="utf-8")
    interpreter.chmod(0o600)
    sidecar = tmp_path / ".npm.py"
    wrapper = f"#!/bin/sh\nexec {shlex.quote(str(interpreter))} {shlex.quote(str(sidecar))} \"$@\"\n".encode()

    assert package_shim_interpreter_runnable(wrapper) is False


def test_package_shim_interpreter_runnable_accepts_executable_launcher(tmp_path: Path) -> None:
    from codex_plugin_scanner.guard.package_shim_frozen import package_shim_interpreter_runnable

    interpreter = tmp_path / "hol-guard"
    interpreter.write_text("", encoding="utf-8")
    interpreter.chmod(0o755)
    sidecar = tmp_path / ".npm.py"
    wrapper = f"#!/bin/sh\nexec {shlex.quote(str(interpreter))} {shlex.quote(str(sidecar))} \"$@\"\n".encode()

    assert package_shim_interpreter_runnable(wrapper) is True
