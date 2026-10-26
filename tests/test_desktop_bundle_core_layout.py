"""Desktop unpacks a Core release below ``versions/<release>/bundle/``.

A generated Pi-family extension that bakes that launcher keeps running a
superseded CLI after Desktop moves ``current`` to a newer release, so the stable
``current-hol-guard`` launcher has to be recognized for this layout too.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.adapters import pi_extension_pinned_core, pi_extension_source
from codex_plugin_scanner.guard.adapters.base import HarnessAdapter, HarnessContext
from codex_plugin_scanner.guard.adapters.pi import OmpHarnessAdapter, PiHarnessAdapter
from codex_plugin_scanner.guard.stable_guard_cli import (
    argv0_is_ephemeral_desktop_cli,
    desktop_core_shim_for_executable,
    frozen_launcher_is_prune_safe,
)

_RELEASE = "3.50.0a5-97b143fb3d2adf30a07b97d621d5d4eb0031db45822b3869c2e87442c94e2150"
_NEWER = "3.50.0a6-1c0e7f2a9b4d3856e1f09a7c2d8b5e3f4a6c1d0b9e8f7a6b5c4d3e2f1a0b9c8d"
_posix_only = pytest.mark.skipif(os.name == "nt", reason="POSIX launcher contract")


def _select(launcher: Path, release: str) -> None:
    """Point Desktop's ``current.json`` at `release`, as an update does."""

    root = launcher.parents[3]
    pointer = {"schema": "guard-core-install.v1", "relativePath": f"versions/{release}/bundle/hol-guard"}
    (root / "current.json").write_text(json.dumps(pointer), encoding="utf-8")


def _core(tmp_path: Path, *, stable: bool = True) -> tuple[Path, Path]:
    root = tmp_path / "Application Support" / "org.hol.guard.desktop" / "core"
    launcher = root / "versions" / _RELEASE / "bundle" / "hol-guard"
    launcher.parent.mkdir(parents=True)
    launcher.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    launcher.chmod(0o755)
    shim = root / "current-hol-guard"
    if stable:
        shim.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        shim.chmod(0o755)
    return launcher, shim


def test_the_stable_launcher_is_found_for_the_bundle_layout(tmp_path: Path) -> None:
    launcher, shim = _core(tmp_path)

    assert desktop_core_shim_for_executable(launcher) == shim
    assert argv0_is_ephemeral_desktop_cli(str(launcher))
    assert not frozen_launcher_is_prune_safe(str(launcher))


def test_the_bundle_layout_is_recognized_for_the_windows_launcher(tmp_path: Path) -> None:
    launcher = tmp_path / "core" / "versions" / _RELEASE / "bundle" / "hol-guard.exe"

    assert desktop_core_shim_for_executable(launcher) is not None
    assert desktop_core_shim_for_executable(launcher).parent == tmp_path / "core"


@pytest.mark.parametrize(
    "relative",
    [
        ("bundle", "_internal", "hol-guard"),
        ("bundle", "lib", "hol-guard"),
        ("other", "hol-guard"),
        ("hol-guard",),
    ],
)
def test_only_the_release_launcher_names_a_core(tmp_path: Path, relative: tuple[str, ...]) -> None:
    executable = tmp_path / "core" / "versions" / _RELEASE
    for part in relative:
        executable = executable / part

    assert (desktop_core_shim_for_executable(executable) is None) == (len(relative) != 1 or relative[0] != "hol-guard")


def test_a_versions_directory_elsewhere_in_the_tree_is_not_a_core(tmp_path: Path) -> None:
    executable = tmp_path / "versions" / "tool" / "bundle" / "src" / "hol-guard"

    assert desktop_core_shim_for_executable(executable) is None


@_posix_only
def test_a_generated_extension_bakes_the_stable_launcher_for_the_bundle_layout(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    launcher, shim = _core(tmp_path)
    monkeypatch.setenv("HOL_GUARD_DESKTOP_RUNTIME_OWNER", str(launcher))

    source = pi_extension_source.managed_extension_source(
        guard_home=tmp_path / "guard-home",
        home_dir=tmp_path / "home",
        settings_path=tmp_path / "settings.json",
        harness="omp",
        display_name="Oh My Pi",
    )

    assert f"const GUARD_CLI_WRAPPER_COMMAND = {json.dumps(str(shim))};" in source
    assert f"const GUARD_DAEMON_RECOVERY_COMMAND = {json.dumps(str(shim))};" in source
    assert _RELEASE not in source


def _extension(tmp_path: Path, command: str) -> Path:
    extension = tmp_path / "home" / ".omp" / "agent" / "extensions" / "hol-guard.ts"
    extension.parent.mkdir(parents=True)
    extension.write_text(
        "// generated\n"
        f"const GUARD_CLI_WRAPPER_COMMAND = {json.dumps(command)};\n"
        "const GUARD_CLI_WRAPPER_ACCEPTS_JSON_ARGS = false;\n"
        f"const GUARD_DAEMON_RECOVERY_COMMAND = {json.dumps(command)};\n",
        encoding="utf-8",
    )
    return extension


@_posix_only
def test_an_extension_pinned_to_a_core_that_desktop_replaced_is_found(tmp_path: Path) -> None:
    launcher, _shim = _core(tmp_path)
    _select(launcher, _NEWER)
    extension = _extension(tmp_path, str(launcher))

    assert pi_extension_pinned_core.pinned_versioned_core(extension) == str(launcher)


@_posix_only
def test_an_extension_pinned_to_the_selected_core_is_healthy(tmp_path: Path) -> None:
    """Desktop's update binds each adapter to the candidate before it moves ``current.json``."""

    launcher, _shim = _core(tmp_path)
    _select(launcher, _RELEASE)

    assert pi_extension_pinned_core.pinned_versioned_core(_extension(tmp_path, str(launcher))) is None


@_posix_only
def test_a_pin_is_not_judged_without_a_readable_pointer(tmp_path: Path) -> None:
    launcher, _shim = _core(tmp_path)
    extension = _extension(tmp_path, str(launcher))

    assert pi_extension_pinned_core.pinned_versioned_core(extension) is None
    (launcher.parents[3] / "current.json").write_text("not json", encoding="utf-8")
    assert pi_extension_pinned_core.pinned_versioned_core(extension) is None


@_posix_only
def test_a_pin_that_a_repair_could_not_replace_is_not_reported(tmp_path: Path) -> None:
    launcher, _shim = _core(tmp_path, stable=False)
    _select(launcher, _NEWER)

    assert pi_extension_pinned_core.pinned_versioned_core(_extension(tmp_path, str(launcher))) is None


@_posix_only
def test_an_extension_on_the_stable_launcher_or_another_cli_is_not_reported(tmp_path: Path) -> None:
    _launcher, shim = _core(tmp_path)

    assert pi_extension_pinned_core.pinned_versioned_core(_extension(tmp_path, str(shim))) is None
    other = tmp_path / "home" / ".local" / "bin" / "hol-guard"
    assert pi_extension_pinned_core.pinned_versioned_core(_extension(tmp_path / "other", str(other))) is None
    assert pi_extension_pinned_core.pinned_versioned_core(tmp_path / "missing.ts") is None


@_posix_only
@pytest.mark.parametrize("adapter_type", [OmpHarnessAdapter, PiHarnessAdapter])
def test_diagnostics_call_a_pinned_extension_broken_so_repair_regenerates_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, adapter_type: type[HarnessAdapter]
) -> None:
    adapter = adapter_type()
    launcher, _shim = _core(tmp_path)
    _select(launcher, _NEWER)
    context = HarnessContext(home_dir=tmp_path / "home", workspace_dir=None, guard_home=tmp_path / "guard-home")
    extension = adapter._managed_extension_path(context)  # type: ignore[attr-defined]
    extension.parent.mkdir(parents=True)
    extension.write_text(f"const GUARD_CLI_WRAPPER_COMMAND = {json.dumps(str(launcher))};\n", encoding="utf-8")
    healthy = {"harness": adapter.harness, "setup_status": "active", "warnings": ["existing"]}
    monkeypatch.setattr(HarnessAdapter, "diagnostics", lambda _self, _context: dict(healthy))

    report = adapter.diagnostics(context)

    assert report["setup_status"] == "broken"
    assert report["warnings"][0] == "existing"
    assert "hol-guard repair" in report["warnings"][1]
    extension.write_text('const GUARD_CLI_WRAPPER_COMMAND = "/usr/bin/true";\n', encoding="utf-8")
    assert adapter.diagnostics(context)["setup_status"] == "active"
    extension.write_text(f"const GUARD_CLI_WRAPPER_COMMAND = {json.dumps(str(launcher))};\n", encoding="utf-8")
    _select(launcher, _RELEASE)
    assert adapter.diagnostics(context)["setup_status"] == "active"
