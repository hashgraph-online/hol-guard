"""Frozen daemon process-inventory and runtime-identity coverage."""

from __future__ import annotations

import ast
import hashlib
import json
import os
import runpy
import subprocess
import sys
from pathlib import Path
from types import ModuleType

import pytest

from codex_plugin_scanner.guard import frozen_daemon_runtime, frozen_runtime_commands
from codex_plugin_scanner.guard import native_daemon_manage as manager

ROOT = Path(__file__).resolve().parents[1]
FROZEN_ENTRYPOINT = ROOT / "scripts" / "mdm" / "hol-guard-entry.py"


def _daemon_command(executable: Path, guard_home: Path, home: Path, *, port: int = 4781) -> str:
    return f"{executable} daemon --serve --guard-home {guard_home} --home {home} --port {port}"


def test_frozen_entrypoint_dispatches_multiprocessing_before_guard_imports(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[str] = []
    multiprocessing = ModuleType("multiprocessing")
    daemon_runtime = ModuleType("codex_plugin_scanner.guard.frozen_daemon_runtime")
    codex_runtime = ModuleType("codex_plugin_scanner.guard.frozen_codex_runtime")
    cli = ModuleType("codex_plugin_scanner.cli")

    multiprocessing.__dict__["freeze_support"] = lambda: events.append("freeze-support")
    daemon_runtime.__dict__["install_frozen_daemon_runtime"] = lambda: events.append("daemon-runtime")
    codex_runtime.__dict__["install_frozen_codex_runtime"] = lambda: events.append("codex-runtime")
    codex_runtime.__dict__["run_frozen_internal_command"] = lambda: events.append("private-command")
    cli.__dict__["main"] = lambda: events.append("public-cli") or 0
    monkeypatch.setitem(sys.modules, "multiprocessing", multiprocessing)
    monkeypatch.setitem(sys.modules, "codex_plugin_scanner.guard.frozen_daemon_runtime", daemon_runtime)
    monkeypatch.setitem(sys.modules, "codex_plugin_scanner.guard.frozen_codex_runtime", codex_runtime)
    monkeypatch.setitem(sys.modules, "codex_plugin_scanner.cli", cli)

    with pytest.raises(SystemExit) as exit_info:
        _ = runpy.run_path(str(FROZEN_ENTRYPOINT), run_name="__main__")

    assert exit_info.value.code == 0
    assert events == [
        "freeze-support",
        "daemon-runtime",
        "codex-runtime",
        "private-command",
        "public-cli",
    ]


def test_version_probe_answers_before_guard_imports(tmp_path: Path) -> None:
    marker = tmp_path / "guard-imported"
    package = tmp_path / "codex_plugin_scanner"
    package.mkdir()
    (package / "__init__.py").write_text(
        "import os\nfrom pathlib import Path\nPath(os.environ['GUARD_IMPORT_MARKER']).write_text('imported')\n",
        encoding="utf-8",
    )
    environment = dict(os.environ)
    environment["PYTHONPATH"] = str(tmp_path)
    environment["GUARD_IMPORT_MARKER"] = str(marker)
    result = subprocess.run(
        [sys.executable, str(FROZEN_ENTRYPOINT), "--version"],
        capture_output=True,
        env=environment,
        check=False,
        text=True,
    )

    version_file = ROOT / "src" / "codex_plugin_scanner" / "version.py"
    version_tree = ast.parse(version_file.read_text(encoding="utf-8"))
    version = next(
        node.value.value
        for node in version_tree.body
        if isinstance(node, ast.Assign)
        and any(isinstance(target, ast.Name) and target.id == "__version__" for target in node.targets)
        and isinstance(node.value, ast.Constant)
        and isinstance(node.value.value, str)
    )
    assert result.returncode == 0
    assert result.stdout.strip() == f"{FROZEN_ENTRYPOINT.name} {version}"
    assert result.stderr == ""
    assert not marker.exists()


def test_frozen_version_probe_reads_bundled_version_without_guard_imports(tmp_path: Path) -> None:
    bundle = tmp_path / "bundle"
    bundle.mkdir()
    (bundle / "version.py").write_text('__version__ = "9.9.9"  # x-release-please-version\n', encoding="utf-8")
    marker = tmp_path / "guard-imported"
    package = tmp_path / "codex_plugin_scanner"
    package.mkdir()
    (package / "__init__.py").write_text(
        "import os\nfrom pathlib import Path\nPath(os.environ['GUARD_IMPORT_MARKER']).write_text('imported')\n",
        encoding="utf-8",
    )
    invocation = (
        "import sys; "
        f"sys.frozen=True; sys._MEIPASS={str(bundle)!r}; "
        "sys.argv=['hol-guard','--version']; "
        f"entrypoint={str(FROZEN_ENTRYPOINT)!r}; "
        "exec(compile(open(entrypoint, 'rb').read(), entrypoint, 'exec'), "
        "{'__name__':'__main__','__file__':entrypoint})"
    )
    environment = dict(os.environ)
    environment["PYTHONPATH"] = str(tmp_path)
    environment["GUARD_IMPORT_MARKER"] = str(marker)
    result = subprocess.run(
        [sys.executable, "-c", invocation],
        capture_output=True,
        env=environment,
        check=False,
        text=True,
    )

    assert result.returncode == 0
    assert result.stdout.strip() == "hol-guard 9.9.9"
    assert result.stderr == ""
    assert not marker.exists()


def test_frozen_entrypoint_rejects_held_gate_before_guard_package_import(
    tmp_path: Path,
) -> None:
    marker = tmp_path / "guard-imported"
    package = tmp_path / "codex_plugin_scanner"
    package.mkdir()
    (package / "__init__.py").write_text(
        "import os\nfrom pathlib import Path\nPath(os.environ['GUARD_IMPORT_MARKER']).write_text('imported')\n",
        encoding="utf-8",
    )
    guard_home = tmp_path / "guard-home"
    home_dir = tmp_path / "home"
    payload = json.dumps(
        {
            "guard_home": str(guard_home.resolve()),
            "home_dir": str(home_dir.resolve()),
            "port": 4781,
        },
        separators=(",", ":"),
    )
    invocation = (
        "import sys; "
        f"sys.argv=[sys.executable,{'--_hol-guard-daemon-serve'!r},{payload!r}]; "
        f"entrypoint={str(FROZEN_ENTRYPOINT)!r}; "
        "exec(compile(open(entrypoint, 'rb').read(), entrypoint, 'exec'), "
        "{'__name__':'__main__','__file__':entrypoint})"
    )
    environment = dict(os.environ)
    environment["PYTHONPATH"] = str(tmp_path)
    environment["GUARD_IMPORT_MARKER"] = str(marker)
    result = subprocess.run(
        [sys.executable, "-c", invocation],
        input=b"",
        capture_output=True,
        env=environment,
        check=False,
    )

    assert result.returncode == 70
    assert not marker.exists()

    marker.unlink(missing_ok=True)
    released = subprocess.run(
        [sys.executable, "-c", invocation],
        input=b"1",
        capture_output=True,
        env=environment,
        check=False,
    )

    assert released.returncode != 70
    assert marker.exists()


def test_frozen_runtime_gate_fails_closed_on_stream_runtime_error(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard-home"
    home_dir = tmp_path / "home"
    payload = json.dumps(
        {
            "guard_home": str(guard_home.resolve()),
            "home_dir": str(home_dir.resolve()),
            "port": 4781,
        },
        separators=(",", ":"),
    )

    class RuntimeErrorStream:
        def read(self, _size: int) -> bytes:
            raise RuntimeError("stream closed unexpectedly")

    with pytest.raises(SystemExit) as exit_info:
        frozen_runtime_commands.consume_frozen_daemon_serve_gate(
            [sys.executable, frozen_runtime_commands.FROZEN_DAEMON_SERVE_ARG, payload],
            stdin=RuntimeErrorStream(),
        )

    assert exit_info.value.code == 70


def test_frozen_runtime_source_root_uses_stable_executable_path(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    executable = tmp_path / "hol-guard"
    executable.write_bytes(b"signed-core")
    monkeypatch.setattr(frozen_daemon_runtime.sys, "executable", str(executable))

    assert frozen_daemon_runtime._frozen_runtime_source_root() == str(executable.resolve())


def test_frozen_runtime_fingerprint_binds_exact_executable_bytes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    executable = tmp_path / "hol-guard"
    payload = b"signed-core-bytes"
    executable.write_bytes(payload)
    monkeypatch.setattr(frozen_daemon_runtime.sys, "executable", str(executable))
    monkeypatch.setattr(frozen_daemon_runtime, "_frozen_runtime_fingerprint_cache", None)

    assert frozen_daemon_runtime._frozen_runtime_fingerprint() == hashlib.sha256(payload).hexdigest()


def test_frozen_runtime_caches_verified_team_until_executable_changes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    executable = tmp_path / "managed-core"
    executable.write_bytes(b"first")
    calls: list[Path] = []

    def verify(path: Path, *, deep: bool = False) -> str:
        assert deep is True
        calls.append(path)
        return "TEAM123"

    frozen_daemon_runtime._signing_team_cache.clear()
    monkeypatch.setattr(frozen_daemon_runtime, "verified_macos_signing_team", verify)

    assert frozen_daemon_runtime._cached_macos_signing_team(executable) == "TEAM123"
    assert frozen_daemon_runtime._cached_macos_signing_team(executable) == "TEAM123"
    executable.write_bytes(b"second-version")
    assert frozen_daemon_runtime._cached_macos_signing_team(executable) == "TEAM123"
    assert calls == [executable, executable]


def test_frozen_daemon_launcher_preserves_pyinstaller_reset(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(manager.sys, "frozen", True, raising=False)
    monkeypatch.setenv("PYINSTALLER_RESET_ENVIRONMENT", "untrusted-parent-value")
    monkeypatch.setenv("HOL_GUARD_DESKTOP", "1")

    child_env = manager._daemon_launcher_env(home_dir=tmp_path)

    assert child_env["PYINSTALLER_RESET_ENVIRONMENT"] == "1"
    assert child_env["HOL_GUARD_DESKTOP"] == "1"


def test_frozen_daemon_launcher_preserves_persistent_desktop_runtime_owner(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime_owner = tmp_path / "desktop-core" / "bin" / "hol-guard"
    runtime_owner.parent.mkdir(parents=True)
    runtime_owner.write_text("#!/bin/sh\n", encoding="utf-8")
    monkeypatch.setattr(manager.sys, "frozen", True, raising=False)
    monkeypatch.setenv("HOL_GUARD_DESKTOP", "1")
    monkeypatch.setenv("HOL_GUARD_DESKTOP_RUNTIME_OWNER", str(runtime_owner))

    child_env = manager._daemon_launcher_env(home_dir=tmp_path)

    assert child_env["HOL_GUARD_DESKTOP_RUNTIME_OWNER"] == str(runtime_owner)


def test_non_frozen_daemon_launcher_drops_desktop_environment(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(manager.sys, "frozen", False, raising=False)
    monkeypatch.setenv("PYINSTALLER_RESET_ENVIRONMENT", "1")
    monkeypatch.setenv("HOL_GUARD_DESKTOP", "1")

    child_env = manager._daemon_launcher_env(home_dir=tmp_path)

    assert "PYINSTALLER_RESET_ENVIRONMENT" not in child_env
    assert "HOL_GUARD_DESKTOP" not in child_env




