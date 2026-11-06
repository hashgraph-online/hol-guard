from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path
from types import ModuleType

import pytest

_REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
_LAUNCHER = _REPOSITORY_ROOT / "scripts" / "mdm" / "run-local-lab-container.py"


def _load_launcher() -> ModuleType:
    spec = importlib.util.spec_from_file_location("run_local_lab_container", _LAUNCHER)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_local_mdm_container_launcher_disables_network() -> None:
    completed = subprocess.run(
        [sys.executable, str(_LAUNCHER), "--dry-run"],
        check=False,
        cwd=_REPOSITORY_ROOT,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 0, completed.stderr
    commands = json.loads(completed.stdout)
    assert commands["build"] == [
        "docker",
        "build",
        "--tag",
        "hol-guard-mdm-local-lab:local",
        "--file",
        str(_REPOSITORY_ROOT / "scripts" / "mdm" / "Dockerfile.local-lab"),
        str(_REPOSITORY_ROOT),
    ]
    assert commands["run"] == [
        "docker",
        "run",
        "--rm",
        "--network=none",
        "--mount",
        f"type=bind,src={_REPOSITORY_ROOT},dst=/hol-guard-source,readonly",
        "hol-guard-mdm-local-lab:local",
        "--json",
    ]


def test_local_mdm_container_launcher_applies_timeout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    launcher = _load_launcher()
    calls: list[tuple[list[str], dict[str, object]]] = []

    def fake_run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        calls.append((command, kwargs))
        return subprocess.CompletedProcess(command, returncode=0)

    monkeypatch.setattr(sys, "argv", [str(_LAUNCHER)])
    monkeypatch.setattr(launcher.subprocess, "run", fake_run)

    assert launcher.main() == 0
    assert calls == [
        (launcher._docker_build_command("hol-guard-mdm-local-lab:local"), {"check": True, "timeout": 300}),
        (launcher._docker_run_command("hol-guard-mdm-local-lab:local"), {"check": False, "timeout": 300}),
    ]


def test_local_mdm_container_launcher_reports_timeout(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    launcher = _load_launcher()

    def timeout_run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        raise subprocess.TimeoutExpired(command, timeout=300)

    monkeypatch.setattr(sys, "argv", [str(_LAUNCHER)])
    monkeypatch.setattr(launcher.subprocess, "run", timeout_run)

    assert launcher.main() == 124
    assert capsys.readouterr().err.startswith("local MDM container command timed out after 300 seconds:")


def test_local_mdm_container_launcher_reports_failed_build(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    launcher = _load_launcher()

    def failed_run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        raise subprocess.CalledProcessError(9, command)

    monkeypatch.setattr(sys, "argv", [str(_LAUNCHER)])
    monkeypatch.setattr(launcher.subprocess, "run", failed_run)

    assert launcher.main() == 9
    assert "failed with exit code 9" in capsys.readouterr().err


def test_local_mdm_container_launcher_reports_missing_docker(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    launcher = _load_launcher()

    def missing_run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        raise FileNotFoundError("docker")

    monkeypatch.setattr(sys, "argv", [str(_LAUNCHER)])
    monkeypatch.setattr(launcher.subprocess, "run", missing_run)

    assert launcher.main() == 127
    assert "could not start: docker" in capsys.readouterr().err
