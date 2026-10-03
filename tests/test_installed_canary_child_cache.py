"""Installed canary children must not add bytecode to verified package files."""

import subprocess
import sys
from types import SimpleNamespace

import pytest

from scripts import run_installed_canary as canary
from scripts.run_installed_canary import _child_python_environment


def test_child_interpreter_inherits_command_line_cache_prefix(tmp_path, monkeypatch):
    package = tmp_path / "installed-package"
    package.mkdir()
    module = package / "canary_cache_probe.py"
    module.write_text("VALUE = 1\n", encoding="utf-8")
    cache = tmp_path / "external-cache"
    monkeypatch.setattr(sys, "pycache_prefix", str(cache))
    monkeypatch.delenv("PYTHONPYCACHEPREFIX", raising=False)

    completed = subprocess.run(
        [sys.executable, "-c", "import canary_cache_probe; import sys; print(sys.pycache_prefix)"],
        cwd=package,
        env=_child_python_environment(),
        capture_output=True,
        text=True,
        check=True,
    )

    assert completed.stdout.strip() == str(cache)
    assert set(package.iterdir()) == {module}
    assert list(cache.rglob("canary_cache_probe.*.pyc"))


def test_child_environment_preserves_settings_without_command_line_prefix(monkeypatch):
    monkeypatch.setattr(sys, "pycache_prefix", None)
    monkeypatch.setenv("PYTHONPYCACHEPREFIX", "existing-cache")
    monkeypatch.setenv("CANARY_CACHE_PROBE", "preserved")

    environment = _child_python_environment()

    assert environment["PYTHONPYCACHEPREFIX"] == "existing-cache"
    assert environment["CANARY_CACHE_PROBE"] == "preserved"


def test_relative_cache_prefix_stays_relative_to_parent(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(sys, "pycache_prefix", "external-cache")
    child_directory = tmp_path / "child"
    child_directory.mkdir()
    completed = subprocess.run(
        [sys.executable, "-c", "import sys; print(sys.pycache_prefix)"],
        cwd=child_directory,
        env=_child_python_environment(),
        capture_output=True,
        text=True,
        check=True,
    )
    assert completed.stdout.strip() == str(tmp_path / "external-cache")


@pytest.mark.parametrize("call_site", ["corpus", "no_post_execution"])
def test_real_canary_child_calls_forward_cache_prefix(tmp_path, monkeypatch, call_site):
    cache = tmp_path / "external-cache"
    monkeypatch.setattr(sys, "pycache_prefix", str(cache))
    monkeypatch.delenv("PYTHONPYCACHEPREFIX", raising=False)
    captured = []

    def intercept_child(argv, **kwargs):
        if argv[0] == "git":
            return subprocess.CompletedProcess(argv, 0)
        assert argv[0] == sys.executable
        captured.append(kwargs["env"])
        raise subprocess.TimeoutExpired(argv, 1)

    monkeypatch.setattr(canary.subprocess, "run", intercept_child)
    if call_site == "corpus":
        suffix = ".exe" if sys.platform == "win32" else ""
        for binary in ["hol-guard-runtime", "guard-command-source"]:
            (tmp_path / f"{binary}{suffix}").touch()
        monkeypatch.setattr(canary, "_validate_corpus_bindings", lambda root: {})
        monkeypatch.setattr(canary, "distribution", lambda name: SimpleNamespace(locate_file=lambda path: tmp_path))
        with pytest.raises(canary.InstalledCanaryError, match="exceeded its time limit"):
            canary._run_corpus(tmp_path)
    else:
        with pytest.raises(subprocess.TimeoutExpired):
            canary._no_post_execution_proof_smoke()

    assert len(captured) == 1
    assert captured[0]["PYTHONPYCACHEPREFIX"] == str(cache)
