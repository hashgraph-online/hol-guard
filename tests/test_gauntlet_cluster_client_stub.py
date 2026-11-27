"""The kubectl stand-in answers like a client with no cluster, on every runner.

The environment-variable-names case declares the unreachable-cluster exit as a
benign answer. Before the stand-in, a runner with no kubectl failed the call
with exit 127, which the declaration rightly never excuses, so the case passed
or failed depending on what the host had installed.
"""

from __future__ import annotations

import os
import subprocess
import sys

import pytest

from ci.gauntlet.catalog import load_catalog
from ci.gauntlet.evidence import declared_benign_exit
from ci.gauntlet.fixtures import KUBECTL_UNREACHABLE, write_cluster_client_stub

CASE = "omp-native-kubectl-environment-variable-names"


def _run_stub(bin_dir, command: str) -> subprocess.CompletedProcess[str]:
    if os.name == "nt":
        argv = [sys.executable, "-I", str(bin_dir / "kubectl.py"), *command.split()[1:]]
    else:
        argv = [str(bin_dir / "kubectl"), *command.split()[1:]]
    return subprocess.run(argv, capture_output=True, text=True, timeout=30, check=False)


def test_stub_exit_is_the_declared_benign_answer(tmp_path) -> None:
    scenario = next(s for s in load_catalog() if s.id == CASE)
    command = scenario.commands[0]
    write_cluster_client_stub(tmp_path)

    completed = _run_stub(tmp_path, command)

    assert completed.returncode == 1
    assert completed.stdout == ""
    assert completed.stderr.strip() == KUBECTL_UNREACHABLE
    call = {"name": "bash", "args": {"command": command}, "result": {"details": {"exitCode": completed.returncode}}}
    assert declared_benign_exit(scenario, call)


@pytest.mark.skipif(os.name != "nt", reason="the .cmd launcher exists only on Windows")
def test_windows_launcher_resolves_through_pathext(tmp_path) -> None:
    write_cluster_client_stub(tmp_path)

    assert (tmp_path / "kubectl.cmd").is_file()
