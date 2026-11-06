from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

from scripts import native_slo_process_tree as process_tree

pytestmark = pytest.mark.skipif(os.name == "nt", reason="process-tree RSS sampling is POSIX-only")


def test_process_tree_rss_needs_no_guard_runtime(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # The installed SLO samples RSS after its session closed the resident, so
    # sampling must not depend on a resident-backed helper or on caller PATH.
    shadow = tmp_path / "ps"
    shadow.write_text("#!/bin/sh\necho '1 0 999999999'\n")
    shadow.chmod(0o755)
    monkeypatch.setenv("PATH", str(tmp_path))

    rss = process_tree.process_tree_rss_bytes((os.getpid(),))

    assert isinstance(rss, int) and 0 < rss < 999999999 * 1024


def test_process_tree_rss_rejects_untrusted_ps(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    user_owned = tmp_path / "ps"
    user_owned.write_text("#!/bin/sh\n")
    user_owned.chmod(0o755)
    monkeypatch.setattr(process_tree, "_SYSTEM_PS_PATHS", (tmp_path / "missing", user_owned))

    assert process_tree.process_tree_rss_bytes((os.getpid(),)) is None


def test_rss_observer_decomposes_the_exact_gate_snapshot_without_another_probe(monkeypatch: pytest.MonkeyPatch) -> None:
    probes = []
    rows = "10 1 100\n11 10 30\n12 11 20\n13 1 999\n"

    def run(command, **kwargs):
        probes.append(command)
        return subprocess.CompletedProcess(command, 0, rows, "")

    monkeypatch.setattr(process_tree, "_system_ps_path", lambda: Path("/bin/ps"))
    monkeypatch.setattr(process_tree.subprocess, "run", run)
    observed = []
    with process_tree.observe_rss_reads(observed.append):
        assert process_tree.process_tree_rss_bytes((10,)) == 150 * 1024
    assert len(probes) == 1
    assert observed == [
        {"rss_bytes": 150 * 1024, "root_rss_bytes": 100 * 1024, "descendant_rss_bytes": 50 * 1024, "processes": 3}
    ]
    assert process_tree.process_tree_rss_bytes((10,)) == 150 * 1024
    assert len(observed) == 1


def test_rss_observer_is_reset_on_error_and_does_not_replace_failed_snapshots(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(process_tree, "_system_ps_path", lambda: Path("/bin/ps"))
    monkeypatch.setattr(
        process_tree.subprocess,
        "run",
        lambda *args, **kwargs: subprocess.CompletedProcess(args, 0, "10 1 100\n", ""),
    )
    observed = []
    with pytest.raises(RuntimeError, match="fixture failure"), process_tree.observe_rss_reads(observed.append):
        assert process_tree.process_tree_rss_bytes((99,)) is None
        raise RuntimeError("fixture failure")
    assert process_tree.process_tree_rss_bytes((10,)) == 100 * 1024
    assert not observed
