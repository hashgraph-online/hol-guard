from __future__ import annotations

import os
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
