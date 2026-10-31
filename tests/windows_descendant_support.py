"""Process-tree probes for the Windows Job Object updater regressions.

The probe parent spawns one descendant and records its process id. The
descendant does nothing until the test releases it, then writes its escape
marker. A Job that contained the tree has already killed it by then, so the
marker can only appear if the descendant outlived its Job. The test never
races a timer against the Job's cleanup.
"""

from __future__ import annotations

import time
from pathlib import Path

_DESCENDANT_EXIT_TIMEOUT_SECONDS = 10.0
_DESCENDANT_RELEASE_TIMEOUT_SECONDS = 30.0


def windows_descendant_parent_script(mode: str) -> str:
    """Return a parent that spawns a descendant held until the test releases it.

    Arguments: release marker, escape marker, spawned marker (receives the
    descendant's process id).
    """
    descendant_script = "\n".join(
        [
            "import sys, time",
            "from pathlib import Path",
            "release = Path(sys.argv[1])",
            f"deadline = time.monotonic() + {_DESCENDANT_RELEASE_TIMEOUT_SECONDS}",
            "while not release.exists() and time.monotonic() < deadline:",
            "    time.sleep(0.01)",
            "Path(sys.argv[2]).write_text('escaped', encoding='utf-8')",
        ]
    )
    lines = [
        "import subprocess",
        "import sys",
        "import time",
        "from pathlib import Path",
        f"descendant_script = {descendant_script!r}",
        "child = subprocess.Popen([sys.executable, '-I', '-S', '-c', descendant_script, sys.argv[1], sys.argv[2]])",
        "Path(sys.argv[3]).write_text(str(child.pid), encoding='utf-8')",
    ]
    if mode == "timeout":
        lines.append("time.sleep(30)")
    elif mode == "overflow":
        lines.extend(
            [
                "sys.stdout.write('x' * (1024 * 1024))",
                "sys.stdout.flush()",
                "time.sleep(30)",
            ]
        )
    elif mode != "parent_exit":
        raise ValueError(f"unsupported process-tree test mode: {mode}")
    return "\n".join(lines)


def assert_descendant_contained(*, spawned_marker: Path, escape_marker: Path, release_marker: Path) -> None:
    """Release the descendant and prove it was already gone.

    A contained descendant is dead before the updater returns, so it never sees
    the release. One that escaped sees it, writes its marker and exits; either
    way the wait below ends on a real process exit, not a sleep.
    """
    from codex_plugin_scanner.guard.windows_paths import windows_process_is_running

    descendant_process_id = int(spawned_marker.read_text(encoding="utf-8"))
    assert descendant_process_id > 0
    _ = release_marker.write_text("release", encoding="utf-8")
    deadline = time.monotonic() + _DESCENDANT_EXIT_TIMEOUT_SECONDS
    while windows_process_is_running(descendant_process_id):
        assert time.monotonic() < deadline, "descendant outlived its updater Job"
        time.sleep(0.01)
    assert escape_marker.exists() is False
