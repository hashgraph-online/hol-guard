"""The test session must never resolve the developer's real home."""

from __future__ import annotations

import hashlib
import os
import subprocess
import sys
from pathlib import Path

from tests.home_isolation import _HOME_OVERRIDES


def test_session_home_is_private():
    private_home = os.environ["HOL_GUARD_TEST_PRIVATE_HOME"]

    assert str(Path.home()) == private_home
    assert Path("~").expanduser() == Path(private_home)
    for variable in _HOME_OVERRIDES:
        assert variable not in os.environ
    if os.name == "nt":
        assert Path(os.environ["APPDATA"]).is_relative_to(private_home)


def test_private_home_is_stable_for_shard_planning():
    # CI collects node IDs in one job and runs them in another.
    assert Path(os.environ["HOL_GUARD_TEST_PRIVATE_HOME"]).name == (
        "home-" + hashlib.sha256(str(Path(__file__).resolve().parents[1]).encode()).hexdigest()[:12]
    )


def test_spawned_helpers_inherit_private_home():
    completed = subprocess.run(
        [sys.executable, "-c", "from pathlib import Path; print(Path.home())"],
        capture_output=True,
        text=True,
        check=True,
    )

    assert completed.stdout.strip() == os.environ["HOL_GUARD_TEST_PRIVATE_HOME"]
