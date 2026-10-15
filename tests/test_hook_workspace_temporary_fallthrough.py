"""The daemon's hook workspace vectors the resident direct lane repeats.

`rust/crates/guard-runtime/src/hook_direct_workspace_tests.rs` asserts the same
vectors against the Rust mirror, so a change on either side must change both.
"""

from __future__ import annotations

import os
import shutil
import sys
from collections.abc import Iterator
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.daemon.server import _GuardDaemonHandler

pytestmark = pytest.mark.skipif(os.name != "posix", reason="POSIX temporary roots")

normalized = _GuardDaemonHandler._normalized_hook_workspace_string


def _workdir(value: str) -> tuple[bool, str | None]:
    return _GuardDaemonHandler._runtime_hook_exec_command_workdir(
        {"tool_name": "exec_command", "tool_input": {"workdir": value}}
    )


@pytest.fixture
def scratch() -> Iterator[Path]:
    root = Path(f"/tmp/hdw-oracle-{os.getpid()}")
    shutil.rmtree(root, ignore_errors=True)
    (root / "sub").mkdir(parents=True)
    (root / "to-tmp").symlink_to("/tmp")
    (root / "sub" / "up").symlink_to("../..")
    yield root
    shutil.rmtree(root, ignore_errors=True)


@pytest.mark.parametrize("value", ["/tmp", "/var/tmp", "/tmp/None", "/tmp/x/..", " /tmp/ "])
def test_temporary_roots_are_skipped(value: str) -> None:
    assert normalized(value) is None


def test_links_to_a_temporary_root_are_skipped_and_children_kept(scratch: Path) -> None:
    for link in ("to-tmp", "sub/up"):
        assert normalized(f"{scratch}/{link}") is None
    for kept in (str(scratch), f"{scratch}/sub", f"{scratch}/missing", "/work/repo"):
        assert normalized(kept) == kept


@pytest.mark.skipif(sys.platform != "darwin", reason="Darwin temporary roots")
def test_darwin_temporary_roots() -> None:
    assert normalized("/private/tmp") is None
    assert normalized("/private/var/tmp") is None
    assert normalized("/var/folders/abc/id/T") == "/var/folders/abc/id/T"


@pytest.mark.skipif(sys.platform == "darwin", reason="non-Darwin roots")
def test_darwin_only_roots_are_kept_elsewhere() -> None:
    assert normalized("/private/tmp") == "/private/tmp"


def test_temporary_workdir_rejects_instead_of_falling_through() -> None:
    assert _workdir("/tmp") == (True, None)
    assert _workdir("/tmp/None") == (True, "/tmp/None")
