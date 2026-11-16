"""Idle Windows workers must not start a runtime process for every private-state recheck."""

from __future__ import annotations

import base64
import os
from collections import OrderedDict
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import native_policy_snapshot_windows_atomic as private_state
from codex_plugin_scanner.guard import store_base
from codex_plugin_scanner.guard.native_policy_snapshot_constants import NativePolicySnapshotError


class _WindowsOSProxy:
    """Expose Windows branching without mutating process-wide ``os.name``."""

    name = "nt"

    def __getattr__(self, name: str) -> object:
        return getattr(os, name)


class _Runtime:
    """Answers private-state requests from the real files, and counts them."""

    def __init__(self) -> None:
        self.requests: list[tuple[str, str]] = []
        self.during_read: list[Path] = []
        self.error: str | None = None

    def __call__(self, request: dict[str, object], *, output_limit: int, feature: str) -> dict[str, object]:
        del output_limit, feature
        op = str(request["op"])
        path = Path(str(request["directory"])) / str(request["name"])
        self.requests.append((op, path.name))
        if self.error is not None:
            return {"error": self.error}
        if op == "read":
            content = path.read_bytes() if path.exists() else None
            for changed in self.during_read:
                _replace(changed, b"changed during the read")
            self.during_read = []
            return {"content_b64": None if content is None else base64.b64encode(content).decode("ascii")}
        if op == "write":
            _replace(path, base64.b64decode(str(request["content_b64"])))
            return {"written": True}
        if op == "delete":
            existed = path.exists()
            path.unlink(missing_ok=True)
            return {"deleted": existed}
        raise AssertionError(op)


def _replace(path: Path, content: bytes) -> None:
    staged = path.with_name(f".{path.name}.tmp")
    staged.write_bytes(content)
    os.replace(staged, path)


@pytest.fixture
def runtime(monkeypatch: pytest.MonkeyPatch) -> _Runtime:
    answer = _Runtime()
    monkeypatch.setattr(private_state, "os", _WindowsOSProxy())
    monkeypatch.setattr(private_state, "_private_state_answer", answer)
    monkeypatch.setattr(private_state, "_private_reads", OrderedDict())
    return answer


@pytest.fixture
def clock(monkeypatch: pytest.MonkeyPatch) -> list[float]:
    now = [1000.0]
    monkeypatch.setattr(private_state, "_clock", lambda: now[0])
    return now


@pytest.fixture
def state(tmp_path: Path) -> Path:
    directory = tmp_path / "guard" / "native-runtime"
    directory.mkdir(parents=True)
    (directory / "command-control-authority.v1.json").write_bytes(b'{"generation":1}')
    return directory


def _idle_poll(state: Path) -> tuple[bytes | None, bytes | None, bool]:
    """What one publisher reconcile pass asks for on an idle home."""

    home = state.parent
    authority = private_state._windows_read_private_file(
        state, "command-control-authority.v1.json", maximum_bytes=4096, private_root=home
    )
    source = private_state._windows_read_private_file(
        state, "business-source-authority.v1.json", maximum_bytes=4096, private_root=home
    )
    deleted = private_state._windows_delete_private_child(directory=state, name="ack.json", private_root=home)
    return authority, source, deleted


def test_an_idle_minute_of_polls_starts_one_runtime_per_file_per_window(
    runtime: _Runtime, clock: list[float], state: Path
) -> None:
    for _second in range(120):
        assert _idle_poll(state) == (b'{"generation":1}', None, False)
        clock[0] += 1.0

    # One verified read per file per recheck window, and no delete of a
    # missing acknowledgment. Before, this was 360 runtime processes.
    assert (
        runtime.requests
        == [
            ("read", "command-control-authority.v1.json"),
            ("read", "business-source-authority.v1.json"),
        ]
        * 2
    )


def test_a_replaced_or_rewritten_file_is_read_again_at_once(runtime: _Runtime, clock: list[float], state: Path) -> None:
    authority = state / "command-control-authority.v1.json"
    _idle_poll(state)

    _replace(authority, b'{"generation":2}')
    assert _idle_poll(state)[0] == b'{"generation":2}'

    # Same size, same inode, only the write time moves.
    authority.write_bytes(b'{"generation":3}')
    stamp = authority.stat().st_mtime_ns + 1_000_000
    os.utime(authority, ns=(stamp, stamp))
    assert _idle_poll(state)[0] == b'{"generation":3}'

    (state / "business-source-authority.v1.json").write_bytes(b"{}")
    assert _idle_poll(state)[1] == b"{}"
    assert [name for op, name in runtime.requests if op == "read"].count("command-control-authority.v1.json") == 3
    assert [name for op, name in runtime.requests if op == "read"].count("business-source-authority.v1.json") == 2


def test_a_removed_file_is_seen_missing_at_once(runtime: _Runtime, clock: list[float], state: Path) -> None:
    _idle_poll(state)
    (state / "command-control-authority.v1.json").unlink()

    assert _idle_poll(state)[0] is None
    assert runtime.requests.count(("read", "command-control-authority.v1.json")) == 2


def test_writes_and_deletes_through_the_runtime_forget_the_file(
    runtime: _Runtime, clock: list[float], state: Path
) -> None:
    home = state.parent
    _idle_poll(state)

    private_state._windows_write_private_file_atomic(
        directory=state, name="ack.json", payload=b"ack", maximum_bytes=64, private_root=home
    )
    assert private_state._windows_delete_private_child(directory=state, name="ack.json", private_root=home) is True
    private_state._windows_write_private_file_atomic(
        directory=state, name="command-control-authority.v1.json", payload=b"new", maximum_bytes=4096, private_root=home
    )

    assert _idle_poll(state) == (b"new", None, False)
    assert runtime.requests[2:] == [
        ("write", "ack.json"),
        ("delete", "ack.json"),
        ("write", "command-control-authority.v1.json"),
        ("read", "command-control-authority.v1.json"),
    ]


def test_a_file_changed_during_the_read_is_not_remembered(runtime: _Runtime, clock: list[float], state: Path) -> None:
    authority = state / "command-control-authority.v1.json"
    runtime.during_read = [authority]
    assert _idle_poll(state)[0] == b'{"generation":1}'

    assert _idle_poll(state)[0] == b"changed during the read"
    assert runtime.requests.count(("read", "command-control-authority.v1.json")) == 2


def test_a_recreated_directory_is_verified_again(runtime: _Runtime, clock: list[float], state: Path) -> None:
    _idle_poll(state)
    moved = state.with_name("moved")
    state.rename(moved)
    state.mkdir()
    (moved / "command-control-authority.v1.json").rename(state / "command-control-authority.v1.json")

    _idle_poll(state)
    assert runtime.requests.count(("read", "command-control-authority.v1.json")) == 2
    assert runtime.requests.count(("read", "business-source-authority.v1.json")) == 2


def test_a_path_through_a_junction_or_link_always_asks_the_runtime(
    runtime: _Runtime, clock: list[float], state: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(store_base, "_windows_path_is_direct", lambda path: False)

    for _second in range(3):
        _idle_poll(state)
    assert runtime.requests.count(("read", "command-control-authority.v1.json")) == 3
    assert runtime.requests.count(("delete", "ack.json")) == 3


def test_runtime_failures_are_never_remembered(runtime: _Runtime, clock: list[float], state: Path) -> None:
    runtime.error = "native_resident_windows_access_denied"
    for _attempt in range(2):
        with pytest.raises(NativePolicySnapshotError, match="access_denied"):
            private_state._windows_read_private_file(state, "command-control-authority.v1.json", maximum_bytes=4096)
    runtime.error = None

    assert private_state._windows_read_private_file(state, "command-control-authority.v1.json", maximum_bytes=4096) == (
        b'{"generation":1}'
    )
    assert len(runtime.requests) == 3


def test_other_systems_never_remember_reads(state: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    runtime = _Runtime()
    monkeypatch.setattr(private_state, "_remembers_private_reads", lambda: False)
    monkeypatch.setattr(private_state, "_private_state_answer", runtime)
    monkeypatch.setattr(private_state, "_private_reads", OrderedDict())

    for _second in range(3):
        _idle_poll(state)
    assert len(runtime.requests) == 9
