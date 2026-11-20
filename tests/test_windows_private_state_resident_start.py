"""The Windows daemon host opens its resident stream while admission runs.

Before admission ends, the host's private-state checks used to start a runtime
process each, because no stream was open yet and every other caller only
borrows one. The host now opens the stream itself with one real check of its
runtime directory; every other caller still never starts one.
"""

from __future__ import annotations

import json
import os
import threading
from pathlib import Path
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard import native_policy_snapshot_windows_atomic as private_state
from codex_plugin_scanner.guard import native_policy_snapshot_windows_resident as resident
from codex_plugin_scanner.guard import native_resident_client, native_runtime
from codex_plugin_scanner.guard.mdm import runtime_request
from codex_plugin_scanner.guard.native_policy_snapshot_constants import NativePolicySnapshotError
from codex_plugin_scanner.guard.workers import host as worker_host

EXECUTABLE = Path("/runtime/hol-guard-runtime.exe")


class _WindowsOSProxy:
    name = "nt"

    def __getattr__(self, name: str) -> object:
        return getattr(os, name)


class _PosixOSProxy(_WindowsOSProxy):
    name = "posix"


class _Stream:
    """Records each resident request and whether it could start a stream."""

    def __init__(self) -> None:
        self.requests: list[tuple[str, Path, bool]] = []

    def __call__(self, *, guard_home: Path, payload: bytes, idle_only: bool = False, **_: object) -> bytes | None:
        state = json.loads(payload)["request"]["state"]
        self.requests.append((str(state["op"]), guard_home, idle_only))
        if idle_only:
            return None
        return json.dumps({"schema": "windows-private-state-resident.v1", "answer": {"ensured": True}}).encode()


@pytest.fixture
def home(tmp_path: Path) -> Path:
    guard_home = tmp_path.resolve() / "guard"
    (guard_home / "native-runtime").mkdir(parents=True)
    return guard_home


@pytest.fixture
def process_starts(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    starts: list[str] = []

    def one_shot(feature: str, command: str, request: dict[str, object], **_: object) -> dict[str, object]:
        starts.append(str(request["op"]))
        return {"ensured": True}

    monkeypatch.setattr(runtime_request, "runtime_answer", one_shot)
    return starts


@pytest.fixture
def stream(monkeypatch: pytest.MonkeyPatch) -> _Stream:
    """A Windows process with no resident client pool yet."""

    status = SimpleNamespace(
        available=True,
        compatible=True,
        identity=SimpleNamespace(path=EXECUTABLE),
        capabilities=SimpleNamespace(features=("native-windows-private-state-v1", resident.RESIDENT_FEATURE)),
    )
    recorder = _Stream()
    monkeypatch.setattr(resident, "os", _WindowsOSProxy())
    monkeypatch.setattr(private_state, "os", _WindowsOSProxy())
    monkeypatch.setattr(native_runtime, "native_runtime_status", lambda **_: status)
    monkeypatch.setattr(native_runtime, "_isolated_environment", lambda: {})
    monkeypatch.setattr(native_resident_client, "native_resident_client_request", recorder)
    monkeypatch.setattr(native_resident_client, "_CLIENT_POOLS", {})
    return recorder


def test_the_host_opens_its_stream_with_one_check_of_its_runtime_directory(
    stream: _Stream, process_starts: list[str], home: Path
) -> None:
    resident.start_private_state_resident(home)

    assert stream.requests == [("ensure", home, False)]
    assert process_starts == []


def test_other_callers_still_only_borrow_a_stream(stream: _Stream, process_starts: list[str], home: Path) -> None:
    resident.start_private_state_resident(home)
    # With no pool of its own, an ordinary caller does not ask the resident at all.
    private_state._windows_ensure_private_directory(home / "native-runtime", private_root=home)

    assert stream.requests == [("ensure", home, False)]
    assert process_starts == ["ensure"]


def test_paths_outside_the_starting_home_only_borrow(
    stream: _Stream, process_starts: list[str], home: Path, tmp_path: Path
) -> None:
    with resident._starting_stream(home):
        # A sibling whose name only starts with the home's name is not inside it.
        private_state._windows_ensure_private_directory(tmp_path / "guard-other")

    assert stream.requests == []
    assert process_starts == ["ensure"]


def test_a_missing_runtime_directory_is_created_before_the_stream_opens(
    stream: _Stream, process_starts: list[str], home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (home / "native-runtime").rmdir()
    created: list[Path] = []
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.native_policy_snapshot_windows_support._runtime_state_directory",
        lambda guard_home: created.append(guard_home),
    )

    resident.start_private_state_resident(home)

    assert created == [home]
    assert stream.requests == [("ensure", home, False)]


def test_a_failed_start_falls_back_to_the_command(
    stream: _Stream, process_starts: list[str], home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(native_resident_client, "native_resident_client_request", lambda **_: None)

    resident.start_private_state_resident(home)

    assert process_starts == ["ensure"]


def test_a_failed_check_is_raised(stream: _Stream, home: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    denied = json.dumps(
        {"schema": "windows-private-state-resident.v1", "answer": {"error": "native_resident_windows_access_denied"}}
    ).encode()
    monkeypatch.setattr(native_resident_client, "native_resident_client_request", lambda **_: denied)

    with pytest.raises(NativePolicySnapshotError, match="native_resident_windows_access_denied"):
        resident.start_private_state_resident(home)


def test_other_systems_start_nothing(stream: _Stream, process_starts: list[str], home: Path, monkeypatch) -> None:
    monkeypatch.setattr(resident, "os", _PosixOSProxy())

    resident.start_private_state_resident(home)

    assert stream.requests == []
    assert process_starts == []


class _Store:
    def __init__(self, guard_home: Path) -> None:
        self.guard_home = guard_home

    def migrate_installed_command_pack_authority(self) -> None:
        return None


@pytest.fixture
def host_parts(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    calls: list[str] = []
    monkeypatch.setattr(worker_host.WorkerHost, "_build_hook_worker", lambda self: None)
    monkeypatch.setattr(worker_host.WorkerHost, "_start_policy_publication", lambda self: calls.append("publish"))
    return calls


def test_the_windows_host_opens_the_stream_beside_admission(
    tmp_path: Path, host_parts: list[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    opened: list[Path] = []
    done = threading.Event()

    def start(guard_home: Path) -> None:
        opened.append(guard_home)
        done.set()

    monkeypatch.setattr(worker_host, "os", _WindowsOSProxy())
    monkeypatch.setattr(resident, "start_private_state_resident", start)
    host = worker_host.WorkerHost(_Store(tmp_path), home_dir=tmp_path)  # pyright: ignore[reportArgumentType]

    host.start()

    assert done.wait(5.0)
    assert opened == [tmp_path]
    assert [thread.name for thread in host._threads] == ["guard-worker-resident-start"]
    assert host_parts == ["publish"]


def test_a_stream_that_cannot_open_does_not_stop_the_host(
    tmp_path: Path, host_parts: list[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    def start(guard_home: Path) -> None:
        raise NativePolicySnapshotError("native_windows_private_state_unavailable")

    monkeypatch.setattr(worker_host, "os", _WindowsOSProxy())
    monkeypatch.setattr(resident, "start_private_state_resident", start)
    host = worker_host.WorkerHost(_Store(tmp_path), home_dir=tmp_path)  # pyright: ignore[reportArgumentType]

    host.start()
    for thread in host._threads:
        thread.join(5.0)

    assert host_parts == ["publish"]


def test_other_hosts_open_no_stream_early(tmp_path: Path, host_parts: list[str], monkeypatch) -> None:
    monkeypatch.setattr(worker_host, "os", _PosixOSProxy())
    monkeypatch.setattr(resident, "start_private_state_resident", lambda guard_home: pytest.fail("started"))
    host = worker_host.WorkerHost(_Store(tmp_path), home_dir=tmp_path)  # pyright: ignore[reportArgumentType]

    host.start()

    assert host._threads == []
    assert host_parts == ["publish"]
