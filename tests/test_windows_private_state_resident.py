"""An idle Windows worker that talks to its resident starts no private-state runtime process."""

from __future__ import annotations

import base64
import json
import os
from collections import OrderedDict
from pathlib import Path
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard import native_policy_snapshot_windows_atomic as private_state
from codex_plugin_scanner.guard import native_policy_snapshot_windows_resident as resident
from codex_plugin_scanner.guard import native_resident_client, native_runtime
from codex_plugin_scanner.guard import native_resident_client_pool as pool_module
from codex_plugin_scanner.guard.mdm import runtime_request
from codex_plugin_scanner.guard.native_policy_snapshot_constants import NativePolicySnapshotError
from codex_plugin_scanner.guard.native_policy_snapshot_direct_lane_windows import write_windows_ack

EXECUTABLE = Path("/runtime/hol-guard-runtime.exe")
_REAL_REQUEST = native_resident_client.native_resident_client_request


class _WindowsOSProxy:
    """Expose Windows branching without mutating process-wide ``os.name``."""

    name = "nt"

    def __getattr__(self, name: str) -> object:
        return getattr(os, name)


class _PosixOSProxy(_WindowsOSProxy):
    name = "posix"


class _Resident:
    """Answers the resident operation from the real files, and counts round trips."""

    def __init__(self) -> None:
        self.operations: list[tuple[str, str]] = []
        self.homes: list[Path] = []
        self.frame: bytes | None = None

    def __call__(
        self,
        *,
        executable: Path,
        guard_home: Path,
        payload: bytes,
        idle_only: bool = False,
        idle_wait_seconds: float = 0.0,
        **_: object,
    ) -> bytes | None:
        assert executable == EXECUTABLE
        # Only a stream this process holds is borrowed; asking never starts one,
        # but an op landing while that stream is busy waits for it to be parked.
        assert idle_only is True
        assert idle_wait_seconds > 0
        envelope = json.loads(payload)
        assert envelope["operation"] == "windows_private_state"
        assert envelope["request"]["guard_home"] == str(guard_home)
        state = envelope["request"]["state"]
        assert state["schema"] == "windows-private-state.v1"
        self.homes.append(guard_home)
        self.operations.append((state["op"], state.get("name", "")))
        if self.frame is not None:
            return self.frame
        path = Path(state["directory"]) / state.get("name", "")
        if state["op"] == "read":
            content = path.read_bytes() if path.exists() else None
            answer: dict[str, object] = {
                "content_b64": None if content is None else base64.b64encode(content).decode("ascii")
            }
        elif state["op"] == "write":
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(base64.b64decode(state["content_b64"]))
            answer = {"written": True}
        elif state["op"] == "delete":
            existed = path.exists()
            path.unlink(missing_ok=True)
            answer = {"deleted": existed}
        else:
            Path(state["directory"]).mkdir(parents=True, exist_ok=True)
            answer = {"ensured": True}
        return json.dumps({"schema": "windows-private-state-resident.v1", "answer": answer}).encode()


@pytest.fixture
def home(tmp_path: Path) -> Path:
    guard_home = tmp_path.resolve() / "guard"
    (guard_home / "native-runtime").mkdir(parents=True)
    (guard_home / "native-runtime" / "command-control-authority.v1.json").write_bytes(b'{"generation":1}')
    return guard_home


@pytest.fixture
def process_starts(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """Every one-shot ``windows-private-state`` process the wrappers would start."""

    starts: list[str] = []

    def one_shot(feature: str, command: str, request: dict[str, object], **_: object) -> dict[str, object]:
        starts.append(str(request["op"]))
        return {"error": "native_windows_private_state_unavailable"}

    monkeypatch.setattr(runtime_request, "runtime_answer", one_shot)
    return starts


@pytest.fixture
def worker(monkeypatch: pytest.MonkeyPatch, home: Path) -> _Resident:
    """A worker process holding a resident client pool for `home`."""

    features = ("native-windows-private-state-v1", resident.RESIDENT_FEATURE)
    status = SimpleNamespace(
        available=True,
        compatible=True,
        identity=SimpleNamespace(path=EXECUTABLE),
        capabilities=SimpleNamespace(features=features),
    )
    answer = _Resident()
    monkeypatch.setattr(resident, "os", _WindowsOSProxy())
    monkeypatch.setattr(private_state, "os", _WindowsOSProxy())
    monkeypatch.setattr(native_runtime, "native_runtime_status", lambda **_: status)
    monkeypatch.setattr(native_runtime, "_isolated_environment", lambda: {})
    monkeypatch.setattr(native_resident_client, "native_resident_client_request", answer)
    monkeypatch.setattr(private_state, "_private_reads", OrderedDict())
    pools = {(str(EXECUTABLE), str(home / "native-runtime")): None}
    monkeypatch.setattr(native_resident_client, "_CLIENT_POOLS", pools)
    return answer


@pytest.fixture
def clock(monkeypatch: pytest.MonkeyPatch) -> list[float]:
    now = [1000.0]
    monkeypatch.setattr(private_state, "_clock", lambda: now[0])
    return now


def _idle_second(home: Path) -> None:
    """What an idle worker asks for in one second: its rechecks and an ACK lease renewal."""

    state = home / "native-runtime"
    private_state._windows_read_private_file(
        state, "command-control-authority.v1.json", maximum_bytes=4096, private_root=home
    )
    private_state._windows_read_private_file(state, "business-source-authority.v1.json", maximum_bytes=4096)
    write_windows_ack(home, state / "direct-lane" / "ack.json", b'{"lease":1}')
    private_state._windows_ensure_private_directory(state, private_root=home)


def test_an_idle_worker_starts_no_runtime_process(
    worker: _Resident, process_starts: list[str], home: Path, clock: list[float]
) -> None:
    for _second in range(150):
        _idle_second(home)
        clock[0] += 1.0

    assert process_starts == []
    # The read memo lapses every 60 s; each recheck goes to the resident too.
    reads = [name for operation, name in worker.operations if operation == "read"]
    assert reads.count("command-control-authority.v1.json") == 3
    assert reads.count("business-source-authority.v1.json") == 3
    assert {operation for operation, _name in worker.operations} == {"read", "write", "ensure"}
    assert worker.operations.count(("write", "ack.json")) == 150
    assert set(worker.homes) == {home}
    assert (home / "native-runtime" / "direct-lane" / "ack.json").read_bytes() == b'{"lease":1}'
    assert private_state._windows_delete_private_child(
        directory=home / "native-runtime" / "direct-lane", name="ack.json", private_root=home
    )


def test_file_op_failures_from_the_resident_are_raised_not_retried(
    worker: _Resident, process_starts: list[str], home: Path
) -> None:
    worker.frame = json.dumps(
        {"schema": "windows-private-state-resident.v1", "answer": {"error": "native_resident_windows_access_denied"}}
    ).encode()

    with pytest.raises(NativePolicySnapshotError, match="native_resident_windows_access_denied"):
        write_windows_ack(home, home / "native-runtime" / "direct-lane" / "ack.json", b"{}")
    assert process_starts == []


@pytest.mark.parametrize(
    "frame",
    [
        None,
        b'{"error":"native_request_schema_unsupported","retryable":false}',
        b'{"error":"native_overloaded","retryable":true}',
        b"not json",
        b'{"schema":"windows-private-state-resident.v1","answer":[]}',
    ],
)
def test_a_resident_that_cannot_answer_falls_back_to_the_command(
    worker: _Resident, process_starts: list[str], home: Path, frame: bytes | None, monkeypatch: pytest.MonkeyPatch
) -> None:
    def failing(**kwargs: object) -> bytes | None:
        worker(**kwargs)  # type: ignore[arg-type]
        return frame

    monkeypatch.setattr(native_resident_client, "native_resident_client_request", failing)
    worker.frame = b"{}"

    with pytest.raises(NativePolicySnapshotError, match="native_windows_private_state_unavailable"):
        write_windows_ack(home, home / "native-runtime" / "direct-lane" / "ack.json", b"{}")
    assert process_starts == ["write"]


def test_paths_outside_every_resident_home_use_the_command(
    worker: _Resident, process_starts: list[str], home: Path, tmp_path: Path
) -> None:
    other = tmp_path / "other-home"
    with pytest.raises(NativePolicySnapshotError):
        private_state._windows_ensure_private_directory(other)
    with pytest.raises(NativePolicySnapshotError):
        private_state._windows_ensure_private_directory(home / "native-runtime", private_root=tmp_path)
    # A sibling whose name only starts with the home's name is not inside it.
    with pytest.raises(NativePolicySnapshotError):
        private_state._windows_ensure_private_directory(tmp_path / "guard-other")

    assert worker.operations == []
    assert process_starts == ["ensure", "ensure", "ensure"]


def test_a_runtime_without_the_operation_uses_the_command(
    worker: _Resident, process_starts: list[str], home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    status = native_runtime.native_runtime_status()
    status.capabilities.features = ("native-windows-private-state-v1",)

    with pytest.raises(NativePolicySnapshotError):
        private_state._windows_ensure_private_directory(home)

    assert worker.operations == []
    assert process_starts == ["ensure"]


def test_other_systems_never_ask_the_resident(worker: _Resident, monkeypatch: pytest.MonkeyPatch, home: Path) -> None:
    monkeypatch.setattr(resident, "os", _PosixOSProxy())

    assert resident.resident_private_state_answer({"op": "ensure", "directory": str(home)}, output_limit=4096) is None
    assert worker.operations == []


def test_a_pool_without_an_idle_stream_starts_no_client(
    worker: _Resident, process_starts: list[str], home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Through the real pool: with no parked stream, nothing is started and the command answers."""

    started: list[Path] = []

    def no_client(**kwargs: object) -> None:
        started.append(Path(str(kwargs.get("state_dir"))))
        raise AssertionError("a private-state request must not start a client stream")

    state_dir = native_resident_client._pinned_state_dir(home / "native-runtime")
    pool = native_resident_client._PersistentNativeClientPool(
        executable=EXECUTABLE, state_dir=state_dir, environment={}
    )
    asked: list[bool] = []
    real_request = pool.request

    def counted(payload: bytes, **kwargs: object) -> bytes | None:
        asked.append(bool(kwargs.get("idle_only")))
        return real_request(payload, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(pool, "request", counted)
    monkeypatch.setattr(native_resident_client, "_CLIENT_POOLS", {(str(EXECUTABLE), str(state_dir)): pool})
    monkeypatch.setattr(native_resident_client, "native_resident_client_request", _REAL_REQUEST)
    monkeypatch.setattr(pool_module, "_PersistentNativeClient", no_client)

    with pytest.raises(NativePolicySnapshotError, match="native_windows_private_state_unavailable"):
        write_windows_ack(home, home / "native-runtime" / "direct-lane" / "ack.json", b"{}")

    assert asked == [True]
    assert started == []
    assert process_starts == ["write"]
