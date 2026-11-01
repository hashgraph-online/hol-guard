from __future__ import annotations

import base64
import os
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import native_policy_snapshot_windows_atomic as private_state
from codex_plugin_scanner.guard.native_policy_snapshot_constants import NativePolicySnapshotError

STATE = Path("C:/Users/guard/.hol-guard/native-runtime")
HOME = Path("C:/Users/guard/.hol-guard")


class _WindowsOSProxy:
    """Expose Windows branching without mutating process-wide ``os.name``."""

    name = "nt"

    def __getattr__(self, name: str) -> object:
        return getattr(os, name)


def _fake_runtime(
    monkeypatch: pytest.MonkeyPatch,
    answer: dict[str, object] | None,
) -> list[tuple[dict[str, object], int]]:
    requests: list[tuple[dict[str, object], int]] = []

    def fake_answer(request: dict[str, object], *, output_limit: int, feature: str) -> dict[str, object] | None:
        # Directories have their own feature, so a runtime without them is unavailable.
        ensure = request["op"] == "ensure"
        assert feature == ("native-windows-private-directory-v1" if ensure else "native-windows-private-state-v1")
        requests.append((request, output_limit))
        return answer

    monkeypatch.setattr(private_state, "_private_state_answer", fake_answer)
    return requests


def test_reads_decode_the_runtime_content(monkeypatch: pytest.MonkeyPatch) -> None:
    requests = _fake_runtime(monkeypatch, {"content_b64": base64.b64encode(b"{}").decode()})

    assert private_state._windows_read_private_file(STATE, "a.json", maximum_bytes=8, private_root=HOME) == b"{}"
    assert private_state._windows_read_snapshot_bytes(STATE / "b.json", maximum_bytes=8) == b"{}"
    assert requests == [
        (
            {"op": "read", "directory": str(STATE), "name": "a.json", "private_root": str(HOME), "maximum_bytes": 8},
            12 + private_state._PRIVATE_STATE_ANSWER_OVERHEAD,
        ),
        (
            {"op": "read", "directory": str(STATE), "name": "b.json", "maximum_bytes": 8},
            12 + private_state._PRIVATE_STATE_ANSWER_OVERHEAD,
        ),
    ]


def test_missing_files_read_as_none(monkeypatch: pytest.MonkeyPatch) -> None:
    _fake_runtime(monkeypatch, {"content_b64": None})

    assert private_state._windows_read_private_file(STATE, "a.json", maximum_bytes=8) is None


@pytest.mark.parametrize(
    "content",
    [7, "not base64!", "", base64.b64encode(b"123456789").decode()],
)
def test_reads_refuse_malformed_or_oversized_content(monkeypatch: pytest.MonkeyPatch, content: object) -> None:
    _fake_runtime(monkeypatch, {"content_b64": content})

    with pytest.raises(NativePolicySnapshotError, match="native_windows_private_state_invalid"):
        private_state._windows_read_private_file(STATE, "a.json", maximum_bytes=8)


def test_writes_send_the_payload_and_private_root(monkeypatch: pytest.MonkeyPatch) -> None:
    requests = _fake_runtime(monkeypatch, {"written": True})

    private_state._windows_write_private_file_atomic(
        directory=STATE, name="a.json", payload=b"abc", maximum_bytes=8, private_root=HOME
    )

    assert [request for request, _limit in requests] == [
        {
            "op": "write",
            "directory": str(STATE),
            "name": "a.json",
            "private_root": str(HOME),
            "maximum_bytes": 8,
            "content_b64": base64.b64encode(b"abc").decode(),
        }
    ]


@pytest.mark.parametrize("payload", [b"", b"123456789"])
def test_writes_outside_their_bound_never_reach_the_runtime(monkeypatch: pytest.MonkeyPatch, payload: bytes) -> None:
    requests = _fake_runtime(monkeypatch, {"written": True})

    with pytest.raises(NativePolicySnapshotError, match="native_policy_windows_write_too_large"):
        private_state._windows_write_private_file_atomic(
            directory=STATE, name="a.json", payload=payload, maximum_bytes=8
        )
    assert requests == []


def test_deletes_report_whether_the_file_existed(monkeypatch: pytest.MonkeyPatch) -> None:
    requests = _fake_runtime(monkeypatch, {"deleted": True})
    assert private_state._windows_delete_private_child(directory=STATE, name="a.json") is True
    _fake_runtime(monkeypatch, {"deleted": False})
    assert private_state._windows_delete_private_child(directory=STATE, name="a.json", private_root=HOME) is False
    assert requests == [
        ({"op": "delete", "directory": str(STATE), "name": "a.json"}, private_state._PRIVATE_STATE_ANSWER_OVERHEAD)
    ]


def test_ensure_sends_absolute_directories_without_a_file_name(monkeypatch: pytest.MonkeyPatch) -> None:
    requests = _fake_runtime(monkeypatch, {"ensured": True})

    private_state._windows_ensure_private_directory(STATE)
    private_state._windows_ensure_private_directory(STATE, private_root=HOME)

    assert [request for request, _limit in requests] == [
        {"op": "ensure", "directory": os.path.abspath(STATE)},
        {"op": "ensure", "directory": os.path.abspath(STATE), "private_root": os.path.abspath(HOME)},
    ]


def test_runtime_state_directory_is_ensured_below_the_guard_home(monkeypatch: pytest.MonkeyPatch) -> None:
    from codex_plugin_scanner.guard import native_policy_snapshot as snapshot_api
    from codex_plugin_scanner.guard import native_policy_snapshot_windows_support as windows_support

    ensured: list[tuple[Path, Path | None]] = []

    def ensure(path: Path, *, private_root: Path | None = None) -> None:
        ensured.append((path, private_root))

    monkeypatch.setattr(windows_support, "os", _WindowsOSProxy())
    monkeypatch.setattr(snapshot_api, "_windows_ensure_private_directory", ensure)
    state = Path(os.path.abspath(HOME)) / "native-runtime"

    assert windows_support._runtime_state_directory(HOME) == state
    assert ensured == [(state, state.parent)]


def test_runtime_failure_codes_are_raised(monkeypatch: pytest.MonkeyPatch) -> None:
    _fake_runtime(monkeypatch, {"error": "native_resident_windows_access_denied"})

    with pytest.raises(NativePolicySnapshotError, match="native_resident_windows_access_denied"):
        private_state._windows_delete_private_child(directory=STATE, name="a.json")


@pytest.mark.parametrize("answer", [None, {}, {"error": ""}])
def test_missing_runtime_answers_are_unavailable(
    monkeypatch: pytest.MonkeyPatch, answer: dict[str, object] | None
) -> None:
    _fake_runtime(monkeypatch, answer)

    with pytest.raises(NativePolicySnapshotError, match="native_windows_private_state_unavailable"):
        private_state._windows_write_private_file_atomic(directory=STATE, name="a.json", payload=b"a", maximum_bytes=8)


@pytest.mark.skipif(os.name != "nt", reason="needs the Windows private-state runtime")
def test_native_runtime_round_trips_private_state(tmp_path: Path) -> None:
    home = tmp_path / "guard"
    state = home / "native-runtime"

    assert private_state._windows_read_private_file(state, "a.json", maximum_bytes=64, private_root=home) is None
    private_state._windows_write_private_file_atomic(
        directory=state, name="a.json", payload=b"first", maximum_bytes=64, private_root=home
    )
    private_state._windows_write_private_file_atomic(
        directory=state, name="a.json", payload=b"second", maximum_bytes=64, private_root=home
    )
    assert private_state._windows_read_snapshot_bytes(state / "a.json", maximum_bytes=64) == b"second"
    assert sorted(path.name for path in state.iterdir()) == ["a.json"]
    assert private_state._windows_delete_private_child(directory=state, name="a.json", private_root=home) is True
    assert private_state._windows_delete_private_child(directory=state, name="a.json", private_root=home) is False


@pytest.mark.skipif(os.name != "nt", reason="needs the Windows private-state runtime")
def test_native_runtime_ensures_missing_private_directories(tmp_path: Path) -> None:
    nested = tmp_path / "missing" / "deeper" / "state"

    private_state._windows_ensure_private_directory(nested)
    private_state._windows_ensure_private_directory(nested, private_root=tmp_path / "missing")

    assert nested.is_dir()
