from __future__ import annotations

import os

import pytest

from codex_plugin_scanner.guard import posix_processes
from codex_plugin_scanner.guard.daemon import manager


class _Runtime:
    def __init__(self) -> None:
        self.replies: dict[str, object] = {}
        self.sent: list[object] = []

    def answer(self, feature: str, command: str, request: dict[str, object], **_kwargs: object) -> object:
        assert (feature, command) == ("native-posix-processes-v1", "posix-processes")
        self.sent.append(request)
        return self.replies.get(str(request["op"]))


@pytest.fixture
def runtime(monkeypatch: pytest.MonkeyPatch) -> _Runtime:
    fake = _Runtime()
    monkeypatch.setattr("codex_plugin_scanner.guard.mdm.runtime_request.runtime_answer", fake.answer)
    return fake


@pytest.mark.skipif(os.name == "nt", reason="POSIX process queries")
def test_parent_pid_reads_only_a_positive_integer(runtime: _Runtime) -> None:
    runtime.replies["parent"] = {"parent_pid": 4242}
    assert manager._guard_daemon_parent_pid(4243) == 4242
    assert runtime.sent[-1] == {"schema": "posix-processes.v1", "op": "parent", "pid": 4243}
    for reply in ({"parent_pid": 0}, {"parent_pid": True}, {"parent_pid": "7"}, {"parent_pid": None}, None):
        runtime.replies["parent"] = reply
        assert posix_processes.posix_parent_pid(4243) is None
    sent = len(runtime.sent)
    assert posix_processes.posix_parent_pid(0) is None
    assert len(runtime.sent) == sent, "an invalid pid is never sent"


@pytest.mark.skipif(os.name == "nt", reason="POSIX process queries")
def test_command_reads_a_non_empty_command_line(runtime: _Runtime) -> None:
    runtime.replies["command"] = {"command": "hol-guard daemon --serve"}
    assert posix_processes.posix_process_command(42) == "hol-guard daemon --serve"
    for reply in ({"command": ""}, {"command": 7}, None):
        runtime.replies["command"] = reply
        assert posix_processes.posix_process_command(42) is None


@pytest.mark.skipif(os.name == "nt", reason="POSIX process queries")
def test_inventory_answers_a_listing_or_well_formed_entries(runtime: _Runtime) -> None:
    runtime.replies["inventory"] = {"listing": "1 init\n", "entries": None}
    assert posix_processes.posix_process_inventory() == "1 init\n"
    runtime.replies["inventory"] = {"listing": None, "entries": [[4242, "daemon"], [7, "x"]]}
    assert posix_processes.posix_process_inventory() == [(4242, "daemon"), (7, "x")]
    for entries in ([[True, "x"]], [[1, 2]], [[1]], ["1 x"], None):
        runtime.replies["inventory"] = {"listing": None, "entries": entries}
        assert posix_processes.posix_process_inventory() is None
    runtime.replies["inventory"] = None
    assert posix_processes.posix_process_inventory() is None


@pytest.mark.skipif(os.name == "nt", reason="POSIX process queries")
def test_elapsed_listing_is_text_or_none(runtime: _Runtime) -> None:
    runtime.replies["elapsed"] = {"listing": "42 01:02 hol-guard\n"}
    assert posix_processes.posix_process_elapsed_listing() == "42 01:02 hol-guard\n"
    runtime.replies["elapsed"] = {"listing": None}
    assert posix_processes.posix_process_elapsed_listing() is None


def test_windows_never_asks(monkeypatch: pytest.MonkeyPatch) -> None:
    def refuse(*_args, **_kwargs):
        raise AssertionError("asked the runtime")

    monkeypatch.setattr(posix_processes.os, "name", "nt")
    monkeypatch.setattr("codex_plugin_scanner.guard.mdm.runtime_request.runtime_answer", refuse)
    assert posix_processes.posix_process_inventory() is None
    assert posix_processes.posix_process_elapsed_listing() is None
    assert posix_processes.posix_parent_pid(42) is None
    assert posix_processes.posix_process_command(42) is None
