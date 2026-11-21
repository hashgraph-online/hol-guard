"""The Python side of the Codex app-server reachability proof.

Whether a target is safe and accepting connections is the native runtime's call,
tested in `rust/crates/guard-runtime/src/codex_app_server_target_op_tests.rs`.
"""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.codex_app_server_target import codex_app_server_target_reachable


class NativeStub:
    def __init__(self, monkeypatch, answer):
        self.answer = answer
        self.calls: list[dict[str, object]] = []
        monkeypatch.setattr("codex_plugin_scanner.guard.mdm.runtime_request.runtime_answer", self)

    def __call__(self, feature, command, request, *, output_limit, timeout_seconds=None, **_):
        assert feature == "native-codex-app-server-target-v1" and command == "codex-app-server-target"
        assert output_limit > 0 and timeout_seconds and timeout_seconds > 0
        self.calls.append(json.loads(request))
        return self.answer


def test_the_recorded_target_and_this_process_roots_are_sent(monkeypatch):
    stub = NativeStub(monkeypatch, {"reachable": True})
    metadata = {"codex_thread_id": "thread-1", "codex_home": "/synthetic/home", "unrelated": "dropped"}

    assert codex_app_server_target_reachable(metadata) is True

    [request] = stub.calls
    assert request["metadata"] == {"codex_thread_id": "thread-1", "codex_home": "/synthetic/home"}
    assert request["home_dir"] == str(Path.home())
    assert request["temp_dir"] == tempfile.gettempdir()
    assert request["cwd"] == os.getcwd()


@pytest.mark.parametrize("answer", [{"reachable": False}, {"reachable": "yes"}, {}, None])
def test_only_a_native_true_proves_the_target(monkeypatch, answer):
    NativeStub(monkeypatch, answer)

    assert codex_app_server_target_reachable({"codex_thread_id": "thread-1"}) is False


def test_metadata_that_cannot_be_encoded_proves_nothing(monkeypatch):
    stub = NativeStub(monkeypatch, {"reachable": True})

    assert codex_app_server_target_reachable({"codex_thread_id": float("nan"), "thread_id": object()}) is False
    assert stub.calls == []
