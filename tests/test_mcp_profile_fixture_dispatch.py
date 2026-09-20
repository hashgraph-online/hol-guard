"""Exercise live fixture selection through the actual profiler send boundary."""

from __future__ import annotations

import importlib
import io
import json
from pathlib import Path

import pytest


@pytest.mark.parametrize(
    ("module_name", "variant"),
    [
        ("profile_guard_mcp_session", "owned"),
        ("profile_guard_mcp_streaming_session", "streaming"),
    ],
)
@pytest.mark.parametrize("kind", ["ascii", "unicode"])
def test_fixture_replacement_reaches_each_serialized_request(monkeypatch, module_name, variant, kind):
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[1] / "scripts"))
    wrapper = importlib.import_module(module_name)
    shared = importlib.import_module("profile_guard_mcp_case")
    markers = importlib.import_module("compare_guard_mcp_native_markers")
    framing = importlib.import_module("codex_plugin_scanner.guard.proxy.framing")
    stdio = importlib.import_module("codex_plugin_scanner.guard.proxy.stdio")
    writes = []
    responses = []
    launches = []
    retired = []

    class ObservedSecondRequestError(Exception):
        pass

    stopped = ObservedSecondRequestError("controlled stop after the second serialized request")

    class Input(io.StringIO):
        def write(self, encoded):
            message = json.loads(encoded)
            writes.append(message)
            method = message["method"]
            if method == "initialize":
                result = {}
            elif method == "tools/list":
                result = {"tools": [{}]}
            else:
                assert method == "tools/call"
                if message["id"] == "call-1":
                    raise stopped
                assert type(message["id"]) is int and message["id"] == 0
                payload = message["params"]["arguments"]["text"]
                result = {
                    "content": [{"type": "text", "text": payload}],
                    "structuredContent": {"text": payload, "generation": 0},
                    "_meta": {"synthetic": True},
                }
                monkeypatch.setattr(
                    wrapper,
                    "fixture_arguments",
                    lambda size, payload_kind, index: markers.marker_arguments(size, payload_kind, index, "late"),
                )
            responses.append(json.dumps({"jsonrpc": "2.0", "id": message["id"], "result": result}))
            return len(encoded)

    class Process:
        stdin = Input()
        stdout = io.StringIO()

        def poll(self):
            return 0

    process = Process()

    def popen(argv, **kwargs):
        config = json.loads(Path(argv[-1]).read_text())
        launches.append((argv, kwargs, config))
        return process

    def read(stream, **_kwargs):
        assert stream is process.stdout
        return responses.pop(0)

    monkeypatch.setattr(
        wrapper,
        "fixture_arguments",
        lambda size, payload_kind, index: markers.marker_arguments(size, payload_kind, index, "early"),
    )
    monkeypatch.setattr(shared.subprocess, "Popen", popen)
    monkeypatch.setattr(shared, "tree_sample", lambda _process: {})
    monkeypatch.setattr(stdio, "_readline_with_timeout", read)
    monkeypatch.setattr(framing, "retire_reader", retired.append)

    try:
        with pytest.raises(shared.BenchmarkCaseError) as caught:
            wrapper.run_case(catalog_size=1, payload_bytes=997, payload_kind=kind, samples=1)
        assert caught.value.__cause__ is stopped
        evidence = caught.value.evidence
        assert evidence["stage"] == "tool_call"
        assert evidence["attempted_tool_requests"] == 2
        assert evidence["observed_tool_responses"] == evidence["accepted"] == 1
        assert evidence["errors"] == 1
        requests = [message for message in writes if message["method"] == "tools/call"]
        assert [message["id"] for message in requests] == [0, "call-1"]
        assert type(requests[0]["id"]) is int and type(requests[1]["id"]) is str
        assert [message["params"]["arguments"] for message in requests] == [
            markers.marker_arguments(997, kind, 0, "early"),
            markers.marker_arguments(997, kind, 1, "late"),
        ]
        assert len(launches) == 1
        argv, _kwargs, config = launches[0]
        assert Path(argv[1]).name == "profile_guard_mcp_worker.py"
        assert argv[2:5] == ["--variant", variant, "--config"]
        assert config[f"{variant}_preparation_pilot"] is False
        assert config["payload_kind"] == kind
        assert retired == [process.stdout]
        assert process.stdout.closed
        assert responses == []
    finally:
        process.stdin.close()
