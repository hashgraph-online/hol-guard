"""`hol-guard cloud-actions bridge`: MCP over stdio, forwarded to Guard Cloud.

Guard Cloud is replaced at the HTTP layer. The access comes from a stand-in
exchange so these tests can count exchanges and check the access never reaches
the AI tool's side of the bridge.
"""

from __future__ import annotations

import io
import json
import threading
import time
import urllib.error
import urllib.request
from collections.abc import Callable
from email.message import Message
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.cli.cloud_actions_access import CloudActionsAccess, CloudActionsAccessError
from codex_plugin_scanner.guard.cli.cloud_actions_bridge import CloudActionsBridge, run_cloud_actions_bridge

URL = "https://hol.org/api/guard/gateway/mcp"
WS = "6f1c2a52-6a4e-4b8e-9f0e-3f3d6c1b2a10"
INITIALIZE = {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}
INITIALIZED = {"jsonrpc": "2.0", "method": "notifications/initialized"}
LIST_TOOLS = {"jsonrpc": "2.0", "id": 2, "method": "tools/list"}


class _Response(io.BytesIO):
    def __init__(self, body: bytes, headers: dict[str, str]) -> None:
        super().__init__(body)
        self.headers = Message()
        for name, value in headers.items():
            self.headers[name] = value


def _json(message: object, **headers: str) -> _Response:
    return _Response(json.dumps(message).encode(), {"Content-Type": "application/json", **headers})


def _events(*messages: object) -> _Response:
    body = "".join(f"event: message\ndata: {json.dumps(message)}\n\n" for message in messages)
    return _Response(body.encode(), {"Content-Type": "text/event-stream"})


def _http_error(status: int) -> urllib.error.HTTPError:
    return urllib.error.HTTPError(URL, status, "error", Message(), io.BytesIO(b""))


class Cloud:
    def __init__(self, answer: Callable[[urllib.request.Request], object]) -> None:
        self.answer = answer
        self.requests: list[urllib.request.Request] = []
        self.lock = threading.Lock()

    def open(self, request: urllib.request.Request, timeout: float) -> _Response:
        del timeout
        with self.lock:
            self.requests.append(request)
        result = self.answer(request)
        if isinstance(result, BaseException):
            raise result
        assert isinstance(result, _Response)
        return result

    def posts(self) -> list[dict[str, object]]:
        return [json.loads(item.data) for item in self.requests if isinstance(item.data, bytes)]


class Exchange:
    def __init__(self, *, lifetime: float = 300) -> None:
        self.count = 0
        self.lifetime = lifetime

    def __call__(self) -> CloudActionsAccess:
        self.count += 1
        return CloudActionsAccess(
            access_token=f"access-{self.count}",
            expires_at=time.time() + self.lifetime,
            workspace_id=WS,
            scopes=("gateway:invoke",),
        )


def _mcp_server(request: urllib.request.Request) -> object:
    if request.get_method() == "DELETE":
        return _Response(b"", {})
    message = json.loads(request.data) if isinstance(request.data, bytes) else {}
    if message.get("method") == "initialize":
        result = {"protocolVersion": "2025-06-18", "capabilities": {}}
        return _json({"jsonrpc": "2.0", "id": message["id"], "result": result}, **{"Mcp-Session-Id": "session-1"})
    if "id" not in message:
        return _Response(b"", {})
    return _events(
        {"jsonrpc": "2.0", "method": "notifications/progress", "params": {"progress": 1}},
        {"jsonrpc": "2.0", "id": message["id"], "result": {"tools": []}},
    )


def _serve(cloud: Cloud, exchange: Exchange, *messages: object) -> list[dict[str, object]]:
    output = io.StringIO()
    bridge = CloudActionsBridge(url=URL, exchange=exchange, output=output, opener=cloud.open)
    lines = [message if isinstance(message, str) else json.dumps(message) for message in messages]
    bridge.serve(line + "\n" for line in lines)
    return [json.loads(line) for line in output.getvalue().splitlines()]


def test_a_session_runs_through_the_bridge_and_ends_at_eof() -> None:
    cloud, exchange = Cloud(_mcp_server), Exchange()

    answers = _serve(cloud, exchange, INITIALIZE, INITIALIZED, LIST_TOOLS)

    assert answers[0] == {"jsonrpc": "2.0", "id": 1, "result": {"protocolVersion": "2025-06-18", "capabilities": {}}}
    assert {"jsonrpc": "2.0", "id": 2, "result": {"tools": []}} in answers
    assert len(answers) == 3
    assert cloud.posts()[0] == INITIALIZE
    assert sorted(map(json.dumps, cloud.posts()[1:])) == sorted(map(json.dumps, [INITIALIZED, LIST_TOOLS]))
    first, *later = cloud.requests
    assert first.get_header("Mcp-session-id") is None
    for request in later:
        assert request.get_header("Mcp-session-id") == "session-1"
        assert request.get_header("Mcp-protocol-version") == "2025-06-18"
    assert cloud.requests[-1].get_method() == "DELETE"
    assert {request.get_header("Authorization") for request in cloud.requests} == {"Bearer access-1"}
    assert exchange.count == 1


def test_the_access_never_reaches_the_ai_tool() -> None:
    cloud, exchange = Cloud(_mcp_server), Exchange()

    answers = _serve(cloud, exchange, INITIALIZE, LIST_TOOLS)

    assert "access-1" not in json.dumps(answers)


def test_refused_access_is_exchanged_once_more() -> None:
    refused = {"done": False}

    def server(request: urllib.request.Request) -> object:
        if not refused["done"]:
            refused["done"] = True
            return _http_error(401)
        return _mcp_server(request)

    cloud, exchange = Cloud(server), Exchange()

    answers = _serve(cloud, exchange, INITIALIZE)

    assert answers[0]["id"] == 1 and "result" in answers[0]
    assert [request.get_header("Authorization") for request in cloud.requests[:2]] == [
        "Bearer access-1",
        "Bearer access-2",
    ]


def test_access_close_to_expiry_is_replaced_before_use() -> None:
    cloud, exchange = Cloud(_mcp_server), Exchange(lifetime=10)

    _ = _serve(cloud, exchange, INITIALIZE)

    assert exchange.count >= 2


def test_a_cloud_failure_answers_the_request_and_never_the_notification(capsys: pytest.CaptureFixture[str]) -> None:
    def server(request: urllib.request.Request) -> object:
        return _http_error(503) if request.get_method() == "POST" else _Response(b"", {})

    answers = _serve(Cloud(server), Exchange(), LIST_TOOLS, INITIALIZED)

    assert answers == [
        {"jsonrpc": "2.0", "id": 2, "error": {"code": -32000, "message": "Guard Cloud answered HTTP 503."}}
    ]
    assert "Guard Cloud answered HTTP 503." in capsys.readouterr().err


def test_a_refused_exchange_answers_with_its_message() -> None:
    def refuse() -> CloudActionsAccess:
        raise CloudActionsAccessError("cloud_actions_off", "Cloud actions are off for this computer.")

    output = io.StringIO()
    bridge = CloudActionsBridge(url=URL, exchange=refuse, output=output, opener=Cloud(_mcp_server).open)
    bridge.serve([json.dumps(LIST_TOOLS) + "\n"])

    assert json.loads(output.getvalue()) == {
        "jsonrpc": "2.0",
        "id": 2,
        "error": {"code": -32000, "message": "Cloud actions are off for this computer."},
    }


def test_a_line_that_is_not_json_gets_a_parse_error() -> None:
    cloud = Cloud(_mcp_server)

    answers = _serve(cloud, Exchange(), "{not json")

    assert answers == [{"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "Parse error"}}]
    assert cloud.requests == []


def test_an_unpaired_computer_does_not_start_the_bridge(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    output = io.StringIO()

    code = run_cloud_actions_bridge(
        tmp_path / "guard-home", ai_tool="codex", input_stream=io.StringIO(""), output_stream=output
    )

    assert code == 4
    assert output.getvalue() == ""
    assert "hol-guard connect" in capsys.readouterr().err
    assert not (tmp_path / "guard-home").exists()


def test_the_settings_entry_command_reaches_the_bridge(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    from codex_plugin_scanner import cli

    try:
        code = cli.main(["cloud-actions", "bridge", "codex", "--guard-home", str(tmp_path / "guard-home")])
    except SystemExit as exit_:
        code = int(exit_.code or 0)

    assert code == 4
    assert "hol-guard connect" in capsys.readouterr().err
