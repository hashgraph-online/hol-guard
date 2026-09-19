"""Pin native body-reader edge cases to the bound current Python HTTPResponse contract."""

from __future__ import annotations

import http.client
import io
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard.adapters import claude_daemon_hook_transport as transport
from codex_plugin_scanner.guard.adapters import codex_daemon_hook_auth as auth
from tests.test_claude_native_launcher_transport import owned_interpreter  # noqa: F401


@pytest.mark.parametrize("reader", ["hook", "challenge"])
@pytest.mark.parametrize("case", ["complete_late", "zero_late", "early_eof_late", "complete_in_time"])
def test_current_python_final_eof_budget_contract(monkeypatch, reader, case):
    clock = [0.995 if case == "zero_late" else 0.0]
    monkeypatch.setattr(transport, "time", SimpleNamespace(monotonic=lambda: clock[0]))
    monkeypatch.setattr(auth, "time", SimpleNamespace(monotonic=lambda: clock[0]))
    body = b"" if case == "zero_late" else b"{}"
    length = len(body) + (20 if case == "early_eof_late" else 0)
    wire = f"HTTP/1.1 200 OK\r\nContent-Length: {length}\r\n\r\n".encode() + body
    response = http.client.HTTPResponse(SimpleNamespace(makefile=lambda *_a, **_kw: io.BytesIO(wire)))
    response.begin()
    real_read = response.read1
    reads = []

    def read_and_advance_budget(size):
        chunk = real_read(size)
        reads.append(len(chunk))
        clock[0] = 0.995 if case == "complete_late" or not chunk else 0.05
        return chunk

    monkeypatch.setattr(response, "read1", read_and_advance_budget)
    connection = SimpleNamespace(sock=None)

    def invoke():
        if reader == "hook":
            return transport._read_hook_response(response, connection=connection, deadline=1.0)
        return auth._http_json_response(
            response,
            connection=connection,
            deadline=1.0,
            label="daemon identity challenge",
            authenticated=False,
        )

    if case in {"complete_late", "zero_late"}:
        with pytest.raises(TimeoutError, match="deadline"):
            invoke()
        assert reads == ([2] if case == "complete_late" else [])
    else:
        assert invoke() == ("{}" if reader == "hook" else {})
        assert reads == [2, 0]
