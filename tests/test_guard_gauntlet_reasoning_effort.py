"""Check that a configured reasoning effort is pinned by the relay, not chosen by the agent."""

import json
import threading
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from ci.gauntlet.agent_configuration import write_agent_configuration
from ci.gauntlet.provider import InferenceRelay


def _relay_round(reasoning_effort, agent_payload):
    """Send one agent request through the relay and return the upstream body and evidence."""
    forwarded = []

    class Upstream(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *_args):
            pass

        def do_POST(self):
            forwarded.append(json.loads(self.rfile.read(int(self.headers["Content-Length"]))))
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.end_headers()
            self.wfile.write(b'data: {"model":"unit-transport-only","choices":[]}\n\ndata: [DONE]\n\n')
            self.wfile.flush()
            self.close_connection = True

    server = ThreadingHTTPServer(("127.0.0.1", 0), Upstream)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        with InferenceRelay(
            base_url=f"http://127.0.0.1:{server.server_port}/v1",
            model="unit-transport-only",
            api_key="test-only-key",
            canary="synthetic-test-canary",
            identity="unit-transport-only",
            allow_loopback=True,
            reasoning_effort=reasoning_effort,
        ) as relay:
            request = urllib.request.Request(
                relay.base_url + "/chat/completions",
                data=json.dumps(agent_payload).encode(),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(request, timeout=5) as response:
                response.read()
            return forwarded[0], relay.evidence()
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_configured_effort_overrides_the_agent_request():
    upstream, evidence = _relay_round("high", {"messages": [], "reasoning_effort": "low", "model": "other"})
    assert upstream["reasoning_effort"] == "high"
    assert upstream["model"] == "unit-transport-only"
    assert evidence["requested_reasoning_effort"] == "high"
    assert evidence["live_rounds"][0]["status"] == "completed"


def test_unset_effort_leaves_request_and_evidence_unchanged():
    upstream, evidence = _relay_round(None, {"messages": []})
    assert "reasoning_effort" not in upstream
    assert "requested_reasoning_effort" not in evidence


def test_unknown_effort_is_rejected():
    with pytest.raises(ValueError, match="unsupported reasoning effort"):
        InferenceRelay(
            base_url="https://provider.invalid/v1",
            model="unit-transport-only",
            api_key="test-only-key",
            canary="synthetic-test-canary",
            identity="unit-transport-only",
            reasoning_effort="maximum",
        )


@pytest.mark.parametrize(("effort", "max_tokens"), [(None, 8192), ("high", 32768)])
def test_agent_output_budget_leaves_room_for_reasoning(tmp_path: Path, effort, max_tokens):
    relay = InferenceRelay(
        base_url="https://provider.invalid/v1",
        model="unit-transport-only",
        api_key="test-only-key",
        canary="synthetic-test-canary",
        identity="unit-transport-only",
        reasoning_effort=effort,
    )
    write_agent_configuration(tmp_path / "agent", relay)
    configuration = json.loads((tmp_path / "agent" / "models.yml").read_text())
    assert configuration["providers"]["gauntlet-live"]["models"][0]["maxTokens"] == max_tokens


def test_invalid_environment_effort_fails_before_any_case(tmp_path: Path, monkeypatch, capsys):
    from ci.gauntlet import __main__ as cli

    monkeypatch.setenv("GUARD_GAUNTLET_REASONING_EFFORT", "max")
    monkeypatch.setenv("GUARD_GAUNTLET_API_KEY", "test-only-key")
    monkeypatch.setattr(
        "sys.argv",
        [
            "gauntlet",
            "run",
            "--expected-source-sha",
            "0" * 40,
            "--output",
            str(tmp_path / "evidence"),
            "--provider-url",
            "https://provider.invalid/v1",
            "--model",
            "unit-transport-only",
            "--provider-identity",
            "unit-transport-only",
        ],
    )
    assert cli.main() != 0
    assert "unsupported reasoning effort" in capsys.readouterr().err
    assert not (tmp_path / "evidence").exists()
