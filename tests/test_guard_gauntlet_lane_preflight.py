"""Lane preflight tests: the dead-lane signature is rejected before a run starts. No live inference."""

from __future__ import annotations

import io
import json
import time
from pathlib import Path
from typing import Any

import pytest

from ci.gauntlet import lane_preflight


def sse(chunks: list[dict[str, Any]], done: bool = True) -> io.BytesIO:
    body = "".join(f"data: {json.dumps(chunk)}\n\n" for chunk in chunks)
    if done:
        body += "data: [DONE]\n\n"
    return io.BytesIO(body.encode())


def delta(text: str) -> dict[str, Any]:
    return {"choices": [{"index": 0, "delta": {"content": text}, "finish_reason": None}]}


def usage(total: int, completion: int = 2) -> dict[str, Any]:
    return {
        "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}],
        "usage": {"prompt_tokens": 9, "completion_tokens": completion, "total_tokens": total},
    }


class Route:
    """Stand in for the adapter: no process, no port, just the relay settings."""

    def __init__(self, response: Any) -> None:
        self.response = response
        self.stopped = False

    def __enter__(self) -> Route:
        return self

    def __exit__(self, *exc: object) -> None:
        self.stopped = True

    def provider(self, *, max_rounds: int, timeout: float) -> dict[str, Any]:
        return {
            "base_url": "http://127.0.0.1:1/v1",
            "model": "native-luna",
            "api_key": "token",
            "identity": "openai-codex/gpt-6-luna/medium via test",
        }


def install(monkeypatch: pytest.MonkeyPatch, response: Any) -> Route:
    route = Route(response)
    monkeypatch.setattr(lane_preflight, "NativeLunaRoute", lambda **kwargs: route)

    class Opened:
        def __enter__(self) -> Any:
            if isinstance(response, Exception):
                raise response
            return response

        def __exit__(self, *exc: object) -> None:
            return None

    monkeypatch.setattr(lane_preflight.urllib.request, "urlopen", lambda *a, **k: Opened())
    return route


def test_reported_token_usage_proves_the_lane_answered(monkeypatch: pytest.MonkeyPatch) -> None:
    route = install(monkeypatch, sse([delta("OK"), usage(11)]))
    result = lane_preflight.check_lane(Path("/sdk"))
    assert result["total_tokens"] == 11
    assert result["delivered"] == 2
    assert route.stopped


def test_empty_stop_without_usage_is_the_signed_out_signature(monkeypatch: pytest.MonkeyPatch) -> None:
    """A signed-out provider streams a well-formed stop that reports no tokens."""
    route = install(monkeypatch, sse([{"choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}]}]))
    with pytest.raises(RuntimeError, match="generated no tokens"):
        lane_preflight.check_lane(Path("/sdk"))
    assert route.stopped


def test_prompt_tokens_alone_are_not_a_completed_round(monkeypatch: pytest.MonkeyPatch) -> None:
    """A stop that reports the prompt it never answered proves only that the request was read."""
    install(monkeypatch, sse([usage(9, completion=0)]))
    with pytest.raises(RuntimeError, match="generated no tokens"):
        lane_preflight.check_lane(Path("/sdk"))


def test_a_stream_cut_off_before_its_marker_is_not_a_completed_round(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Usage at a bare end of file is a truncated response, not a finished round."""
    install(monkeypatch, sse([delta("OK"), usage(11)], done=False))
    with pytest.raises(RuntimeError, match="stopped mid-response"):
        lane_preflight.check_lane(Path("/sdk"))


def test_keepalives_do_not_let_a_stalled_lane_outlive_the_probe(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Each keepalive resets the socket timeout, so only an elapsed deadline bounds this."""

    def stalled() -> Any:
        while True:
            time.sleep(0.01)
            yield b": keepalive\n\n"

    install(monkeypatch, stalled())
    with pytest.raises(RuntimeError, match="did not finish within"):
        lane_preflight.check_lane(Path("/sdk"), timeout=0.05)


def test_a_transport_failure_names_the_lane_rather_than_the_product(monkeypatch: pytest.MonkeyPatch) -> None:
    install(monkeypatch, OSError("connection refused"))
    with pytest.raises(RuntimeError, match="not answering"):
        lane_preflight.check_lane(Path("/sdk"))


def test_malformed_chunks_do_not_count_as_a_round(monkeypatch: pytest.MonkeyPatch) -> None:
    stream = io.BytesIO(b"data: not-json\n\n: keepalive\n\ndata: [DONE]\n\n")
    install(monkeypatch, stream)
    with pytest.raises(RuntimeError, match="generated no tokens"):
        lane_preflight.check_lane(Path("/sdk"))


def test_the_request_matches_the_selection_the_adapter_requires(monkeypatch: pytest.MonkeyPatch) -> None:
    """The adapter rejects any body that is not this model, streaming, at this effort."""
    settings = {"base_url": "http://127.0.0.1:1/v1", "model": "native-luna", "api_key": "token"}
    request = lane_preflight._request(settings, "medium")
    body = json.loads(request.data)
    assert body["model"] == "native-luna"
    assert body["stream"] is True
    assert body["reasoning_effort"] == "medium"
    assert request.full_url.endswith("/v1/chat/completions")


def test_backend_defaults_to_luna_and_honours_an_explicit_route() -> None:
    assert lane_preflight.backend_for(None) == lane_preflight.BACKEND
    assert lane_preflight.backend_for("devin/swe-2") == ("devin", "swe-2")
    with pytest.raises(ValueError):
        lane_preflight.backend_for("openai-codex/not-a-model")
