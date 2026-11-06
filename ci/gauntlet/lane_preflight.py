"""One bounded exchange that proves the native inference lane answers at all.

A signed-out or misconfigured provider does not fail loudly. Every case runs,
every case reaches its round cap with an empty assistant stop, and the catalog
records the whole attempt as ``inference-error`` -- after the wheel build and a
full retry. The lane is dead for environmental reasons that say nothing about
Guard, and the evidence looks like a product failure. This module spends one
trivial completion up front instead, through the same adapter and the same
loopback Chat Completions protocol the cases use, so a dead lane is named in
seconds.
"""

from __future__ import annotations

import http.client
import json
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

from .luna_route import BACKEND, DEFAULT_EFFORT, NativeLunaRoute, parse_backend

# Short enough to cost almost nothing, long enough to need a real completion.
PROMPT = "Reply with exactly: OK"
MAX_TOKENS = 16
TIMEOUT = 120.0
# A live backend generates tokens and says so. A signed-out one stops empty: it
# reports no usage at all, or only the prompt it never answered.
ANSWER_PROOF = "completion_tokens"
USAGE_PROOF = "total_tokens"


def backend_for(native_route: str | None) -> tuple[str, str]:
    """The backend a run will use: the explicitly named one, or the default Luna pair."""
    return parse_backend(native_route) if native_route else BACKEND


def _request(settings: dict[str, Any], effort: str) -> urllib.request.Request:
    """The same selection the relay sends: this model, streaming, this effort."""
    body = json.dumps(
        {
            "model": settings["model"],
            "messages": [{"role": "user", "content": PROMPT}],
            "max_completion_tokens": MAX_TOKENS,
            "reasoning_effort": effort,
            "stream": True,
        }
    ).encode()
    return urllib.request.Request(
        settings["base_url"].rstrip("/") + "/chat/completions",
        data=body,
        headers={
            "Authorization": "Bearer " + settings["api_key"],
            "Content-Type": "application/json",
            "Accept": "text/event-stream",
        },
        method="POST",
    )


def _read_stream(response: Any, identity: str, limit: float) -> dict[str, Any]:
    """Collect the delivered text, the final usage and the completion marker.

    The socket timeout is per read, and a backend that streams keepalives while
    generating nothing resets it on every one, so the exchange needs an elapsed
    deadline of its own to stay the cheap probe it is meant to be.
    """
    deadline = time.monotonic() + limit
    delivered = 0
    usage: dict[str, Any] = {}
    completed = False
    for raw in response:
        if time.monotonic() > deadline:
            raise RuntimeError(
                f"inference lane did not finish within {limit:.0f}s ({identity}): "
                f"{delivered} delivered characters so far."
            )
        line = raw.decode("utf-8", "replace").strip()
        if not line.startswith("data:"):
            continue
        payload = line[len("data:") :].strip()
        if payload == "[DONE]":
            completed = True
            break
        try:
            chunk = json.loads(payload)
        except json.JSONDecodeError:
            continue
        if isinstance(chunk.get("usage"), dict):
            usage = chunk["usage"]
        for choice in chunk.get("choices") or ():
            delta = choice.get("delta")
            if isinstance(delta, dict):
                delivered += sum(len(value) for value in delta.values() if isinstance(value, str))
    return {"delivered": delivered, "usage": usage, "completed": completed}


def check_lane(
    sdk_root: Path,
    *,
    effort: str = DEFAULT_EFFORT,
    backend: tuple[str, str] = BACKEND,
    timeout: float = TIMEOUT,
) -> dict[str, Any]:
    """Prove this backend completes one exchange, or raise naming the dead lane.

    The adapter owns its own process group and is reaped by its context manager,
    so a failure here leaves nothing behind for the run that follows.
    """
    with NativeLunaRoute(sdk_root=sdk_root, effort=effort, backend=backend) as route:
        settings = route.provider(max_rounds=1, timeout=timeout)
        identity = settings["identity"]
        try:
            with urllib.request.urlopen(_request(settings, effort), timeout=timeout) as response:
                result = _read_stream(response, identity, timeout)
        except (urllib.error.URLError, http.client.HTTPException, OSError, TimeoutError) as exc:
            raise RuntimeError(f"inference lane is not answering ({identity}): {exc}") from exc
    if not result["completed"]:
        raise RuntimeError(
            f"inference lane stopped mid-response ({identity}): "
            f"{result['delivered']} delivered characters and no completion marker. "
            "The stream ended before the backend finished its round."
        )
    usage = result["usage"]
    generated = usage.get(ANSWER_PROOF)
    if not isinstance(generated, int) or generated <= 0:
        # Prompt tokens alone prove only that the request was read. A round that
        # generated nothing is the empty stop this check exists to catch.
        raise RuntimeError(
            f"inference lane generated no tokens ({identity}): "
            f"{result['delivered']} delivered characters and usage "
            f"{usage or 'absent'}. "
            "The provider is most likely signed out; restore its login before qualifying."
        )
    total = usage.get(USAGE_PROOF)
    return {
        "identity": identity,
        "delivered": result["delivered"],
        "total_tokens": total if isinstance(total, int) and total > 0 else generated,
    }
