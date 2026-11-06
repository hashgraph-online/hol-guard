"""Native decisions of the public release transport.

The runtime decides what a destination, a response and a failure mean: the
host allow-list, the byte bounds, the redirect budget, the retry schedule and
the advisory selector contract. This adapter carries the question to it and
turns a rejection back into the ``ValueError`` its callers expect.
"""

from __future__ import annotations

from typing import Any

from . import lifecycle

REQUEST_INVALID = "release transport request invalid"


def decide(operation: str, *, invalid: str = REQUEST_INVALID, **fields: Any) -> dict[str, Any]:
    """Ask one question; ``invalid`` names a request that cannot be serialised."""
    try:
        reply = lifecycle.invoke("release-transport", operation=operation, **fields)
    except (TypeError, OverflowError) as error:
        raise ValueError(invalid) from error
    rejected = reply.get("rejected")
    if rejected is not None:
        raise ValueError(rejected)
    return reply
