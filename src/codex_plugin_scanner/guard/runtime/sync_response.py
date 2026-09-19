"""Validate decoded Cloud sync responses without exposing response contents."""

from __future__ import annotations

import json
from collections.abc import Callable


class InvalidSyncResponseError(RuntimeError):
    """A response could not be decoded as the expected JSON object."""


def read_sync_object(fetch: Callable[[], object]) -> dict[str, object]:
    try:
        payload = fetch()
    except (json.JSONDecodeError, UnicodeDecodeError) as error:
        raise InvalidSyncResponseError("Guard Cloud sync returned an invalid response payload.") from error
    if not isinstance(payload, dict):
        raise InvalidSyncResponseError("Guard Cloud sync returned an invalid response payload.")
    return payload
