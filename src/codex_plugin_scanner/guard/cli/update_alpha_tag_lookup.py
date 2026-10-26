"""Bounded GitHub lookup confirming an alpha release's tag is still published."""

from __future__ import annotations

import http.client
import json
import time
import urllib.error
import urllib.request
from collections.abc import Callable
from contextlib import AbstractContextManager
from urllib.parse import quote

from ..mdm.network import ManagedNetworkError

GITHUB_ALPHA_TAG_REF_URL = "https://api.github.com/repos/hashgraph-online/hol-guard/git/ref/tags/alpha/v"
_ALPHA_TAG_REF_PREFIX = "refs/tags/alpha/v"

Opener = Callable[[urllib.request.Request], AbstractContextManager[object]]
BoundedReader = Callable[[object], bytes]
DeadlineReader = Callable[..., bytes]


def alpha_tag_is_live(version: str, *, opener: Opener, read_bounded: BoundedReader) -> bool | None:
    """Return True when ``alpha/v<version>`` exists, False when it is gone, None when unverifiable.

    Retracting an alpha deletes its GitHub prerelease and tag. A 404 therefore
    means the alpha was retracted; any other failure (network error, timeout,
    rate limit, malformed response) is reported as unverifiable and never raises.
    """

    request = urllib.request.Request(
        f"{GITHUB_ALPHA_TAG_REF_URL}{quote(version, safe='')}",
        headers={
            "Accept": "application/vnd.github+json",
            "User-Agent": "hol-guard-update",
        },
    )
    try:
        with opener(request) as response:
            status = getattr(response, "status", 200)
            if status != 200:
                return None
            payload = json.loads(read_bounded(response).decode("utf-8"))
    except urllib.error.HTTPError as error:
        error.close()
        return False if error.code == 404 else None
    except (
        ManagedNetworkError,
        OSError,
        TimeoutError,
        urllib.error.URLError,
        http.client.IncompleteRead,
        json.JSONDecodeError,
        UnicodeDecodeError,
    ):
        return None
    if isinstance(payload, dict) and payload.get("ref") == f"{_ALPHA_TAG_REF_PREFIX}{version}":
        return True
    return None


def fail_closed_alpha_checker(
    lookup: Callable[[str], bool | None],
) -> Callable[[str], bool]:
    """Adapt a tri-state lookup into a boolean check that stops after the first unverifiable result."""

    unverifiable = False

    def alpha_is_live(version: str) -> bool:
        nonlocal unverifiable
        if unverifiable:
            return False
        result = lookup(version)
        if result is None:
            unverifiable = True
            return False
        return result

    return alpha_is_live


def build_alpha_liveness_checker(
    *,
    opener: Opener,
    read_bounded: DeadlineReader,
    timeout: float,
) -> Callable[[str], bool]:
    """Build a fail-closed ``alpha/v<version>`` tag check for one selection walk.

    ``read_bounded`` is called as ``read_bounded(response, deadline=...)`` with a
    fresh monotonic deadline per lookup.
    """

    def lookup(version: str) -> bool | None:
        deadline = time.monotonic() + timeout
        return alpha_tag_is_live(
            version,
            opener=opener,
            read_bounded=lambda response: read_bounded(response, deadline=deadline),
        )

    return fail_closed_alpha_checker(lookup)


__all__ = [
    "GITHUB_ALPHA_TAG_REF_URL",
    "alpha_tag_is_live",
    "build_alpha_liveness_checker",
    "fail_closed_alpha_checker",
]
