"""HOL Registry trust scores for new or changed skills, MCP servers and plugins.

Guard asks the fixed Guard Cloud origin for an artifact's public registry trust
score and sends it to the resident, which reviews the artifact through the
``low_trust_artifact`` risk action when the score is below the threshold it
holds. Only the artifact's kind and public name go on the wire: no credential,
cookie, path or device identifier.

A missing score never triggers a review. An unknown artifact, an unreachable
origin, a malformed answer, an ambiguous match, a kind the origin cannot score
yet or an unavailable native runtime all resolve to ``None``, so the lookup can
only add a review, never remove one. Lookups run only for artifacts the policy
engine is about to decide fresh (first seen or changed), and answers are cached
on disk to keep repeat scans off the network.

Python sends the search request; the native runtime's one-shot
``registry-trust`` command keeps the cache and decides what Guard Cloud's reply
means.

Rollback: ``HOL_GUARD_REGISTRY_TRUST=off`` (or ``low_trust_artifact = "allow"``)
skips the lookup entirely.
"""

from __future__ import annotations

import base64
import os
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Mapping
from pathlib import Path
from typing import Protocol, cast

from ..no_redirect import RejectRedirects
from ..version import __version__
from .mdm.network_transport import managed_opener

REGISTRY_TRUST_ENV = "HOL_GUARD_REGISTRY_TRUST"

TRUST_ORIGIN = "https://hol.org"
PLUGIN_SEARCH_PATH = "/api/guard/plugins/search"
TRUST_USER_AGENT = f"hol-guard/{__version__}"
TRUST_DEADLINE_SECONDS = 2.0
MAX_TRUST_RESPONSE_BYTES = 65_536
_SEARCH_LIMIT = 20

CACHE_FILE_NAME = "registry-trust-cache.json"
_FEATURE = "native-registry-trust-v1"
_COMMAND = "registry-trust"
_DISABLED_VALUES = frozenset({"0", "off", "false", "disabled"})


class _ReadableResponse(Protocol):
    @property
    def status(self) -> int: ...

    def read(self, amount: int, /) -> bytes: ...

    def close(self) -> None: ...


class TrustOpener(Protocol):
    def open(self, request: urllib.request.Request, timeout: float) -> _ReadableResponse: ...


def registry_trust_enabled(environ: Mapping[str, str] | None = None) -> bool:
    source = environ if environ is not None else os.environ
    return source.get(REGISTRY_TRUST_ENV, "").strip().lower() not in _DISABLED_VALUES


def registry_trust_score(
    guard_home: Path | None,
    *,
    artifact_type: str | None,
    name: str | None,
    opener: TrustOpener | None = None,
    now: float | None = None,
) -> int | None:
    """Return the artifact's registry trust score (0-100), or ``None`` when unknown."""

    if not registry_trust_enabled():
        return None
    request: dict[str, object] = {
        "home": str(guard_home.absolute()) if guard_home is not None else None,
        "artifact_type": artifact_type,
        "name": name,
        "now": time.time() if now is None else now,
    }
    answer = _ask({"op": "lookup", **request})
    fetch = answer.get("fetch") if answer is not None else None
    if not isinstance(fetch, str):
        return _score(answer)
    status, body = _fetch_plugin_reply(fetch, opener=opener)
    reply = {"status": status, "body": base64.b64encode(body).decode("ascii")}
    return _score(_ask({"op": "record", **request, **reply}))


def _ask(request: dict[str, object]) -> dict[str, object] | None:
    from .mdm.runtime_request import runtime_answer

    return runtime_answer(_FEATURE, _COMMAND, request, output_limit=4096, timeout_seconds=5.0)


def _score(answer: Mapping[str, object] | None) -> int | None:
    score = answer.get("score") if answer is not None else None
    return score if isinstance(score, int) and not isinstance(score, bool) else None


def _fetch_plugin_reply(name: str, *, opener: TrustOpener | None) -> tuple[int | None, bytes]:
    """Guard Cloud's status and search reply, read one byte past the limit.

    The status is ``None`` when Guard Cloud could not be reached.
    """

    query = urllib.parse.urlencode({"q": name, "limit": _SEARCH_LIMIT})
    request = urllib.request.Request(
        f"{TRUST_ORIGIN}{PLUGIN_SEARCH_PATH}?{query}",
        method="GET",
        headers={
            "Accept": "application/json",
            "Accept-Encoding": "identity",
            "Cache-Control": "no-store",
            "User-Agent": TRUST_USER_AGENT,
        },
    )
    handler = opener if opener is not None else cast(TrustOpener, managed_opener(redirect_handler=RejectRedirects()))
    try:
        response = handler.open(request, timeout=TRUST_DEADLINE_SECONDS)
    except (urllib.error.URLError, OSError, ValueError):
        return None, b""
    try:
        status = int(response.status)
        return status, _read_reply(response) if status == 200 else b""
    except (OSError, ValueError):
        return None, b""
    finally:
        response.close()


def _read_reply(response: _ReadableResponse) -> bytes:
    chunks: list[bytes] = []
    size = 0
    while size <= MAX_TRUST_RESPONSE_BYTES:
        chunk = response.read(min(8192, MAX_TRUST_RESPONSE_BYTES + 1 - size))
        if not chunk:
            break
        chunks.append(chunk)
        size += len(chunk)
    return b"".join(chunks)


__all__ = [
    "REGISTRY_TRUST_ENV",
    "registry_trust_enabled",
    "registry_trust_score",
]
