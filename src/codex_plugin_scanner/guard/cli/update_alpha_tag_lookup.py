"""Bounded GitHub lookup confirming an alpha release's tag is still published.

The lookup uses GitHub's unauthenticated REST API, which allows 60 requests
an hour per address and is shared with the HOL Guard app's own updater.
Every update-status check walks up to three alphas, so without a memory of
earlier answers a dashboard that refreshes its update status a few times can
spend the whole budget. Once it is spent, every alpha turns unverifiable and
the offered update disappears between one status check and the next.

Answers are therefore remembered for the life of the process: a confirmed
answer is reused for a short while without asking again, a rate-limit reply
pauses all lookups until GitHub's reset time, and while GitHub cannot answer
the last confirmed answer stands in for a bounded time.
"""

from __future__ import annotations

import http.client
import json
import threading
import time
import urllib.error
import urllib.request
from collections.abc import Callable
from contextlib import AbstractContextManager
from email.utils import parsedate_to_datetime
from urllib.parse import quote

from ..mdm.network import ManagedNetworkError

GITHUB_ALPHA_TAG_REF_URL = "https://api.github.com/repos/hashgraph-online/hol-guard/git/ref/tags/alpha/v"
_ALPHA_TAG_REF_PREFIX = "refs/tags/alpha/v"

# A confirmed answer is reused without asking GitHub again for this long.
CONFIRMED_ANSWER_TTL_SECONDS = 10 * 60
# While GitHub cannot answer, a confirmed answer this recent still stands.
STALE_ANSWER_LIMIT_SECONDS = 24 * 60 * 60
# Pause after a rate-limit reply that names no reset time, and the longest pause.
DEFAULT_RATE_LIMIT_PAUSE_SECONDS = 5 * 60
MAX_RATE_LIMIT_PAUSE_SECONDS = 60 * 60
_MAX_REMEMBERED_VERSIONS = 64

Opener = Callable[[urllib.request.Request], AbstractContextManager[object]]
BoundedReader = Callable[[object], bytes]
DeadlineReader = Callable[..., bytes]
Lookup = Callable[[str], "tuple[bool | None, float | None]"]


def _rate_limit_pause(error: urllib.error.HTTPError, *, wall_clock: Callable[[], float]) -> float | None:
    """Seconds to wait before asking GitHub again, or None when the error is not a rate limit."""

    headers = error.headers
    retry_after = headers.get("Retry-After") if headers is not None else None
    remaining = headers.get("X-RateLimit-Remaining") if headers is not None else None
    reset = headers.get("X-RateLimit-Reset") if headers is not None else None
    if error.code != 429 and retry_after is None and remaining != "0":
        return None
    pause: float | None = None
    if retry_after is not None:
        try:
            pause = float(retry_after)
        except ValueError:
            try:
                pause = parsedate_to_datetime(retry_after).timestamp() - wall_clock()
            except (TypeError, ValueError, IndexError, OverflowError):
                pause = None
    if pause is None and reset is not None:
        try:
            pause = float(reset) - wall_clock()
        except ValueError:
            pause = None
    if pause is None:
        pause = DEFAULT_RATE_LIMIT_PAUSE_SECONDS
    return min(max(pause, 1.0), MAX_RATE_LIMIT_PAUSE_SECONDS)


def lookup_alpha_tag(
    version: str,
    *,
    opener: Opener,
    read_bounded: BoundedReader,
    wall_clock: Callable[[], float] = time.time,
) -> tuple[bool | None, float | None]:
    """Ask GitHub whether ``alpha/v<version>`` exists.

    Returns the answer (True live, False retracted, None unverifiable) and,
    for a rate-limit reply, how many seconds to wait before asking again.
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
                return None, None
            payload = json.loads(read_bounded(response).decode("utf-8"))
    except urllib.error.HTTPError as error:
        try:
            if error.code == 404:
                return False, None
            return None, _rate_limit_pause(error, wall_clock=wall_clock)
        finally:
            error.close()
    except (
        ManagedNetworkError,
        OSError,
        TimeoutError,
        urllib.error.URLError,
        http.client.IncompleteRead,
        json.JSONDecodeError,
        UnicodeDecodeError,
    ):
        return None, None
    if isinstance(payload, dict) and payload.get("ref") == f"{_ALPHA_TAG_REF_PREFIX}{version}":
        return True, None
    return None, None


def alpha_tag_is_live(version: str, *, opener: Opener, read_bounded: BoundedReader) -> bool | None:
    """Return True when ``alpha/v<version>`` exists, False when it is gone, None when unverifiable.

    Retracting an alpha deletes its GitHub prerelease and tag. A 404 therefore
    means the alpha was retracted; any other failure (network error, timeout,
    rate limit, malformed response) is reported as unverifiable and never raises.
    """

    answer, _pause = lookup_alpha_tag(version, opener=opener, read_bounded=read_bounded)
    return answer


class AlphaTagAnswers:
    """Process-wide memory of GitHub's alpha tag answers and its rate-limit pause."""

    def __init__(self, clock: Callable[[], float] = time.monotonic) -> None:
        self._clock = clock
        self._lock = threading.Lock()
        self._answers: dict[str, tuple[bool, float]] = {}
        self._paused_until = 0.0
        self._in_flight: dict[str, threading.Lock] = {}

    def clear(self) -> None:
        with self._lock:
            self._answers.clear()
            self._in_flight.clear()
            self._paused_until = 0.0

    def _remembered(self, version: str, now: float, max_age: float) -> bool | None:
        entry = self._answers.get(version)
        if entry is None or now - entry[1] >= max_age:
            return None
        return entry[0]

    def _settled(self, version: str) -> tuple[bool, bool | None]:
        """Return (settled, answer): settled when no lookup should be sent now."""

        now = self._clock()
        with self._lock:
            fresh = self._remembered(version, now, CONFIRMED_ANSWER_TTL_SECONDS)
            if fresh is not None:
                return True, fresh
            if now < self._paused_until:
                return True, self._remembered(version, now, STALE_ANSWER_LIMIT_SECONDS)
            return False, None

    def _gate(self, version: str) -> threading.Lock:
        with self._lock:
            gate = self._in_flight.get(version)
            if gate is None:
                if len(self._in_flight) >= _MAX_REMEMBERED_VERSIONS:
                    for idle in [name for name, lock in self._in_flight.items() if not lock.locked()]:
                        del self._in_flight[idle]
                gate = self._in_flight[version] = threading.Lock()
            return gate

    def answer(self, version: str, lookup: Lookup) -> bool | None:
        settled, remembered = self._settled(version)
        if settled:
            return remembered
        # One lookup per version at a time: callers that arrive while it is in
        # flight wait for it and reuse its answer or rate-limit pause.
        with self._gate(version):
            settled, remembered = self._settled(version)
            if settled:
                return remembered
            result, pause = lookup(version)
            now = self._clock()
            with self._lock:
                if result is not None:
                    self._answers.pop(version, None)
                    self._answers[version] = (result, now)
                    while len(self._answers) > _MAX_REMEMBERED_VERSIONS:
                        self._answers.pop(next(iter(self._answers)))
                    return result
                if pause is not None:
                    self._paused_until = max(self._paused_until, now + pause)
                return self._remembered(version, now, STALE_ANSWER_LIMIT_SECONDS)


_ANSWERS = AlphaTagAnswers()


def forget_alpha_tag_answers() -> None:
    """Drop every remembered answer and rate-limit pause (tests and fresh starts)."""

    _ANSWERS.clear()


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
    answers: AlphaTagAnswers | None = None,
) -> Callable[[str], bool]:
    """Build a fail-closed ``alpha/v<version>`` tag check for one selection walk.

    ``read_bounded`` is called as ``read_bounded(response, deadline=...)`` with a
    fresh monotonic deadline per lookup. Answers come from ``answers`` (the
    process-wide memory by default) before GitHub is asked.
    """

    memory = answers if answers is not None else _ANSWERS

    def fetch(version: str) -> tuple[bool | None, float | None]:
        deadline = time.monotonic() + timeout
        return lookup_alpha_tag(
            version,
            opener=opener,
            read_bounded=lambda response: read_bounded(response, deadline=deadline),
        )

    return fail_closed_alpha_checker(lambda version: memory.answer(version, fetch))


__all__ = [
    "CONFIRMED_ANSWER_TTL_SECONDS",
    "DEFAULT_RATE_LIMIT_PAUSE_SECONDS",
    "GITHUB_ALPHA_TAG_REF_URL",
    "MAX_RATE_LIMIT_PAUSE_SECONDS",
    "STALE_ANSWER_LIMIT_SECONDS",
    "AlphaTagAnswers",
    "alpha_tag_is_live",
    "build_alpha_liveness_checker",
    "fail_closed_alpha_checker",
    "forget_alpha_tag_answers",
    "lookup_alpha_tag",
]
