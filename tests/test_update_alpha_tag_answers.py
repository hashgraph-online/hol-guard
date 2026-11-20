"""Remembered alpha tag answers keep an offered update visible through GitHub rate limits."""

from __future__ import annotations

import io
import json
import threading
import urllib.error
import urllib.request
from email.message import Message

import pytest

from codex_plugin_scanner.guard.cli import update_alpha_tag_lookup, update_commands
from codex_plugin_scanner.guard.cli.update_alpha_tag_lookup import (
    CONFIRMED_ANSWER_TTL_SECONDS,
    GITHUB_ALPHA_TAG_REF_URL,
    STALE_ANSWER_LIMIT_SECONDS,
    AlphaTagAnswers,
    lookup_alpha_tag,
)


def _payload(*versions: str) -> dict[str, object]:
    return {"releases": {version: [{"yanked": False}] for version in versions}}


class _Response:
    def __init__(self, body: bytes, status: int = 200) -> None:
        self._body = body
        self.status = status

    def __enter__(self) -> _Response:
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def read(self, _limit: int) -> bytes:
        return self._body


def _read(response: object) -> bytes:
    assert isinstance(response, _Response)
    return response._body


def _tag_body(version: str) -> bytes:
    return json.dumps({"ref": f"refs/tags/alpha/v{version}"}).encode()


class _Clock:
    def __init__(self) -> None:
        self.now = 1_000.0

    def __call__(self) -> float:
        return self.now


def _http_error_with_headers(code: int, headers: dict[str, str]) -> urllib.error.HTTPError:
    message = Message()
    for name, value in headers.items():
        message[name] = value
    return urllib.error.HTTPError(GITHUB_ALPHA_TAG_REF_URL, code, "status", message, io.BytesIO(b"{}"))


def test_rate_limit_reply_reports_a_pause_from_the_reset_header() -> None:

    def opener(_request: urllib.request.Request) -> _Response:
        raise _http_error_with_headers(403, {"X-RateLimit-Remaining": "0", "X-RateLimit-Reset": "5000"})

    answer, pause = lookup_alpha_tag(
        "3.43.0a1",
        opener=opener,  # type: ignore[arg-type]
        read_bounded=_read,
        wall_clock=lambda: 4_000.0,
    )

    assert answer is None
    assert pause == 1_000.0


@pytest.mark.parametrize(
    ("code", "headers", "expected"),
    [
        (429, {"Retry-After": "30"}, 30.0),
        (403, {"Retry-After": "120"}, 120.0),
        (429, {}, 300.0),
        (403, {"X-RateLimit-Remaining": "0", "X-RateLimit-Reset": "999999999"}, 3_600.0),
        (403, {"X-RateLimit-Remaining": "0", "X-RateLimit-Reset": "1"}, 1.0),
        (403, {}, None),
        (500, {}, None),
    ],
)
def test_rate_limit_pause_is_bounded(code: int, headers: dict[str, str], expected: float | None) -> None:

    def opener(_request: urllib.request.Request) -> _Response:
        raise _http_error_with_headers(code, headers)

    _answer, pause = lookup_alpha_tag(
        "3.43.0a1",
        opener=opener,  # type: ignore[arg-type]
        read_bounded=_read,
        wall_clock=lambda: 4_000.0,
    )

    assert pause == expected


def test_confirmed_answers_are_reused_without_asking_github_again() -> None:

    clock = _Clock()
    answers = AlphaTagAnswers(clock)
    calls: list[str] = []

    def lookup(version: str) -> tuple[bool | None, float | None]:
        calls.append(version)
        return version == "3.43.0a2", None

    assert answers.answer("3.43.0a2", lookup) is True
    assert answers.answer("3.43.0a1", lookup) is False
    clock.now += CONFIRMED_ANSWER_TTL_SECONDS - 1
    assert answers.answer("3.43.0a2", lookup) is True
    assert answers.answer("3.43.0a1", lookup) is False
    assert calls == ["3.43.0a2", "3.43.0a1"]
    clock.now += 2
    assert answers.answer("3.43.0a2", lookup) is True
    assert calls == ["3.43.0a2", "3.43.0a1", "3.43.0a2"]


def test_rate_limit_keeps_the_last_confirmed_answer_and_pauses_lookups() -> None:
    """The reported bug: an offered alpha vanished once GitHub's budget ran out."""

    clock = _Clock()
    answers = AlphaTagAnswers(clock)
    replies: list[tuple[bool | None, float | None]] = [(True, None), (None, 600.0)]
    calls: list[str] = []

    def lookup(version: str) -> tuple[bool | None, float | None]:
        calls.append(version)
        return replies.pop(0)

    assert answers.answer("3.43.0a5", lookup) is True
    clock.now += CONFIRMED_ANSWER_TTL_SECONDS + 1
    # GitHub is rate limited: the confirmed answer stands in.
    assert answers.answer("3.43.0a5", lookup) is True
    # While paused, nothing is sent and the remembered answer still stands.
    clock.now += 300
    assert answers.answer("3.43.0a5", lookup) is True
    # An alpha never confirmed stays unverifiable during the pause.
    assert answers.answer("3.43.0a6", lookup) is None
    assert calls == ["3.43.0a5", "3.43.0a5"]


def test_stale_answers_expire_while_github_cannot_answer() -> None:

    clock = _Clock()
    answers = AlphaTagAnswers(clock)
    replies: list[tuple[bool | None, float | None]] = [(True, None), (None, None)]

    def lookup(_version: str) -> tuple[bool | None, float | None]:
        return replies.pop(0)

    assert answers.answer("3.43.0a5", lookup) is True
    clock.now += STALE_ANSWER_LIMIT_SECONDS + 1
    assert answers.answer("3.43.0a5", lookup) is None


def test_a_retraction_replaces_a_remembered_live_answer() -> None:

    clock = _Clock()
    answers = AlphaTagAnswers(clock)
    replies: list[tuple[bool | None, float | None]] = [(True, None), (False, None), (None, None)]

    def lookup(_version: str) -> tuple[bool | None, float | None]:
        return replies.pop(0)

    assert answers.answer("3.43.0a5", lookup) is True
    clock.now += CONFIRMED_ANSWER_TTL_SECONDS + 1
    assert answers.answer("3.43.0a5", lookup) is False
    clock.now += CONFIRMED_ANSWER_TTL_SECONDS + 1
    assert answers.answer("3.43.0a5", lookup) is False


def test_status_checks_share_one_lookup_per_alpha(monkeypatch: pytest.MonkeyPatch) -> None:
    opened: list[str] = []

    def urlopen(request: urllib.request.Request, **_kwargs: object) -> _Response:
        opened.append(request.full_url)
        return _Response(_tag_body(request.full_url.rsplit("/v", 1)[1]))

    monkeypatch.setattr(update_commands, "_latest_version_from_pypi", lambda: "3.42.0")
    monkeypatch.setattr(update_commands, "_last_pypi_payload", _payload("3.42.0", "3.43.0a1", "3.43.0a2"))
    monkeypatch.setattr(update_commands, "managed_urlopen", urlopen)

    for _ in range(5):
        assert update_commands._latest_alpha_version_from_pypi("3.42.0") == "3.43.0a2"
    assert opened == [f"{GITHUB_ALPHA_TAG_REF_URL}3.43.0a2"]


def test_offered_alpha_survives_a_rate_limited_recheck(monkeypatch: pytest.MonkeyPatch) -> None:
    replies: list[object] = []

    def urlopen(request: urllib.request.Request, **_kwargs: object) -> _Response:
        reply = replies.pop(0)
        if isinstance(reply, Exception):
            raise reply
        return _Response(_tag_body(request.full_url.rsplit("/v", 1)[1]))

    monkeypatch.setattr(update_commands, "_latest_version_from_pypi", lambda: "3.42.0")
    monkeypatch.setattr(update_commands, "_last_pypi_payload", _payload("3.42.0", "3.43.0a1", "3.43.0a2"))
    monkeypatch.setattr(update_commands, "managed_urlopen", urlopen)
    clock = _Clock()
    monkeypatch.setattr(update_alpha_tag_lookup, "_ANSWERS", update_alpha_tag_lookup.AlphaTagAnswers(clock))

    replies.append(object())
    assert update_commands._latest_alpha_version_from_pypi("3.42.0") == "3.43.0a2"
    clock.now += update_alpha_tag_lookup.CONFIRMED_ANSWER_TTL_SECONDS + 1
    replies.append(_http_error_with_headers(403, {"X-RateLimit-Remaining": "0"}))
    assert update_commands._latest_alpha_version_from_pypi("3.42.0") == "3.43.0a2"
    assert replies == []


def test_concurrent_status_checks_share_one_lookup_in_flight() -> None:
    answers = AlphaTagAnswers(_Clock())
    started = threading.Event()
    release = threading.Event()
    calls: list[str] = []

    def lookup(version: str) -> tuple[bool | None, float | None]:
        calls.append(version)
        started.set()
        assert release.wait(5)
        return True, None

    results: list[bool | None] = []
    first = threading.Thread(target=lambda: results.append(answers.answer("3.43.0a5", lookup)))
    first.start()
    assert started.wait(5)
    waiters = [threading.Thread(target=lambda: results.append(answers.answer("3.43.0a5", lookup))) for _ in range(4)]
    for waiter in waiters:
        waiter.start()
    release.set()
    for thread in [first, *waiters]:
        thread.join(5)

    assert calls == ["3.43.0a5"]
    assert results == [True] * 5
