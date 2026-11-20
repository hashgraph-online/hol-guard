"""The alpha channel only offers alphas whose GitHub prerelease tag is still live."""

from __future__ import annotations

import io
import json
import urllib.error
import urllib.request

import pytest
from packaging.version import Version

from codex_plugin_scanner.guard.cli import update_commands
from codex_plugin_scanner.guard.cli.update_alpha_tag_lookup import (
    GITHUB_ALPHA_TAG_REF_URL,
    alpha_tag_is_live,
    fail_closed_alpha_checker,
)
from codex_plugin_scanner.guard.cli.update_release_candidates import (
    newest_live_pypi_version,
    select_live_release,
)


def _candidates(*versions: str) -> list[tuple[Version, str]]:
    return [(Version(version), version) for version in versions]


def _payload(*versions: str) -> dict[str, object]:
    return {"releases": {version: [{"yanked": False}] for version in versions}}


class _Recorder:
    def __init__(self, live: set[str]) -> None:
        self.live = live
        self.calls: list[str] = []

    def __call__(self, version: str) -> bool:
        self.calls.append(version)
        return version in self.live


def test_newest_live_alpha_is_offered_with_one_lookup() -> None:
    check = _Recorder({"3.43.0a2"})

    selected = newest_live_pypi_version(_payload("3.42.0", "3.43.0a1", "3.43.0a2"), alpha_is_live=check)

    assert selected == "3.43.0a2"
    assert check.calls == ["3.43.0a2"]


def test_retracted_newest_alpha_falls_back_to_older_live_alpha() -> None:
    check = _Recorder({"3.43.0a1"})

    selected = newest_live_pypi_version(_payload("3.42.0", "3.43.0a1", "3.43.0a2"), alpha_is_live=check)

    assert selected == "3.43.0a1"
    assert check.calls == ["3.43.0a2", "3.43.0a1"]


def test_all_retracted_alphas_fall_back_to_newest_stable() -> None:
    check = _Recorder(set())

    selected = newest_live_pypi_version(_payload("3.41.0", "3.42.0", "3.43.0a1", "3.43.0a2"), alpha_is_live=check)

    assert selected == "3.42.0"
    assert check.calls == ["3.43.0a2", "3.43.0a1"]


def test_stable_newer_than_alphas_needs_no_lookup() -> None:
    check = _Recorder({"3.43.0a2"})

    selected = newest_live_pypi_version(_payload("3.43.0", "3.43.0a1", "3.43.0a2"), alpha_is_live=check)

    assert selected == "3.43.0"
    assert check.calls == []


def test_lookup_budget_is_bounded_and_unchecked_alphas_are_never_offered() -> None:
    check = _Recorder({"3.43.0a1"})

    selected = select_live_release(
        _candidates("3.42.0", "3.43.0a1", "3.43.0a2", "3.43.0a3", "3.43.0a4"),
        alpha_is_live=check,
        max_lookups=3,
    )

    assert selected == "3.42.0"
    assert check.calls == ["3.43.0a4", "3.43.0a3", "3.43.0a2"]


def test_no_candidates_and_alpha_only_unverifiable_return_none() -> None:
    assert newest_live_pypi_version({"releases": {}}, alpha_is_live=_Recorder(set())) is None
    assert newest_live_pypi_version(None, alpha_is_live=_Recorder(set())) is None
    assert newest_live_pypi_version(_payload("3.43.0a1"), alpha_is_live=_Recorder(set())) is None


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


def _lookup(opener: object, version: str = "3.43.0a1") -> bool | None:
    return alpha_tag_is_live(version, opener=opener, read_bounded=_read)  # type: ignore[arg-type]


def _tag_body(version: str) -> bytes:
    return json.dumps({"ref": f"refs/tags/alpha/v{version}"}).encode()


def test_tag_lookup_requests_exact_ref_and_accepts_existing_tag() -> None:
    requests: list[urllib.request.Request] = []

    def opener(request: urllib.request.Request) -> _Response:
        requests.append(request)
        return _Response(_tag_body("3.43.0a1"))

    assert _lookup(opener) is True
    assert [request.full_url for request in requests] == [f"{GITHUB_ALPHA_TAG_REF_URL}3.43.0a1"]
    assert requests[0].full_url.endswith("/git/ref/tags/alpha/v3.43.0a1")


def _http_error(code: int) -> urllib.error.HTTPError:
    return urllib.error.HTTPError(GITHUB_ALPHA_TAG_REF_URL, code, "status", {}, io.BytesIO(b"{}"))  # type: ignore[arg-type]


def test_tag_lookup_treats_404_as_retracted() -> None:
    def opener(_request: urllib.request.Request) -> _Response:
        raise _http_error(404)

    assert _lookup(opener) is False


@pytest.mark.parametrize(
    "failure",
    [
        _http_error(403),
        _http_error(429),
        _http_error(500),
        urllib.error.URLError("offline"),
        TimeoutError("slow"),
        OSError("reset"),
    ],
)
def test_tag_lookup_failures_are_unverifiable_and_never_raise(failure: Exception) -> None:
    def opener(_request: urllib.request.Request) -> _Response:
        raise failure

    assert _lookup(opener) is None


@pytest.mark.parametrize(
    "body",
    [b"not json", b"\xff", b"[]", json.dumps({"ref": "refs/tags/alpha/v3.43.0a2"}).encode(), b"{}"],
)
def test_tag_lookup_rejects_malformed_or_mismatched_responses(body: bytes) -> None:
    assert _lookup(lambda _request: _Response(body)) is None


def test_fail_closed_checker_stops_looking_after_unverifiable_lookup() -> None:
    results: list[bool | None] = [None, True]
    calls: list[str] = []

    def lookup(version: str) -> bool | None:
        calls.append(version)
        return results.pop(0)

    check = fail_closed_alpha_checker(lookup)

    assert check("3.43.0a2") is False
    assert check("3.43.0a1") is False
    assert calls == ["3.43.0a2"]


def test_alpha_channel_resolver_uses_stable_when_tag_lookup_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    opened: list[str] = []

    def failing_urlopen(request: urllib.request.Request, **_kwargs: object) -> _Response:
        opened.append(request.full_url)
        raise _http_error(403)

    monkeypatch.setattr(update_commands, "_latest_version_from_pypi", lambda: "3.42.0")
    monkeypatch.setattr(update_commands, "_last_pypi_payload", _payload("3.42.0", "3.43.0a1", "3.43.0a2"))
    monkeypatch.setattr(update_commands, "managed_urlopen", failing_urlopen)

    assert update_commands._latest_alpha_version_from_pypi("3.42.0") == "3.42.0"
    assert opened == [f"{GITHUB_ALPHA_TAG_REF_URL}3.43.0a2"]


def test_alpha_channel_resolver_skips_retracted_alpha(monkeypatch: pytest.MonkeyPatch) -> None:
    opened: list[str] = []

    def urlopen(request: urllib.request.Request, **_kwargs: object) -> _Response:
        opened.append(request.full_url)
        if request.full_url.endswith("3.43.0a2"):
            raise _http_error(404)
        return _Response(_tag_body("3.43.0a1"))

    monkeypatch.setattr(update_commands, "_latest_version_from_pypi", lambda: "3.42.0")
    monkeypatch.setattr(update_commands, "_last_pypi_payload", _payload("3.42.0", "3.43.0a1", "3.43.0a2"))
    monkeypatch.setattr(update_commands, "managed_urlopen", urlopen)

    assert update_commands._latest_alpha_version_from_pypi("3.42.0") == "3.43.0a1"
    assert opened == [f"{GITHUB_ALPHA_TAG_REF_URL}3.43.0a2", f"{GITHUB_ALPHA_TAG_REF_URL}3.43.0a1"]


def test_stable_channel_makes_no_github_lookup(monkeypatch: pytest.MonkeyPatch) -> None:
    def forbidden_urlopen(*_args: object, **_kwargs: object) -> _Response:
        raise AssertionError("stable channel must not call GitHub")

    monkeypatch.setattr(update_commands, "_latest_version_from_pypi", lambda: "3.42.0")
    monkeypatch.setattr(update_commands, "_last_pypi_payload", _payload("3.42.0", "3.43.0a1"))
    monkeypatch.setattr(update_commands, "managed_urlopen", forbidden_urlopen)

    payload = update_commands._version_check_payload("3.41.0")

    assert payload["latest_version"] == "3.42.0"
    assert "release_channel" not in payload


def test_python_incompatible_fallback_skips_retracted_alpha(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(update_commands, "_runtime_python_version", lambda: "3.12.0")
    monkeypatch.setattr(
        update_commands,
        "_last_pypi_payload",
        {
            "releases": {
                "3.42.0": [{"yanked": False, "requires_python": ">=3.13"}],
                "3.43.0a1": [{"yanked": False, "requires_python": ">=3.10"}],
                "3.43.0a2": [{"yanked": False, "requires_python": ">=3.10"}],
            }
        },
    )
    monkeypatch.setattr(
        update_commands,
        "_alpha_liveness_checker",
        lambda: lambda version: version == "3.43.0a1",
    )

    assert update_commands._latest_compatible_release_version("3.41.0", "3.12.0", include_alpha=True) == "3.43.0a1"


def test_live_release_candidates_drop_retracted_and_unchecked_alphas() -> None:
    from codex_plugin_scanner.guard.cli.update_release_candidates import live_release_candidates

    check = _Recorder({"3.43.0a4", "3.43.0a1"})

    live = live_release_candidates(
        ["3.43.0a1", "3.42.0", "3.43.0a2", "3.43.0a3", "bogus", "3.43.0a4", "3.43.0a5"],
        alpha_is_live=check,
        max_lookups=3,
    )

    assert live == ["3.43.0a4", "3.42.0"]
    assert check.calls == ["3.43.0a5", "3.43.0a4", "3.43.0a3"]


def test_desktop_refinement_ignores_retracted_alpha() -> None:
    from codex_plugin_scanner.guard.cli.update_desktop_apply import refine_desktop_version_check

    version_check = {
        "source": "pypi",
        "status": "stale",
        "current_version": "3.43.0a1",
        "latest_version": "3.43.0a2",
        "update_available": True,
    }
    check = _Recorder({"3.43.0a2"})

    refined = refine_desktop_version_check(
        "3.43.0a1",
        version_check,
        candidates=["3.43.0a1", "3.43.0a2", "3.43.0a3"],
        include_alpha=True,
        alpha_is_live=check,
    )

    assert refined["latest_version"] == "3.43.0a2"
    assert refined["update_available"] is True


def test_desktop_refinement_without_live_alpha_stays_current() -> None:
    from codex_plugin_scanner.guard.cli.update_desktop_apply import refine_desktop_version_check

    refined = refine_desktop_version_check(
        "3.43.0a1",
        {
            "source": "pypi",
            "status": "current",
            "current_version": "3.43.0a1",
            "latest_version": "3.43.0a1",
            "update_available": False,
        },
        candidates=["3.43.0a1", "3.43.0a2"],
        include_alpha=True,
        alpha_is_live=_Recorder(set()),
    )

    assert refined["latest_version"] == "3.43.0a1"
    assert refined["update_available"] is False


class _Clock:
    def __init__(self) -> None:
        self.now = 1_000.0

    def __call__(self) -> float:
        return self.now


def _http_error_with_headers(code: int, headers: dict[str, str]) -> urllib.error.HTTPError:
    from email.message import Message

    message = Message()
    for name, value in headers.items():
        message[name] = value
    return urllib.error.HTTPError(GITHUB_ALPHA_TAG_REF_URL, code, "status", message, io.BytesIO(b"{}"))


def test_rate_limit_reply_reports_a_pause_from_the_reset_header() -> None:
    from codex_plugin_scanner.guard.cli.update_alpha_tag_lookup import lookup_alpha_tag

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
    from codex_plugin_scanner.guard.cli.update_alpha_tag_lookup import lookup_alpha_tag

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
    from codex_plugin_scanner.guard.cli.update_alpha_tag_lookup import (
        CONFIRMED_ANSWER_TTL_SECONDS,
        AlphaTagAnswers,
    )

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
    from codex_plugin_scanner.guard.cli.update_alpha_tag_lookup import (
        CONFIRMED_ANSWER_TTL_SECONDS,
        AlphaTagAnswers,
    )

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
    from codex_plugin_scanner.guard.cli.update_alpha_tag_lookup import (
        STALE_ANSWER_LIMIT_SECONDS,
        AlphaTagAnswers,
    )

    clock = _Clock()
    answers = AlphaTagAnswers(clock)
    replies: list[tuple[bool | None, float | None]] = [(True, None), (None, None)]

    def lookup(_version: str) -> tuple[bool | None, float | None]:
        return replies.pop(0)

    assert answers.answer("3.43.0a5", lookup) is True
    clock.now += STALE_ANSWER_LIMIT_SECONDS + 1
    assert answers.answer("3.43.0a5", lookup) is None


def test_a_retraction_replaces_a_remembered_live_answer() -> None:
    from codex_plugin_scanner.guard.cli.update_alpha_tag_lookup import (
        CONFIRMED_ANSWER_TTL_SECONDS,
        AlphaTagAnswers,
    )

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
    from codex_plugin_scanner.guard.cli import update_alpha_tag_lookup

    monkeypatch.setattr(update_alpha_tag_lookup, "_ANSWERS", update_alpha_tag_lookup.AlphaTagAnswers(clock))

    replies.append(object())
    assert update_commands._latest_alpha_version_from_pypi("3.42.0") == "3.43.0a2"
    clock.now += update_alpha_tag_lookup.CONFIRMED_ANSWER_TTL_SECONDS + 1
    replies.append(_http_error_with_headers(403, {"X-RateLimit-Remaining": "0"}))
    assert update_commands._latest_alpha_version_from_pypi("3.42.0") == "3.43.0a2"
    assert replies == []


def test_policy_reaches_initial_and_fallback_tag_lookups(monkeypatch: pytest.MonkeyPatch) -> None:
    from codex_plugin_scanner.guard.mdm.contracts import ManagedNetworkPolicy

    policy = ManagedNetworkPolicy()
    seen: list[tuple[str, object]] = []

    def urlopen(request: urllib.request.Request, **kwargs: object) -> _Response:
        seen.append((request.full_url, kwargs.get("policy")))
        if "/git/ref/tags/" not in request.full_url:
            raise urllib.error.URLError("offline")
        version = request.full_url.rsplit("/v", 1)[1]
        return _Response(_tag_body(version))

    monkeypatch.setattr(update_commands, "_latest_version_from_pypi", lambda: "3.42.0")
    monkeypatch.setattr(update_commands, "_runtime_python_version", lambda: "3.12.0")
    monkeypatch.setattr(
        update_commands,
        "_last_pypi_payload",
        {
            "releases": {
                "3.42.0": [{"yanked": False, "requires_python": ">=3.10"}],
                "3.43.0a1": [{"yanked": False, "requires_python": ">=3.10"}],
                "3.43.0a2": [{"yanked": False, "requires_python": ">=3.13"}],
            }
        },
    )
    monkeypatch.setattr(update_commands, "managed_urlopen", urlopen)

    payload = update_commands._version_check_payload("3.41.0", network_policy=policy, include_alpha=True)

    assert payload["latest_version"] == "3.43.0a1"
    assert payload["pypi_latest_version"] == "3.43.0a2"
    tag_lookups = [(url, used) for url, used in seen if "/git/ref/tags/" in url]
    assert [url.rsplit("/v", 1)[1] for url, _used in tag_lookups] == ["3.43.0a2", "3.43.0a1"]
    assert all(used is policy for _url, used in seen)
