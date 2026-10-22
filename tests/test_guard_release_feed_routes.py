"""The local release routes stay on /v1 and still require the daemon token."""

from __future__ import annotations

from types import SimpleNamespace
from urllib.parse import urlparse

import pytest

from codex_plugin_scanner.guard.daemon import server as daemon_server_module
from codex_plugin_scanner.guard.daemon.release_feed_read import (
    RELEASE_FEED_REQUEST_INVALID,
    RELEASE_FEED_UNAVAILABLE,
    RELEASE_INDEX_PATH,
)


def _handler(path: str) -> daemon_server_module._GuardDaemonHandler:
    handler = object.__new__(daemon_server_module._GuardDaemonHandler)
    handler.path = path
    handler.headers = {}
    handler.server = SimpleNamespace(store=SimpleNamespace(guard_home="/tmp/guard-home"))
    handler._touch_runtime_heartbeat = lambda _path: None
    handler._origin_is_allowed_for_request = lambda _path: True
    handler._route_home = lambda: "/tmp/guard-home"
    handler._query_has_guard_token = lambda _query: False
    handler._record_query_token_rejection = lambda: None
    handler._cors_headers_for_request = lambda **_kwargs: {}
    return handler


def _answers(handler: daemon_server_module._GuardDaemonHandler) -> list[object]:
    answers: list[object] = []
    handler._write_json = lambda payload, *, status=200, extra_headers=None: answers.append(
        (status, payload)
    )
    handler._write_json_bytes = lambda body, *, status, extra_headers=None: answers.append(
        (status, body, extra_headers)
    )
    return answers


def _projection(**kwargs: object) -> SimpleNamespace:
    return SimpleNamespace(
        status=kwargs.get("status", 200),
        etag=None,
        body=kwargs.get("body"),
        error_code=kwargs.get("error_code"),
    )


def test_the_local_index_route_is_not_the_portal_path(monkeypatch: pytest.MonkeyPatch) -> None:
    handler = _handler("/v1/releases/index")
    answers = _answers(handler)
    asked: list[dict[str, object]] = []
    monkeypatch.setattr(daemon_server_module, "release_feed_rollout_enabled", lambda: True)
    monkeypatch.setattr(
        daemon_server_module,
        "release_feed_projection",
        lambda **kwargs: (asked.append(kwargs), _projection(body=b'{"releases":[]}'))[1],
    )

    handler._serve_release_feed_read(urlparse("/v1/releases/index?page=2&pageSize=10"))

    assert answers == [(200, b'{"releases":[]}', {"Cache-Control": "no-store"})]
    assert asked[0]["kind"] == "index"
    assert (asked[0]["page"], asked[0]["page_size"]) == (2, 10)
    assert RELEASE_INDEX_PATH != "/v1/releases/index"


def test_a_detail_read_carries_exactly_one_slug(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(daemon_server_module, "release_feed_rollout_enabled", lambda: True)
    asked: list[dict[str, object]] = []
    monkeypatch.setattr(
        daemon_server_module,
        "release_feed_projection",
        lambda **kwargs: (asked.append(kwargs), _projection(body=b"{}"))[1],
    )

    handler = _handler("/v1/releases/release")
    answers = _answers(handler)
    handler._serve_release_feed_read(urlparse("/v1/releases/release?slug=v3-44-0"))
    assert asked[0]["slug"] == "v3-44-0"
    assert answers[0][0] == 200

    # No slug, and a repeated slug, are caller mistakes rather than a guess.
    for query in ("", "?slug=v3-44-0&slug=v3-45-0"):
        handler = _handler("/v1/releases/release")
        answers = _answers(handler)
        handler._serve_release_feed_read(urlparse(f"/v1/releases/release{query}"))
        assert answers == [(400, {"error": RELEASE_FEED_REQUEST_INVALID})]
    assert len(asked) == 1


def test_unreadable_paging_is_refused_rather_than_silently_reset(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(daemon_server_module, "release_feed_rollout_enabled", lambda: True)

    def never_called(**_kwargs: object) -> object:  # pragma: no cover - must not run
        raise AssertionError("a bad page must not read a different one")

    monkeypatch.setattr(daemon_server_module, "release_feed_projection", never_called)
    for query in ("?page=nine", "?page=0", "?pageSize=-3", "?page=1&page=2"):
        handler = _handler("/v1/releases/index")
        answers = _answers(handler)
        handler._serve_release_feed_read(urlparse(f"/v1/releases/index{query}"))
        assert answers == [(400, {"error": RELEASE_FEED_REQUEST_INVALID})], query


def test_an_unknown_releases_path_is_not_served(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(daemon_server_module, "release_feed_rollout_enabled", lambda: True)
    handler = _handler("/v1/releases/contributors")
    answers = _answers(handler)
    handler._serve_release_feed_read(urlparse("/v1/releases/contributors"))
    assert answers == [(404, {"error": "not_found"})]


def test_the_rollback_switch_answers_before_anything_that_can_fail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(daemon_server_module, "release_feed_rollout_enabled", lambda: False)

    def never_called(**_kwargs: object) -> object:  # pragma: no cover - must not run
        raise AssertionError("the rollback switch must dispatch nothing")

    monkeypatch.setattr(daemon_server_module, "release_feed_projection", never_called)
    handler = _handler("/v1/releases/index")
    answers = _answers(handler)
    handler._serve_release_feed_read(urlparse("/v1/releases/index"))
    assert answers == [(503, {"error": RELEASE_FEED_UNAVAILABLE})]


def test_an_absent_projector_answers_unavailable_rather_than_an_empty_archive(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(daemon_server_module, "release_feed_rollout_enabled", lambda: True)
    monkeypatch.setattr(daemon_server_module, "release_feed_projection", lambda **_k: None)
    handler = _handler("/v1/releases/index")
    answers = _answers(handler)
    handler._serve_release_feed_read(urlparse("/v1/releases/index"))
    assert answers == [(501, {"error": RELEASE_FEED_UNAVAILABLE})]


def test_a_typed_transport_failure_keeps_its_status(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(daemon_server_module, "release_feed_rollout_enabled", lambda: True)
    monkeypatch.setattr(
        daemon_server_module,
        "release_feed_projection",
        lambda **_k: _projection(status=404, error_code="release_not_found"),
    )
    handler = _handler("/v1/releases/release")
    answers = _answers(handler)
    handler._serve_release_feed_read(urlparse("/v1/releases/release?slug=v9-9-9"))
    assert answers == [(404, {"error": "release_not_found"})]


def test_the_release_routes_require_the_header_token(monkeypatch: pytest.MonkeyPatch) -> None:
    handler = _handler("/v1/releases/index")
    handler._header_token_is_valid = lambda: False
    denied: list[str] = []
    handler._write_unauthorized = lambda **_kwargs: denied.append("denied")

    def never_called(_parsed: object) -> None:  # pragma: no cover - must not run
        raise AssertionError("an unauthenticated read must not reach the feed")

    monkeypatch.setattr(
        daemon_server_module._GuardDaemonHandler,
        "_serve_release_feed_read",
        never_called,
    )
    handler.do_GET()
    assert denied == ["denied"]


def test_a_digit_the_parser_refuses_is_an_invalid_request(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # "²" is a digit to str.isdigit and not a number to int. The route owes
    # such a page a 400, not an exception thrown out of the handler.
    monkeypatch.setattr(daemon_server_module, "release_feed_rollout_enabled", lambda: True)

    def never_called(**_kwargs: object) -> object:  # pragma: no cover - must not run
        raise AssertionError("an unreadable page must not reach the projection")

    monkeypatch.setattr(daemon_server_module, "release_feed_projection", never_called)
    for query in ("?page=%C2%B2", "?pageSize=%C2%B2", "?page=١٢"):
        handler = _handler("/v1/releases/index")
        answers = _answers(handler)
        handler._serve_release_feed_read(urlparse(f"/v1/releases/index{query}"))
        assert answers == [(400, {"error": RELEASE_FEED_REQUEST_INVALID})], query
