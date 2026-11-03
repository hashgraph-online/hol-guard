"""Adapter tests for the published release archive transport.

These exercise the I/O-only daemon adapter with a dependency-injected opener:
a fixed origin and path set, no caller-selected URLs, bounded reads, ETag
reuse, the cache bound, and the rollout switch. The projection itself is
proved by the Rust vector suite; here the native call is stubbed at the
resident-client boundary so the adapter's own contract is what fails.
"""

from __future__ import annotations

import http.client
import io
import json
import urllib.error
import urllib.request
from pathlib import Path
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard.daemon import release_feed_read as feed


class FakeResponse(io.BytesIO):
    def __init__(self, body: bytes, status: int = 200, headers: dict[str, str] | None = None) -> None:
        super().__init__(body)
        self.status = status
        self.headers = {"ETag": ""} | (headers or {})


class FakeOpener:
    def __init__(self, responses: list[FakeResponse | urllib.error.HTTPError]) -> None:
        self.responses = list(responses)
        self.requests: list[urllib.request.Request] = []

    def open(self, request: urllib.request.Request, timeout: float) -> FakeResponse:
        self.requests.append(request)
        response = self.responses.pop(0)
        if isinstance(response, urllib.error.HTTPError):
            raise response
        return response


def http_error(code: int) -> urllib.error.HTTPError:
    return urllib.error.HTTPError(feed.RELEASE_INDEX_PATH, code, "error", hdrs=None, fp=io.BytesIO(b"{}"))


@pytest.fixture(autouse=True)
def _reset_cache() -> None:
    feed.reset_release_feed_cache_for_tests()
    yield
    feed.reset_release_feed_cache_for_tests()


def index_body() -> bytes:
    return json.dumps(
        {
            "schemaVersion": "guard-release-client-index/v1",
            "page": 1,
            "pageSize": 25,
            "total": 0,
            "totalPages": 1,
            "generatedAt": "2026-10-21T00:00:00.000Z",
            "releases": [],
        }
    ).encode("utf-8")


def native_status() -> SimpleNamespace:
    identity = SimpleNamespace(path="/usr/bin/false")
    capabilities = SimpleNamespace(features={feed._RESIDENT_PROTOCOL_FEATURE, feed.RELEASE_FEED_NATIVE_FEATURE})
    return SimpleNamespace(available=True, compatible=True, identity=identity, capabilities=capabilities)


def test_index_reads_the_fixed_origin_with_no_identifier_on_the_wire() -> None:
    opener = FakeOpener([FakeResponse(index_body())])
    feed.fetch_release_document(path=feed.RELEASE_INDEX_PATH, query="page=1&pageSize=25", opener=opener)
    request = opener.requests[0]
    assert request.full_url == ("https://hol.org/api/guard/releases/v1/index?page=1&pageSize=25")
    assert request.method == "GET"
    assert not request.has_header("Authorization")
    assert not request.has_header("Cookie")
    assert request.get_header("User-agent") == feed.RELEASE_FEED_USER_AGENT
    assert feed.RELEASE_FEED_USER_AGENT.startswith("hol-guard/")


def test_the_caller_selects_a_position_not_a_url() -> None:
    path, query = feed.release_feed_target(kind="index", page=2, page_size=10)
    assert (path, query) == (feed.RELEASE_INDEX_PATH, "page=2&pageSize=10")
    path, query = feed.release_feed_target(kind="detail", slug="v3-44-0")
    assert (path, query) == (feed.RELEASE_DETAIL_PATH, "slug=v3-44-0")
    for bad in (
        {"kind": "detail", "slug": "../etc/passwd"},
        {"kind": "detail", "slug": None},
        {"kind": "detail", "slug": "V3-44-0"},
        {"kind": "index", "page": 0},
        {"kind": "index", "page_size": feed.MAX_RELEASE_FEED_PAGE_SIZE + 1},
        {"kind": "whatever"},
    ):
        with pytest.raises(feed.ReleaseFeedReadError) as error:
            feed.release_feed_target(**bad)  # type: ignore[arg-type]
        assert error.value.status == 400


def test_a_fresh_document_is_reused_and_a_refetch_sends_the_validator() -> None:
    opener = FakeOpener(
        [
            FakeResponse(index_body(), headers={"ETag": '"rf-abc"'}),
            FakeResponse(index_body(), headers={"ETag": '"rf-abc"'}),
        ]
    )
    feed.fetch_release_document(path=feed.RELEASE_INDEX_PATH, query="page=1", opener=opener)
    feed.fetch_release_document(path=feed.RELEASE_INDEX_PATH, query="page=1", opener=opener)
    assert len(opener.requests) == 1
    feed.fetch_release_document(path=feed.RELEASE_INDEX_PATH, query="page=1", opener=opener, force=True)
    assert opener.requests[1].has_header("If-none-match")


def test_a_304_reuses_the_stored_body() -> None:
    opener = FakeOpener([FakeResponse(index_body(), headers={"ETag": '"rf-def"'})])
    original = feed.fetch_release_document(path=feed.RELEASE_INDEX_PATH, query="page=1", opener=opener, force=True)
    opener.responses.append(http_error(304))
    reused = feed.fetch_release_document(path=feed.RELEASE_INDEX_PATH, query="page=1", opener=opener, force=True)
    assert reused.body == original.body
    assert reused.etag == original.etag


def test_an_unknown_release_is_a_404_not_an_upstream_failure() -> None:
    opener = FakeOpener([http_error(404)])
    with pytest.raises(feed.ReleaseFeedReadError) as error:
        feed.fetch_release_document(path=feed.RELEASE_DETAIL_PATH, query="slug=v9-9-9", opener=opener)
    assert (error.value.code, error.value.status) == ("release_not_found", 404)


def test_redirects_and_oversized_bodies_are_refused() -> None:
    redirect = urllib.error.HTTPError(feed.RELEASE_INDEX_PATH, 302, "Found", hdrs=None, fp=io.BytesIO(b""))
    with pytest.raises(feed.ReleaseFeedReadError):
        feed.fetch_release_document(path=feed.RELEASE_INDEX_PATH, query="page=1", opener=FakeOpener([redirect]))
    oversized = FakeResponse(b"x" * (feed.MAX_RELEASE_FEED_RESPONSE_BYTES + 1))
    with pytest.raises(feed.ReleaseFeedReadError) as error:
        feed.fetch_release_document(path=feed.RELEASE_INDEX_PATH, query="page=2", opener=FakeOpener([oversized]))
    assert error.value.code == "release_feed_response_too_large"


def test_the_document_cache_stays_bounded() -> None:
    for position in range(feed.MAX_CACHED_RELEASE_DOCUMENTS + 4):
        feed.fetch_release_document(
            path=feed.RELEASE_DETAIL_PATH,
            query=f"slug=v3-{position}-0",
            opener=FakeOpener([FakeResponse(index_body())]),
        )
    assert len(feed._cached_documents) <= feed.MAX_CACHED_RELEASE_DOCUMENTS


def test_the_rollout_switch_answers_without_any_upstream_or_native_work(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(feed.RELEASE_FEED_ROLLOUT_ENV, "off")
    assert feed.release_feed_rollout_enabled() is False

    def never_called(**_kwargs: object) -> object:  # pragma: no cover - must not run
        raise AssertionError("the rollback switch must dispatch nothing")

    monkeypatch.setattr(feed, "native_runtime_status", never_called)
    monkeypatch.setattr(feed, "fetch_release_document", never_called)
    result = feed.release_feed_projection(guard_home=Path("/tmp"), kind="index", opener=FakeOpener([]))
    assert result is not None
    assert (result.status, result.error_code) == (503, feed.RELEASE_FEED_UNAVAILABLE)


def test_an_absent_native_capability_has_no_python_fallback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    status = native_status()
    status.capabilities = SimpleNamespace(features={feed._RESIDENT_PROTOCOL_FEATURE})
    monkeypatch.setattr(feed, "native_runtime_status", lambda **_kwargs: status)
    monkeypatch.setattr(
        feed,
        "fetch_release_document",
        lambda **_kwargs: (_ for _ in ()).throw(AssertionError("no fetch without the projector")),
    )
    assert feed.release_feed_projection(guard_home=Path("/tmp"), kind="index", opener=FakeOpener([])) is None


def test_the_projected_body_is_what_the_route_serves(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(feed, "native_runtime_status", lambda **_kwargs: native_status())
    sent: list[bytes] = []

    def resident(**kwargs: object) -> bytes:
        sent.append(kwargs["payload"])  # type: ignore[arg-type]
        return json.dumps(
            {
                "schema": feed.RELEASE_FEED_RESULT_SCHEMA,
                "outcome": "ok",
                "http_status": 200,
                "etag": None,
                "body": '{"schemaVersion":"guard-release-client-index/v1"}',
                "error_code": None,
            }
        ).encode("utf-8")

    monkeypatch.setattr(feed, "native_resident_client_request", resident)
    result = feed.release_feed_projection(
        guard_home=Path("/tmp"),
        kind="index",
        opener=FakeOpener([FakeResponse(index_body())]),
    )
    assert result is not None
    assert result.status == 200
    assert result.body == b'{"schemaVersion":"guard-release-client-index/v1"}'
    envelope = json.loads(sent[0])
    assert envelope["operation"] == "release_feed_project"
    assert envelope["request"]["kind"] == "index"
    # The adapter forwards upstream bytes verbatim; it parses nothing.
    assert envelope["request"]["body"] == index_body().decode("utf-8")


def test_an_unrenderable_upstream_answer_is_reported_as_an_upstream_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(feed, "native_runtime_status", lambda **_kwargs: native_status())
    monkeypatch.setattr(
        feed,
        "native_resident_client_request",
        lambda **_kwargs: json.dumps(
            {
                "schema": feed.RELEASE_FEED_RESULT_SCHEMA,
                "outcome": "error",
                "http_status": 502,
                "etag": None,
                "body": None,
                "error_code": "release_feed_payload_invalid",
            }
        ).encode("utf-8"),
    )
    result = feed.release_feed_projection(
        guard_home=Path("/tmp"),
        kind="index",
        opener=FakeOpener([FakeResponse(index_body())]),
    )
    assert result is not None
    assert (result.status, result.error_code) == (502, "release_feed_payload_invalid")


def test_a_frame_that_is_not_the_agreed_result_is_refused(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(feed, "native_runtime_status", lambda **_kwargs: native_status())
    for frame in (
        {
            "schema": "something-else",
            "outcome": "ok",
            "http_status": 200,
            "etag": None,
            "body": "{}",
            "error_code": None,
        },
        {
            "schema": feed.RELEASE_FEED_RESULT_SCHEMA,
            "outcome": "ok",
            "http_status": 200,
            "etag": None,
            "body": "{}",
            "error_code": "release_feed_body_invalid",
        },
        # An error status the operation never produces cannot be relayed.
        {
            "schema": feed.RELEASE_FEED_RESULT_SCHEMA,
            "outcome": "error",
            "http_status": 418,
            "etag": None,
            "body": None,
            "error_code": "release_feed_payload_invalid",
        },
    ):
        monkeypatch.setattr(
            feed,
            "native_resident_client_request",
            lambda frame=frame, **_kwargs: json.dumps(frame).encode("utf-8"),
        )
        feed.reset_release_feed_cache_for_tests()
        assert (
            feed.release_feed_projection(
                guard_home=Path("/tmp"),
                kind="index",
                opener=FakeOpener([FakeResponse(index_body())]),
            )
            is None
        )


def test_a_connection_that_dies_mid_body_is_a_transport_failure() -> None:
    # The body read is as exposed as the connect: a reset while streaming must
    # reach the dashboard as the typed transport failure, not as a traceback
    # escaping the route.
    class DyingResponse(io.BytesIO):
        status = 200
        headers = {"ETag": ""}

        def read(self, _size: int | None = None) -> bytes:
            raise TimeoutError("the connection died while the body was read")

    # A chunked body cut off partway raises IncompleteRead, which descends from
    # HTTPException rather than OSError, so a tuple of the socket error classes
    # alone would let it escape as a traceback.
    class TruncatedResponse(io.BytesIO):
        status = 200
        headers = {"ETag": ""}

        def read(self, _size: int | None = None) -> bytes:
            raise http.client.IncompleteRead(b'{"schemaVersion"', 4096)

    for dying in (DyingResponse, TruncatedResponse):
        with pytest.raises(feed.ReleaseFeedReadError) as error:
            feed.fetch_release_document(
                path=feed.RELEASE_INDEX_PATH,
                query="page=1",
                opener=FakeOpener([dying(b"")]),
            )
        assert (error.value.code, error.value.status) == (feed.RELEASE_FEED_TRANSPORT_FAILED, 503), dying.__name__
