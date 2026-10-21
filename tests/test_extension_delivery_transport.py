"""Update transport bounds and advisory selectors never substitute for authority."""

from __future__ import annotations

import io
import json
import urllib.error

import pytest

from codex_plugin_scanner.guard.catalog_delivery import transport


def test_source_ancestry_is_bounded_and_skips_identical_sources(monkeypatch):
    calls = []

    def download(url, maximum):
        calls.append((url, maximum))
        return json.dumps(
            {
                "status": "ahead",
                "base_commit": {"sha": "1" * 40},
                "merge_base_commit": {"sha": "1" * 40},
                "ahead_by": 2,
                "behind_by": 0,
            }
        ).encode()

    monkeypatch.setattr(transport, "download", download)
    transport.require_source_ancestor("1" * 40, "1" * 40)
    assert calls == []
    transport.require_source_ancestor("1" * 40, "2" * 40)
    assert len(calls) == 1
    assert calls[0][1] == 64 * 1024
    assert calls[0][0].endswith("?per_page=1&page=2")


@pytest.mark.parametrize(
    "change",
    [
        {"status": "behind"},
        {"base_commit": None},
        {"merge_base_commit": []},
        {"merge_base_commit": {"sha": "3" * 40}},
        {"behind_by": True},
        {"ahead_by": 0},
    ],
)
def test_source_ancestry_rejects_regression_divergence_or_malformed_responses(monkeypatch, change):
    value = {
        "status": "ahead",
        "base_commit": {"sha": "1" * 40},
        "merge_base_commit": {"sha": "1" * 40},
        "ahead_by": 2,
        "behind_by": 0,
        **change,
    }
    monkeypatch.setattr(transport, "download", lambda *args: json.dumps(value).encode())
    with pytest.raises(ValueError, match="descendant"):
        transport.require_source_ancestor("1" * 40, "2" * 40)


@pytest.mark.parametrize(
    "url",
    [
        "http://github.com/a",
        "https://github.com.evil.invalid/a",
        "https://user:pass@github.com/a",
        "https://github.com:444/a",
        "file:///tmp/data",
    ],
)
def test_transport_rejects_unapproved_destinations(url):
    with pytest.raises(ValueError, match="destination"):
        transport.download(url, 100)


class Response(io.BytesIO):
    def __init__(self, data, headers):
        super().__init__(data)
        self.headers = headers


@pytest.mark.parametrize(
    "data,headers",
    [
        (b"x" * 101, {}),
        (b"x", {"Content-Length": "101"}),
        (b"x", {"Content-Length": "2"}),
        (b"x", {"Content-Encoding": "gzip"}),
    ],
)
def test_transport_bounds_declared_and_actual_bodies(monkeypatch, data, headers):
    monkeypatch.setattr(
        transport,
        "managed_urlopen",
        lambda *args, **kwargs: Response(data, headers),
    )
    with pytest.raises(ValueError):
        transport.download("https://github.com/hashgraph-online/hol-guard/releases/download/data/asset", 100)


@pytest.mark.parametrize(
    "target", ["https://evil.invalid/asset", "http://github.com/asset", "https://user:pass@github.com/asset"]
)
def test_redirect_destination_is_checked_before_managed_egress(monkeypatch, target):
    calls = []

    def open_managed(request, **kwargs):
        calls.append(request)
        assert kwargs == {"timeout": 20, "allow_redirects": False}
        raise urllib.error.HTTPError(request.full_url, 302, "redirect", {"Location": target}, io.BytesIO())

    monkeypatch.setattr(transport, "managed_urlopen", open_managed)
    with pytest.raises(ValueError, match="destination"):
        transport.download("https://github.com/asset", 100)
    assert len(calls) == 1


def test_approved_redirect_reenters_managed_transport_without_credentials(monkeypatch):
    calls = []

    def open_managed(request, **kwargs):
        calls.append(request)
        assert kwargs["allow_redirects"] is False
        assert request.get_header("Authorization") is None
        if len(calls) == 1:
            raise urllib.error.HTTPError(
                request.full_url,
                302,
                "redirect",
                {"Location": "https://release-assets.githubusercontent.com/asset"},
                io.BytesIO(),
            )
        return Response(b"ok", {"Content-Length": "2"})

    monkeypatch.setattr(transport, "managed_urlopen", open_managed)
    assert transport.download("https://github.com/asset", 100) == b"ok"
    assert len(calls) == 2


def test_transient_refusals_are_retried_and_permanent_ones_are_not(monkeypatch):
    monkeypatch.setattr(transport.time, "sleep", lambda seconds: None)
    calls = []

    def refusing(status, body=b"ok"):
        def open_managed(request, **kwargs):
            calls.append(request.full_url)
            if len(calls) <= 2:
                raise urllib.error.HTTPError(request.full_url, status, "refused", {}, io.BytesIO())
            return Response(body, {"Content-Length": str(len(body))})

        return open_managed

    monkeypatch.setattr(transport, "managed_urlopen", refusing(429))
    assert transport.download("https://github.com/asset", 100) == b"ok"
    assert len(calls) == 3

    calls.clear()
    monkeypatch.setattr(transport, "managed_urlopen", refusing(503))
    assert transport.download("https://github.com/asset", 100) == b"ok"
    assert len(calls) == 3

    # A connection that never completed is the same transient shape.
    calls.clear()

    def unreachable(request, **kwargs):
        calls.append(request.full_url)
        if len(calls) <= 2:
            raise urllib.error.URLError("unreachable")
        return Response(b"ok", {"Content-Length": "2"})

    monkeypatch.setattr(transport, "managed_urlopen", unreachable)
    assert transport.download("https://github.com/asset", 100) == b"ok"
    assert len(calls) == 3

    # A missing release and a refused request are answers, not outages.
    for status, error in ((404, transport.MissingReleaseError), (403, urllib.error.HTTPError)):
        calls.clear()

        def permanent(request, _status=status, **kwargs):
            calls.append(request.full_url)
            raise urllib.error.HTTPError(request.full_url, _status, "no", {}, io.BytesIO())

        monkeypatch.setattr(transport, "managed_urlopen", permanent)
        with pytest.raises(error):
            transport.download("https://github.com/asset", 100)
        assert len(calls) == 1


def test_retry_gives_up_after_a_bounded_number_of_attempts(monkeypatch):
    monkeypatch.setattr(transport.time, "sleep", lambda seconds: None)
    calls = []

    def open_managed(request, **kwargs):
        calls.append(request.full_url)
        raise urllib.error.HTTPError(request.full_url, 503, "refused", {}, io.BytesIO())

    monkeypatch.setattr(transport, "managed_urlopen", open_managed)
    with pytest.raises(urllib.error.HTTPError):
        transport.download("https://github.com/asset", 100)
    assert len(calls) == len(transport._RETRY_DELAYS) + 1


def test_redirect_loop_is_bounded(monkeypatch):
    calls = []

    def open_managed(request, **kwargs):
        calls.append(request)
        raise urllib.error.HTTPError(request.full_url, 302, "redirect", {"Location": "/asset"}, io.BytesIO())

    monkeypatch.setattr(transport, "managed_urlopen", open_managed)
    with pytest.raises(ValueError, match="redirect limit"):
        transport.download("https://github.com/asset", 100)
    assert len(calls) == 5


def test_pointer_digest_and_publication_are_bound_before_returning_a_root(monkeypatch):
    selection = {
        "schema": "guard.extension-distribution-selector.v2",
        "source_sha": "1" * 40,
        "publication_id": "12.1",
        "root_sha256": "2" * 64,
    }
    monkeypatch.setattr(transport, "root_assets", lambda *args: (b"changed", b"proof"))
    monkeypatch.setattr(
        transport, "verify_distribution", lambda *args, **kwargs: pytest.fail("substituted root reached verification")
    )
    with pytest.raises(ValueError, match="differs from advisory"):
        transport.fetch_root(now=1000, selection=selection)


def test_untrusted_location_cannot_choose_a_url_or_path():
    for value in ({"url": "https://evil.invalid/object"}, {"tag": "../data", "asset": "object-" + "1" * 64 + ".json"}):
        with pytest.raises(ValueError, match="location"):
            transport.fetch_object(value, 100)


def test_selector_is_bounded_and_never_treats_a_local_build_as_published(monkeypatch):
    value = {
        "schema": "guard.extension-distribution-selector.v2",
        "source_sha": "1" * 40,
        "publication_id": "0.0",
        "root_sha256": "2" * 64,
    }
    monkeypatch.setattr(transport, "download", lambda *args: json.dumps(value).encode())
    with pytest.raises(ValueError, match="local publication"):
        transport.selected()
