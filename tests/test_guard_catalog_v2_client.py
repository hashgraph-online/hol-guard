"""Typed v2 catalog client: 200/304, fallback rules, traversal integrity, CLI parity."""

from __future__ import annotations

import argparse
import functools
import io
import json
import threading
from collections.abc import Callable, Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace
from typing import cast
from urllib.parse import parse_qs, urlsplit

import pytest

from codex_plugin_scanner.guard import native_catalog_read as transport
from codex_plugin_scanner.guard.cli import extension_catalog_reads as reads
from codex_plugin_scanner.guard.cli import extension_controls_commands
from codex_plugin_scanner.guard.daemon import catalog_read_v2
from codex_plugin_scanner.guard.daemon import server as server_module
from codex_plugin_scanner.guard.daemon.catalog_v2_client import (
    CatalogTraversalError,
    CatalogV2Client,
    CatalogV2UnsupportedError,
)
from codex_plugin_scanner.guard.daemon.client import GuardDaemonRequestError, GuardSurfaceDaemonClient
from codex_plugin_scanner.guard.daemon.manager import load_guard_daemon_auth_token
from codex_plugin_scanner.guard.daemon.server import GuardDaemonServer
from codex_plugin_scanner.guard.runtime.command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY
from codex_plugin_scanner.guard.store import GuardStore

Reply = tuple[int, dict[str, str], bytes]
Responder = Callable[[str, dict[str, list[str]], str | None], Reply]


def _json(status: int, payload: object, etag: str | None = None) -> Reply:
    headers = {"Content-Type": "application/json"}
    if etag is not None:
        headers["ETag"] = etag
    return status, headers, json.dumps(payload).encode()


def _page(items: list[str], *, total: int, cursor: str | None, snapshot: str = "cs1-a") -> dict[str, object]:
    return {
        "snapshot_id": snapshot,
        "native_catalog_digest": "d" * 64,
        "total_count": total,
        "items": [{"extension_id": item} for item in items],
        "next_cursor": cursor,
    }


class _Server:
    def __init__(self, responder: Responder) -> None:
        self.responder = responder
        self.requests: list[tuple[str, str | None]] = []
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                parsed = urlsplit(self.path)
                validator = self.headers.get("If-None-Match")
                outer.requests.append((self.path, validator))
                if self.headers.get("X-Guard-Token") != "token":
                    status, headers, body = _json(401, {"error": "unauthorized"})
                else:
                    status, headers, body = outer.responder(parsed.path, parse_qs(parsed.query), validator)
                self.send_response(status)
                for key, value in headers.items():
                    self.send_header(key, value)
                if status != 304:
                    self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                if status != 304:
                    self.wfile.write(body)

            def log_message(self, format: str, *args: object) -> None:  # noqa: A002
                return

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()

    def client(self, token: str = "token") -> GuardSurfaceDaemonClient:
        return GuardSurfaceDaemonClient(f"http://127.0.0.1:{self.httpd.server_address[1]}", token)

    def close(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()


@pytest.fixture
def serve() -> Iterator[Callable[[Responder], _Server]]:
    servers: list[_Server] = []

    def start(responder: Responder) -> _Server:
        server = _Server(responder)
        servers.append(server)
        return server

    yield start
    for server in servers:
        server.close()


def test_get_revalidates_and_reuses_cached_body_on_304(serve: Callable[[Responder], _Server]) -> None:
    def responder(_path: str, _query: dict[str, list[str]], validator: str | None) -> Reply:
        if validator == '"cr1-x"':
            return 304, {"ETag": '"cr1-x"'}, b""
        return _json(200, {"value": 1}, '"cr1-x"')

    server = serve(responder)
    reader = CatalogV2Client(server.client())
    assert reader.get("index") == {"value": 1}
    assert reader.get("index") == {"value": 1}
    assert [validator for _, validator in server.requests] == [None, '"cr1-x"']


def test_unsatisfiable_304_gets_one_unconditional_retry(serve: Callable[[Responder], _Server]) -> None:
    calls = {"count": 0}

    def responder(_path: str, _query: dict[str, list[str]], validator: str | None) -> Reply:
        calls["count"] += 1
        if calls["count"] == 2:
            return 304, {"ETag": '"cr1-other"'}, b""
        return _json(200, {"value": calls["count"]}, f'"cr1-{calls["count"]}"')

    server = serve(responder)
    reader = CatalogV2Client(server.client())
    assert reader.get("index") == {"value": 1}
    assert reader.get("index") == {"value": 3}
    assert [validator for _, validator in server.requests] == [None, '"cr1-1"', None]


@pytest.mark.parametrize(
    "reply",
    [
        (404, {}, b""),
        _json(404, {"error": "not_found"}),
        _json(501, {"error": "catalog_read_model_unavailable"}),
    ],
)
def test_protocol_absence_is_the_only_fallback_signal(serve: Callable[[Responder], _Server], reply: Reply) -> None:
    server = serve(lambda *_args: reply)
    with pytest.raises(CatalogV2UnsupportedError):
        CatalogV2Client(server.client()).get("index")


@pytest.mark.parametrize(
    ("reply", "code"),
    [
        (_json(404, {"error": "catalog_extension_not_found"}), "catalog_extension_not_found"),
        (_json(413, {"error": "too_large"}), "too_large"),
        (_json(429, {"error": "rate_limited"}), "rate_limited"),
        (_json(500, {"error": "catalog_item_exceeds_page_budget"}), "catalog_item_exceeds_page_budget"),
        (_json(503, {"error": "catalog_snapshot_mismatch"}), "catalog_snapshot_mismatch"),
    ],
)
def test_real_errors_never_fall_back(serve: Callable[[Responder], _Server], reply: Reply, code: str) -> None:
    server = serve(lambda *_args: reply)
    with pytest.raises(GuardDaemonRequestError) as raised:
        CatalogV2Client(server.client()).get("index")
    assert not isinstance(raised.value, CatalogV2UnsupportedError)
    assert raised.value.code == code


def test_auth_failure_does_not_fall_back_to_v1(serve: Callable[[Responder], _Server]) -> None:
    server = serve(lambda *_args: _json(200, {}, '"cr1-x"'))
    client = server.client(token="wrong")
    with pytest.raises(GuardDaemonRequestError) as raised:
        reads.catalog_list(client)
    assert raised.value.status == 401
    assert all(path.startswith("/v2/") for path, _ in server.requests)


def test_old_daemon_falls_back_to_v1_catalog(serve: Callable[[Responder], _Server]) -> None:
    legacy = {"catalog_digest": "d" * 64, "extensions": [{"extension_id": "command.a", "permissions": []}]}

    def responder(path: str, _query: dict[str, list[str]], _validator: str | None) -> Reply:
        if path == "/v1/extension-controls/catalog":
            return _json(200, legacy)
        return 404, {}, b""

    server = serve(responder)
    assert reads.catalog_list(server.client()) == legacy
    assert reads.catalog_show(server.client(), "command.a") == legacy["extensions"][0]


def _paged(pages: dict[str | None, dict[str, object]]) -> Responder:
    def responder(_path: str, query: dict[str, list[str]], _validator: str | None) -> Reply:
        cursor = query.get("cursor", [None])[0]
        return _json(200, pages[cursor], f'"cr1-{cursor}"')

    return responder


def test_traversal_collects_every_page_in_order(serve: Callable[[Responder], _Server]) -> None:
    server = serve(_paged({None: _page(["a", "b"], total=3, cursor="c1"), "c1": _page(["c"], total=3, cursor=None)}))
    traversal = CatalogV2Client(server.client()).traverse("index", item_key="extension_id")
    assert [item["extension_id"] for item in traversal.items] == ["a", "b", "c"]
    assert all("limit=100" in path for path, _ in server.requests)


@pytest.mark.parametrize(
    "pages",
    [
        {None: _page(["a"], total=2, cursor="c1"), "c1": _page(["a"], total=2, cursor=None)},
        {None: _page(["a"], total=3, cursor="c1"), "c1": _page(["b"], total=3, cursor="c1")},
        {None: _page(["a"], total=2, cursor=None)},
        {None: _page([], total=2, cursor="c1"), "c1": _page(["a", "b"], total=2, cursor=None)},
    ],
)
def test_traversal_rejects_duplicates_loops_and_incomplete_results(
    serve: Callable[[Responder], _Server], pages: dict[str | None, dict[str, object]]
) -> None:
    server = serve(_paged(pages))
    with pytest.raises(CatalogTraversalError):
        CatalogV2Client(server.client()).traverse("index", item_key="extension_id")


def test_traversal_restarts_once_when_snapshot_changes(serve: Callable[[Responder], _Server]) -> None:
    state = {"first": True}

    def responder(_path: str, query: dict[str, list[str]], _validator: str | None) -> Reply:
        cursor = query.get("cursor", [None])[0]
        if cursor is None:
            snapshot = "cs1-old" if state["first"] else "cs1-new"
            return _json(200, _page(["a"], total=2, cursor="c1", snapshot=snapshot), f'"cr1-{snapshot}"')
        if state["first"]:
            state["first"] = False
            return _json(409, {"error": "catalog_snapshot_expired"})
        return _json(200, _page(["b"], total=2, cursor=None, snapshot="cs1-new"), '"cr1-b"')

    server = serve(responder)
    traversal = CatalogV2Client(server.client()).traverse("index", item_key="extension_id")
    assert traversal.snapshot_id == "cs1-new"
    assert [item["extension_id"] for item in traversal.items] == ["a", "b"]


def test_traversal_gives_up_after_a_second_snapshot_change(serve: Callable[[Responder], _Server]) -> None:
    def responder(_path: str, query: dict[str, list[str]], _validator: str | None) -> Reply:
        if query.get("cursor"):
            return _json(409, {"error": "catalog_snapshot_expired"})
        return _json(200, _page(["a"], total=2, cursor="c1"), '"cr1-a"')

    server = serve(responder)
    with pytest.raises(CatalogTraversalError):
        CatalogV2Client(server.client()).traverse("index", item_key="extension_id")


@pytest.fixture
def native_daemon(
    native_hook_force: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> Iterator[SimpleNamespace]:
    from codex_plugin_scanner.guard.native_resident_client import close_native_residents

    # Debug builds construct the snapshot slowly on the first read; the default
    # 2s native budget is a production bound, not what parity tests measure.
    monkeypatch.setattr(
        server_module,
        "serve_catalog_read_v2",
        functools.partial(
            catalog_read_v2.serve_catalog_read_v2,
            reader=functools.partial(transport.native_catalog_read, timeout_seconds=60.0),
        ),
    )
    store = GuardStore(tmp_path / "guard-home")
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    daemon.start()
    try:
        token = load_guard_daemon_auth_token(store.guard_home)
        assert token is not None
        client = GuardSurfaceDaemonClient(f"http://127.0.0.1:{daemon.port}", token)
        # A cold debug resident can miss the Rust client's fixed 9s start window
        # while it also builds the snapshot; warm it with a bounded retry.
        for attempt in range(3):
            try:
                CatalogV2Client(client, timeout=60.0).get("index")
                break
            except CatalogV2UnsupportedError:
                if attempt == 2:
                    raise
        yield SimpleNamespace(client=client, guard_home=store.guard_home, native=native_hook_force)
    finally:
        daemon.stop()
        close_native_residents(store.guard_home)


def test_real_native_v2_reproduces_every_v1_extension_exactly(native_daemon: SimpleNamespace) -> None:
    """Golden cross-language parity: Rust v2 pages reassemble the Python v1 objects."""

    client = native_daemon.client
    expected = {
        extension.extension_id: extension.to_dict() for extension in BUILT_IN_COMMAND_EXTENSION_REGISTRY.extensions
    }
    listing = reads.catalog_list(client)
    assert listing["schema_version"] == reads.CATALOG_LIST_SCHEMA
    assert listing["native_catalog_digest"] == BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest
    listed = listing["extensions"]
    assert isinstance(listed, list)
    assert [item["extension_id"] for item in listed] == sorted(expected)
    reader = CatalogV2Client(client)
    for extension_id, legacy in expected.items():
        assert reads.v1_extension_from_v2(reader, extension_id) == legacy, extension_id


def _patterns_output(client: GuardSurfaceDaemonClient, query: str, tool: str | None) -> dict[str, object]:
    output = io.StringIO()
    args = argparse.Namespace(query=query, tool=tool, json=True)
    assert extension_controls_commands._patterns(client, args, output) == 0
    return json.loads(output.getvalue())


@pytest.mark.parametrize(
    ("query", "tool"),
    [("", None), ("push", None), ("git push", None), ("FORCE", None), ("zz-none", None), ("", "command.git")],
)
def test_real_native_cli_patterns_output_matches_v1(
    native_daemon: SimpleNamespace, monkeypatch: pytest.MonkeyPatch, query: str, tool: str | None
) -> None:
    client = native_daemon.client
    v2 = _patterns_output(client, query, tool)
    with monkeypatch.context() as patch:
        patch.setattr(reads, "catalog_reader", lambda _client: None)
        v1 = _patterns_output(client, query, tool)
    assert v2 == v1
    if query == "push":
        count = v2["count"]
        assert isinstance(count, int) and count > 0


def test_real_native_patterns_search_is_bounded_and_rust_filtered(native_daemon: SimpleNamespace) -> None:
    requests: list[str] = []
    original = CatalogV2Client._request

    def counting(self: CatalogV2Client, route: str, query: str, *, if_none_match: str | None):
        requests.append(f"{route}?{query}")
        return original(self, route, query, if_none_match=if_none_match)

    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(CatalogV2Client, "_request", counting)
        rows = reads.pattern_extensions(native_daemon.client, None, "git push")
    assert len(requests) <= 4, requests
    assert any(route.startswith("permissions?") and "q=git+push" in route for route in requests)
    assert rows and all(row["permissions"] for row in rows)
    assert reads.pattern_extensions(native_daemon.client, "command.missing") == []
    with pytest.raises(ValueError, match="unknown extension target"):
        reads.catalog_show(native_daemon.client, "command.missing")


def test_patterns_search_skips_q_when_its_encoding_exceeds_the_query_cap() -> None:
    sent: list[dict[str, str] | None] = []

    class _Reader:
        def traverse(self, route: str, *, item_key: str, params: dict[str, str] | None = None) -> SimpleNamespace:
            if route == "permissions":
                sent.append(params)
            return SimpleNamespace(items=[])

    reader = cast(CatalogV2Client, _Reader())
    reads._v2_permission_search(reader, "git push")
    # 220 CJK characters fit the character bound but percent-encode to 1,980 bytes.
    reads._v2_permission_search(reader, "推" * 220)
    assert sent == [{"q": "git push"}, None]


def _detail(snapshot: str, *, permissions: int) -> dict[str, object]:
    return {
        "snapshot_id": snapshot,
        "native_catalog_digest": "d" * 64,
        "extension": {"extension_id": "command.a", "catalog_defaults": {"enabled": True, "activation": "default"}},
        "collections": {"permissions": {"total_count": permissions}, "rules": {"total_count": 0}},
    }


def _collection(snapshot: str, key: str, ids: list[str]) -> dict[str, object]:
    return {
        "snapshot_id": snapshot,
        "native_catalog_digest": "d" * 64,
        "total_count": len(ids),
        "items": [{key: item} for item in ids],
        "next_cursor": None,
    }


def test_show_restarts_when_a_collection_comes_from_another_snapshot(serve: Callable[[Responder], _Server]) -> None:
    details = iter(["cs1-old", "cs1-new"])

    def responder(path: str, _query: dict[str, list[str]], _validator: str | None) -> Reply:
        if path.endswith("/permissions"):
            return _json(200, _collection("cs1-new", "permission_id", ["p1", "p2"]), '"cr1-p"')
        if path.endswith("/rules"):
            return _json(200, _collection("cs1-new", "rule_id", []), '"cr1-r"')
        snapshot = next(details)
        return _json(200, _detail(snapshot, permissions=2), f'"cr1-{snapshot}"')

    server = serve(responder)
    extension = reads.v1_extension_from_v2(CatalogV2Client(server.client()), "command.a")
    assert [item["permission_id"] for item in extension["permissions"]] == ["p1", "p2"]  # type: ignore[index]
    assert sum(path.endswith("/command.a") for path, _ in server.requests) == 2


def test_show_rejects_a_collection_that_disagrees_with_its_detail(serve: Callable[[Responder], _Server]) -> None:
    def responder(path: str, _query: dict[str, list[str]], _validator: str | None) -> Reply:
        if path.endswith("/permissions"):
            return _json(200, _collection("cs1-a", "permission_id", ["p1"]), '"cr1-p"')
        return _json(200, _detail("cs1-a", permissions=2), '"cr1-a"')

    server = serve(responder)
    with pytest.raises(CatalogTraversalError, match="does not match its detail"):
        reads.v1_extension_from_v2(CatalogV2Client(server.client()), "command.a")
