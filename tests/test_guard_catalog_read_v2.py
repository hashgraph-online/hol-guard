"""Transport, authentication and fallback tests for the v2 catalog read model.

Rust owns paging, cursors and ETags (covered by ``catalog_read_model_tests.rs``);
these tests pin the thin Python boundary: frame validation, request bounds,
authentication on every ``/v2`` route, 501 fallback and verbatim body delivery.
"""

from __future__ import annotations

import ast
import functools
import json
import urllib.error
import urllib.request
from collections.abc import Callable, Iterator
from pathlib import Path
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard import native_catalog_read as transport
from codex_plugin_scanner.guard import native_runtime_resilience as resilience
from codex_plugin_scanner.guard.daemon import catalog_read_v2
from codex_plugin_scanner.guard.daemon import server as server_module
from codex_plugin_scanner.guard.daemon.manager import load_guard_daemon_auth_token
from codex_plugin_scanner.guard.daemon.server import GuardDaemonServer
from codex_plugin_scanner.guard.native_catalog_read import NativeCatalogReadResult
from codex_plugin_scanner.guard.runtime.command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY
from codex_plugin_scanner.guard.store import GuardStore

ETAG = '"cr1-' + "a" * 32 + '"'
DIGEST = BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest
V2_ROUTES = (
    "/v2/extension-controls/catalog/index",
    "/v2/extension-controls/catalog/index?limit=1",
    "/v2/extension-controls/catalog/extensions/command.git",
    "/v2/extension-controls/catalog/extensions/command.git/permissions",
    "/v2/extension-controls/catalog/extensions/command.git/rules",
    "/v2/extension-controls/catalog/extensions/command.git/mcp-tools",
    "/v2/unknown",
)


def _frame(**overrides: object) -> dict[str, object]:
    frame: dict[str, object] = {
        "schema": "guard-catalog-read-result.v1",
        "outcome": "ok",
        "http_status": 200,
        "etag": ETAG,
        "body": '{"items":[]}',
        "error_code": None,
    }
    frame.update(overrides)
    return frame


def test_result_frame_accepts_exact_ok_not_modified_and_error_shapes() -> None:
    ok = transport._validated_result(_frame())
    assert ok == NativeCatalogReadResult(status=200, etag=ETAG, body=b'{"items":[]}')
    not_modified = transport._validated_result(_frame(outcome="not_modified", http_status=304, body=None))
    assert not_modified == NativeCatalogReadResult(status=304, etag=ETAG)
    error = transport._validated_result(
        _frame(outcome="error", http_status=409, etag=None, body=None, error_code="catalog_snapshot_expired")
    )
    assert error == NativeCatalogReadResult(status=409, error_code="catalog_snapshot_expired")


@pytest.mark.parametrize(
    "frame",
    [
        _frame(schema="guard-catalog-read-result.v2"),
        _frame(extra=True),
        {key: value for key, value in _frame().items() if key != "error_code"},
        _frame(http_status=201),
        _frame(etag='W/"cr1-' + "a" * 32 + '"'),
        _frame(etag='"cr1-short"'),
        _frame(body=None),
        _frame(body={"items": []}),
        _frame(error_code="catalog_query_invalid"),
        _frame(body="x" * (transport.MAX_CATALOG_V2_BODY_BYTES + 1)),
        _frame(outcome="not_modified", http_status=304),
        _frame(outcome="not_modified", http_status=200, body=None),
        _frame(outcome="error", http_status=400, etag=None, body=None, error_code="catalog_snapshot_expired"),
        _frame(outcome="error", http_status=500, etag=None, body=None, error_code="made_up"),
        _frame(outcome="error", http_status=409, body=None, error_code="catalog_snapshot_expired"),
        _frame(outcome="partial"),
        [],
    ],
)
def test_result_frame_rejects_inconsistent_or_unbounded_shapes(frame: object) -> None:
    assert transport._validated_result(frame) is None


class _Resident:
    def __init__(self, response: bytes | None) -> None:
        self.response = response
        self.payloads: list[dict[str, object]] = []
        self.failures: list[str] = []
        self.successes = 0

    def install(self, monkeypatch: pytest.MonkeyPatch, *, available: bool = True) -> None:
        identity = SimpleNamespace(path=Path("/native"), sha256="0" * 64)
        self.status_probes: list[float | None] = []

        def status(*, deadline_monotonic: float | None = None) -> SimpleNamespace:
            self.status_probes.append(deadline_monotonic)
            return SimpleNamespace(identity=identity)

        monkeypatch.setattr(transport, "native_runtime_status", status)
        monkeypatch.setattr(transport, "_supports_catalog_read", lambda _status: available)
        monkeypatch.setattr(transport, "_isolated_environment", dict)
        monkeypatch.setattr(transport, "native_resident_client_request", self.request)
        monkeypatch.setattr(
            resilience, "native_record_resident_failure", lambda *args, reason: self.failures.append(reason)
        )
        monkeypatch.setattr(resilience, "native_record_resident_success", lambda *args: self.record_success())

    def record_success(self) -> None:
        self.successes += 1

    def request(self, **kwargs: object) -> bytes | None:
        payload = kwargs["payload"]
        assert isinstance(payload, bytes)
        self.payloads.append(json.loads(payload))
        return self.response


def _read(
    tmp_path: Path,
    *,
    route: str = "index",
    query: str = "limit=2",
    if_none_match: str | None = ETAG,
    expected_catalog_digest: str = DIGEST,
) -> NativeCatalogReadResult | None:
    return transport.native_catalog_read(
        guard_home=tmp_path,
        route=route,
        query=query,
        if_none_match=if_none_match,
        expected_catalog_digest=expected_catalog_digest,
    )


def test_transport_forwards_raw_request_and_returns_body_bytes(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    resident = _Resident(json.dumps(_frame()).encode())
    resident.install(monkeypatch)
    assert _read(tmp_path) == NativeCatalogReadResult(status=200, etag=ETAG, body=b'{"items":[]}')
    assert resident.payloads[0]["operation"] == "catalog_read"
    assert resident.payloads[0]["request"] == {
        "schema": "guard-catalog-read-request.v1",
        "route": "index",
        "query": "limit=2",
        "if_none_match": ETAG,
        "expected_catalog_digest": DIGEST,
    }
    # Catalog reads never touch the shared hook circuit health.
    assert resident.successes == 0 and resident.failures == []
    # One status probe per read, bounded by the same deadline as the resident call.
    assert len(resident.status_probes) == 1 and resident.status_probes[0] is not None


def test_busy_resident_is_a_retryable_fault_not_protocol_absence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    resident = _Resident(None)
    resident.install(monkeypatch)
    assert _read(tmp_path) == NativeCatalogReadResult(status=503, error_code=transport.CATALOG_READ_TRANSPORT_FAILED)
    assert resident.failures == []


@pytest.mark.parametrize(
    ("response", "reason"),
    [
        (b"\xff", "malformed"),
        (b'{"schema":"a","schema":"b"}', "duplicate-key"),
        (json.dumps(_frame(http_status=201)).encode(), "schema"),
    ],
)
def test_transport_failures_are_unavailable_without_tripping_hook_circuit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, response: bytes | None, reason: str
) -> None:
    resident = _Resident(response)
    resident.install(monkeypatch)
    assert _read(tmp_path) is None, reason
    assert resident.failures == [] and resident.successes == 0


def test_transport_bounds_requests_before_native_dispatch(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    resident = _Resident(json.dumps(_frame()).encode())
    resident.install(monkeypatch)
    assert _read(tmp_path, route="x" * 513) == NativeCatalogReadResult(status=404, error_code="catalog_route_not_found")
    assert _read(tmp_path, query="q=" + "x" * 2047) == NativeCatalogReadResult(
        status=400, error_code="catalog_query_invalid"
    )
    assert _read(tmp_path, expected_catalog_digest="not-a-digest") is None
    assert resident.payloads == []
    _read(tmp_path, if_none_match='"' + "x" * 2048 + '"')
    request = resident.payloads[0]["request"]
    assert isinstance(request, dict) and request["if_none_match"] is None


def test_transport_without_capability_is_unavailable(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    resident = _Resident(json.dumps(_frame()).encode())
    resident.install(monkeypatch, available=False)
    assert _read(tmp_path) is None
    assert resident.payloads == []


class _Recorder:
    def __init__(self, result: NativeCatalogReadResult | None) -> None:
        self.result = result
        self.calls: list[dict[str, object]] = []

    def __call__(self, **kwargs: object) -> NativeCatalogReadResult | None:
        self.calls.append(kwargs)
        return self.result


@pytest.fixture
def daemon(tmp_path: Path) -> Iterator[SimpleNamespace]:
    store = GuardStore(tmp_path / "guard-home")
    server = GuardDaemonServer(store, host="127.0.0.1", port=0)
    server.start()
    try:
        token = load_guard_daemon_auth_token(store.guard_home)
        assert token is not None
        yield SimpleNamespace(port=server.port, token=token, guard_home=store.guard_home)
    finally:
        server.stop()


def _use_reader(monkeypatch: pytest.MonkeyPatch, reader: Callable[..., NativeCatalogReadResult | None]) -> None:
    monkeypatch.setattr(
        server_module,
        "serve_catalog_read_v2",
        functools.partial(catalog_read_v2.serve_catalog_read_v2, reader=reader),
    )


def _get(
    daemon: SimpleNamespace, path: str, headers: dict[str, str], *, timeout: float = 10.0
) -> tuple[int, dict[str, str], bytes]:
    request = urllib.request.Request(f"http://127.0.0.1:{daemon.port}{path}", headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return response.status, dict(response.headers), response.read()
    except urllib.error.HTTPError as error:
        return error.code, dict(error.headers), error.read()


@pytest.mark.parametrize("path", V2_ROUTES)
@pytest.mark.parametrize(
    "headers",
    [
        {},
        {"If-None-Match": ETAG},
        {"X-Guard-Token": "wrong"},
        {"X-Guard-Token": "wrong", "If-None-Match": "*"},
    ],
)
def test_every_v2_route_requires_header_auth_before_native_dispatch(
    daemon: SimpleNamespace, monkeypatch: pytest.MonkeyPatch, path: str, headers: dict[str, str]
) -> None:
    reader = _Recorder(NativeCatalogReadResult(status=304, etag=ETAG))
    _use_reader(monkeypatch, reader)
    status, response_headers, _ = _get(daemon, path, headers)
    assert status == 401
    assert "ETag" not in response_headers
    assert reader.calls == []


def test_v2_rejects_query_string_token(daemon: SimpleNamespace, monkeypatch: pytest.MonkeyPatch) -> None:
    reader = _Recorder(NativeCatalogReadResult(status=200, etag=ETAG, body=b"{}"))
    _use_reader(monkeypatch, reader)
    token = daemon.token
    path = f"/v2/extension-controls/catalog/index?token={token}"
    status, _, _ = _get(daemon, path, {"X-Guard-Token": token})
    assert status == 401
    assert reader.calls == []


def test_authenticated_v2_serves_native_bytes_verbatim(
    daemon: SimpleNamespace, monkeypatch: pytest.MonkeyPatch
) -> None:
    body = b'{"items":[],"note":"\\u003cb\\u003e"}'
    reader = _Recorder(NativeCatalogReadResult(status=200, etag=ETAG, body=body))
    _use_reader(monkeypatch, reader)
    status, headers, received = _get(
        daemon,
        "/v2/extension-controls/catalog/index?limit=2&q=git",
        {"X-Guard-Token": daemon.token},
    )
    assert (status, received) == (200, body)
    assert headers["ETag"] == ETAG
    assert headers["Cache-Control"] == "private, no-cache"
    assert headers["X-Content-Type-Options"] == "nosniff"
    assert headers["Content-Type"].startswith("application/json")
    assert reader.calls == [
        {
            "guard_home": daemon.guard_home,
            "route": "index",
            "query": "limit=2&q=git",
            "if_none_match": None,
            "expected_catalog_digest": DIGEST,
        }
    ]


def test_authenticated_v2_not_modified_has_etag_and_no_body(
    daemon: SimpleNamespace, monkeypatch: pytest.MonkeyPatch
) -> None:
    reader = _Recorder(NativeCatalogReadResult(status=304, etag=ETAG))
    _use_reader(monkeypatch, reader)
    status, headers, body = _get(
        daemon,
        "/v2/extension-controls/catalog/extensions/command.git",
        {"X-Guard-Token": daemon.token, "If-None-Match": ETAG},
    )
    assert (status, body) == (304, b"")
    assert headers["ETag"] == ETAG
    assert reader.calls[0]["if_none_match"] == ETAG


@pytest.mark.parametrize(
    ("result", "status", "code"),
    [
        (None, 501, "catalog_read_model_unavailable"),
        (NativeCatalogReadResult(status=409, error_code="catalog_snapshot_expired"), 409, "catalog_snapshot_expired"),
        (NativeCatalogReadResult(status=400, error_code="catalog_cursor_invalid"), 400, "catalog_cursor_invalid"),
    ],
)
def test_authenticated_v2_errors_are_typed_and_uncached(
    daemon: SimpleNamespace,
    monkeypatch: pytest.MonkeyPatch,
    result: NativeCatalogReadResult | None,
    status: int,
    code: str,
) -> None:
    _use_reader(monkeypatch, _Recorder(result))
    received_status, headers, body = _get(
        daemon,
        "/v2/extension-controls/catalog/index",
        {"X-Guard-Token": daemon.token},
    )
    assert received_status == status
    assert json.loads(body) == {"error": code}
    assert headers["Cache-Control"] == "no-store"
    assert "ETag" not in headers


@pytest.mark.parametrize("value", ["off", "0", "false", " Disabled "])
def test_rollback_switch_answers_unavailable_without_native_dispatch(
    daemon: SimpleNamespace, monkeypatch: pytest.MonkeyPatch, value: str
) -> None:
    reader = _Recorder(NativeCatalogReadResult(status=200, etag=ETAG, body=b"{}"))
    _use_reader(monkeypatch, reader)
    monkeypatch.setenv(catalog_read_v2.CATALOG_V2_ROLLOUT_ENV, value)
    status, headers, body = _get(daemon, "/v2/extension-controls/catalog/index", {"X-Guard-Token": daemon.token})
    assert status == 501
    assert json.loads(body) == {"error": "catalog_read_model_unavailable"}
    assert "ETag" not in headers
    assert reader.calls == []


@pytest.mark.parametrize("value", [None, "", "on", "1"])
def test_v2_read_path_is_on_unless_switched_off(value: str | None) -> None:
    environ = {} if value is None else {catalog_read_v2.CATALOG_V2_ROLLOUT_ENV: value}
    assert catalog_read_v2.catalog_read_v2_enabled(environ)


def test_authenticated_unknown_v2_path_is_not_found(daemon: SimpleNamespace, monkeypatch: pytest.MonkeyPatch) -> None:
    reader = _Recorder(None)
    _use_reader(monkeypatch, reader)
    status, _, body = _get(daemon, "/v2/unknown", {"X-Guard-Token": daemon.token})
    assert status == 404
    assert json.loads(body) == {"error": "not_found"}
    assert reader.calls == []


def test_v2_python_boundary_never_reserializes_the_catalog() -> None:
    """Python must not build v2 content: no registry, ``to_dict`` or body parsing."""

    for module in (transport, catalog_read_v2):
        source = Path(module.__file__ or "").read_text(encoding="utf-8")
        names = {node.id for node in ast.walk(ast.parse(source)) if isinstance(node, ast.Name)}
        attributes = {node.attr for node in ast.walk(ast.parse(source)) if isinstance(node, ast.Attribute)}
        assert "to_dict" not in attributes
        assert "extensions" not in attributes
        assert not any("REGISTRY" in name for name in names)
    # The only JSON parse in the transport is the result frame, never ``body``.
    transport_source = Path(transport.__file__ or "").read_text(encoding="utf-8")
    assert transport_source.count("json.loads(") == 1


_V2_READ_MODULES = frozenset({"native_catalog_read", "catalog_read_v2", "catalog_v2_client"})


def _imported_modules(tree: ast.AST) -> set[str]:
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            names.update((node.module or "").split("."))
            names.update(alias.name for alias in node.names)
        elif isinstance(node, ast.Import):
            for alias in node.names:
                names.update(alias.name.split("."))
    return names


def test_v2_read_model_is_reachable_only_from_read_paths() -> None:
    """Catalog read metadata must not reach authority, mutation, hook or Cloud code."""

    package = Path(transport.__file__ or "").parent
    importers = {
        path.relative_to(package).as_posix()
        for path in package.rglob("*.py")
        if path.stem not in _V2_READ_MODULES
        and _imported_modules(ast.parse(path.read_text(encoding="utf-8"))) & _V2_READ_MODULES
    }
    # The daemon GET route and the CLI catalog readers are the only callers.
    assert importers == {"daemon/server.py", "cli/extension_catalog_reads.py"}
    # The v2 modules import transport helpers only: no store, authority, policy or sync code.
    for module in _V2_READ_MODULES:
        source = next(package.rglob(f"{module}.py")).read_text(encoding="utf-8")
        imported = _imported_modules(ast.parse(source))
        assert not imported & {"store", "authority", "extension_control_api", "extension_catalog_sync", "policy"}


def test_real_native_read_model_traverses_index_and_revalidates(
    native_hook_force: Path, daemon: SimpleNamespace, monkeypatch: pytest.MonkeyPatch
) -> None:
    from codex_plugin_scanner.guard.native_resident_client import close_native_residents

    # Debug builds construct the snapshot slowly on the first read; the default
    # 2s budget is a production bound, not what this end-to-end test measures.
    _use_reader(monkeypatch, functools.partial(transport.native_catalog_read, timeout_seconds=60.0))  # type: ignore[arg-type]
    guard_home = daemon.guard_home
    token = daemon.token
    try:
        # A cold debug resident can exceed the Rust client's fixed 9s start
        # window while it also builds the snapshot; warm it before measuring.
        warm_status = None
        for _ in range(3):
            warm_status, _, _ = _get(
                daemon, "/v2/extension-controls/catalog/index?limit=1", {"X-Guard-Token": token}, timeout=60.0
            )
            if warm_status == 200:
                break
        assert warm_status == 200
        seen: list[str] = []
        path = "/v2/extension-controls/catalog/index?limit=100"
        first_etag = None
        while True:
            status, headers, body = _get(daemon, path, {"X-Guard-Token": token}, timeout=60.0)
            assert status == 200, body
            page = json.loads(body)
            assert page["native_catalog_digest"] == DIGEST
            first_etag = first_etag or headers["ETag"]
            seen.extend(item["extension_id"] for item in page["items"])
            if page["next_cursor"] is None:
                break
            path = f"/v2/extension-controls/catalog/index?limit=100&cursor={page['next_cursor']}"
        expected = sorted(extension.extension_id for extension in BUILT_IN_COMMAND_EXTENSION_REGISTRY.extensions)
        assert seen == expected
        status, headers, body = _get(
            daemon,
            "/v2/extension-controls/catalog/index?limit=100",
            {"X-Guard-Token": token, "If-None-Match": first_etag},
        )
        assert (status, body, headers["ETag"]) == (304, b"", first_etag)
    finally:
        close_native_residents(guard_home)
