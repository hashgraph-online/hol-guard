from __future__ import annotations

import json
import urllib.error
import urllib.request
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.daemon import extension_control_api as api_module
from codex_plugin_scanner.guard.daemon.extension_control_api import (
    ExtensionControlApiError,
    ExtensionControlApiService,
)
from codex_plugin_scanner.guard.daemon.manager import load_guard_daemon_auth_token
from codex_plugin_scanner.guard.daemon.server import GuardDaemonServer
from codex_plugin_scanner.guard.json_transport import escape_json_for_html
from codex_plugin_scanner.guard.runtime.command_extensions import (
    BUILT_IN_COMMAND_EXTENSION_REGISTRY,
)
from codex_plugin_scanner.guard.runtime.extension_control_authority import (
    AuthorityHealth,
    ExtensionControlAuthorityView,
)
from codex_plugin_scanner.guard.runtime.extension_control_limits import (
    CLOUD_V1_MAX_CATALOG_PAYLOAD_BYTES,
    MAX_DAEMON_CATALOG_RESPONSE_BYTES,
)
from codex_plugin_scanner.guard.runtime.extension_control_runtime import (
    ExtensionControlRuntime,
)
from codex_plugin_scanner.guard.store import GuardStore


def _service(tmp_path: Path) -> ExtensionControlApiService:
    view = ExtensionControlAuthorityView(
        AuthorityHealth.PROTECTED,
        1,
        BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest,
        (),
    )
    return ExtensionControlApiService(
        store=GuardStore(tmp_path / "guard-home"),
        registry=BUILT_IN_COMMAND_EXTENSION_REGISTRY,
        runtime=ExtensionControlRuntime(view),
    )


def _wire_bytes(payload: dict[str, object]) -> bytes:
    return escape_json_for_html(json.dumps(payload).encode("utf-8"))


def test_catalog_payload_limit_uses_exact_daemon_wire_encoding(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service = _service(tmp_path)
    payload = service.catalog()
    wire_size = len(_wire_bytes(payload))
    unescaped_size = len(json.dumps(payload).encode("utf-8"))
    compact_size = len(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8"))
    assert wire_size > unescaped_size > compact_size
    monkeypatch.setattr(api_module, "MAX_DAEMON_CATALOG_RESPONSE_BYTES", wire_size)
    service.catalog()
    for limit in (wire_size - 1, unescaped_size):
        monkeypatch.setattr(api_module, "MAX_DAEMON_CATALOG_RESPONSE_BYTES", limit)
        with pytest.raises(ExtensionControlApiError) as raised:
            service.catalog()
        assert raised.value.status == 413
        assert raised.value.code == "catalog_payload_limit_exceeded"


def test_catalog_wire_measurement_counts_markup_escapes_and_utf8_bytes() -> None:
    payload: dict[str, object] = {"text": "<a & b> \u00e9\u6f22"}
    wire = _wire_bytes(payload)
    assert json.loads(wire) == payload
    assert b"<" not in wire and b"&" not in wire and b">" not in wire
    assert len(wire) == len(json.dumps(payload).encode("utf-8")) + 3 * len("\\u0026") - 3


def test_catalog_http_body_matches_service_wire_measurement(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    daemon.start()
    try:
        auth_token = load_guard_daemon_auth_token(store.guard_home)
        assert auth_token is not None
        request = urllib.request.Request(
            f"http://127.0.0.1:{daemon.port}/v1/extension-controls/catalog",
            method="GET",
            headers={"X-Guard-Token": auth_token},
        )
        with urllib.request.urlopen(request, timeout=10) as response:
            body = response.read()
        payload = json.loads(body)
        assert body == _wire_bytes(payload)
        assert len(body) <= MAX_DAEMON_CATALOG_RESPONSE_BYTES
        assert payload["limits"]["max_body_bytes"] == MAX_DAEMON_CATALOG_RESPONSE_BYTES
        assert payload["limits"]["max_catalog_payload_bytes"] == CLOUD_V1_MAX_CATALOG_PAYLOAD_BYTES
    finally:
        daemon.stop()


def test_catalog_http_route_maps_bounded_service_error_to_413(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = GuardStore(tmp_path / "guard-home")
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    daemon.start()
    try:
        auth_token = load_guard_daemon_auth_token(store.guard_home)
        assert auth_token is not None

        def reject_catalog() -> dict[str, object]:
            raise ExtensionControlApiError(
                413,
                "catalog_payload_limit_exceeded",
            )

        monkeypatch.setattr(
            daemon._server.extension_control_api,
            "catalog",
            reject_catalog,
        )
        request = urllib.request.Request(
            f"http://127.0.0.1:{daemon.port}/v1/extension-controls/catalog",
            method="GET",
            headers={"X-Guard-Token": auth_token},
        )
        with pytest.raises(urllib.error.HTTPError) as raised:
            urllib.request.urlopen(request, timeout=2)
        assert raised.value.code == 413
        assert json.loads(raised.value.read()) == {
            "error": "catalog_payload_limit_exceeded",
        }
    finally:
        daemon.stop()
