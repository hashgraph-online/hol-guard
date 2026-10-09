"""Representation-specific catalog delivery budgets (Stage A)."""

from __future__ import annotations

import io
import json
import time
from collections.abc import Callable, Mapping
from dataclasses import replace
from importlib import resources
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.daemon.client import (
    GuardDaemonResponseSchemaError,
    GuardSurfaceDaemonClient,
)
from codex_plugin_scanner.guard.daemon.manager import load_guard_daemon_auth_token
from codex_plugin_scanner.guard.daemon.server import GuardDaemonServer
from codex_plugin_scanner.guard.managed_controls.feature_flags import GUARD_EXTENSION_CATALOG_SYNC_V1
from codex_plugin_scanner.guard.runtime import extension_control_limits as limits_module
from codex_plugin_scanner.guard.runtime import managed_controls_sync, runner
from codex_plugin_scanner.guard.runtime.command_extensions import CommandSafetyExtensionRegistry
from codex_plugin_scanner.guard.runtime.extension_catalog_handshake import prepare_extension_catalog_handshake
from codex_plugin_scanner.guard.runtime.extension_catalog_sync import ExtensionCatalogLimitError
from codex_plugin_scanner.guard.runtime.extension_control_limits import (
    CLOUD_V1_CATALOG_SYNC_MAX_BODY_BYTES,
    CLOUD_V1_MAX_CATALOG_PAYLOAD_BYTES,
    MAX_CATALOG_EXTENSIONS,
    MAX_DAEMON_CATALOG_RESPONSE_BYTES,
    MAX_DAEMON_GET_RESPONSE_BYTES,
    MAX_GENERATED_CATALOG_ARTIFACT_BYTES,
    MAX_NATIVE_COMMAND_PROGRAM_BYTES,
)
from codex_plugin_scanner.guard.runtime.generated_command_catalog_loader import (
    GeneratedCommandCatalogError,
    _read_bounded_resource,
    load_generated_command_catalog_bytes,
)
from codex_plugin_scanner.guard.store import GuardStore
from tests.test_managed_controls_limits import _catalog_extension

ROOT = Path(__file__).resolve().parents[1]
DELIVERY_LIMITS = ROOT / "contracts" / "catalog-delivery" / "limits.json"
CLOUD_V1_LIMITS = ROOT / "contracts" / "managed-controls" / "v1" / "limits.json"
_DATA = "contracts/data/extensions"
_UPLOAD_PATH = "/api/guard/runtime/extension-catalog/sync"
_DIGEST = "a" * 64


def test_delivery_manifest_matches_python_constants() -> None:
    manifest = json.loads(DELIVERY_LIMITS.read_text(encoding="utf-8"))
    assert manifest == {
        "schema_version": 1,
        "unit": "bytes",
        "max_daemon_catalog_response_bytes": MAX_DAEMON_CATALOG_RESPONSE_BYTES,
        "max_daemon_get_response_bytes": MAX_DAEMON_GET_RESPONSE_BYTES,
        "max_generated_catalog_artifact_bytes": MAX_GENERATED_CATALOG_ARTIFACT_BYTES,
        "max_native_catalog_projection_bytes": 8_000_000,
        "max_native_command_program_bytes": MAX_NATIVE_COMMAND_PROGRAM_BYTES,
        "cloud_v1_catalog_sync_max_body_bytes": CLOUD_V1_CATALOG_SYNC_MAX_BODY_BYTES,
    }


def test_cloud_v1_profile_stays_at_the_receiver_contract() -> None:
    cloud = json.loads(CLOUD_V1_LIMITS.read_text(encoding="utf-8"))
    assert cloud["max_catalog_payload_bytes"] == CLOUD_V1_MAX_CATALOG_PAYLOAD_BYTES == 1_000_000
    assert CLOUD_V1_CATALOG_SYNC_MAX_BODY_BYTES == 1_016_384
    assert not hasattr(limits_module, "MAX_CATALOG_PAYLOAD_BYTES")


def _read(payload: bytes, max_bytes: int, *, read1: bool) -> bytes:
    class PlainResponse:
        def __init__(self) -> None:
            self._stream = io.BytesIO(payload)

        def read(self, amount: int = -1) -> bytes:
            return self._stream.read(amount)

        def settimeout(self, _timeout: float) -> None:
            return None

    response: object = io.BytesIO(payload) if read1 else PlainResponse()
    return GuardSurfaceDaemonClient._read_response_with_deadline(
        response,  # pyright: ignore[reportArgumentType]
        deadline=time.monotonic() + 10,
        max_bytes=max_bytes,
    )


@pytest.mark.parametrize("read1", (True, False))
@pytest.mark.parametrize("cap", (MAX_DAEMON_GET_RESPONSE_BYTES, MAX_DAEMON_CATALOG_RESPONSE_BYTES))
def test_client_body_cap_boundaries(cap: int, read1: bool) -> None:
    assert len(_read(b"x" * (cap - 1), cap, read1=read1)) == cap - 1
    assert len(_read(b"x" * cap, cap, read1=read1)) == cap
    with pytest.raises(GuardDaemonResponseSchemaError, match="size limit"):
        _read(b"x" * (cap + 1), cap, read1=read1)


@pytest.mark.parametrize("max_bytes", (0, -1, MAX_DAEMON_CATALOG_RESPONSE_BYTES + 1, True, 1.5))
def test_client_rejects_unbounded_read_limits(max_bytes: object) -> None:
    with pytest.raises(ValueError, match="positive bounded integer"):
        _read(b"{}", max_bytes, read1=True)  # pyright: ignore[reportArgumentType]


def _handshake(catalog: Mapping[str, object]) -> tuple[dict[str, object], object]:
    return prepare_extension_catalog_handshake(
        runtime_sync_url="https://cloud.example/api/guard/runtime/sync",
        runtime_response={
            "extensionCatalogSync": {
                "catalogDigest": _DIGEST,
                "catalogKnown": False,
                "uploadRequired": True,
                "uploadPath": _UPLOAD_PATH,
            }
        },
        session_payload={"extensionCatalogDigest": _DIGEST, "updatedAt": "2026-10-09T00:00:00Z"},
        catalog_factory=lambda _generated_at: catalog,
        fallback_generated_at="2026-10-09T00:00:00Z",
    )


def _compact_size(value: object) -> int:
    return len(json.dumps(value, separators=(",", ":"), ensure_ascii=False).encode("utf-8"))


def _catalog_with_size(size: int) -> dict[str, object]:
    catalog: dict[str, object] = {"catalogDigest": _DIGEST, "filler": ""}
    overhead = _compact_size(catalog)
    catalog["filler"] = "é" * ((size - overhead) // 2) + "x" * ((size - overhead) % 2)
    return catalog


_DOWNGRADED = {
    "managedControlsCapabilities": [],
    "extension_catalog_sync_status": "downgraded",
    "extension_catalog_sync_reason": "catalog_upload_exceeds_cloud_limit",
}


def test_upload_body_is_compact_utf8() -> None:
    _, upload = _handshake({"catalogDigest": _DIGEST, "text": "café"})
    body = upload.body  # pyright: ignore[reportAttributeAccessIssue]
    assert (
        body
        == (
            '{"idempotencyKey":"catalog:' + _DIGEST + '","catalog":{"catalogDigest":"' + _DIGEST + '","text":"café"}}'
        ).encode()
    )


@pytest.mark.parametrize("size", (CLOUD_V1_MAX_CATALOG_PAYLOAD_BYTES - 1, CLOUD_V1_MAX_CATALOG_PAYLOAD_BYTES))
def test_catalog_at_or_below_cloud_cap_is_sent(size: int) -> None:
    catalog = _catalog_with_size(size)
    assert _compact_size(catalog) == size
    status, upload = _handshake(catalog)
    assert status["extension_catalog_sync_status"] == "uploaded"
    assert len(upload.body) <= CLOUD_V1_CATALOG_SYNC_MAX_BODY_BYTES  # pyright: ignore[reportAttributeAccessIssue]


def test_catalog_over_cloud_cap_downgrades_even_when_its_body_fits() -> None:
    catalog = _catalog_with_size(CLOUD_V1_MAX_CATALOG_PAYLOAD_BYTES + 1)
    assert _compact_size({"idempotencyKey": f"catalog:{_DIGEST}", "catalog": catalog}) < (
        CLOUD_V1_CATALOG_SYNC_MAX_BODY_BYTES
    )
    status, upload = _handshake(catalog)
    assert upload is None
    assert status == _DOWNGRADED


def test_upload_body_over_cloud_cap_downgrades_without_sending() -> None:
    status, upload = _handshake(_catalog_with_size(CLOUD_V1_CATALOG_SYNC_MAX_BODY_BYTES + 1))
    assert upload is None
    assert status == _DOWNGRADED


def _over_limit(_generated_at: str) -> Mapping[str, object]:
    raise ExtensionCatalogLimitError("Extension catalog payload limit exceeded")


def test_builder_limit_failure_downgrades_a_requested_upload() -> None:
    status, upload = prepare_extension_catalog_handshake(
        runtime_sync_url="https://cloud.example/api/guard/runtime/sync",
        runtime_response={
            "extensionCatalogSync": {
                "catalogDigest": _DIGEST,
                "catalogKnown": False,
                "uploadRequired": True,
                "uploadPath": _UPLOAD_PATH,
            }
        },
        session_payload={"extensionCatalogDigest": _DIGEST},
        catalog_factory=_over_limit,
        fallback_generated_at="2026-10-09T00:00:00Z",
    )
    assert upload is None
    assert status == _DOWNGRADED


def _unadvertised(
    session_payload: dict[str, object], factory: Callable[[str], Mapping[str, object]]
) -> tuple[dict[str, object], object]:
    return prepare_extension_catalog_handshake(
        runtime_sync_url="https://cloud.example/api/guard/runtime/sync",
        runtime_response={},
        session_payload=session_payload,
        catalog_factory=factory,
        fallback_generated_at="2026-10-09T00:00:00Z",
    )


def test_posture_without_digest_reports_the_cloud_limit_reason() -> None:
    assert _unadvertised({"managedControlsCapabilities": []}, _over_limit) == (_DOWNGRADED, None)


def test_posture_without_digest_for_other_failures_reports_nothing() -> None:
    def broken(_generated_at: str) -> Mapping[str, object]:
        raise ValueError("Invalid Extension catalog source")

    assert _unadvertised({"managedControlsCapabilities": []}, broken) == ({}, None)


def test_catalog_sync_disabled_never_builds_the_catalog() -> None:
    def factory(_generated_at: str) -> Mapping[str, object]:
        pytest.fail("catalog sync is disabled")

    assert _unadvertised({}, factory) == ({}, None)


def test_managed_posture_omits_the_digest_when_the_builder_hits_a_limit(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(GUARD_EXTENSION_CATALOG_SYNC_V1, "true")

    def over_limit(**_kwargs: object) -> Mapping[str, object]:
        raise ExtensionCatalogLimitError("Extension catalog limit exceeded")

    monkeypatch.setattr(managed_controls_sync, "build_builtin_extension_catalog_wire", over_limit)
    posture = managed_controls_sync.managed_controls_runtime_sync_posture(None, generated_at="2026-10-09T00:00:00Z")  # pyright: ignore[reportArgumentType]
    assert posture == {"managedControlsCapabilities": []}


def _packaged(name: str) -> bytes:
    return resources.files("codex_plugin_scanner.guard").joinpath(f"{_DATA}/{name}").read_bytes()


def test_loader_accepts_artifacts_padded_to_their_budgets_and_rejects_one_more_byte() -> None:
    catalog = _packaged("command-catalog.v1.json")
    program = _packaged("native-command-program.v1.json")
    padded_catalog = catalog + b" " * (MAX_GENERATED_CATALOG_ARTIFACT_BYTES - len(catalog))
    padded_program = program + b" " * (MAX_NATIVE_COMMAND_PROGRAM_BYTES - len(program))
    assert load_generated_command_catalog_bytes(padded_catalog, padded_program).extensions
    with pytest.raises(GeneratedCommandCatalogError):
        load_generated_command_catalog_bytes(padded_catalog + b" ", program)
    with pytest.raises(GeneratedCommandCatalogError):
        load_generated_command_catalog_bytes(catalog, padded_program + b" ")


def test_loader_resource_read_stops_one_byte_past_budget(tmp_path: Path) -> None:
    resource = tmp_path / "artifact.json"
    resource.write_bytes(b"x" * 11)
    with pytest.raises(GeneratedCommandCatalogError, match="too_large"):
        _read_bounded_resource(resource, 10)
    assert _read_bounded_resource(resource, 11) == b"x" * 11


def test_valid_catalog_over_one_mebibyte_round_trips_real_daemon_and_client(tmp_path: Path) -> None:
    extensions = tuple(
        replace(_catalog_extension(index), description="Bounded catalog fixture. " * 40)
        for index in range(MAX_CATALOG_EXTENSIONS)
    )
    registry = CommandSafetyExtensionRegistry(extensions)
    store = GuardStore(tmp_path / "guard-home")
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    daemon.start()
    try:
        daemon._server.extension_control_api._registry = registry
        token = load_guard_daemon_auth_token(store.guard_home)
        assert token is not None
        client = GuardSurfaceDaemonClient(f"http://127.0.0.1:{daemon.port}", token)
        payload = client.extension_control_catalog()
    finally:
        daemon.stop()
    assert len(json.dumps(payload).encode("utf-8")) > MAX_DAEMON_GET_RESPONSE_BYTES
    assert payload["catalog_digest"] == registry.catalog_digest
    extensions_wire = payload["extensions"]
    limits = payload["limits"]
    assert isinstance(extensions_wire, list) and len(extensions_wire) == MAX_CATALOG_EXTENSIONS
    assert isinstance(limits, dict) and limits["max_body_bytes"] == MAX_DAEMON_CATALOG_RESPONSE_BYTES


def test_known_digest_never_builds_or_uploads_catalog() -> None:
    def factory(_generated_at: str) -> Mapping[str, object]:
        pytest.fail("a known catalog must not be built")

    status, upload = prepare_extension_catalog_handshake(
        runtime_sync_url="https://cloud.example/api/guard/runtime/sync",
        runtime_response={
            "extensionCatalogSync": {
                "catalogDigest": _DIGEST,
                "catalogKnown": True,
                "uploadRequired": False,
                "uploadPath": _UPLOAD_PATH,
            }
        },
        session_payload={"extensionCatalogDigest": _DIGEST},
        catalog_factory=factory,
        fallback_generated_at="2026-10-09T00:00:00Z",
    )
    assert upload is None
    assert status == {"extension_catalog_sync_status": "already_known", "extension_catalog_sync_digest": _DIGEST}


def test_runtime_sync_sends_nothing_when_upload_exceeds_cloud_cap(monkeypatch: pytest.MonkeyPatch) -> None:
    oversized = _catalog_with_size(CLOUD_V1_MAX_CATALOG_PAYLOAD_BYTES + 1)
    monkeypatch.setattr(runner, "build_builtin_extension_catalog_wire", lambda **_kwargs: oversized)
    monkeypatch.setattr(runner, "_guard_sync_request", lambda *_args, **_kwargs: pytest.fail("must not upload"))
    summary = runner._sync_extension_catalog_from_runtime_handshake(
        auth_context={},
        runtime_sync_url="https://cloud.example/api/guard/runtime/sessions/sync",
        runtime_response={
            "extensionCatalogSync": {
                "catalogDigest": _DIGEST,
                "catalogKnown": False,
                "uploadRequired": True,
                "uploadPath": _UPLOAD_PATH,
            }
        },
        session_payload={"extensionCatalogDigest": _DIGEST, "updatedAt": "2026-10-09T00:00:00Z"},
    )
    assert summary["extension_catalog_sync_status"] == "downgraded"
    assert summary["managedControlsCapabilities"] == []
