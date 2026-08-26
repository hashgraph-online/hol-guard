from __future__ import annotations

import json

import pytest

from codex_plugin_scanner.guard.runtime import runner


def _catalog_handshake(digest: str, *, known: bool) -> dict[str, object]:
    return {
        "extensionCatalogSync": {
            "catalogDigest": digest,
            "catalogKnown": known,
            "uploadRequired": not known,
            "uploadPath": "/api/guard/runtime/extension-catalog/sync",
        }
    }


def test_runtime_catalog_handshake_skips_known_catalog_without_upload(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    catalog = runner.build_builtin_extension_catalog_wire(
        guard_version=runner.__version__, generated_at="2026-08-25T00:00:00Z"
    )
    monkeypatch.setattr(
        runner,
        "_urlopen_json_with_timeout_retry",
        lambda **_kwargs: pytest.fail("known catalog must not be uploaded"),
    )
    summary = runner._sync_extension_catalog_from_runtime_handshake(
        auth_context={},
        runtime_sync_url="https://hol.org/api/guard/runtime/sessions/sync",
        runtime_response=_catalog_handshake(catalog["catalogDigest"], known=True),
        session_payload={"extensionCatalogDigest": catalog["catalogDigest"]},
    )
    assert summary["extension_catalog_sync_status"] == "already_known"


def test_runtime_catalog_handshake_uploads_unknown_builtin_catalog_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    catalog = runner.build_builtin_extension_catalog_wire(
        guard_version=runner.__version__, generated_at="2026-08-25T00:00:00Z"
    )
    requests: list[dict[str, object]] = []

    def fake_request(
        _auth_context: object,
        *,
        request_url: str,
        method: str,
        data: bytes,
        extra_headers: object,
    ) -> dict[str, object]:
        request = {"url": request_url, "method": method, "data": data, "headers": extra_headers}
        requests.append(request)
        return request

    monkeypatch.setattr(runner, "_guard_sync_request", fake_request)
    monkeypatch.setattr(
        runner,
        "_urlopen_json_with_timeout_retry",
        lambda **_kwargs: {
            "schemaVersion": "guard.extension-catalog-sync.v1",
            "accepted": True,
            "catalogDigest": catalog["catalogDigest"],
            "alreadyKnown": False,
            "deviceCount": 1,
            "firstSeenAt": "2026-08-25T00:00:00Z",
            "lastSeenAt": "2026-08-25T00:00:00Z",
        },
    )
    summary = runner._sync_extension_catalog_from_runtime_handshake(
        auth_context={},
        runtime_sync_url="https://hol.org/api/guard/runtime/sessions/sync?tenant=guard",
        runtime_response=_catalog_handshake(catalog["catalogDigest"], known=False),
        session_payload={
            "extensionCatalogDigest": catalog["catalogDigest"],
            "updatedAt": "2026-08-25T00:00:00Z",
        },
    )
    assert summary["extension_catalog_sync_status"] == "uploaded"
    assert len(requests) == 1
    assert requests[0]["url"] == "https://hol.org/api/guard/runtime/extension-catalog/sync?tenant=guard"
    body = json.loads(requests[0]["data"])
    assert body == {"idempotencyKey": f"catalog:{catalog['catalogDigest']}", "catalog": catalog}


@pytest.mark.parametrize(
    "handshake",
    (
        {
            "catalogDigest": "a" * 64,
            "catalogKnown": False,
            "uploadRequired": False,
            "uploadPath": "/api/guard/runtime/extension-catalog/sync",
        },
        {
            "catalogDigest": "b" * 64,
            "catalogKnown": True,
            "uploadRequired": False,
            "uploadPath": "/api/guard/runtime/extension-catalog/sync",
        },
        {
            "catalogDigest": "a" * 64,
            "catalogKnown": False,
            "uploadRequired": True,
            "uploadPath": "/attacker/upload",
        },
    ),
)
def test_runtime_catalog_handshake_rejects_malformed_or_unbound_signal(
    handshake: dict[str, object],
) -> None:
    with pytest.raises(RuntimeError, match="handshake"):
        runner._sync_extension_catalog_from_runtime_handshake(
            auth_context={},
            runtime_sync_url="https://hol.org/api/guard/runtime/sessions/sync",
            runtime_response={"extensionCatalogSync": handshake},
            session_payload={"extensionCatalogDigest": "a" * 64},
        )


def test_runtime_catalog_handshake_downgrades_when_cloud_has_no_signal() -> None:
    summary = runner._sync_extension_catalog_from_runtime_handshake(
        auth_context={},
        runtime_sync_url="https://hol.org/api/guard/runtime/sessions/sync",
        runtime_response={},
        session_payload={"extensionCatalogDigest": "a" * 64},
    )
    assert summary == {
        "managedControlsCapabilities": [],
        "extension_catalog_sync_status": "downgraded",
        "extension_catalog_sync_reason": "catalog_handshake_unavailable",
    }


def test_catalog_upload_response_validation_fails_closed() -> None:
    with pytest.raises(RuntimeError, match="catalog sync response"):
        runner._validate_extension_catalog_sync_response(
            {
                "schemaVersion": "guard.extension-catalog-sync.v1",
                "accepted": True,
                "catalogDigest": "b" * 64,
                "alreadyKnown": False,
                "deviceCount": 1,
                "firstSeenAt": "2026-08-25T00:00:00Z",
                "lastSeenAt": "2026-08-25T00:00:00Z",
            },
            expected_digest="a" * 64,
        )


def test_runtime_session_summary_uses_server_normalized_device_identity() -> None:
    session_payload = {
        "sessionId": "runtime-session-1",
        "deviceId": "client-installation-id",
        "harness": "hol-guard",
        "surface": "cli",
        "workspace": "local-machine",
    }

    summary = runner.runtime_session_success_summary(
        session_payload=session_payload,
        response_payload={
            "items": [
                {
                    "sessionId": "runtime-session-1",
                    "deviceId": "trusted-oauth-machine-id",
                }
            ]
        },
        synced_at="2026-08-25T00:00:00Z",
        catalog_sync={},
    )

    assert summary["runtime_device_id"] == "trusted-oauth-machine-id"
