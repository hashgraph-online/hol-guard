from __future__ import annotations

import json
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.runtime import extension_catalog_handshake as handshake_module
from codex_plugin_scanner.guard.runtime import extension_catalog_sync as runner_sync
from codex_plugin_scanner.guard.runtime import runner

# The negotiation verdicts (summary, upload decision, upload URL, acknowledgement) are
# judged by the resident; their decision tests are in
# rust/crates/guard-command/src/cloud_catalog_wire_v1_sync_tests.rs. The tests here drive
# the real resident through the Python adapter.
_DIGEST = "a" * 64
_URL = "https://hol.org/api/guard/runtime/sessions/sync"


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
    tmp_path: Path,
) -> None:
    catalog = runner.build_builtin_extension_catalog_wire(
        guard_version=runner.__version__, generated_at="2026-08-25T00:00:00Z", guard_home=tmp_path
    )
    monkeypatch.setattr(
        runner,
        "_urlopen_json_with_timeout_retry",
        lambda **_kwargs: pytest.fail("known catalog must not be uploaded"),
    )
    summary = runner._sync_extension_catalog_from_runtime_handshake(
        guard_home=tmp_path,
        auth_context={},
        runtime_sync_url="https://hol.org/api/guard/runtime/sessions/sync",
        runtime_response=_catalog_handshake(catalog["catalogDigest"], known=True),
        session_payload={"extensionCatalogDigest": catalog["catalogDigest"]},
    )
    assert summary["extension_catalog_sync_status"] == "already_known"


def test_runtime_catalog_handshake_uploads_unknown_builtin_catalog_once(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    catalog = runner.build_builtin_extension_catalog_wire(
        guard_version=runner.__version__, generated_at="2026-08-25T00:00:00Z", guard_home=tmp_path
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
        guard_home=tmp_path,
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
    tmp_path: Path,
) -> None:
    with pytest.raises(RuntimeError, match="handshake"):
        runner._sync_extension_catalog_from_runtime_handshake(
            guard_home=tmp_path,
            auth_context={},
            runtime_sync_url="https://hol.org/api/guard/runtime/sessions/sync",
            runtime_response={"extensionCatalogSync": handshake},
            session_payload={"extensionCatalogDigest": "a" * 64},
        )


def test_runtime_catalog_handshake_downgrades_when_cloud_has_no_signal(tmp_path: Path) -> None:
    summary = runner._sync_extension_catalog_from_runtime_handshake(
        guard_home=tmp_path,
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


def test_runtime_catalog_handshake_downgrades_when_native_runtime_is_unavailable(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    def unavailable(**_kwargs: object) -> dict[str, object]:
        raise runner_sync.ExtensionCatalogUnavailableError("Native Extension catalog runtime unavailable")

    monkeypatch.setattr(runner, "build_builtin_extension_catalog_wire", unavailable)
    summary = runner._sync_extension_catalog_from_runtime_handshake(
        guard_home=tmp_path,
        auth_context={},
        runtime_sync_url="https://hol.org/api/guard/runtime/sessions/sync",
        runtime_response=_catalog_handshake("a" * 64, known=False),
        session_payload={"extensionCatalogDigest": "a" * 64},
    )
    assert summary == {
        "managedControlsCapabilities": [],
        "extension_catalog_sync_status": "downgraded",
        "extension_catalog_sync_reason": "catalog_runtime_unavailable",
    }


def _prepare(
    tmp_path: Path, **overrides: object
) -> tuple[dict[str, object], handshake_module.ExtensionCatalogUpload | None]:
    arguments: dict[str, object] = {
        "guard_home": tmp_path,
        "runtime_sync_url": _URL,
        "runtime_response": _catalog_handshake(_DIGEST, known=False),
        "session_payload": {"extensionCatalogDigest": _DIGEST, "updatedAt": "2026-08-25T00:00:00Z"},
        "catalog_factory": lambda _generated_at: {"catalogDigest": _DIGEST},
        "fallback_generated_at": "2026-08-25T00:00:00Z",
    }
    arguments.update(overrides)
    return handshake_module.prepare_extension_catalog_handshake(**arguments)  # pyright: ignore[reportArgumentType]


def test_session_without_catalog_posture_never_reaches_the_resident(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(handshake_module, "native_wire_call", lambda *_a, **_k: pytest.fail("no posture to judge"))
    summary, upload = _prepare(tmp_path, session_payload={"sessionId": "runtime-session-1"})
    assert (summary, upload) == ({}, None)


def test_unreachable_resident_downgrades_with_the_resident_wording(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    resident = runner_sync.native_wire_call(
        "v1_handshake",
        guard_home=tmp_path,
        session={"extensionCatalogDigest": _DIGEST},
        handshake=_catalog_handshake(_DIGEST, known=False)["extensionCatalogSync"],
        runtime_sync_url=_URL,
        fallback_generated_at="2026-08-25T00:00:00Z",
        catalog={"outcome": "unavailable"},
    )

    def unreachable(*_args: object, **_kwargs: object) -> dict[str, object]:
        raise runner_sync.ExtensionCatalogUnavailableError("Native Extension catalog runtime unavailable")

    monkeypatch.setattr(handshake_module, "native_wire_call", unreachable)
    summary, upload = _prepare(tmp_path)
    assert upload is None
    assert summary == resident["summary"]


def test_upload_url_is_the_digest_bound_resident_answer(tmp_path: Path) -> None:
    summary, upload = _prepare(tmp_path, runtime_sync_url=f"{_URL}?tenant=guard#fragment")
    assert summary["extension_catalog_sync_status"] == "uploaded"
    assert upload is not None
    assert upload.url == "https://hol.org/api/guard/runtime/extension-catalog/sync?tenant=guard"
    assert json.loads(upload.body) == {
        "idempotencyKey": f"catalog:{_DIGEST}",
        "catalog": {"catalogDigest": _DIGEST},
    }


def test_upload_url_without_a_scheme_and_authority_is_refused(tmp_path: Path) -> None:
    with pytest.raises(RuntimeError, match="upload URL"):
        _prepare(tmp_path, runtime_sync_url="/api/guard/runtime/sessions/sync")


def test_catalog_that_changed_during_negotiation_is_refused(tmp_path: Path) -> None:
    with pytest.raises(RuntimeError, match="changed during runtime synchronization"):
        _prepare(tmp_path, catalog_factory=lambda _generated_at: {"catalogDigest": "b" * 64})


def test_a_failing_catalog_build_is_not_swallowed_for_a_requested_upload(tmp_path: Path) -> None:
    def broken(_generated_at: str) -> dict[str, object]:
        raise ValueError("Invalid Extension catalog source")

    with pytest.raises(ValueError, match="Invalid Extension catalog source"):
        _prepare(tmp_path, catalog_factory=broken)


def test_an_unrecognized_resident_decision_fails_closed(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(handshake_module, "native_wire_call", lambda *_a, **_k: {"decision": "upload_everything"})
    with pytest.raises(RuntimeError, match="malformed"):
        _prepare(tmp_path)


def test_catalog_upload_response_validation_fails_closed(tmp_path: Path) -> None:
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
            guard_home=tmp_path,
        )


def _acknowledgement(**overrides: object) -> dict[str, object]:
    return {
        "schemaVersion": "guard.extension-catalog-sync.v1",
        "accepted": True,
        "catalogDigest": _DIGEST,
        "alreadyKnown": False,
        "deviceCount": 1,
        "firstSeenAt": "2026-08-25T00:00:00Z",
        "lastSeenAt": "2026-08-25T00:00:00Z",
        **overrides,
    }


def test_catalog_upload_response_is_accepted_by_the_resident(tmp_path: Path) -> None:
    assert (
        handshake_module.validate_extension_catalog_sync_response(
            _acknowledgement(), expected_digest=_DIGEST, guard_home=tmp_path
        )
        is None
    )


@pytest.mark.parametrize("count", (float("nan"), float("inf")))
def test_catalog_upload_response_the_wire_cannot_carry_is_invalid(count: float, tmp_path: Path) -> None:
    with pytest.raises(RuntimeError, match="Invalid Extension catalog sync response"):
        handshake_module.validate_extension_catalog_sync_response(
            _acknowledgement(deviceCount=count), expected_digest=_DIGEST, guard_home=tmp_path
        )


@pytest.mark.parametrize("verdict", ({}, {"accepted": False}, {"accepted": "true"}))
def test_a_resident_verdict_that_does_not_accept_fails_closed(
    verdict: dict[str, object], monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(handshake_module, "native_wire_call", lambda *_a, **_k: verdict)
    with pytest.raises(RuntimeError, match="Invalid Extension catalog sync response"):
        handshake_module.validate_extension_catalog_sync_response(
            _acknowledgement(), expected_digest=_DIGEST, guard_home=tmp_path
        )


def test_unreachable_resident_leaves_the_upload_unverified_and_downgrades(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    catalog = runner.build_builtin_extension_catalog_wire(
        guard_version=runner.__version__, generated_at="2026-08-25T00:00:00Z", guard_home=tmp_path
    )
    digest = str(catalog["catalogDigest"])
    real = handshake_module.native_wire_call

    def resident(action: str, **fields: object) -> dict[str, object]:
        if action == "v1_sync_ack":
            raise runner_sync.ExtensionCatalogUnavailableError("Native Extension catalog runtime unavailable")
        return real(action, **fields)

    monkeypatch.setattr(handshake_module, "native_wire_call", resident)
    monkeypatch.setattr(runner, "_guard_sync_request", lambda *_args, **_kwargs: object())
    monkeypatch.setattr(
        runner, "_urlopen_json_with_timeout_retry", lambda **_kwargs: _acknowledgement(catalogDigest=digest)
    )
    summary = runner._sync_extension_catalog_from_runtime_handshake(
        guard_home=tmp_path,
        auth_context={},
        runtime_sync_url=_URL,
        runtime_response=_catalog_handshake(digest, known=False),
        session_payload={"extensionCatalogDigest": digest, "updatedAt": "2026-08-25T00:00:00Z"},
    )
    assert summary == handshake_module._CATALOG_RUNTIME_UNAVAILABLE


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
