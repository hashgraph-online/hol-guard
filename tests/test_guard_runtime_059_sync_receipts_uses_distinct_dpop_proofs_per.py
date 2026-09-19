"""Runtime regression tests: sync receipts uses distinct dpop proofs per."""

from __future__ import annotations

from tests.guard_runtime_test_dependencies import (
    GuardReceipt,
    GuardStore,
    generate_dpop_key_pair,
    guard_runner_module,
    json,
    pytest,
    stub_authenticated_urlopen,
    threading,
    urllib,
)
from tests.guard_runtime_test_support import (
    _isolate_codex_runtime_marker as _isolate_codex_runtime_marker,
)
from tests.guard_runtime_test_support import (
    _request_header,
)


def test_sync_receipts_uses_distinct_dpop_proofs_per_batch(tmp_path, monkeypatch):
    store = GuardStore(tmp_path / "guard-home")
    dpop_key_material = generate_dpop_key_pair()
    store.set_oauth_local_credentials(
        issuer="https://hol.org",
        client_id="guard-local-daemon",
        refresh_token="refresh-token-1",
        dpop_private_key_pem=dpop_key_material.private_key_pem,
        dpop_public_jwk=dpop_key_material.public_jwk,
        dpop_public_jwk_thumbprint=dpop_key_material.public_jwk_thumbprint,
        grant_id="grant-1",
        machine_id="machine-1",
        workspace_id="workspace-1",
        now="2026-06-01T00:00:00+00:00",
    )
    for index in range(51):
        store.add_receipt(
            GuardReceipt(
                receipt_id=f"receipt-{index}",
                timestamp="2026-06-01T00:00:00+00:00",
                harness="codex",
                artifact_id=f"artifact-{index}",
                artifact_hash=f"sha256:{index:064x}",
                policy_decision="review",
                capabilities_summary="requests file write",
                changed_capabilities=("fs_write",),
                provenance_summary="local codex workspace",
                artifact_name=f"artifact-{index}",
                source_scope="workspace",
            )
        )
    token_requests: list[urllib.request.Request] = []
    receipt_dpop_headers: list[str] = []

    class _Response:
        def __init__(self, payload: dict[str, object]) -> None:
            self._payload = payload

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def read(self) -> bytes:
            return json.dumps(self._payload).encode("utf-8")

    def _fake_urlopen(request, timeout):
        if request.full_url == "https://hol.org/api/guard/oauth/token":
            token_requests.append(request)
            return _Response(
                {
                    "access_token": "oauth-access-token-1",
                    "refresh_token": "refresh-token-1",
                    "token_type": "Bearer",
                    "expires_in": 3600,
                }
            )
        dpop_header = _request_header(request, "DPoP")
        assert isinstance(dpop_header, str) and dpop_header
        receipt_dpop_headers.append(dpop_header)
        assert _request_header(request, "Authorization") == "Bearer oauth-access-token-1"
        payload = json.loads(request.data.decode("utf-8"))
        if "receipts" not in payload:
            return _Response(
                {
                    "syncedAt": "2026-06-01T00:00:10+00:00",
                    "accepted": len(payload.get("events", [])),
                    "events": len(payload.get("events", [])),
                }
            )
        return _Response(
            {
                "syncedAt": "2026-06-01T00:00:10+00:00",
                "receiptsStored": len(payload["receipts"]),
                "advisories": [],
                "policy": {},
                "alertPreferences": {},
                "teamPolicyPack": {},
                "exceptions": [],
            }
        )

    stub_authenticated_urlopen(monkeypatch, _fake_urlopen)

    payload = guard_runner_module.sync_receipts(store)

    assert len(token_requests) == 1
    assert _request_header(token_requests[0], "User-Agent") == f"hol-guard/{guard_runner_module.__version__}"
    assert len(receipt_dpop_headers) >= 2
    assert receipt_dpop_headers[0] != receipt_dpop_headers[1]
    assert payload["receipts_stored"] == 51


def test_sync_local_guard_cloud_proof_refreshes_oauth_once(tmp_path, monkeypatch):
    store = GuardStore(tmp_path / "guard-home")
    dpop_key_material = generate_dpop_key_pair()
    store.set_oauth_local_credentials(
        issuer="https://hol.org",
        client_id="guard-local-daemon",
        refresh_token="refresh-token-1",
        dpop_private_key_pem=dpop_key_material.private_key_pem,
        dpop_public_jwk=dpop_key_material.public_jwk,
        dpop_public_jwk_thumbprint=dpop_key_material.public_jwk_thumbprint,
        grant_id="grant-1",
        machine_id="machine-1",
        workspace_id="workspace-1",
        now="2026-06-01T00:00:00+00:00",
    )
    token_requests: list[urllib.request.Request] = []
    sync_requests: list[urllib.request.Request] = []

    class _Response:
        def __init__(self, payload: dict[str, object]) -> None:
            self._payload = payload

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def read(self) -> bytes:
            return json.dumps(self._payload).encode("utf-8")

    def _fake_urlopen(request, timeout):
        if request.full_url == "https://hol.org/api/guard/oauth/token":
            token_requests.append(request)
            return _Response(
                {
                    "access_token": "oauth-access-token-1",
                    "refresh_token": "refresh-token-1",
                    "token_type": "Bearer",
                    "expires_in": 3600,
                }
            )
        sync_requests.append(request)
        if request.full_url == "https://hol.org/api/guard/runtime/sessions/sync":
            return _Response(
                {
                    "syncedAt": "2026-06-01T00:00:05+00:00",
                    "items": [{"sessionId": "runtime-session-1"}],
                }
            )
        if request.full_url == "https://hol.org/api/guard/receipts/sync":
            return _Response(
                {
                    "syncedAt": "2026-06-01T00:00:06+00:00",
                    "receiptsStored": 0,
                    "advisories": [],
                    "policy": {},
                    "alertPreferences": {},
                    "teamPolicyPack": {},
                    "exceptions": [],
                }
            )
        if request.full_url == "https://hol.org/api/v1/guard/events":
            return _Response(
                {
                    "syncedAt": "2026-06-01T00:00:07+00:00",
                    "accepted": 1,
                    "events": 1,
                }
            )
        raise AssertionError(f"unexpected request: {request.full_url}")

    stub_authenticated_urlopen(monkeypatch, _fake_urlopen)

    payload = guard_runner_module.sync_local_guard_cloud_proof(store)
    expected_session_id = guard_runner_module._cloud_runtime_session_payload(
        store,
        guard_runner_module._local_guard_runtime_session(),
    )["sessionId"]

    assert len(token_requests) == 1
    assert _request_header(token_requests[0], "User-Agent") == f"hol-guard/{guard_runner_module.__version__}"
    sync_urls = [request.full_url for request in sync_requests]
    assert sync_urls[:2] == [
        "https://hol.org/api/guard/runtime/sessions/sync",
        "https://hol.org/api/guard/receipts/sync",
    ]
    assert sync_urls.count("https://hol.org/api/v1/guard/events") >= 1
    assert payload["runtime_session_id"] == expected_session_id


def test_sync_local_guard_cloud_proof_serializes_concurrent_oauth_refresh(tmp_path, monkeypatch):
    store = GuardStore(tmp_path / "guard-home")
    dpop_key_material = generate_dpop_key_pair()
    store.set_oauth_local_credentials(
        issuer="https://hol.org",
        client_id="guard-local-daemon",
        refresh_token="refresh-token-1",
        dpop_private_key_pem=dpop_key_material.private_key_pem,
        dpop_public_jwk=dpop_key_material.public_jwk,
        dpop_public_jwk_thumbprint=dpop_key_material.public_jwk_thumbprint,
        grant_id="grant-1",
        machine_id="machine-1",
        workspace_id="workspace-1",
        now="2026-06-01T00:00:00+00:00",
    )
    token_refreshes: list[str] = []
    sync_errors: list[Exception] = []
    sync_results: list[dict[str, object]] = []
    start_barrier = threading.Barrier(2)

    class _Response:
        def __init__(self, payload: dict[str, object]) -> None:
            self._payload = payload

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def read(self) -> bytes:
            return json.dumps(self._payload).encode("utf-8")

    def _fake_urlopen(request, timeout):
        del timeout
        if request.full_url == "https://hol.org/api/guard/oauth/token":
            body = urllib.parse.parse_qs(request.data.decode("utf-8"))
            refresh_token = body["refresh_token"][0]
            token_refreshes.append(refresh_token)
            threading.Event().wait(0.05)
            rotated_refresh_token = {
                "refresh-token-1": "refresh-token-2",
                "refresh-token-2": "refresh-token-3",
            }.get(refresh_token)
            if rotated_refresh_token is None:
                raise AssertionError(f"unexpected refresh token: {refresh_token}")
            return _Response(
                {
                    "access_token": f"oauth-access-token-for-{refresh_token}",
                    "refresh_token": rotated_refresh_token,
                    "token_type": "Bearer",
                    "expires_in": 3600,
                }
            )
        if request.full_url == "https://hol.org/api/guard/runtime/sessions/sync":
            return _Response(
                {
                    "syncedAt": "2026-06-01T00:00:05+00:00",
                    "items": [{"sessionId": "runtime-session-1"}],
                }
            )
        if request.full_url == "https://hol.org/api/guard/receipts/sync":
            return _Response(
                {
                    "syncedAt": "2026-06-01T00:00:06+00:00",
                    "receiptsStored": 0,
                    "advisories": [],
                    "policy": {},
                    "alertPreferences": {},
                    "teamPolicyPack": {},
                    "exceptions": [],
                }
            )
        if request.full_url == "https://hol.org/api/v1/guard/events":
            return _Response(
                {
                    "syncedAt": "2026-06-01T00:00:07+00:00",
                    "accepted": 1,
                    "events": 1,
                }
            )
        raise AssertionError(f"unexpected request: {request.full_url}")

    def _run_sync() -> None:
        try:
            start_barrier.wait(timeout=5)
            sync_results.append(guard_runner_module.sync_local_guard_cloud_proof(store))
        except Exception as error:  # pragma: no cover - assertion captured below
            sync_errors.append(error)

    stub_authenticated_urlopen(monkeypatch, _fake_urlopen)

    threads = [threading.Thread(target=_run_sync) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=5)

    assert sync_errors == []
    assert len(sync_results) == 2
    assert token_refreshes == ["refresh-token-1"]
    stored_credentials = store.get_oauth_local_credentials()
    assert isinstance(stored_credentials, dict)
    assert stored_credentials["refresh_token"] == "refresh-token-2"
    assert stored_credentials["access_token"] == "oauth-access-token-for-refresh-token-1"


def test_sync_pain_signals_raises_when_oauth_refresh_is_revoked(tmp_path, monkeypatch):
    store = GuardStore(tmp_path / "guard-home")
    dpop_key_material = generate_dpop_key_pair()
    store.set_oauth_local_credentials(
        issuer="https://hol.org",
        client_id="guard-local-daemon",
        refresh_token="refresh-token-1",
        dpop_private_key_pem=dpop_key_material.private_key_pem,
        dpop_public_jwk=dpop_key_material.public_jwk,
        dpop_public_jwk_thumbprint=dpop_key_material.public_jwk_thumbprint,
        grant_id="grant-1",
        machine_id="machine-1",
        workspace_id="workspace-1",
        now="2026-06-01T00:00:00+00:00",
    )

    class _ErrorResponse:
        def read(self) -> bytes:
            return json.dumps(
                {
                    "error": "invalid_grant",
                    "error_description": "refresh token revoked",
                }
            ).encode("utf-8")

        def close(self) -> None:
            return None

    def _fake_urlopen(request, timeout):
        raise urllib.error.HTTPError(
            request.full_url,
            400,
            "Bad Request",
            hdrs=None,
            fp=_ErrorResponse(),
        )

    stub_authenticated_urlopen(monkeypatch, _fake_urlopen)

    with pytest.raises(guard_runner_module.GuardSyncAuthorizationExpiredError) as error:
        guard_runner_module.sync_pain_signals(store)

    assert "hol-guard connect" in str(error.value)


def test_sync_runtime_session_treats_token_endpoint_503_as_retryable_error(tmp_path, monkeypatch):
    store = GuardStore(tmp_path / "guard-home")
    dpop_key_material = generate_dpop_key_pair()
    store.set_oauth_local_credentials(
        issuer="https://hol.org",
        client_id="guard-local-daemon",
        refresh_token="refresh-token-1",
        dpop_private_key_pem=dpop_key_material.private_key_pem,
        dpop_public_jwk=dpop_key_material.public_jwk,
        dpop_public_jwk_thumbprint=dpop_key_material.public_jwk_thumbprint,
        grant_id="grant-1",
        machine_id="machine-1",
        workspace_id="workspace-1",
        now="2026-06-01T00:00:00+00:00",
    )

    class _ErrorResponse:
        def read(self) -> bytes:
            return json.dumps(
                {
                    "error": "temporarily_unavailable",
                    "error_description": "oauth upstream down",
                }
            ).encode("utf-8")

        def close(self) -> None:
            return None

    def _fake_urlopen(request, timeout):
        raise urllib.error.HTTPError(
            request.full_url,
            503,
            "Service Unavailable",
            hdrs=None,
            fp=_ErrorResponse(),
        )

    stub_authenticated_urlopen(monkeypatch, _fake_urlopen)

    with pytest.raises(RuntimeError, match="oauth upstream down") as error:
        guard_runner_module.sync_runtime_session(
            store,
            session={
                "session_id": "session-oauth",
                "harness": "codex",
                "surface": "cli",
                "status": "active",
                "client_name": "Codex",
                "client_title": "Codex CLI",
                "client_version": "1.0.0",
                "workspace": "prod",
                "capabilities": ["chat"],
                "started_at": "2026-06-01T00:00:00+00:00",
                "updated_at": "2026-06-01T00:00:00+00:00",
                "operations": [],
            },
        )

    assert not isinstance(error.value, guard_runner_module.GuardSyncAuthorizationExpiredError)
