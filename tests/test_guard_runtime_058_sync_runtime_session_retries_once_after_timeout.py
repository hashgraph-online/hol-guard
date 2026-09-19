"""Runtime regression tests: sync runtime session retries once after timeout."""

from __future__ import annotations

from tests.guard_runtime_test_dependencies import (
    GuardStore,
    contextmanager,
    datetime,
    generate_dpop_key_pair,
    guard_runner_module,
    hashlib,
    json,
    pytest,
    stub_authenticated_urlopen,
    threading,
    timezone,
    urllib,
)
from tests.guard_runtime_test_support import (
    _decode_jwt_segment,
    _request_header,
    _seed_guard_cloud,
)
from tests.guard_runtime_test_support import (
    _isolate_codex_runtime_marker as _isolate_codex_runtime_marker,
)


def test_sync_runtime_session_retries_once_after_timeout(tmp_path, monkeypatch):
    store = GuardStore(tmp_path / "guard-home")
    dpop_key_material = generate_dpop_key_pair()
    _seed_guard_cloud(store)
    timeouts: list[int] = []

    class _Response:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def read(self) -> bytes:
            return json.dumps(
                {
                    "generatedAt": "2026-04-19T00:00:10+00:00",
                    "items": [{"sessionId": "session-1"}],
                }
            ).encode("utf-8")

    def _fake_urlopen(request, timeout):
        timeouts.append(timeout)
        if len(timeouts) == 1:
            raise urllib.error.URLError(TimeoutError("timed out"))
        return _Response()

    stub_authenticated_urlopen(monkeypatch, _fake_urlopen)

    payload = guard_runner_module.sync_runtime_session(
        store,
        auth_context={
            "sync_url": "https://hol.org/api/guard/receipts/sync",
            "access_token": "oauth-access-token-1",
            "dpop_key_material": dpop_key_material,
        },
        session={
            "session_id": "session-1",
            "harness": "hermes",
            "surface": "agent-sdk",
            "status": "active",
            "client_name": "Hermes",
            "client_title": "Hermes Agent",
            "client_version": "1.0.0",
            "workspace": "prod-e2e",
            "capabilities": ["chat"],
            "started_at": "2026-04-19T00:00:00+00:00",
            "updated_at": "2026-04-19T00:00:00+00:00",
            "operations": [],
        },
    )

    assert timeouts == [10, 90]
    assert payload["runtime_session_id"] == "session-1"


def test_sync_runtime_session_retries_once_after_read_timeout(tmp_path, monkeypatch):
    store = GuardStore(tmp_path / "guard-home")
    dpop_key_material = generate_dpop_key_pair()
    _seed_guard_cloud(store)
    timeouts: list[int] = []

    class _Response:
        def __init__(self, should_timeout: bool) -> None:
            self._should_timeout = should_timeout

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def read(self) -> bytes:
            if self._should_timeout:
                raise TimeoutError("timed out")
            return json.dumps(
                {
                    "generatedAt": "2026-04-19T00:00:10+00:00",
                    "items": [{"sessionId": "session-read-timeout"}],
                }
            ).encode("utf-8")

    def _fake_urlopen(request, timeout):
        timeouts.append(timeout)
        return _Response(should_timeout=len(timeouts) == 1)

    stub_authenticated_urlopen(monkeypatch, _fake_urlopen)

    payload = guard_runner_module.sync_runtime_session(
        store,
        auth_context={
            "sync_url": "https://hol.org/api/guard/receipts/sync",
            "access_token": "oauth-access-token-1",
            "dpop_key_material": dpop_key_material,
        },
        session={
            "session_id": "session-read-timeout",
            "harness": "hermes",
            "surface": "agent-sdk",
            "status": "active",
            "client_name": "Hermes",
            "client_title": "Hermes Agent",
            "client_version": "1.0.0",
            "workspace": "prod-e2e",
            "capabilities": ["chat"],
            "started_at": "2026-04-19T00:00:00+00:00",
            "updated_at": "2026-04-19T00:00:00+00:00",
            "operations": [],
        },
    )

    assert timeouts == [10, 90]
    assert payload["runtime_session_id"] == "session-read-timeout"


def test_sync_runtime_session_rejects_untrusted_oauth_issuer_before_network(tmp_path, monkeypatch):
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
    oauth_payload = store.get_sync_payload("oauth_local_credentials")
    assert isinstance(oauth_payload, dict)
    oauth_payload["issuer"] = "https://evil.example"
    store.set_sync_payload("oauth_local_credentials", oauth_payload, "2026-06-01T00:00:01+00:00")
    attempted_request = False

    def _fake_urlopen(request, timeout):
        nonlocal attempted_request
        attempted_request = True
        raise AssertionError("network call should be blocked before urlopen")

    stub_authenticated_urlopen(monkeypatch, _fake_urlopen)

    with pytest.raises(guard_runner_module.GuardSyncEndpointUntrustedError, match="hol-guard connect"):
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

    assert attempted_request is False


def test_sync_runtime_session_rejects_non_https_legacy_sync_url_before_network(tmp_path, monkeypatch):
    store = GuardStore(tmp_path / "guard-home")
    _seed_guard_cloud(store, workspace_id="workspace-1")
    assert guard_runner_module._test_sync_auth_context_override is not None
    guard_runner_module._test_sync_auth_context_override["sync_url"] = "http://hol.org/api/guard/receipts/sync"
    attempted_request = False

    def _fake_urlopen(request, timeout):
        nonlocal attempted_request
        attempted_request = True
        raise AssertionError("network call should be blocked before urlopen")

    stub_authenticated_urlopen(monkeypatch, _fake_urlopen)

    with pytest.raises(guard_runner_module.GuardSyncNotConfiguredError, match="not trusted"):
        guard_runner_module.sync_runtime_session(
            store,
            session={
                "session_id": "session-http-sync",
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

    assert attempted_request is False


def test_sync_runtime_session_rejects_unallowlisted_legacy_sync_url_before_network(tmp_path, monkeypatch):
    store = GuardStore(tmp_path / "guard-home")
    _seed_guard_cloud(store, workspace_id="workspace-1")
    assert guard_runner_module._test_sync_auth_context_override is not None
    guard_runner_module._test_sync_auth_context_override["sync_url"] = "https://evil.example/api/guard/receipts/sync"
    attempted_request = False

    def _fake_urlopen(request, timeout):
        nonlocal attempted_request
        attempted_request = True
        raise AssertionError("network call should be blocked before urlopen")

    stub_authenticated_urlopen(monkeypatch, _fake_urlopen)

    with pytest.raises(guard_runner_module.GuardSyncNotConfiguredError, match="not trusted"):
        guard_runner_module.sync_runtime_session(
            store,
            session={
                "session_id": "session-unallowlisted-sync",
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

    assert attempted_request is False


def test_sync_runtime_session_refreshes_oauth_access_token_and_rotates_refresh_token(tmp_path, monkeypatch):
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
    captured_requests: list[urllib.request.Request] = []

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
        captured_requests.append(request)
        if request.full_url == "https://hol.org/api/guard/oauth/token":
            assert request.get_method() == "POST"
            body = urllib.parse.parse_qs(request.data.decode("utf-8"))
            assert body["grant_type"] == ["refresh_token"]
            assert body["client_id"] == ["guard-local-daemon"]
            assert body["refresh_token"] == ["refresh-token-1"]
            assert _request_header(request, "User-Agent") == guard_runner_module._GUARD_SYNC_USER_AGENT
            assert isinstance(_request_header(request, "DPoP"), str) and _request_header(request, "DPoP")
            return _Response(
                {
                    "access_token": "oauth-access-token-1",
                    "refresh_token": "refresh-token-2",
                    "token_type": "DPoP",
                    "expires_in": 3600,
                }
            )
        assert request.full_url == "https://hol.org/api/guard/runtime/sessions/sync"
        assert _request_header(request, "Authorization") == "Bearer oauth-access-token-1"
        assert isinstance(_request_header(request, "DPoP"), str) and _request_header(request, "DPoP")
        return _Response(
            {
                "generatedAt": "2026-06-01T00:00:10+00:00",
                "items": [{"sessionId": "session-oauth"}],
            }
        )

    stub_authenticated_urlopen(monkeypatch, _fake_urlopen)

    payload = guard_runner_module.sync_runtime_session(
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

    credentials = store.get_oauth_local_credentials()

    assert [request.full_url for request in captured_requests] == [
        "https://hol.org/api/guard/oauth/token",
        "https://hol.org/api/guard/runtime/sessions/sync",
    ]
    assert payload["runtime_session_id"] == "session-oauth"
    assert credentials is not None
    assert credentials["refresh_token"] == "refresh-token-2"


def test_resolve_guard_sync_auth_context_serializes_refresh_token_rotation(tmp_path, monkeypatch):
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
        supply_chain_entitlement_expires_at="2026-07-01T00:00:00+00:00",
        supply_chain_firewall=True,
        supply_chain_plan_id="team",
        now="2026-06-01T00:00:00+00:00",
    )
    refresh_lock = threading.Lock()
    first_refresh_started = threading.Event()
    allow_first_refresh = threading.Event()
    observed_refresh_tokens: list[str] = []

    @contextmanager
    def _fake_refresh_lock(*, timeout_seconds: float = 30.0):
        del timeout_seconds
        with refresh_lock:
            yield

    def _fake_refresh(
        *,
        token_endpoint: str,
        client_id: str,
        refresh_token: str,
        dpop_key_material,
        credential_reloader=None,
    ) -> dict[str, object]:
        del token_endpoint, client_id, dpop_key_material, credential_reloader
        observed_refresh_tokens.append(refresh_token)
        if refresh_token == "refresh-token-1":
            first_refresh_started.set()
            assert allow_first_refresh.wait(timeout=3)
            return {
                "access_token": "access-token-1",
                "refresh_token": "refresh-token-2",
                "package_firewall_entitlement": {
                    "supply_chain_entitlement_expires_at": "2026-07-05T00:00:00+00:00",
                    "supply_chain_firewall": True,
                    "supply_chain_plan_id": "team",
                },
            }
        if refresh_token == "refresh-token-2":
            return {
                "access_token": "access-token-2",
                "refresh_token": "refresh-token-3",
                "package_firewall_entitlement": {
                    "supply_chain_entitlement_expires_at": "2026-07-05T00:00:00+00:00",
                    "supply_chain_firewall": True,
                    "supply_chain_plan_id": "team",
                },
            }
        raise AssertionError(f"Unexpected refresh token: {refresh_token}")

    monkeypatch.setattr(store, "hold_oauth_refresh_lock", _fake_refresh_lock)
    monkeypatch.setattr(guard_runner_module, "_refresh_guard_oauth_access_token", _fake_refresh)

    results: list[dict[str, object]] = []
    errors: list[Exception] = []

    def _worker() -> None:
        try:
            results.append(guard_runner_module._resolve_guard_sync_auth_context(store))
        except Exception as error:  # pragma: no cover - asserted below
            errors.append(error)

    first = threading.Thread(target=_worker)
    second = threading.Thread(target=_worker)
    first.start()
    assert first_refresh_started.wait(timeout=1)
    second.start()
    allow_first_refresh.set()
    first.join()
    second.join()

    assert errors == []
    assert observed_refresh_tokens == ["refresh-token-1", "refresh-token-2"]
    assert [result["access_token"] for result in results] == ["access-token-1", "access-token-2"]
    credentials = store.get_oauth_local_credentials()
    assert credentials is not None
    assert credentials["refresh_token"] == "refresh-token-3"


def test_sign_guard_dpop_proof_sets_access_token_hash_claim() -> None:
    dpop_key_material = generate_dpop_key_pair()
    access_token = "oauth-access-token-1"

    proof = guard_runner_module._sign_guard_dpop_proof(
        request_url="https://hol.org/api/guard/runtime/sessions/sync",
        method="POST",
        dpop_key_material=dpop_key_material,
        access_token=access_token,
        now=datetime(2026, 6, 1, tzinfo=timezone.utc),
    )

    claims = _decode_jwt_segment(proof.split(".")[1])

    expected_ath = guard_runner_module._base64url_encode(hashlib.sha256(access_token.encode("ascii")).digest())

    assert claims["ath"] == expected_ath
