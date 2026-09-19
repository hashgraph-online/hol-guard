"""Runtime regression tests: codex read only source inspection rejects malformed."""

from __future__ import annotations

from tests.guard_runtime_test_dependencies import (
    GuardStore,
    Path,
    datetime,
    generate_dpop_key_pair,
    guard_commands_module,
    guard_runner_module,
    io,
    json,
    pytest,
    stub_authenticated_urlopen,
    timezone,
    urllib,
)
from tests.guard_runtime_test_support import (
    _decode_jwt_segment,
    _request_header,
    _write_text,
)
from tests.guard_runtime_test_support import (
    _isolate_codex_runtime_marker as _isolate_codex_runtime_marker,
)


def test_codex_read_only_source_inspection_rejects_malformed_chains(tmp_path: Path) -> None:
    workspace_dir = tmp_path / "workspace"
    source_file = workspace_dir / "src" / "safe.ts"
    _write_text(source_file, "export const safe = true;\n")

    commands = [
        "&& sed -n '1,10p' src/safe.ts",
        "sed -n '1,10p' src/safe.ts &&",
        "sed -n '1,10p' src/safe.ts && && cat src/safe.ts",
        "sed -n '1,10p' src/safe.ts || cat src/safe.ts",
        "sed -n '1,10p' src/safe.ts;; cat src/safe.ts",
    ]

    for command in commands:
        assert not guard_commands_module._codex_command_is_read_only_source_inspection(
            command,
            cwd=workspace_dir,
        )


def test_sign_guard_dpop_proof_sets_nonce_claim() -> None:
    dpop_key_material = generate_dpop_key_pair()

    proof = guard_runner_module._sign_guard_dpop_proof(
        request_url="https://hol.org/api/guard/runtime/sessions/sync",
        method="POST",
        dpop_key_material=dpop_key_material,
        nonce="nonce-123",
        now=datetime(2026, 6, 1, tzinfo=timezone.utc),
    )

    claims = _decode_jwt_segment(proof.split(".")[1])

    assert claims["nonce"] == "nonce-123"


def test_guard_http_header_value_matches_case_insensitive_mapping() -> None:
    class _Response:
        def __init__(self) -> None:
            self.headers = {"dpop-nonce": "nonce-123"}

    assert guard_runner_module._guard_http_header_value(_Response(), "DPoP-Nonce") == "nonce-123"


def test_sync_runtime_session_retries_with_dpop_nonce_challenge(tmp_path, monkeypatch):
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
    challenge_nonce = "nonce-runtime"

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
        captured_requests.append(request)
        if len(captured_requests) == 1:
            raise urllib.error.HTTPError(
                request.full_url,
                401,
                "Unauthorized",
                {"DPoP-Nonce": challenge_nonce},
                io.BytesIO(b"{}"),
            )
        assert request.full_url == "https://hol.org/api/guard/runtime/sessions/sync"
        assert _request_header(request, "Authorization") == "Bearer oauth-access-token-1"
        assert isinstance(_request_header(request, "DPoP"), str) and _request_header(request, "DPoP")
        return _Response(
            {
                "generatedAt": "2026-06-01T00:00:10+00:00",
                "items": [{"status": "accepted"}],
            }
        )

    stub_authenticated_urlopen(monkeypatch, _fake_urlopen)

    payload = guard_runner_module.sync_runtime_session(
        store,
        auth_context={
            "sync_url": "https://hol.org/api/guard/receipts/sync",
            "access_token": "oauth-access-token-1",
            "dpop_key_material": dpop_key_material,
        },
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

    first_claims = _decode_jwt_segment(_request_header(captured_requests[0], "DPoP").split(".")[1])
    second_claims = _decode_jwt_segment(_request_header(captured_requests[1], "DPoP").split(".")[1])

    assert len(captured_requests) == 2
    assert "nonce" not in first_claims
    assert second_claims["nonce"] == challenge_nonce
    assert payload["runtime_session_id"] == "session-oauth"


def test_sync_runtime_session_limits_dpop_nonce_retries(tmp_path, monkeypatch):
    store = GuardStore(tmp_path / "guard-home")
    dpop_key_material = generate_dpop_key_pair()
    captured_requests: list[urllib.request.Request] = []

    def _fake_urlopen(request, timeout):
        del timeout
        captured_requests.append(request)
        attempt = len(captured_requests)
        raise urllib.error.HTTPError(
            request.full_url,
            401,
            "Unauthorized",
            {"dpop-nonce": f"nonce-{attempt}"},
            io.BytesIO(json.dumps({"error": "use_dpop_nonce"}).encode("utf-8")),
        )

    stub_authenticated_urlopen(monkeypatch, _fake_urlopen)

    with pytest.raises(RuntimeError, match="HTTP Error 401: Unauthorized"):
        guard_runner_module.sync_runtime_session(
            store,
            auth_context={
                "sync_url": "https://hol.org/api/guard/receipts/sync",
                "access_token": "oauth-access-token-1",
                "dpop_key_material": dpop_key_material,
            },
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

    assert len(captured_requests) == 4


def test_sync_runtime_session_refresh_retries_with_dpop_nonce_challenge(tmp_path, monkeypatch):
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
    challenge_nonce = "nonce-refresh"

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
        captured_requests.append(request)
        if request.full_url == "https://hol.org/api/guard/oauth/token":
            if len([item for item in captured_requests if item.full_url == request.full_url]) == 1:
                raise urllib.error.HTTPError(
                    request.full_url,
                    401,
                    "Unauthorized",
                    {"DPoP-Nonce": challenge_nonce},
                    io.BytesIO(b"{}"),
                )
            body = urllib.parse.parse_qs(request.data.decode("utf-8"))
            assert body["grant_type"] == ["refresh_token"]
            assert body["client_id"] == ["guard-local-daemon"]
            assert body["refresh_token"] == ["refresh-token-1"]
            return _Response(
                {
                    "access_token": "oauth-access-token-1",
                    "refresh_token": "refresh-token-2",
                    "token_type": "DPoP",
                    "expires_in": 3600,
                }
            )
        assert request.full_url == "https://hol.org/api/guard/runtime/sessions/sync"
        return _Response(
            {
                "generatedAt": "2026-06-01T00:00:10+00:00",
                "items": [{"status": "accepted"}],
            }
        )

    stub_authenticated_urlopen(monkeypatch, _fake_urlopen)

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

    refresh_requests = [
        request for request in captured_requests if request.full_url == "https://hol.org/api/guard/oauth/token"
    ]
    assert len(refresh_requests) == 2
    first_claims = _decode_jwt_segment(_request_header(refresh_requests[0], "DPoP").split(".")[1])
    second_claims = _decode_jwt_segment(_request_header(refresh_requests[1], "DPoP").split(".")[1])
    assert "nonce" not in first_claims
    assert second_claims["nonce"] == challenge_nonce

    credentials = store.get_oauth_local_credentials()
    assert credentials is not None
    assert credentials["refresh_token"] == "refresh-token-2"
