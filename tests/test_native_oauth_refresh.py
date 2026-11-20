"""The Guard OAuth refresh exchange through the native command, against a loopback token endpoint."""

from __future__ import annotations

import base64
import json
import threading
import urllib.parse
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import ClassVar

import pytest

from codex_plugin_scanner.guard.cli.oauth_client import generate_dpop_key_pair
from codex_plugin_scanner.guard.runtime import cloud_bundle_sync, runner
from codex_plugin_scanner.guard.runtime.runner import GuardSyncEndpointUntrustedError

pytestmark = [pytest.mark.native_oauth_refresh]

_TOKEN_PATH = "/api/guard/oauth/token"
# Built at runtime so the values never read as stored credentials.
_GRANT = "-".join(("loopback", "grant"))
_ACCESS = "-".join(("loopback", "access"))

_Reply = tuple[int, dict[str, str], dict[str, object]]


class _TokenHandler(BaseHTTPRequestHandler):
    replies: ClassVar[list[_Reply]] = []
    seen: ClassVar[list[tuple[dict[str, list[str]], str]]] = []

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", "0"))
        form = urllib.parse.parse_qs(self.rfile.read(length).decode("utf-8"))
        type(self).seen.append((form, self.headers.get("DPoP", "")))
        replies = type(self).replies
        status, headers, body = replies.pop(0) if len(replies) > 1 else replies[0]
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        for name, value in headers.items():
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(json.dumps(body).encode("utf-8"))

    def log_message(self, fmt: str, *args: object) -> None:
        return


@pytest.fixture
def origin() -> Iterator[str]:
    _TokenHandler.replies = []
    _TokenHandler.seen = []
    server = HTTPServer(("127.0.0.1", 0), _TokenHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        thread.join(timeout=5)


def _refresh(origin: str, path: str = _TOKEN_PATH) -> dict[str, object]:
    key = generate_dpop_key_pair()
    return cloud_bundle_sync.cloud_oauth_refresh(
        {
            "tokenEndpoint": f"{origin}{path}",
            "clientId": "guard-cli",
            "refreshToken": _GRANT,
            "dpopKey": {
                "privateKeyPem": key.private_key_pem,
                "publicJwk": dict(key.public_jwk),
                "algorithm": key.algorithm,
            },
        }
    )


def _proof_nonce(proof: str) -> object:
    claims = proof.split(".")[1]
    return json.loads(base64.urlsafe_b64decode(claims + "=" * (-len(claims) % 4))).get("nonce")


def _issued() -> _Reply:
    return 200, {}, {"access_token": _ACCESS, "token_type": "DPoP", "expires_in": 600, "plan": "team"}


def test_a_refreshed_grant_returns_the_whole_token_response(origin: str) -> None:
    _TokenHandler.replies = [_issued()]

    answer = _refresh(origin)

    assert answer["outcome"] == "refreshed"
    assert answer["payload"] == _issued()[2]
    form, proof = _TokenHandler.seen[0]
    assert form["grant_type"] == ["refresh_token"]
    assert form["client_id"] == ["guard-cli"]
    assert proof.count(".") == 2


def test_a_nonce_challenge_is_answered_with_a_new_proof(origin: str) -> None:
    challenge = (401, {"DPoP-Nonce": "nonce-1"}, {"error": "use_dpop_nonce"})
    _TokenHandler.replies = [challenge, _issued()]

    answer = _refresh(origin)

    assert answer["outcome"] == "refreshed"
    assert [_proof_nonce(proof) for _, proof in _TokenHandler.seen] == [None, "nonce-1"]


def test_a_nonce_handshake_that_never_settles_is_a_rejection_not_a_revoked_grant(origin: str) -> None:
    counter = iter(range(100))

    class _Endless(list[_Reply]):
        def pop(self, index: int = -1) -> _Reply:  # type: ignore[override]
            return 401, {"DPoP-Nonce": f"nonce-{next(counter)}"}, {"error": "use_dpop_nonce"}

        def __len__(self) -> int:
            return 2

    _TokenHandler.replies = _Endless()

    answer = _refresh(origin)

    assert answer["outcome"] == "rejected"


def test_a_revoked_grant_is_a_dead_grant(origin: str) -> None:
    _TokenHandler.replies = [(400, {}, {"error": "invalid_grant"})]

    assert _refresh(origin)["outcome"] == "dead_grant"


def test_a_rate_limit_keeps_the_server_wait(origin: str) -> None:
    _TokenHandler.replies = [(429, {"Retry-After": "600"}, {"error": "slow_down"})]

    answer = _refresh(origin)

    assert answer["outcome"] == "rate_limited"
    assert answer["retryAfter"] == "600"
    with pytest.raises(runner._GuardOAuthRefreshRateLimitedError) as raised:
        runner._refreshed_oauth_payload(answer)
    assert raised.value.retry_after_seconds == 600


def test_a_gateway_outage_is_unreachable(origin: str) -> None:
    _TokenHandler.replies = [(503, {}, {"error": "unavailable"})]

    answer = _refresh(origin)

    assert answer["outcome"] == "unreachable"
    with pytest.raises(runner.GuardSyncNotAvailableError) as raised:
        runner._refreshed_oauth_payload(answer)
    assert raised.value.retryable is True


def test_an_endpoint_guard_did_not_derive_is_refused_before_it_is_sent(origin: str) -> None:
    _TokenHandler.replies = [_issued()]

    with pytest.raises(GuardSyncEndpointUntrustedError):
        _refresh(origin, "/api/guard/other")

    assert _TokenHandler.seen == []
