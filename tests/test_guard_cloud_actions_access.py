"""Cloud actions access taken from the `hol-guard connect` pairing.

The pairing is exchanged at its own Guard Cloud for one AI tool's access, and
the answer is accepted only when it is Cloud actions access for the pairing's
workspace. Guard Cloud is replaced at the HTTP layer; the store is real.
"""

from __future__ import annotations

import base64
import io
import json
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Mapping
from dataclasses import dataclass, field
from email.message import Message
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.cli import cloud_actions_access as access
from codex_plugin_scanner.guard.cli.cloud_actions_access import (
    CloudActionsAccessError,
    CloudActionsPairing,
    exchange_cloud_actions_access,
    open_paired_store,
    read_cloud_actions_access,
    read_cloud_actions_pairing,
    revoke_cloud_actions_access,
)
from codex_plugin_scanner.guard.cli.connect_cloud_actions import record_cloud_actions_connect_report
from codex_plugin_scanner.guard.cli.oauth_client import GuardDpopKeyMaterial, resolve_guard_oauth_client_config
from codex_plugin_scanner.guard.runtime import runner
from codex_plugin_scanner.guard.store import GuardStore

WS = "6f1c2a52-6a4e-4b8e-9f0e-3f3d6c1b2a10"
OTHER_WS = "11111111-1111-4111-8111-111111111111"
ORIGIN = "https://hol.org"
RESOURCE = f"{ORIGIN}/api/guard/gateway/mcp"
TOKEN_ENDPOINT = resolve_guard_oauth_client_config(ORIGIN).token_endpoint
PAIRING = CloudActionsPairing(origin=ORIGIN, workspace_id=WS)
NOW = "2026-11-03T16:00:00+00:00"
DPOP = GuardDpopKeyMaterial(
    algorithm="ES256",
    private_key_pem="private-key",
    public_jwk={"kty": "EC", "crv": "P-256", "x": "x-value", "y": "y-value"},
    public_jwk_thumbprint="thumbprint-1",
)


def _jwt(claims: Mapping[str, object]) -> str:
    def part(value: object) -> str:
        return base64.urlsafe_b64encode(json.dumps(value).encode()).decode().rstrip("=")

    return f"{part({'alg': 'ES256'})}.{part(dict(claims))}.signature"


def _answer(**changes: object) -> dict[str, object]:
    claims = {"aud": [RESOURCE], "workspace": {"workspaceId": WS}}
    claims.update(changes.pop("claims", {}))  # pyright: ignore[reportCallIssue, reportArgumentType]
    answer: dict[str, object] = {
        "access_token": _jwt(claims),
        "token_type": "Bearer",
        "expires_in": 300,
        "scope": "gateway:discover gateway:invoke",
    }
    answer.update(changes)
    return answer


def _refusal(status: int, error: str | None, *, nonce: str | None = None) -> urllib.error.HTTPError:
    headers = Message()
    if nonce is not None:
        headers["DPoP-Nonce"] = nonce
    body = json.dumps({"error": error}).encode() if error else b""
    return urllib.error.HTTPError(TOKEN_ENDPOINT, status, "refused", headers, io.BytesIO(body))


@dataclass
class Cloud:
    answers: list[object] = field(default_factory=list)
    requests: list[urllib.request.Request] = field(default_factory=list)
    proofs: list[str | None] = field(default_factory=list)

    def urlopen(self, request: urllib.request.Request, timeout: float) -> io.BytesIO:
        del timeout
        self.requests.append(request)
        answer = self.answers.pop(0)
        if isinstance(answer, BaseException):
            raise answer
        return io.BytesIO(json.dumps(answer).encode())

    def form(self, index: int = -1) -> dict[str, str]:
        data = self.requests[index].data
        assert isinstance(data, bytes)
        return dict(urllib.parse.parse_qsl(data.decode()))


@pytest.fixture
def store(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> GuardStore:
    guard_store = GuardStore(tmp_path / "guard-home")
    health = {"state": "healthy", "issuer": ORIGIN, "workspace_id": WS, "grant_id": "grant-1"}
    monkeypatch.setattr(GuardStore, "get_oauth_local_credential_health", lambda self: dict(health))
    monkeypatch.setattr(
        GuardStore, "get_oauth_local_credentials", lambda self, **_: {"client_id": "guard-local-daemon"}
    )
    monkeypatch.setattr(
        runner,
        "_resolve_guard_sync_auth_context",
        lambda _store: {"access_token": "pairing-access", "dpop_key_material": DPOP},
    )
    return guard_store


@pytest.fixture
def cloud(monkeypatch: pytest.MonkeyPatch) -> Cloud:
    fake = Cloud()

    def sign(**kwargs: object) -> str:
        nonce = kwargs["nonce"]
        fake.proofs.append(nonce if isinstance(nonce, str) else None)
        return f"proof-{len(fake.proofs)}"

    monkeypatch.setattr(runner, "_sign_guard_dpop_proof", sign)
    monkeypatch.setattr("codex_plugin_scanner.guard.mdm.network.managed_urlopen", fake.urlopen)
    return fake


def test_exchange_names_the_ai_tool_and_signs_with_the_pairing_key(store: GuardStore, cloud: Cloud) -> None:
    cloud.answers.append(_answer())

    granted = exchange_cloud_actions_access(store, ai_tool="codex")

    assert granted.workspace_id == WS
    assert granted.scopes == ("gateway:discover", "gateway:invoke")
    [request] = cloud.requests
    assert request.full_url == TOKEN_ENDPOINT
    assert request.get_header("Dpop") == "proof-1"
    assert cloud.form() == {
        "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
        "client_id": "guard-local-daemon",
        "subject_token": "pairing-access",
        "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
        "resource": RESOURCE,
        "requested_application_id": "codex",
    }


def test_exchange_answers_a_proof_nonce_challenge(store: GuardStore, cloud: Cloud) -> None:
    cloud.answers += [_refusal(400, "use_dpop_nonce", nonce="nonce-1"), _answer()]

    _ = exchange_cloud_actions_access(store, ai_tool="cursor")

    assert cloud.proofs == [None, "nonce-1"]
    assert len(cloud.requests) == 2


@pytest.mark.parametrize(
    ("refusal", "reason"),
    [
        (_refusal(400, "invalid_grant"), "cloud_actions_not_allowed"),
        (_refusal(400, "invalid_target"), "not_available"),
        (_refusal(503, None), "cloud_unreachable"),
        (_refusal(400, "invalid_request"), "exchange_refused"),
    ],
)
def test_exchange_refusals_have_stable_reasons(
    refusal: urllib.error.HTTPError, reason: str, store: GuardStore, cloud: Cloud
) -> None:
    cloud.answers.append(refusal)

    with pytest.raises(CloudActionsAccessError) as error:
        _ = exchange_cloud_actions_access(store, ai_tool="codex")

    assert error.value.reason == reason


def test_exchange_stops_when_connect_turned_cloud_actions_off(store: GuardStore, cloud: Cloud) -> None:
    record_cloud_actions_connect_report(
        store, grant_id="grant-1", report={"status": "off", "workspace_id": WS}, now=NOW
    )

    with pytest.raises(CloudActionsAccessError) as error:
        _ = exchange_cloud_actions_access(store, ai_tool="codex")

    assert error.value.reason == "cloud_actions_off"
    assert cloud.requests == []


@pytest.mark.parametrize(
    "answer",
    [
        _answer(token_type="DPoP"),
        _answer(expires_in=0),
        _answer(scope="gateway:invoke guard:sync"),
        _answer(scope=""),
        _answer(claims={"aud": [f"{ORIGIN}/api/guard/sync"]}),
        _answer(claims={"workspace": {"workspaceId": OTHER_WS}}),
        _answer(claims={"workspace": {}}),
    ],
    ids=["not-bearer", "expired", "extra-scope", "no-scope", "other-audience", "other-workspace", "no-workspace"],
)
def test_only_cloud_actions_access_for_the_paired_workspace_is_accepted(answer: dict[str, object]) -> None:
    with pytest.raises(CloudActionsAccessError) as error:
        _ = read_cloud_actions_access(answer, pairing=PAIRING, now=0)

    assert error.value.reason == "access_invalid"


def test_an_unpaired_computer_has_no_pairing(store: GuardStore, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(GuardStore, "get_oauth_local_credential_health", lambda self: {"state": "missing"})

    with pytest.raises(CloudActionsAccessError) as error:
        _ = read_cloud_actions_pairing(store)

    assert error.value.reason == "not_paired"


def test_reading_the_pairing_never_creates_a_guard_home(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard-home"

    with pytest.raises(CloudActionsAccessError) as error:
        _ = open_paired_store(guard_home)

    assert error.value.reason == "not_paired"
    assert not guard_home.exists()


def test_revoke_ends_one_ai_tools_access_through_the_pairing(
    store: GuardStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    sent: list[urllib.request.Request] = []

    def request(_context: object, *, request_url: str, method: str, data: bytes) -> urllib.request.Request:
        return urllib.request.Request(request_url, data=data, method=method)

    def urlopen(*, request: urllib.request.Request, **_: object) -> dict[str, object]:
        sent.append(request)
        return {"revoked_ai_tools": ["codex"]}

    monkeypatch.setattr(runner, "_guard_sync_request", request)
    monkeypatch.setattr(runner, "_urlopen_json_with_timeout_retry", urlopen)

    assert revoke_cloud_actions_access(store, ai_tool="codex") == ["codex"]
    assert revoke_cloud_actions_access(store, ai_tool=None) == ["codex"]
    assert [item.full_url for item in sent] == [PAIRING.revoke_url] * 2
    assert [item.data for item in sent] == [b'{"ai_tool": "codex"}', b"{}"]


def test_the_gateway_address_follows_the_guard_cloud_path() -> None:
    assert access.CloudActionsPairing(origin=ORIGIN, workspace_id=None).gateway_url == RESOURCE


@pytest.mark.parametrize("call", ["exchange", "revoke"])
def test_a_rate_limited_pairing_refresh_is_an_access_error(
    store: GuardStore, cloud: Cloud, monkeypatch: pytest.MonkeyPatch, call: str
) -> None:
    def rate_limited(_store: GuardStore) -> dict[str, object]:
        raise runner._GuardOAuthRefreshRateLimitedError(30)  # pyright: ignore[reportPrivateUsage]

    monkeypatch.setattr(runner, "_resolve_guard_sync_auth_context", rate_limited)
    monkeypatch.setattr(access, "read_cloud_actions_pairing", lambda _store: PAIRING)

    with pytest.raises(CloudActionsAccessError) as error:
        if call == "exchange":
            _ = exchange_cloud_actions_access(store, ai_tool="codex")
        else:
            _ = revoke_cloud_actions_access(store, ai_tool="codex")

    assert error.value.reason == "rate_limited"
    assert "30 seconds" in str(error.value)
    assert cloud.requests == []
