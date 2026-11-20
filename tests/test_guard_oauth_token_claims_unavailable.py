"""OAuth claim reads when Guard's local runtime cannot answer."""

from __future__ import annotations

import base64
import json

import pytest

from codex_plugin_scanner.guard import oauth_token_claims
from codex_plugin_scanner.guard.cli import connect_flow
from codex_plugin_scanner.guard.native_runner_authority import NativeRunnerAuthorityError


def _token(claims: dict[str, object]) -> str:
    body = base64.urlsafe_b64encode(json.dumps(claims).encode()).decode().rstrip("=")
    return f"header.{body}.signature"


@pytest.fixture
def unavailable(monkeypatch: pytest.MonkeyPatch) -> None:
    def refuse(*_args: object, **_kwargs: object) -> dict[str, object]:
        raise NativeRunnerAuthorityError("unavailable")

    monkeypatch.setattr(oauth_token_claims, "native_runner_authority", refuse)


@pytest.mark.usefixtures("unavailable")
def test_a_new_connection_fails_instead_of_saving_an_unbound_credential() -> None:
    payload = {"access_token": _token({"grant": {"grantId": "grant-1"}}), "token_type": "Bearer", "expires_in": 60}
    with pytest.raises(RuntimeError, match="could not read the access token"):
        connect_flow._parse_guard_token_exchange_payload(payload)


@pytest.mark.usefixtures("unavailable")
def test_a_refresh_still_returns_the_rotated_refresh_token() -> None:
    payload = {
        "access_token": _token({"grant": {"grantId": "grant-1"}}),
        "token_type": "Bearer",
        "expires_in": 60,
        "refresh_token": "rotated-refresh",
    }
    result = connect_flow._parse_guard_token_exchange_payload(payload, require_entitlement=False)
    assert result.refresh_token == "rotated-refresh"
    assert (result.grant_id, result.machine_id, result.workspace_id, result.device_id) == (None, None, None, None)
    assert result.access_token_expires_at is None


@pytest.mark.usefixtures("unavailable")
def test_a_rotated_credential_keeps_its_saved_binding() -> None:
    credentials: dict[str, object] = {"grant_id": " grant-1 ", "machine_id": "machine-1", "device_id": ""}
    binding = oauth_token_claims.oauth_effective_binding(credentials, access_token=None, issuer="https://issuer.test")
    assert binding == {"device_id": None, "grant_id": "grant-1", "machine_id": "machine-1", "workspace_id": None}


@pytest.mark.usefixtures("unavailable")
def test_a_new_access_token_never_inherits_the_previous_binding() -> None:
    credentials: dict[str, object] = {"grant_id": "grant-1", "machine_id": "machine-1", "workspace_id": "ws-1"}
    binding = oauth_token_claims.oauth_effective_binding(
        credentials,
        access_token=_token({"grant": {"grantId": "grant-2"}}),
        issuer="https://issuer.test",
    )
    assert binding == {"device_id": None, "grant_id": None, "machine_id": None, "workspace_id": None}


@pytest.mark.usefixtures("unavailable")
def test_credential_recovery_reads_no_binding_and_expiry_lookup_raises() -> None:
    token = _token({"exp": 1})
    assert oauth_token_claims.oauth_binding_metadata(token, issuer="https://issuer.test") == {}
    assert oauth_token_claims.oauth_binding_from_credentials({"access_token": token, "issuer": "x"}) == {}
    with pytest.raises(NativeRunnerAuthorityError):
        oauth_token_claims.oauth_access_token_expires_at(token, expires_in=60, now=connect_flow.datetime.now())


def test_a_new_connection_keeps_its_identity_when_only_the_expiry_lookup_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def answer(_kind: str, args: dict[str, object]) -> dict[str, object]:
        if args["op"] == "expires_at":
            raise OSError("guard home unreadable")
        return {"identity": {"grant_id": "grant-1", "machine_id": "machine-1", "workspace_id": "ws-1"}}

    monkeypatch.setattr(oauth_token_claims, "native_runner_authority", answer)
    monkeypatch.setattr(connect_flow, "build_oauth_package_firewall_entitlement", lambda *_a, **_k: None)
    payload = {"access_token": _token({}), "token_type": "Bearer", "expires_in": 60}
    result = connect_flow._parse_guard_token_exchange_payload(payload)
    assert (result.grant_id, result.machine_id, result.workspace_id) == ("grant-1", "machine-1", "ws-1")
    assert result.access_token_expires_at is None
