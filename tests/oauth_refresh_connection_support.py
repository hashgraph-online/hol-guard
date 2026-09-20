"""Shared offline OAuth refresh fixtures and controlled provider responses."""

from __future__ import annotations

import base64
import io
import json
import socket
import urllib.error
from email.message import Message
from typing import Any

import pytest

from codex_plugin_scanner.guard.runtime import runner
from codex_plugin_scanner.guard.store import GuardStore
from tests.test_oauth_connection_authority import NOW, _inputs


def _encoded(value: object) -> str:
    return base64.urlsafe_b64encode(json.dumps(value).encode()).decode().rstrip("=")


def _token(inputs: dict[str, Any]) -> str:
    return ".".join(
        (
            "synthetic",
            _encoded(
                {
                    "iss": inputs["issuer"],
                    "grant": {"grantId": inputs["grant_id"]},
                    "machine": {"machineId": inputs["machine_id"]},
                    "workspace": {"workspaceId": inputs["workspace_id"]},
                    "deviceId": inputs["device_id"],
                    "exp": 4070908800,
                }
            ),
            "synthetic",
        )
    )


class _Response:
    def __init__(self, inputs: dict[str, Any], *, rotate: bool = True) -> None:
        self.payload = {
            "access_token": _token(inputs),
            "token_type": "DPoP",
            "expires_in": 300,
            "refresh_token": "rotated-refresh" if rotate else inputs["refresh_token"],
        }

    def __enter__(self) -> _Response:
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def read(self) -> bytes:
        return json.dumps(self.payload).encode()


def _error(request: Any, *, nonce: bool = False) -> urllib.error.HTTPError:
    headers = Message()
    if nonce:
        headers["DPoP-Nonce"] = "controlled-nonce"
    return urllib.error.HTTPError(
        request.full_url,
        400,
        "controlled",
        headers,
        io.BytesIO(
            json.dumps(
                {
                    "error": "use_dpop_nonce" if nonce else "invalid_grant",
                    **({"dpop_nonce": "controlled-nonce"} if nonce else {}),
                }
            ).encode()
        ),
    )


@pytest.fixture(autouse=True)
def _offline(monkeypatch: pytest.MonkeyPatch) -> None:
    def denied(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("Unexpected raw network operation")

    monkeypatch.setattr(socket.socket, "connect", denied)
    monkeypatch.setattr(socket, "create_connection", denied)
    monkeypatch.setattr(runner, "_guard_runtime_was_upgraded", lambda: False)
    monkeypatch.setattr(runner, "_test_sync_auth_context_override", None)
    monkeypatch.delenv("HOL_GUARD_TEST_SYNC_AUTH_CONTEXT_JSON", raising=False)


def _mutate(peer: GuardStore, inputs: dict[str, Any], mutation: str) -> None:
    if mutation == "unchanged":
        return
    if mutation == "unrelated":
        peer.set_sync_payload("receipt_cursor", {"cursor": 7}, NOW)
    elif mutation == "named-source":
        other = GuardStore(peer.guard_home, source="other", allow_system_keyring=False)
        other.set_oauth_local_credentials(**inputs)
    elif mutation == "withdrawal":
        peer.delete_sync_payload(peer._oauth_local_credentials_state_key)
    elif mutation == "reset":
        peer.clear_cloud_sync_state_for_reconnect(now=NOW)
    elif mutation == "aba":
        peer.delete_sync_payload(peer._oauth_local_credentials_state_key)
        peer.set_oauth_local_credentials(**inputs)
    else:
        replacement = dict(inputs)
        if mutation in {"workspace", "grant"}:
            replacement[mutation + "_id"] = "replacement"
        elif mutation == "key":
            replacement.update({k: v for k, v in _inputs().items() if k.startswith("dpop_")})
        elif mutation == "endpoint":
            replacement.update(issuer="http://localhost:3041", client_id="replacement-client")
        elif mutation != "identical":
            raise AssertionError(mutation)
        peer.set_oauth_local_credentials(**replacement)
