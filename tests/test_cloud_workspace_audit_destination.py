"""Credential-bearing audit requests must stay on their validated sync origin."""

from __future__ import annotations

import json
from unittest.mock import Mock

import pytest

from codex_plugin_scanner.guard import local_supply_chain
from codex_plugin_scanner.guard.cloud_audit_request import build_cloud_workspace_audit_request


@pytest.mark.parametrize(
    "destination",
    [
        "https://attacker.invalid/audit",
        "http://hol.org/audit",
        "https://hol.org.attacker.invalid/audit",
        "https://user:password@hol.org/audit",
        "https://hol.org/audit#fragment",
        "https://staging.hol.org/audit",
        "http://127.0.0.1:3000/audit",
        "https://hol.org:444/audit",
        "//attacker.invalid/audit",
        "/audit",
    ],
)
def test_untrusted_audit_destination_never_receives_headers_or_network_access(
    monkeypatch: pytest.MonkeyPatch, destination: str
) -> None:
    monkeypatch.delenv("HOL_GUARD_STAGING_ORIGIN", raising=False)
    runner = local_supply_chain._runtime_runner_module()
    headers = Mock(side_effect=AssertionError("must not create credentials"))
    transport = Mock(side_effect=AssertionError("must not contact destination"))
    monkeypatch.setattr(runner, "_guard_sync_headers", headers)
    monkeypatch.setattr(local_supply_chain, "managed_urlopen", transport)
    with pytest.raises(ValueError):
        local_supply_chain._execute_cloud_workspace_audit_request(
            auth_context={"sync_url": "https://hol.org/api/guard/receipts/sync", "access_token": "fixture-token"},
            request_url=destination,
            method="POST",
            payload={"packages": []},
        )
    headers.assert_not_called()
    transport.assert_not_called()


@pytest.mark.parametrize("sync_url", [None, 7, "https://attacker.invalid/sync", "https://user@hol.org/sync"])
def test_invalid_sync_authority_is_rejected_before_headers(sync_url: object) -> None:
    headers = Mock()
    with pytest.raises(ValueError):
        build_cloud_workspace_audit_request(
            auth_context={"sync_url": sync_url},
            request_url="https://hol.org/audit",
            method="GET",
            payload=None,
            build_headers=headers,
        )
    headers.assert_not_called()


@pytest.mark.parametrize(
    "origin", ["https://hol.org", "https://staging.hol.org", "http://127.0.0.1:3000", "http://[::1]:3000"]
)
@pytest.mark.parametrize("method,payload", [("GET", None), ("POST", {"packages": []})])
def test_trusted_same_origin_preserves_method_body_and_query(origin: str, method: str, payload) -> None:
    context = {"sync_url": origin + "/prefix/api/guard/receipts/sync"}
    url = origin + "/prefix/api/guard/supply-chain/evaluate/batch?workspaceId=fixture&pageSize=20"
    headers = Mock(return_value={"Authorization": "Bearer fixture-token"})
    request = build_cloud_workspace_audit_request(
        auth_context=context,
        request_url=url,
        method=method,
        payload=payload,
        build_headers=headers,
    )
    assert request.full_url == url
    assert request.get_method() == method
    assert request.get_header("Authorization") == ("Bearer fixture-token" if origin.startswith("https:") else None)
    assert (json.loads(request.data) if request.data is not None else None) == payload
    if origin.startswith("https:"):
        headers.assert_called_once_with(context, request_url=url, method=method)
    else:
        headers.assert_not_called()


def test_explicit_staging_origin_is_preserved(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HOL_GUARD_STAGING_ORIGIN", "https://private-staging.example|/points")
    request = build_cloud_workspace_audit_request(
        auth_context={"sync_url": "https://private-staging.example/points/api/guard/receipts/sync"},
        request_url="https://private-staging.example/points/api/guard/supply-chain/evaluate/batch",
        method="GET",
        payload=None,
        build_headers=Mock(return_value={}),
    )
    assert request.full_url.startswith("https://private-staging.example/points/")
