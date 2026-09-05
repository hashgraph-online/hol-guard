"""The untrusted batch job identifier cannot replace the authenticated audit origin."""

from __future__ import annotations

import io
import json
from unittest.mock import Mock
from urllib.parse import parse_qs, urlsplit

import pytest

from codex_plugin_scanner.guard import local_supply_chain
from codex_plugin_scanner.guard.cloud_audit_request import build_cloud_workspace_audit_request
from codex_plugin_scanner.guard.mdm import network_transport
from codex_plugin_scanner.guard.mdm.contracts import ManagedNetworkPolicy
from codex_plugin_scanner.no_redirect import RejectRedirects


@pytest.mark.parametrize(
    "job_id",
    [
        "job-123",
        "https://attacker.invalid/",
        "//attacker.invalid/",
        "\\\\attacker.invalid\\x",
        "../other",
        "%2f%2fattacker.invalid",
        "x?next=https://attacker.invalid/",
        "x#fragment",
        "x@attacker.invalid",
        "x\r\nHost: attacker.invalid",
        "./../..",
        "x\x00y",
        "résumé/東京",
    ],
)
@pytest.mark.parametrize("origin", ["https://hol.org", "https://staging.hol.org"])
def test_server_job_id_cannot_change_request_or_credential_origin(
    monkeypatch: pytest.MonkeyPatch, job_id: str, origin: str
) -> None:
    monkeypatch.delenv("HOL_GUARD_STAGING_ORIGIN", raising=False)
    context = {"sync_url": origin + "/api/guard/receipts/sync", "access_token": "fixture-token"}
    url = local_supply_chain._normalized_supply_chain_batch_job_url(
        str(context["sync_url"]), "workspace", job_id, page_size=20
    )
    header_builder = Mock(return_value={"Authorization": "Bearer fixture-token"})
    request = build_cloud_workspace_audit_request(
        auth_context=context, request_url=url, method="GET", payload=None, build_headers=header_builder
    )
    parsed = urlsplit(request.full_url)
    assert (parsed.scheme, parsed.netloc) == ("https", urlsplit(origin).netloc)
    assert parsed.fragment == ""
    assert parse_qs(parsed.query)["pageSize"] == ["20"]
    assert parsed.path.startswith("/api/guard/supply-chain/evaluate/batch/")
    assert request.get_header("Authorization") == "Bearer fixture-token"
    header_builder.assert_called_once_with(context, request_url=url, method="GET")


@pytest.mark.parametrize("managed", [False, True])
def test_authenticated_audit_transport_does_not_follow_redirects(
    monkeypatch: pytest.MonkeyPatch, managed: bool
) -> None:
    policy = ManagedNetworkPolicy()
    monkeypatch.setattr(network_transport, "resolved_network_policy", Mock(return_value=(policy, managed)))
    opener = Mock()
    direct = Mock(return_value=opener)
    managed_factory = Mock(return_value=opener)
    monkeypatch.setattr(network_transport.urllib.request, "build_opener", direct)
    monkeypatch.setattr(network_transport, "managed_opener", managed_factory)
    request = build_cloud_workspace_audit_request(
        auth_context={"sync_url": "https://hol.org/api/guard/receipts/sync"},
        request_url="https://hol.org/api/guard/supply-chain/evaluate/batch/job-123",
        method="GET",
        payload=None,
        build_headers=Mock(return_value={"Authorization": "Bearer fixture-token"}),
    )
    network_transport.managed_urlopen(request, timeout=5)
    handler = managed_factory.call_args.kwargs["redirect_handler"] if managed else direct.call_args.args[0]
    assert isinstance(handler, RejectRedirects)
    assert handler.redirect_request(request, None, 302, "Found", {}, "https://attacker.invalid/") is None
    opener.open.assert_called_once_with(request, timeout=5)


def test_polling_passes_only_same_origin_job_url_to_live_request_boundary(monkeypatch: pytest.MonkeyPatch) -> None:
    context = {"sync_url": "https://hol.org/api/guard/receipts/sync"}
    header_builder = Mock(return_value={"Authorization": "Bearer fixture-token"})
    transport = Mock(side_effect=lambda *_args, **_kwargs: io.StringIO(json.dumps({"status": "completed"})))
    runner = local_supply_chain._runtime_runner_module()
    monkeypatch.setattr(runner, "_guard_sync_headers", header_builder)
    monkeypatch.setattr(local_supply_chain, "managed_urlopen", transport)
    result = local_supply_chain._poll_cloud_workspace_audit_job(
        auth_context=context, workspace_id="workspace", job_id="//attacker.invalid/x"
    )
    assert result["status"] == "completed"
    request = transport.call_args.args[0]
    assert urlsplit(request.full_url).netloc == "hol.org"
    assert "%2F%2Fattacker.invalid%2Fx" in request.full_url
    header_builder.assert_called_once()
    transport.assert_called_once()
