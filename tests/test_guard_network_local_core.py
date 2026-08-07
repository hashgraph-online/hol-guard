from __future__ import annotations

from codex_plugin_scanner.guard.runtime.network_local_core import (
    bind_resolution,
    consolidate_network_intent,
    detect_proxy_tunnel,
    logical_flow_id,
    resolution_allows,
)
from codex_plugin_scanner.guard.runtime.network_policy_contract import (
    Destination,
    DestinationKind,
    NetworkFlowRequest,
    NetworkProtocol,
    ProcessTreeIdentity,
)

_DIGEST = "a" * 64


def _request(*, request_id: str, observed_at: int) -> NetworkFlowRequest:
    return NetworkFlowRequest(
        request_id=request_id,
        process_tree=ProcessTreeIdentity("install.alpha", "session.alpha", 42, 100, _DIGEST),
        destination=Destination(DestinationKind.HOST, "api.example.com"),
        protocol=NetworkProtocol.TCP,
        port=443,
        observed_at_epoch_ms=observed_at,
    )


def test_network_intent_consolidates_all_sources_canonically() -> None:
    intent = consolidate_network_intent(
        declared_hosts=("API.Example.COM.", "192.0.2.1"),
        command="curl https://downloads.example.com/archive --proxy=http://proxy.example.com:8080",
        environment={"HTTPS_PROXY": "http://egress.example.com:3128", "NO_PROXY": "localhost,api.example.com"},
    )

    assert tuple((item.kind.value, item.value) for item in intent.destinations) == (
        ("host", "api.example.com"),
        ("host", "downloads.example.com"),
        ("host", "egress.example.com"),
        ("host", "localhost"),
        ("host", "proxy.example.com"),
        ("ip", "192.0.2.1"),
    )
    assert intent.sources == (
        "command",
        "declared",
        "environment:HTTPS_PROXY",
        "environment:NO_PROXY",
    )


def test_network_intent_parses_url_credentials_and_bare_proxy_authorities() -> None:
    intent = consolidate_network_intent(
        command=("curl https://user:pass@api.example.com/path --proxy proxy.example.com:8080 --host [2001:db8::1]:443")
    )

    assert tuple((item.kind.value, item.value) for item in intent.destinations) == (
        ("host", "api.example.com"),
        ("host", "proxy.example.com"),
        ("ip", "2001:db8::1"),
    )

    bare_ipv6 = consolidate_network_intent(declared_hosts=("2001:db8::2",))
    assert bare_ipv6.destinations == (Destination(DestinationKind.IP, "2001:db8::2"),)


def test_proxy_tunnel_detection_covers_environment_flags_and_ssh_forwarding() -> None:
    findings = detect_proxy_tunnel(
        command="ssh -D 1080 gateway.example.com --proxy=http://proxy.example.com",
        environment={"ALL_PROXY": "socks5://127.0.0.1:9050"},
    )

    assert {(item.kind, item.source, item.value) for item in findings} == {
        ("proxy", "command", "--proxy"),
        ("proxy", "environment:ALL_PROXY", "socks5://127.0.0.1:9050"),
        ("tunnel", "command", "ssh"),
        ("tunnel", "command", "ssh-forward"),
    }


def test_proxy_tunnel_detection_ignores_unrelated_ssh_options() -> None:
    findings = detect_proxy_tunnel(command="ssh -LogLevel INFO gateway.example.com")

    assert {(item.kind, item.value) for item in findings} == {("tunnel", "ssh")}


def test_resolution_binding_never_widens_and_expires_monotonically() -> None:
    binding = bind_resolution(
        host="api.example.com",
        addresses=("2001:0db8::1", "192.0.2.1", "192.0.2.1"),
        observed_at_epoch_ms=1_000,
        ttl_seconds=2,
    )

    assert tuple(item.value for item in binding.addresses) == ("192.0.2.1", "2001:db8::1")
    assert not resolution_allows(binding, address="192.0.2.1", now_epoch_ms=999)
    assert resolution_allows(binding, address="192.0.2.1", now_epoch_ms=1_000)
    assert not resolution_allows(binding, address="192.0.2.2", now_epoch_ms=1_001)
    assert not resolution_allows(binding, address="192.0.2.1", now_epoch_ms=3_000)


def test_logical_flow_groups_retries_but_not_distinct_connections() -> None:
    first = _request(request_id="request.one", observed_at=1_000)
    retry = _request(request_id="request.two", observed_at=2_000)
    different = NetworkFlowRequest(
        request_id="request.three",
        process_tree=first.process_tree,
        destination=first.destination,
        protocol=first.protocol,
        port=8443,
        observed_at_epoch_ms=2_000,
    )

    assert logical_flow_id(first) == logical_flow_id(retry)
    assert logical_flow_id(first) != logical_flow_id(different)
