from __future__ import annotations

import json
from pathlib import Path

from codex_plugin_scanner.guard.mdm import network_transport as transport_module


def _manifest() -> dict[str, object]:
    path = Path(__file__).parents[1] / "docs" / "guard" / "mdm-endpoints.v1.json"
    payload = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(payload, dict)
    return payload


def test_endpoint_manifest_is_versioned_complete_and_machine_readable() -> None:
    payload = _manifest()

    assert payload["schemaVersion"] == "hol-guard-endpoints.v1"
    endpoints = payload["endpoints"]
    assert isinstance(endpoints, list)
    assert endpoints

    seen_hosts: set[str] = set()
    for raw_endpoint in endpoints:
        assert isinstance(raw_endpoint, dict)
        assert set(raw_endpoint) == {
            "hostname",
            "port",
            "purpose",
            "required",
            "methods",
            "dataClass",
            "offlineFallback",
        }
        hostname = raw_endpoint["hostname"]
        assert isinstance(hostname, str) and hostname
        assert hostname == hostname.lower()
        assert hostname not in seen_hosts
        seen_hosts.add(hostname)
        assert raw_endpoint["port"] == 443
        assert isinstance(raw_endpoint["purpose"], str) and raw_endpoint["purpose"]
        assert isinstance(raw_endpoint["required"], bool)
        methods = raw_endpoint["methods"]
        assert isinstance(methods, list) and methods
        assert all(method in {"GET", "POST"} for method in methods)
        assert isinstance(raw_endpoint["dataClass"], str) and raw_endpoint["dataClass"]
        assert isinstance(raw_endpoint["offlineFallback"], str) and raw_endpoint["offlineFallback"]


def test_required_guard_cloud_is_separate_from_optional_public_registries() -> None:
    endpoints = _manifest()["endpoints"]
    assert isinstance(endpoints, list)
    by_host = {
        str(endpoint["hostname"]): endpoint
        for endpoint in endpoints
        if isinstance(endpoint, dict) and isinstance(endpoint.get("hostname"), str)
    }

    cloud = by_host["hol.org"]
    assert cloud["required"] is True
    assert "Guard Cloud" in str(cloud["purpose"])
    assert "Local enforcement continues" in str(cloud["offlineFallback"])

    public_registries = transport_module._PUBLIC_REGISTRIES
    assert public_registries <= by_host.keys()
    for hostname in public_registries:
        endpoint = by_host[hostname]
        assert endpoint["required"] is False
        assert str(endpoint["purpose"]).startswith("Optional")
        assert "signed cached intelligence" in str(endpoint["offlineFallback"])
