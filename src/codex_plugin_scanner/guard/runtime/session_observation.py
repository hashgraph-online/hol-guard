"""Bounded source labels for runtime session observations."""

from __future__ import annotations


def cloud_local_identity_source_payload(local_identity: dict[str, object]) -> dict[str, str]:
    source: dict[str, str] = {
        "daemonId": "local-guard",
        "daemonVersion": "local-guard",
        "daemonStatus": "local-guard",
        "relayState": "local-guard",
    }
    if "hostname" in local_identity:
        source["hostname"] = "local-guard"
    if "ipAddress" in local_identity:
        source["ipAddress"] = "local-guard"
    if "privateIpAddress" in local_identity:
        source["privateIpAddress"] = "local-guard"
    if "publicIpAddress" in local_identity:
        source["publicIpAddress"] = "local-guard"
    return source
