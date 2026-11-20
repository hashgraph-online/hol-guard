"""Signed network protection bundle: the saved form the runtime reads.

Guard Cloud signs one bundle per workspace with the supply-chain bundle key.
It carries the workspace's URL allow and block rules and known-bad URL
indicators collected from threat intelligence feeds. The native runtime owns
verification -- the canonical payload hash, the contract version, the
workspace, freshness, rollback, the trusted keyring and the RSA-PSS signature
-- and a bundle that fails there never reaches enforcement. What is left here
is the state key the saved copy lives under and the summary status output
reads off it.
"""

from __future__ import annotations

import time

NETWORK_PROTECTION_SYNC_STATE_KEY = "network_protection_bundle"
_MAX_AGE_SECONDS = 7 * 24 * 60 * 60


class NetworkProtectionBundleError(Exception):
    """The network protection bundle failed verification."""


def network_protection_status(saved: object, *, now: float | None = None) -> dict[str, object]:
    """A summary of the saved bundle for status output."""

    if not isinstance(saved, dict) or not isinstance(saved.get("bundle"), dict):
        return {"configured": False}
    bundle = saved["bundle"]
    rules = bundle.get("workspaceRules") if isinstance(bundle.get("workspaceRules"), list) else []
    threat_urls = bundle.get("threatUrls") if isinstance(bundle.get("threatUrls"), dict) else {}
    threat_hosts = bundle.get("threatHosts") if isinstance(bundle.get("threatHosts"), dict) else {}
    expires_at_epoch = saved.get("expiresAtEpoch")
    current_time = now if now is not None else time.time()
    indicators_fresh = isinstance(expires_at_epoch, int) and current_time <= expires_at_epoch + _MAX_AGE_SECONDS
    return {
        "configured": True,
        "bundle_version": bundle.get("bundleVersion"),
        "generated_at": bundle.get("generatedAt"),
        "expires_at": bundle.get("expiresAt"),
        "block_rules": sum(1 for rule in rules if isinstance(rule, dict) and rule.get("action") == "block"),
        "allow_rules": sum(1 for rule in rules if isinstance(rule, dict) and rule.get("action") == "allow"),
        "known_bad_urls": sum(len(group) for group in threat_urls.values() if isinstance(group, list)),
        "known_bad_hosts": sum(len(group) for group in threat_hosts.values() if isinstance(group, list)),
        "indicators_applied": indicators_fresh,
    }
