"""Seed builders and case list for ``record_cloud_vectors.py``."""

from __future__ import annotations

import base64
import hashlib
import json
from datetime import datetime, timedelta, timezone

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.rsa import generate_private_key

BASE_COMMIT = "7a712222b1"
WORKSPACE_ID = "workspace-alpha"
NOW = "2026-05-19T00:00:00Z"
TABLES = ("sync_state", "guard_supply_chain_bundle_cache", "guard_supply_chain_eval_cache")
KEY = generate_private_key(public_exponent=65537, key_size=2048)
PUBLIC_PEM = (
    KEY.public_key()
    .public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    .decode("utf-8")
    .strip()
)


def _iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def package(name: str, version: str, action: str, **extra: object) -> dict[str, object]:
    record: dict[str, object] = {
        "confidence": 990,
        "defaultAction": action,
        "ecosystem": "npm",
        "exploitLevel": "active",
        "knownExploited": True,
        "malwareState": "known",
        "name": name,
        "namespace": None,
        "normalizedSeverity": "critical",
        "packageAgeState": "watch",
        "purl": f"pkg:npm/{name}@{version}",
        "reachability": "reachable",
        "recommendedFixVersion": "1.2.9",
        "relatedAdvisoryIds": ["GHSA-vh95-rmgr-6w4m"],
        "riskScore": 980,
        "sourceIntegrityState": "high-risk",
        "version": version,
    }
    record.update(extra)
    return record


def signed_bundle(
    packages: list[dict[str, object]],
    *,
    policy_rules: list[dict[str, object]] | None = None,
    generated_at: datetime | None = None,
    expires_at: datetime | None = None,
    tier: str = "premium",
) -> dict[str, object]:
    generated = generated_at or datetime(2026, 5, 19, tzinfo=timezone.utc)
    bundle = {
        "advisories": [
            {
                "advisoryId": "GHSA-vh95-rmgr-6w4m",
                "aliases": ["CVE-2020-7598"],
                "confidence": 990,
                "exploitLevel": "active",
                "knownExploited": True,
                "malwareState": "known",
                "normalizedSeverity": "critical",
                "recommendedFixVersion": "1.2.9",
                "sourceKey": "ghsa",
                "summary": "Prototype pollution in minimist",
                "title": "Prototype pollution in minimist",
            }
        ],
        "bundleVersion": "1747612800000-deadbeef",
        "expiresAt": _iso(expires_at or generated + timedelta(hours=12)),
        "feedSnapshotHash": "feed-snapshot-1",
        "generatedAt": _iso(generated),
        "keyId": "guard-bundle-key-2026-05",
        "packages": packages,
        "policyHash": "policy-hash-1",
        "policyRules": policy_rules or [],
        "scoringVersion": "scf-v1",
        "sourceHashes": [{"payloadHash": "ghsa-feed-hash", "sourceKey": "ghsa", "staleStatus": "fresh"}],
        "tier": tier,
        "workspaceId": WORKSPACE_ID,
    }
    canonical = json.dumps(bundle, sort_keys=True, separators=(",", ":")).encode("utf-8")
    signature = KEY.sign(
        canonical,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256(),
    )
    return {
        "bundle": bundle,
        "payloadHash": hashlib.sha256(canonical).hexdigest(),
        "signature": base64.b64encode(signature).decode("utf-8"),
        "signatureAlgorithm": "rsa-pss-sha256",
        "verificationKeys": [
            {
                "fingerprintSha256": hashlib.sha256(PUBLIC_PEM.encode("utf-8")).hexdigest(),
                "keyId": "guard-bundle-key-2026-05",
                "publicKeyPem": PUBLIC_PEM,
                "state": "active",
                "validUntil": None,
            }
        ],
    }


def policy_rule(action: str, rule_id: str, **extra: object) -> dict[str, object]:
    rule: dict[str, object] = {
        "action": action,
        "ruleId": rule_id,
        "ecosystemSelector": "npm",
        "enabled": True,
        "expiresAt": "2099-01-01T00:00:00Z",
        "harnessSelector": "codex",
        "packageSelector": "minimist",
        "priority": 1,
        "severityThreshold": "low",
        "versionRangeSelector": "1.2.8",
    }
    rule.update(extra)
    return rule


def cloud_response(decision: str, enforcement: str, entitlement_state: str, name: str) -> dict[str, object]:
    blocked = decision == "block"
    return {
        "cacheStatus": "miss" if enforcement != "upgrade_required" else "upgrade-gated",
        "copy": {
            "ctaHref": "/guard/inbox",
            "ctaLabel": "Review evidence",
            "summary": f"{name} needs a safer version before you continue.",
            "title": "Critical install blocked" if blocked else "Upgrade required for cloud evaluation",
        },
        "decision": decision,
        "enforcement": enforcement,
        "entitlementState": entitlement_state,
        "evidenceIds": ["evidence-1"],
        "expiresAt": "2026-05-19T00:15:00Z",
        "generatedAt": NOW,
        "packages": [
            {
                "advisoryIds": ["GHSA-vh95-rmgr-6w4m"],
                "decision": decision,
                "ecosystem": "npm",
                "name": name,
                "namespace": None,
                "reasons": [
                    {
                        "advisoryId": "GHSA-vh95-rmgr-6w4m",
                        "code": "known_advisory",
                        "message": "Prototype pollution in minimist",
                        "packageName": name,
                        "severity": "critical" if blocked else "unknown",
                        "source": "ghsa",
                    }
                ],
                "recommendedFixVersion": "1.2.9" if blocked else None,
                "requestedVersion": "1.2.8" if blocked else None,
                "resolvedVersion": "1.2.8" if blocked else None,
                "riskScore": 980 if blocked else None,
                "sourceKeys": ["ghsa"] if blocked else [],
                "sourceStale": False,
                "status": "known" if blocked else "unknown",
            }
        ],
        "policyId": f"workspace:{WORKSPACE_ID}:supply-chain",
        "policyVersion": "policy-version-1",
        "reasons": [
            {
                "advisoryId": "GHSA-vh95-rmgr-6w4m",
                "code": "known_advisory" if blocked else "upgrade_required",
                "message": "Prototype pollution in minimist"
                if blocked
                else "Upgrade to a paid Guard workspace to unlock cloud package intelligence.",
                "packageName": name,
                "severity": "critical" if blocked else "unknown",
                "source": "ghsa" if blocked else "guard-cloud",
            }
        ],
        "recommendation": decision,
        "staleSources": [],
        "workspaceId": WORKSPACE_ID,
    }


CONNECTED = {"issuer": "https://hol.org", "client_id": "guard-local-daemon", "workspace_id": WORKSPACE_ID}
PAID = {"allowed": True, "reason": "paid_oauth_entitlement_active", "tier": "team", "upgrade_cta": None}
UNPAID = {"allowed": False, "reason": "paid_guard_cloud_required", "tier": "free", "upgrade_cta": "Upgrade"}
RECONNECT = {"allowed": False, "reason": "guard_cloud_reconnect_required", "tier": "team", "upgrade_cta": "Reconnect"}
MINIMIST_BLOCK = [package("minimist", "1.2.8", "block")]
LEFT_PAD_MONITOR = package(
    "left-pad",
    "1.0.0",
    "monitor",
    normalizedSeverity="low",
    exploitLevel="none",
    knownExploited=False,
    malwareState="none",
    riskScore=220,
    recommendedFixVersion=None,
)
LOCKFILE = '{"packages":{"node_modules/minimist":{"version":"1.2.8"}}}'


def tampered(response: dict[str, object]) -> dict[str, object]:
    """A cached bundle whose signed content changed after signing."""

    copy = json.loads(json.dumps(response))
    copy["bundle"]["packages"][0]["defaultAction"] = "monitor"
    return copy


def case(name: str, targets: list[str], **fields: object) -> dict[str, object]:
    return {
        "name": name,
        "targets": targets,
        "entitlement": fields.pop("entitlement", None),
        "files": fields.pop("files", {}),
        "lockfile_paths": fields.pop("lockfile_paths", []),
        "bundle": fields.pop("bundle", None),
        "bundle_cached_at": fields.pop("bundle_cached_at", NOW),
        "eval_cache": fields.pop("eval_cache", False),
        "network": fields.pop("network", None),
        **fields,
    }


def cases() -> list[dict[str, object]]:
    stale = signed_bundle(
        [LEFT_PAD_MONITOR],
        generated_at=datetime(2026, 5, 18, tzinfo=timezone.utc),
        expires_at=datetime(2026, 5, 18, 1, tzinfo=timezone.utc),
    )
    block_bundle = signed_bundle(MINIMIST_BLOCK)
    minimist = ["minimist@1.2.8"]
    lock = {"files": {"package-lock.json": LOCKFILE}, "lockfile_paths": ["package-lock.json"]}
    scenarios: list[tuple[str, list[str], dict[str, object]]] = [
        ("bundle_block", minimist, {"bundle": block_bundle}),
        (
            "bundle_policy_warn_override",
            minimist,
            {"bundle": signed_bundle(MINIMIST_BLOCK, policy_rules=[policy_rule("warn", "policy-rule-1")])},
        ),
        (
            "bundle_policy_block_override",
            minimist,
            {
                "bundle": signed_bundle(
                    [package("minimist", "1.2.8", "monitor")], policy_rules=[policy_rule("block", "policy-rule-2")]
                )
            },
        ),
        (
            "bundle_allow_exception",
            minimist,
            {
                "bundle": signed_bundle(
                    MINIMIST_BLOCK, policy_rules=[policy_rule("allow", "guard-exception-123", severityThreshold=None)]
                )
            },
        ),
        (
            "bundle_rule_wrong_harness",
            minimist,
            {
                "bundle": signed_bundle(
                    MINIMIST_BLOCK, policy_rules=[policy_rule("warn", "r3", harnessSelector="claude")]
                )
            },
        ),
        ("bundle_unlisted_package", ["left-pad@1.0.0"], {"bundle": block_bundle}),
        (
            "bundle_multi_package",
            ["minimist@1.2.8", "left-pad@1.0.0"],
            {"bundle": signed_bundle([*MINIMIST_BLOCK, LEFT_PAD_MONITOR])},
        ),
        ("stale_bundle", ["left-pad@1.0.0"], {"bundle": stale, "bundle_cached_at": "2026-05-18T01:00:00Z"}),
        ("bundle_transitive_lockfile", ["express@4.18.2"], {"bundle": block_bundle, **lock}),
        ("eval_cache_hit", minimist, {"bundle": block_bundle, "eval_cache": True}),
        ("tampered_bundle", minimist, {"bundle": tampered(block_bundle)}),
        ("no_bundle", ["left-pad@1.0.0"], {}),
        ("insecure_http_source", ["demo@http://packages.example.com/demo-1.0.0.tgz"], {"bundle": block_bundle}),
    ]
    out = [case(f"offline_{name}", targets, **extra) for name, targets, extra in scenarios]
    out += [
        case(f"unpaid_unreachable_{name}", targets, entitlement=UNPAID, network={"mode": "dropped"}, **extra)
        for name, targets, extra in scenarios
    ]
    ok = {"mode": "http", "status": 200}
    for status in (500, 401, 403, 422):
        for label, entitlement, extra in (
            ("paid", PAID, {}),
            ("unpaid_bundle", UNPAID, {"bundle": block_bundle}),
            ("unpaid_no_bundle", UNPAID, {}),
        ):
            out.append(
                case(
                    f"cloud_http_{status}_{label}",
                    minimist,
                    entitlement=entitlement,
                    network={**ok, "status": status, "payload": {}},
                    **extra,
                )
            )
    out += [
        case(
            "cloud_block_response",
            minimist,
            entitlement=PAID,
            network={**ok, "payload": cloud_response("block", "premium_cloud", "premium", "minimist")},
            **lock,
        ),
        case(
            "cloud_monitor_beats_bundle",
            minimist,
            entitlement=PAID,
            bundle=block_bundle,
            network={**ok, "payload": cloud_response("monitor", "premium_cloud", "premium", "minimist")},
        ),
        case(
            "cloud_upgrade_required",
            minimist,
            entitlement=UNPAID,
            network={**ok, "payload": cloud_response("upgrade_required", "upgrade_required", "free", "minimist")},
        ),
        case("cloud_invalid_payload_paid", minimist, entitlement=PAID, network={**ok, "payload": {"decision": 7}}),
        case("cloud_unreachable_paid", minimist, entitlement=PAID, network={"mode": "dropped"}),
        case(
            "cloud_unreachable_paid_bundle",
            minimist,
            entitlement=PAID,
            bundle=block_bundle,
            network={"mode": "dropped"},
        ),
        case("cloud_unreachable_reconnect", minimist, entitlement=RECONNECT, network={"mode": "dropped"}),
    ]
    return out
