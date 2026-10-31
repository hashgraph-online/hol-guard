"""Known-vulnerable runtime launch cases: Guard checks the Node.js a command names before it runs.

Each case seeds the fixture Guard home with a signed supply-chain bundle whose runtime
advisory covers Node.js 20.0.0 up to 22.5.0, plus the sync records that anchor it to the
fixture workspace, so launch admission has the same local inputs a connected install has.
No Cloud call is made: the recorded sign-in holds a workspace and no credential.

The ``node`` executables are shell scripts unpacked in the fixture workspace the way a
Node.js release archive unpacks (``node-v22.1.0-linux-x64/bin/node``). Guard identifies the
build from that layout, so the script's text never matters, and a script that claims a
patched build cannot clear an affected path. Each one records that it ran, so a stopped
launch is proved by the missing record, not only by the hook verdict.
"""

from __future__ import annotations

import base64
import hashlib
import json
import shlex
from datetime import datetime, timedelta, timezone
from pathlib import Path

PATCHED_CASE = "runtime-patched-launch-quiet"
UNKNOWN_CASE = "runtime-unknown-balanced-quiet"
AFFECTED_CASE = "runtime-affected-launch-stopped"
SPOOF_CASE = "runtime-version-spoof-unknown"
ALTERNATE_CASE = "runtime-alternate-path-affected"
OFFLINE_CASE = "runtime-offline-affected-stopped"
QUIET_CASES = frozenset({PATCHED_CASE, UNKNOWN_CASE})
STOPPED_CASES = frozenset({AFFECTED_CASE, SPOOF_CASE, ALTERNATE_CASE, OFFLINE_CASE})
RUNTIME_CASES = QUIET_CASES | STOPPED_CASES

FINDING_REASON = "native_runtime_known_vulnerable"
RUNTIME_BLOCK_REASONS: dict[str, frozenset[str]] = {case: frozenset({FINDING_REASON}) for case in STOPPED_CASES}
LAUNCH_CHECK = "runtime-launch-recorded"
NOT_LAUNCHED_CHECK = "runtime-launch-absent"

WORKSPACE_ID = "11111111-1111-4111-8111-111111111111"
ADVISORY_ID = "CVE-2026-0000-GAUNTLET"
AFFECTED_VERSION = "22.1.0"
PATCHED_VERSION = "22.9.1"
OUTPUT = "runtime launched\n"
LAUNCH_RECORD = ".gauntlet-runtime-launched"
STRICT_CONFIG = 'security_level = "strict"\n'

# Workspace-relative launch paths. The archive directory name carries the version.
_AFFECTED_ARCHIVE = f"node-v{AFFECTED_VERSION}-linux-x64/bin/node"
_PATCHED_ARCHIVE = f"node-v{PATCHED_VERSION}-linux-x64/bin/node"
LAUNCH_PATHS: dict[str, str] = {
    PATCHED_CASE: _PATCHED_ARCHIVE,
    UNKNOWN_CASE: "tools/node",
    AFFECTED_CASE: _AFFECTED_ARCHIVE,
    SPOOF_CASE: _AFFECTED_ARCHIVE,
    ALTERNATE_CASE: f"runtimes/{_AFFECTED_ARCHIVE}",
    OFFLINE_CASE: _AFFECTED_ARCHIVE,
}


def _script(record: Path, claim: str = "") -> str:
    lines = ["#!/bin/sh"]
    if claim:
        lines.append(f"# {claim}")
    lines += [f": > {shlex.quote(str(record))}", f"printf '{OUTPUT.rstrip()}\\n'", ""]
    return "\n".join(lines)


def _advisory() -> dict[str, object]:
    return {
        "advisoryId": ADVISORY_ID,
        "aliases": [],
        "backportBuildIds": [],
        "includePrerelease": False,
        "knownExploited": False,
        "normalizedSeverity": "high",
        "ranges": [{"introduced": "20.0.0", "fixed": "22.5.0", "lastAffected": None}],
        "releaseLines": ["20", "22"],
        "sourceKey": "vendor-advisory",
        "summary": "Synthetic Gauntlet runtime advisory.",
        "target": {
            "kind": "runtime",
            "family": "node",
            "vendor": "nodejs.org",
            "component": None,
            "platforms": [{"os": "*", "arch": "*"}],
            "versionScheme": "semver",
        },
        "title": "Synthetic Node.js advisory",
    }


def _iso(moment: datetime) -> str:
    return moment.strftime("%Y-%m-%dT%H:%M:%S.") + f"{moment.microsecond // 1000:03d}Z"


def signed_response(*, expired: bool, now: datetime | None = None) -> dict[str, object]:
    """A bundle signed by a key generated for this run, carrying the one runtime advisory.

    An expired bundle ended a day ago; Guard keeps its affected matches and clears nothing.
    """
    # Imported here so the judge can load the catalog modules without Guard installed.
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding, rsa

    from codex_plugin_scanner.guard.runtime.supply_chain_bundle_runtime import canonical_supply_chain_bundle_payload

    current = now or datetime.now(timezone.utc)
    generated = current - timedelta(days=3 if expired else 0, hours=1)
    expires = current - timedelta(days=1) if expired else current + timedelta(days=1)
    bundle: dict[str, object] = {
        "advisories": [],
        "bundleVersion": f"{int(generated.timestamp() * 1000)}-gauntlet01",
        "emergencyDenylist": [],
        "expiresAt": _iso(expires),
        "feedSnapshotHash": "gauntlet-feed-snapshot",
        "generatedAt": _iso(generated),
        "keyId": "gauntlet-runtime-key",
        "packages": [],
        "policyHash": "gauntlet-policy",
        "policyRules": [],
        "runtimeAdvisories": {
            "schemaVersion": "runtime-advisories.v1",
            "rulesetVersion": "gauntlet-runtime-1",
            "entries": [_advisory()],
        },
        "scoringVersion": "scf-v1",
        "sourceHashes": [],
        "tier": "premium",
        "workspaceId": WORKSPACE_ID,
    }
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = (
        key.public_key()
        .public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        .decode()
    )
    canonical = canonical_supply_chain_bundle_payload(bundle)
    signature = key.sign(
        canonical,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256(),
    )
    return {
        "bundle": bundle,
        "payloadHash": hashlib.sha256(canonical).hexdigest(),
        "signature": base64.b64encode(signature).decode(),
        "signatureAlgorithm": "rsa-pss-sha256",
        "verificationKeys": [
            {
                "fingerprintSha256": hashlib.sha256(pem.strip().encode()).hexdigest(),
                "keyId": bundle["keyId"],
                "publicKeyPem": pem,
                "state": "active",
                "validUntil": None,
            }
        ],
    }


def seed_guard_home(guard_home: Path, *, expired: bool = False, strict: bool = False) -> None:
    """Record the bundle and the sync records that anchor it, as a connected install would."""
    from codex_plugin_scanner.guard.store import GuardStore

    guard_home.mkdir(mode=0o700, parents=True, exist_ok=True)
    if strict:
        (guard_home / "config.toml").write_text(STRICT_CONFIG, encoding="utf-8")
    response = signed_response(expired=expired)
    bundle = response["bundle"]
    assert isinstance(bundle, dict)
    now = _iso(datetime.now(timezone.utc))
    # Opened the way the Gauntlet daemon opens it, so seeding never reaches the host keyring.
    store = GuardStore(guard_home, source="default", prime_policy_integrity=False, allow_system_keyring=False)
    store.set_sync_payload("oauth_local_credentials", {"workspace_id": WORKSPACE_ID}, now)
    store.set_sync_payload(
        "supply_chain_bundle_keyring", {"workspace_id": WORKSPACE_ID, "keys": response["verificationKeys"]}, now
    )
    store.set_sync_payload(
        "supply_chain_bundle_entitlement",
        {"workspace_id": WORKSPACE_ID, "bundle_version": bundle["bundleVersion"]},
        now,
    )
    store.cache_supply_chain_bundle(WORKSPACE_ID, json.loads(json.dumps(response)), now)


def launch_path(workspace: Path, scenario_id: str) -> Path:
    return workspace / LAUNCH_PATHS[scenario_id]


def stage_runtime_cases(guard_home: Path, workspace: Path, scenario_id: str) -> None:
    """Write the case's executables and seed its Guard home; every other case is untouched."""
    if scenario_id not in RUNTIME_CASES:
        return
    record = workspace / LAUNCH_RECORD
    claim = f"node v{PATCHED_VERSION} vendor_verified build" if scenario_id == SPOOF_CASE else ""
    targets = {launch_path(workspace, scenario_id)}
    if scenario_id == ALTERNATE_CASE:
        # The top-level archive is patched; only the alternate copy the command names is affected.
        targets.add(workspace / _PATCHED_ARCHIVE)
    for path in targets:
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        path.write_text(_script(record, claim), encoding="utf-8", newline="\n")
        path.chmod(0o755)
    seed_guard_home(guard_home, expired=scenario_id == OFFLINE_CASE, strict=scenario_id in STOPPED_CASES)


def runtime_case_checks(workspace: Path, scenario_id: str) -> dict[str, bool]:
    """A quiet case's launch ran; a stopped case's launch never did."""
    if scenario_id in QUIET_CASES:
        return {LAUNCH_CHECK: (workspace / LAUNCH_RECORD).is_file()}
    if scenario_id in STOPPED_CASES:
        return {NOT_LAUNCHED_CHECK: not (workspace / LAUNCH_RECORD).exists()}
    return {}


def runtime_required_checks(scenario_id: str) -> set[str]:
    if scenario_id in QUIET_CASES:
        return {LAUNCH_CHECK}
    if scenario_id in STOPPED_CASES:
        return {NOT_LAUNCHED_CHECK}
    return set()
