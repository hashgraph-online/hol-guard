"""Signed network protection bundle: verification and the saved form.

Guard Cloud signs one bundle per workspace with the supply-chain bundle key.
It carries the workspace's URL allow and block rules and known-bad URL
indicators collected from threat intelligence feeds. A bundle is verified
here before it is saved; the native runtime reads only the saved copy, so a
bundle that fails verification never reaches enforcement.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
import time
from collections.abc import Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey

from .supply_chain_bundle_base import SupplyChainBundleMalformedError, _parse_iso_timestamp
from .supply_chain_verification_keys import SupplyChainVerificationKey, load_supply_chain_verification_keys

NETWORK_PROTECTION_SYNC_STATE_KEY = "network_protection_bundle"
NETWORK_PROTECTION_CONTRACT_VERSION = "guard-network-protection-bundle.v1"
# Fingerprint of the production bundle signing key, trusted when no
# supply-chain keyring has been saved yet. A saved keyring takes over once it
# exists, so key rotation follows the keyring.
PINNED_NETWORK_BUNDLE_KEY_FINGERPRINTS = frozenset({"4c8f2d81f564e4a5b108896b87599001bdaf30be8ae961769fe958590b3ebb52"})
_CLOCK_SKEW_SECONDS = 300
_MAX_AGE_SECONDS = 7 * 24 * 60 * 60
_BUNDLE_VERSION = re.compile(r"^network-(\d+)-[0-9a-f]{16}$")
_RULE_ACTIONS = frozenset({"allow", "block"})
_RULE_MATCH_KINDS = frozenset({"domain", "url_prefix"})


class NetworkProtectionBundleError(Exception):
    """The network protection bundle failed verification."""


def _require_string(data: Mapping[str, object], key: str) -> str:
    value = data.get(key)
    if not isinstance(value, str) or not value:
        raise NetworkProtectionBundleError(f"Network protection bundle is missing {key}")
    return value


def _string_lists(data: Mapping[str, object], key: str) -> None:
    value = data.get(key)
    if not isinstance(value, dict):
        raise NetworkProtectionBundleError(f"Network protection bundle {key} must be an object")
    for group in value.values():
        if not isinstance(group, list) or not all(isinstance(item, str) for item in group):
            raise NetworkProtectionBundleError(f"Network protection bundle {key} must map to string lists")


def _validate_rules(bundle: Mapping[str, object]) -> None:
    rules = bundle.get("workspaceRules")
    if not isinstance(rules, list):
        raise NetworkProtectionBundleError("Network protection bundle workspaceRules must be a list")
    for rule in rules:
        if (
            not isinstance(rule, dict)
            or rule.get("action") not in _RULE_ACTIONS
            or rule.get("matchKind") not in _RULE_MATCH_KINDS
            or not isinstance(rule.get("pattern"), str)
            or not rule.get("pattern")
        ):
            raise NetworkProtectionBundleError("Network protection bundle has an invalid workspace rule")


def canonical_network_protection_payload(bundle: Mapping[str, object]) -> bytes:
    """The bytes the cloud hashes and signs: sorted keys, compact, ASCII."""

    return json.dumps(bundle, sort_keys=True, separators=(",", ":")).encode("utf-8")


def network_bundle_version_timestamp(bundle_version: str) -> int:
    match = _BUNDLE_VERSION.match(bundle_version)
    if match is None:
        raise NetworkProtectionBundleError("Network protection bundleVersion is malformed")
    return int(match.group(1))


def _timestamp(bundle: Mapping[str, object], key: str) -> float:
    try:
        return _parse_iso_timestamp(_require_string(bundle, key), field_name=key)
    except SupplyChainBundleMalformedError as error:
        raise NetworkProtectionBundleError(str(error)) from error


def _computed_fingerprint(key: SupplyChainVerificationKey) -> str:
    normalized_pem = key.public_key_pem.replace("\r\n", "\n").strip()
    return hashlib.sha256(normalized_pem.encode("utf-8")).hexdigest()


def _trusted_fingerprints(trusted_keys: tuple[SupplyChainVerificationKey, ...]) -> frozenset[str]:
    usable = frozenset(item.fingerprint_sha256 for item in trusted_keys if item.state != "revoked")
    if trusted_keys:
        return usable
    return PINNED_NETWORK_BUNDLE_KEY_FINGERPRINTS


def _verify_signature(key: SupplyChainVerificationKey, signature: str, payload: bytes) -> None:
    try:
        public_key = serialization.load_pem_public_key(key.public_key_pem.encode("utf-8"))
    except (ValueError, TypeError) as error:
        raise NetworkProtectionBundleError(f"Failed to load verification key: {error}") from error
    if not isinstance(public_key, RSAPublicKey):
        raise NetworkProtectionBundleError("Verification key must be RSA")
    try:
        signature_bytes = base64.b64decode(signature, validate=True)
    except ValueError as error:
        raise NetworkProtectionBundleError("Signature is not valid base64") from error
    try:
        public_key.verify(
            signature_bytes,
            payload,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256(),
        )
    except InvalidSignature as error:
        raise NetworkProtectionBundleError("Network protection bundle signature verification failed") from error


def verify_network_protection_response(
    response: object,
    *,
    workspace_id: str,
    trusted_keys: tuple[SupplyChainVerificationKey, ...] = (),
    cached_bundle_version: str | None = None,
    now: float | None = None,
) -> dict[str, object]:
    """Verify a bundle response and return the form saved in ``sync_state``.

    Checks the payload hash over the canonical payload, the contract version,
    the workspace, freshness, rollback against the saved bundle, that the
    signing key is anchored to the trusted keyring (or the pinned production
    key before any keyring is saved), and the RSA-PSS signature.
    """

    if not isinstance(response, dict):
        raise NetworkProtectionBundleError("Network protection bundle response must be an object")
    bundle = response.get("bundle")
    if not isinstance(bundle, dict):
        raise NetworkProtectionBundleError("Network protection bundle response is missing bundle")
    if response.get("signatureAlgorithm") != "rsa-pss-sha256":
        raise NetworkProtectionBundleError("Unsupported network protection bundle signature algorithm")
    canonical_payload = canonical_network_protection_payload(bundle)
    payload_hash = _require_string(response, "payloadHash")
    if hashlib.sha256(canonical_payload).hexdigest() != payload_hash:
        raise NetworkProtectionBundleError("Network protection bundle payloadHash does not match its payload")
    if bundle.get("contractVersion") != NETWORK_PROTECTION_CONTRACT_VERSION:
        raise NetworkProtectionBundleError("Unsupported network protection bundle contract version")
    if bundle.get("workspaceId") != workspace_id:
        raise NetworkProtectionBundleError("Network protection bundle belongs to a different workspace")
    _validate_rules(bundle)
    _string_lists(bundle, "threatUrls")
    _string_lists(bundle, "threatHosts")
    bundle_version = _require_string(bundle, "bundleVersion")
    version_timestamp = network_bundle_version_timestamp(bundle_version)
    if cached_bundle_version is not None:
        try:
            cached_timestamp = network_bundle_version_timestamp(cached_bundle_version)
        except NetworkProtectionBundleError:
            cached_timestamp = None
        if cached_timestamp is not None and version_timestamp < cached_timestamp:
            raise NetworkProtectionBundleError(
                f"Network protection bundle {bundle_version} is older than saved {cached_bundle_version}"
            )
    current_time = now if now is not None else time.time()
    generated_at = _timestamp(bundle, "generatedAt")
    expires_at = _timestamp(bundle, "expiresAt")
    if current_time > expires_at + _CLOCK_SKEW_SECONDS:
        raise NetworkProtectionBundleError("Network protection bundle has expired")
    if current_time < generated_at - _CLOCK_SKEW_SECONDS:
        raise NetworkProtectionBundleError("Network protection bundle generatedAt is in the future")
    if current_time - generated_at > _MAX_AGE_SECONDS:
        raise NetworkProtectionBundleError("Network protection bundle is too old")
    try:
        advertised = load_supply_chain_verification_keys(response.get("verificationKeys"))
    except SupplyChainBundleMalformedError as error:
        raise NetworkProtectionBundleError(str(error)) from error
    key_id = _require_string(bundle, "keyId")
    signing_key = next((item for item in advertised if item.key_id == key_id), None)
    if signing_key is None:
        raise NetworkProtectionBundleError("Network protection bundle keyId is not in the advertised keyring")
    if signing_key.fingerprint_sha256 != _computed_fingerprint(signing_key):
        raise NetworkProtectionBundleError("Verification key fingerprint does not match its public key")
    if signing_key.fingerprint_sha256 not in _trusted_fingerprints(trusted_keys):
        raise NetworkProtectionBundleError("Network protection bundle signing key is not trusted")
    if signing_key.state == "revoked":
        raise NetworkProtectionBundleError("A revoked key cannot sign the network protection bundle")
    if (
        signing_key.state == "grace"
        and signing_key.valid_until_timestamp is not None
        and current_time > signing_key.valid_until_timestamp
    ):
        raise NetworkProtectionBundleError("The network protection bundle signing key has expired")
    _verify_signature(signing_key, _require_string(response, "signature"), canonical_payload)
    return {
        "bundle": bundle,
        "expiresAtEpoch": int(expires_at),
        "payloadHash": payload_hash,
        "keyId": key_id,
    }


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
