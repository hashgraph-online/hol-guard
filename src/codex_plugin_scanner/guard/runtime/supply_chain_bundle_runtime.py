"""Verification and offline evaluation for supply-chain bundles."""

from __future__ import annotations

import base64
import hashlib
import json
import time
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey

from .supply_chain_bundle_base import (
    _BUNDLE_CLOCK_SKEW_SECONDS,
    _BUNDLE_MAX_AGE_SECONDS,
    SupplyChainBundleExpiredError,
    SupplyChainBundleKeyringError,
    SupplyChainBundleMalformedError,
    SupplyChainBundlePayloadHashError,
    SupplyChainBundleRollbackError,
    SupplyChainBundleSignatureError,
    _bundle_version_timestamp,
    _require_string,
)
from .supply_chain_bundle_models import (
    SupplyChainBundle,
    SupplyChainBundleEmergencyDeny,
    SupplyChainBundlePackage,
    SupplyChainBundleResponse,
    SupplyChainVerificationKey,
)
from .supply_chain_package_identity import (
    PackageIdentityError,
    canonical_package_identity,
    normalize_ecosystem,
    parse_package_identity,
)


@dataclass(frozen=True, slots=True)
class OfflineSupplyChainDecision:
    """Offline decision derived from a cached supply-chain bundle."""

    action: str
    bundle_version: str
    matched_advisory_ids: tuple[str, ...]
    reason: str
    stale: bool
    recommended_fix_version: str | None = None
    emergency_deny: bool = False


def canonical_supply_chain_bundle_payload(bundle: SupplyChainBundle | dict[str, object]) -> bytes:
    """Return the canonical payload used for payloadHash and RSA-PSS signing."""

    payload = bundle.to_dict() if isinstance(bundle, SupplyChainBundle) else bundle
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def payload_hash_for_supply_chain_bundle(bundle: SupplyChainBundle | dict[str, object]) -> str:
    return hashlib.sha256(canonical_supply_chain_bundle_payload(bundle)).hexdigest()


def load_supply_chain_verification_keys(raw: object) -> tuple[SupplyChainVerificationKey, ...]:
    """Load verification keys from a list payload or sync_state wrapper."""

    raw_keys = raw
    if isinstance(raw, dict):
        raw_keys = raw.get("keys")
    if not isinstance(raw_keys, list):
        return ()
    parsed: list[SupplyChainVerificationKey] = []
    for item in raw_keys:
        if not isinstance(item, dict):
            raise SupplyChainBundleMalformedError("verificationKeys must contain objects")
        parsed.append(SupplyChainVerificationKey.from_dict(item))
    return tuple(parsed)


def load_supply_chain_bundle_response(raw_json: str | dict[str, object]) -> SupplyChainBundleResponse:
    """Parse and validate a raw supply-chain bundle response."""

    if isinstance(raw_json, str):
        try:
            data = json.loads(raw_json)
        except json.JSONDecodeError as exc:
            raise SupplyChainBundleMalformedError(f"Bundle JSON is invalid: {exc}") from exc
    else:
        data = raw_json
    if not isinstance(data, dict):
        raise SupplyChainBundleMalformedError("Bundle root must be a JSON object")
    raw_bundle = data.get("bundle")
    if not isinstance(raw_bundle, dict):
        raise SupplyChainBundleMalformedError("Bundle response missing bundle object")
    signature_algorithm = _require_string(data, "signatureAlgorithm")
    if signature_algorithm != "rsa-pss-sha256":
        raise SupplyChainBundleMalformedError("Unsupported bundle signature algorithm")
    verification_keys = load_supply_chain_verification_keys(data.get("verificationKeys"))
    if not verification_keys:
        raise SupplyChainBundleMalformedError("Bundle response must include verification keys")
    return SupplyChainBundleResponse(
        bundle=SupplyChainBundle.from_dict(raw_bundle),
        signed_bundle=raw_bundle,
        payload_hash=_require_string(data, "payloadHash"),
        signature=_require_string(data, "signature"),
        signature_algorithm=signature_algorithm,
        verification_keys=verification_keys,
    )


def check_supply_chain_bundle_freshness(bundle: SupplyChainBundle, now: float | None = None) -> None:
    """Raise if the bundle is outside its freshness window."""

    current_time = now if now is not None else time.time()
    if current_time > bundle.expires_at_timestamp + _BUNDLE_CLOCK_SKEW_SECONDS:
        raise SupplyChainBundleExpiredError(
            f"Bundle expired at {bundle.expires_at}, current time is {current_time:.0f}"
        )
    if current_time < bundle.generated_at_timestamp - _BUNDLE_CLOCK_SKEW_SECONDS:
        raise SupplyChainBundleExpiredError(f"Bundle generatedAt {bundle.generated_at} is in the future")
    age = current_time - bundle.generated_at_timestamp
    if age > _BUNDLE_MAX_AGE_SECONDS:
        raise SupplyChainBundleExpiredError(
            f"Bundle age {age:.0f}s exceeds maximum allowed age of {_BUNDLE_MAX_AGE_SECONDS}s"
        )


def check_supply_chain_bundle_rollback(bundle: SupplyChainBundle, cached_bundle_version: str) -> None:
    """Raise if the bundle version timestamp regresses."""

    if bundle.version_timestamp < _bundle_version_timestamp(cached_bundle_version):
        raise SupplyChainBundleRollbackError(
            f"Bundle version {bundle.bundle_version} is older than cached version {cached_bundle_version}"
        )


def _computed_key_fingerprint(key: SupplyChainVerificationKey) -> str:
    normalized_pem = key.public_key_pem.replace("\r\n", "\n").strip()
    return hashlib.sha256(normalized_pem.encode("utf-8")).hexdigest()


def _validate_key_fingerprints(response: SupplyChainBundleResponse) -> None:
    for key in response.verification_keys:
        if key.fingerprint_sha256 != _computed_key_fingerprint(key):
            raise SupplyChainBundleKeyringError("Verification key fingerprint does not match its public key")


def _signing_key_is_trusted(
    signing_key: SupplyChainVerificationKey,
    trusted_keys: tuple[SupplyChainVerificationKey, ...],
) -> bool:
    trusted_fingerprints = {item.fingerprint_sha256 for item in trusted_keys}
    return signing_key.fingerprint_sha256 in trusted_fingerprints


def verify_supply_chain_bundle_response(
    response: SupplyChainBundleResponse,
    *,
    trusted_keys: tuple[SupplyChainVerificationKey, ...] | None = None,
    cached_bundle_version: str | None = None,
    now: float | None = None,
) -> None:
    """Verify payload hash, freshness, rollback, keyring anchor, and RSA-PSS signature."""

    canonical_payload = canonical_supply_chain_bundle_payload(response.signed_bundle)
    if hashlib.sha256(canonical_payload).hexdigest() != response.payload_hash:
        raise SupplyChainBundlePayloadHashError("Bundle payloadHash does not match the canonical payload")
    if cached_bundle_version is not None:
        check_supply_chain_bundle_rollback(response.bundle, cached_bundle_version)
    check_supply_chain_bundle_freshness(response.bundle, now=now)
    signing_key = next(
        (item for item in response.verification_keys if item.key_id == response.bundle.key_id),
        None,
    )
    if signing_key is None:
        raise SupplyChainBundleKeyringError("Bundle keyId is not present in the advertised verification keyring")
    _validate_key_fingerprints(response)
    if trusted_keys and not _signing_key_is_trusted(signing_key, trusted_keys):
        raise SupplyChainBundleKeyringError("Bundle signing key is not anchored to the trusted keyring")
    current_time = now if now is not None else time.time()
    if signing_key.state == "revoked":
        raise SupplyChainBundleKeyringError("Revoked verification key cannot sign supply-chain bundles")
    if (
        signing_key.state == "grace"
        and signing_key.valid_until_timestamp is not None
        and current_time > signing_key.valid_until_timestamp
    ):
        raise SupplyChainBundleKeyringError("Grace verification key is expired")
    try:
        public_key = serialization.load_pem_public_key(signing_key.public_key_pem.encode("utf-8"))
    except (ValueError, TypeError) as exc:
        raise SupplyChainBundleSignatureError(f"Failed to load verification key: {exc}") from exc
    if not isinstance(public_key, RSAPublicKey):
        raise SupplyChainBundleSignatureError("Verification key must be RSA")
    try:
        signature_bytes = base64.b64decode(response.signature)
    except Exception as exc:
        raise SupplyChainBundleSignatureError(f"Signature is not valid base64: {exc}") from exc
    try:
        public_key.verify(
            signature_bytes,
            canonical_payload,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256(),
        )
    except InvalidSignature as exc:
        raise SupplyChainBundleSignatureError("Supply-chain bundle signature verification failed") from exc


def _package_identity_matches(
    ecosystem: str,
    namespace: str | None,
    name: str,
    package_name: str,
) -> bool:
    try:
        package_identity = canonical_package_identity(
            ecosystem=ecosystem,
            namespace=namespace,
            name=name,
            version="*",
        )
        target_identity = parse_package_identity(ecosystem=ecosystem, package_name=package_name, version="*")
    except PackageIdentityError:
        return False
    return package_identity == target_identity


def _package_matches(package: SupplyChainBundlePackage, package_name: str, package_version: str | None) -> bool:
    if not _package_identity_matches(package.ecosystem, package.namespace, package.name, package_name):
        return False
    return package_version is None or package.version == package_version


def _emergency_deny_identity_matches(entry: SupplyChainBundleEmergencyDeny, package_name: str) -> bool:
    return _package_identity_matches(entry.ecosystem, entry.namespace, entry.name, package_name)


def _matching_emergency_deny_entries(
    bundle: SupplyChainBundle,
    *,
    package_name: str,
    ecosystem: str | None,
) -> tuple[SupplyChainBundleEmergencyDeny, ...]:
    return tuple(
        item
        for item in bundle.emergency_denylist
        if (ecosystem is None or item.ecosystem == ecosystem) and _emergency_deny_identity_matches(item, package_name)
    )


def _is_high_confidence_block(package: SupplyChainBundlePackage) -> bool:
    return package.default_action == "block" and (
        package.known_exploited
        or package.malware_state == "known"
        or (package.normalized_severity == "critical" and package.exploit_level == "active")
    )


def _blocking_bundle_reason(package: SupplyChainBundlePackage) -> str | None:
    if _is_high_confidence_block(package):
        return "known_malware_or_kev"
    if (
        package.default_action == "block"
        and package.source_integrity_state == "high-risk"
        and package.exploit_level in {"active", "elevated"}
        and package.normalized_severity in {"high", "critical"}
    ):
        return "maintainer_compromise"
    return None


def evaluate_cached_supply_chain_bundle(
    response: SupplyChainBundleResponse,
    *,
    package_name: str,
    package_version: str | None = None,
    ecosystem: str | None = None,
    now: float | None = None,
) -> OfflineSupplyChainDecision:
    """Evaluate one package against the cached supply-chain bundle."""

    stale = False
    try:
        check_supply_chain_bundle_freshness(response.bundle, now=now)
    except SupplyChainBundleExpiredError:
        stale = True
    try:
        normalized_ecosystem = normalize_ecosystem(ecosystem) if ecosystem is not None else None
    except PackageIdentityError:
        normalized_ecosystem = ""
    deny_entries = _matching_emergency_deny_entries(
        response.bundle,
        package_name=package_name,
        ecosystem=normalized_ecosystem,
    )
    if deny_entries:
        deny_entry = deny_entries[0]
        return OfflineSupplyChainDecision(
            action="block",
            bundle_version=response.bundle.bundle_version,
            matched_advisory_ids=(),
            reason=deny_entry.reason,
            stale=stale,
            recommended_fix_version=deny_entry.recommended_fix_version,
            emergency_deny=True,
        )
    matches = [
        item
        for item in response.bundle.packages
        if (normalized_ecosystem is None or item.ecosystem == normalized_ecosystem)
        and _package_matches(item, package_name, package_version)
    ]
    if not matches:
        return OfflineSupplyChainDecision(
            action="monitor",
            bundle_version=response.bundle.bundle_version,
            matched_advisory_ids=(),
            reason="no_cached_match",
            stale=stale,
        )
    package = max(matches, key=lambda item: item.risk_score)
    blocking_reason = _blocking_bundle_reason(package)
    if blocking_reason is not None:
        return OfflineSupplyChainDecision(
            action="block",
            bundle_version=response.bundle.bundle_version,
            matched_advisory_ids=package.related_advisory_ids,
            reason=blocking_reason,
            stale=stale,
        )
    if stale:
        return OfflineSupplyChainDecision(
            action="monitor",
            bundle_version=response.bundle.bundle_version,
            matched_advisory_ids=package.related_advisory_ids,
            reason="stale_low_confidence",
            stale=True,
        )
    return OfflineSupplyChainDecision(
        action=package.default_action if package.default_action != "allow" else "monitor",
        bundle_version=response.bundle.bundle_version,
        matched_advisory_ids=package.related_advisory_ids,
        reason="bundle_match",
        stale=False,
    )
