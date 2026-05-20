"""Dataclasses for supply-chain bundle payloads."""

from __future__ import annotations

from dataclasses import dataclass

from .supply_chain_bundle_base import (
    _EXPLOIT_LEVEL_VALUES,
    _MALWARE_STATE_VALUES,
    _PACKAGE_ACTION_VALUES,
    _SEVERITY_VALUES,
    _STALE_STATUS_VALUES,
    _VERIFICATION_KEY_STATE_VALUES,
    SupplyChainBundleMalformedError,
    _bundle_version_timestamp,
    _optional_string,
    _parse_iso_timestamp,
    _require_bool,
    _require_int,
    _require_string,
    _require_string_array,
)


@dataclass(frozen=True, slots=True)
class SupplyChainVerificationKey:
    """Verification key advertised by the cloud bundle route."""

    key_id: str
    public_key_pem: str
    fingerprint_sha256: str
    state: str
    valid_until: str | None

    @property
    def valid_until_timestamp(self) -> float | None:
        if self.valid_until is None:
            return None
        return _parse_iso_timestamp(self.valid_until, field_name="validUntil")

    def to_dict(self) -> dict[str, object]:
        return {
            "fingerprintSha256": self.fingerprint_sha256,
            "keyId": self.key_id,
            "publicKeyPem": self.public_key_pem,
            "state": self.state,
            "validUntil": self.valid_until,
        }

    @staticmethod
    def from_dict(data: dict[str, object]) -> SupplyChainVerificationKey:
        state = _require_string(data, "state")
        if state not in _VERIFICATION_KEY_STATE_VALUES:
            raise SupplyChainBundleMalformedError(f"Unsupported verification key state: {state!r}")
        valid_until = _optional_string(data, "validUntil")
        if valid_until is not None:
            _parse_iso_timestamp(valid_until, field_name="validUntil")
        return SupplyChainVerificationKey(
            key_id=_require_string(data, "keyId"),
            public_key_pem=_require_string(data, "publicKeyPem"),
            fingerprint_sha256=_require_string(data, "fingerprintSha256"),
            state=state,
            valid_until=valid_until,
        )


@dataclass(frozen=True, slots=True)
class SupplyChainBundleAdvisory:
    """Advisory record inside the supply-chain bundle."""

    advisory_id: str
    aliases: tuple[str, ...]
    confidence: int
    exploit_level: str
    known_exploited: bool
    malware_state: str
    normalized_severity: str
    recommended_fix_version: str | None
    source_key: str
    summary: str
    title: str

    def to_dict(self) -> dict[str, object]:
        return {
            "advisoryId": self.advisory_id,
            "aliases": list(self.aliases),
            "confidence": self.confidence,
            "exploitLevel": self.exploit_level,
            "knownExploited": self.known_exploited,
            "malwareState": self.malware_state,
            "normalizedSeverity": self.normalized_severity,
            "recommendedFixVersion": self.recommended_fix_version,
            "sourceKey": self.source_key,
            "summary": self.summary,
            "title": self.title,
        }

    @staticmethod
    def from_dict(data: dict[str, object]) -> SupplyChainBundleAdvisory:
        exploit_level = _require_string(data, "exploitLevel")
        if exploit_level not in _EXPLOIT_LEVEL_VALUES:
            raise SupplyChainBundleMalformedError(f"Unsupported advisory exploitLevel: {exploit_level!r}")
        malware_state = _require_string(data, "malwareState")
        if malware_state not in _MALWARE_STATE_VALUES:
            raise SupplyChainBundleMalformedError(f"Unsupported advisory malwareState: {malware_state!r}")
        normalized_severity = _require_string(data, "normalizedSeverity")
        if normalized_severity not in _SEVERITY_VALUES:
            raise SupplyChainBundleMalformedError(f"Unsupported advisory normalizedSeverity: {normalized_severity!r}")
        return SupplyChainBundleAdvisory(
            advisory_id=_require_string(data, "advisoryId"),
            aliases=_require_string_array(data, "aliases"),
            confidence=_require_int(data, "confidence"),
            exploit_level=exploit_level,
            known_exploited=_require_bool(data, "knownExploited"),
            malware_state=malware_state,
            normalized_severity=normalized_severity,
            recommended_fix_version=_optional_string(data, "recommendedFixVersion"),
            source_key=_require_string(data, "sourceKey"),
            summary=_require_string(data, "summary"),
            title=_require_string(data, "title"),
        )


@dataclass(frozen=True, slots=True)
class SupplyChainBundlePackage:
    """Package record inside the supply-chain bundle."""

    confidence: int
    default_action: str
    ecosystem: str
    exploit_level: str
    known_exploited: bool
    malware_state: str
    name: str
    namespace: str | None
    normalized_severity: str
    package_age_state: str
    purl: str
    reachability: str
    recommended_fix_version: str | None
    related_advisory_ids: tuple[str, ...]
    risk_score: int
    source_integrity_state: str
    version: str

    def to_dict(self) -> dict[str, object]:
        return {
            "confidence": self.confidence,
            "defaultAction": self.default_action,
            "ecosystem": self.ecosystem,
            "exploitLevel": self.exploit_level,
            "knownExploited": self.known_exploited,
            "malwareState": self.malware_state,
            "name": self.name,
            "namespace": self.namespace,
            "normalizedSeverity": self.normalized_severity,
            "packageAgeState": self.package_age_state,
            "purl": self.purl,
            "reachability": self.reachability,
            "recommendedFixVersion": self.recommended_fix_version,
            "relatedAdvisoryIds": list(self.related_advisory_ids),
            "riskScore": self.risk_score,
            "sourceIntegrityState": self.source_integrity_state,
            "version": self.version,
        }

    @staticmethod
    def from_dict(data: dict[str, object]) -> SupplyChainBundlePackage:
        default_action = _require_string(data, "defaultAction")
        if default_action not in _PACKAGE_ACTION_VALUES:
            raise SupplyChainBundleMalformedError(f"Unsupported package defaultAction: {default_action!r}")
        exploit_level = _require_string(data, "exploitLevel")
        if exploit_level not in _EXPLOIT_LEVEL_VALUES:
            raise SupplyChainBundleMalformedError(f"Unsupported package exploitLevel: {exploit_level!r}")
        malware_state = _require_string(data, "malwareState")
        if malware_state not in _MALWARE_STATE_VALUES:
            raise SupplyChainBundleMalformedError(f"Unsupported package malwareState: {malware_state!r}")
        normalized_severity = _require_string(data, "normalizedSeverity")
        if normalized_severity not in _SEVERITY_VALUES:
            raise SupplyChainBundleMalformedError(f"Unsupported package normalizedSeverity: {normalized_severity!r}")
        return SupplyChainBundlePackage(
            confidence=_require_int(data, "confidence"),
            default_action=default_action,
            ecosystem=_require_string(data, "ecosystem"),
            exploit_level=exploit_level,
            known_exploited=_require_bool(data, "knownExploited"),
            malware_state=malware_state,
            name=_require_string(data, "name"),
            namespace=_optional_string(data, "namespace"),
            normalized_severity=normalized_severity,
            package_age_state=_require_string(data, "packageAgeState"),
            purl=_require_string(data, "purl"),
            reachability=_require_string(data, "reachability"),
            recommended_fix_version=_optional_string(data, "recommendedFixVersion"),
            related_advisory_ids=_require_string_array(data, "relatedAdvisoryIds"),
            risk_score=_require_int(data, "riskScore"),
            source_integrity_state=_require_string(data, "sourceIntegrityState"),
            version=_require_string(data, "version"),
        )


@dataclass(frozen=True, slots=True)
class SupplyChainBundlePolicyRule:
    """Policy rule record inside the supply-chain bundle."""

    action: str
    rule_id: str
    ecosystem_selector: str | None
    enabled: bool | None
    expires_at: str | None
    harness_selector: str | None
    package_selector: str | None
    priority: int | None
    severity_threshold: str | None
    version_range_selector: str | None

    def to_dict(self) -> dict[str, object]:
        return {
            "action": self.action,
            "ruleId": self.rule_id,
            "ecosystemSelector": self.ecosystem_selector,
            "enabled": self.enabled,
            "expiresAt": self.expires_at,
            "harnessSelector": self.harness_selector,
            "packageSelector": self.package_selector,
            "priority": self.priority,
            "severityThreshold": self.severity_threshold,
            "versionRangeSelector": self.version_range_selector,
        }

    @staticmethod
    def from_dict(data: dict[str, object]) -> SupplyChainBundlePolicyRule:
        action = _require_string(data, "action")
        if action not in _PACKAGE_ACTION_VALUES | {"review"}:
            raise SupplyChainBundleMalformedError(f"Unsupported policy action: {action!r}")
        severity_threshold = _optional_string(data, "severityThreshold")
        if severity_threshold is not None and severity_threshold not in _SEVERITY_VALUES:
            raise SupplyChainBundleMalformedError(f"Unsupported policy severityThreshold: {severity_threshold!r}")
        expires_at = _optional_string(data, "expiresAt")
        if expires_at is not None:
            _parse_iso_timestamp(expires_at, field_name="expiresAt")
        enabled = data.get("enabled")
        if enabled is not None and not isinstance(enabled, bool):
            raise SupplyChainBundleMalformedError("Policy enabled must be a boolean when present")
        priority = data.get("priority")
        if priority is not None and not isinstance(priority, int):
            raise SupplyChainBundleMalformedError("Policy priority must be an int when present")
        return SupplyChainBundlePolicyRule(
            action=action,
            rule_id=_require_string(data, "ruleId"),
            ecosystem_selector=_optional_string(data, "ecosystemSelector"),
            enabled=enabled,
            expires_at=expires_at,
            harness_selector=_optional_string(data, "harnessSelector"),
            package_selector=_optional_string(data, "packageSelector"),
            priority=priority,
            severity_threshold=severity_threshold,
            version_range_selector=_optional_string(data, "versionRangeSelector"),
        )


@dataclass(frozen=True, slots=True)
class SupplyChainBundleSourceHash:
    """Source-hash metadata inside the supply-chain bundle."""

    payload_hash: str | None
    source_key: str
    stale_status: str

    def to_dict(self) -> dict[str, object]:
        return {
            "payloadHash": self.payload_hash,
            "sourceKey": self.source_key,
            "staleStatus": self.stale_status,
        }

    @staticmethod
    def from_dict(data: dict[str, object]) -> SupplyChainBundleSourceHash:
        payload_hash = _optional_string(data, "payloadHash")
        stale_status = _require_string(data, "staleStatus")
        if stale_status not in _STALE_STATUS_VALUES:
            raise SupplyChainBundleMalformedError(f"Unsupported source staleStatus: {stale_status!r}")
        return SupplyChainBundleSourceHash(
            payload_hash=payload_hash,
            source_key=_require_string(data, "sourceKey"),
            stale_status=stale_status,
        )


@dataclass(frozen=True, slots=True)
class SupplyChainBundle:
    """Verified supply-chain bundle payload."""

    advisories: tuple[SupplyChainBundleAdvisory, ...]
    bundle_version: str
    expires_at: str
    feed_snapshot_hash: str
    generated_at: str
    key_id: str
    packages: tuple[SupplyChainBundlePackage, ...]
    policy_hash: str
    policy_rules: tuple[SupplyChainBundlePolicyRule, ...]
    scoring_version: str
    source_hashes: tuple[SupplyChainBundleSourceHash, ...]
    tier: str
    workspace_id: str

    @property
    def generated_at_timestamp(self) -> float:
        return _parse_iso_timestamp(self.generated_at, field_name="generatedAt")

    @property
    def expires_at_timestamp(self) -> float:
        return _parse_iso_timestamp(self.expires_at, field_name="expiresAt")

    @property
    def version_timestamp(self) -> int:
        return _bundle_version_timestamp(self.bundle_version)

    def to_dict(self) -> dict[str, object]:
        return {
            "advisories": [item.to_dict() for item in self.advisories],
            "bundleVersion": self.bundle_version,
            "expiresAt": self.expires_at,
            "feedSnapshotHash": self.feed_snapshot_hash,
            "generatedAt": self.generated_at,
            "keyId": self.key_id,
            "packages": [item.to_dict() for item in self.packages],
            "policyHash": self.policy_hash,
            "policyRules": [item.to_dict() for item in self.policy_rules],
            "scoringVersion": self.scoring_version,
            "sourceHashes": [item.to_dict() for item in self.source_hashes],
            "tier": self.tier,
            "workspaceId": self.workspace_id,
        }

    @staticmethod
    def from_dict(data: dict[str, object]) -> SupplyChainBundle:
        raw_advisories = data.get("advisories")
        raw_packages = data.get("packages")
        raw_policy_rules = data.get("policyRules")
        raw_source_hashes = data.get("sourceHashes")
        if not isinstance(raw_advisories, list):
            raise SupplyChainBundleMalformedError("Bundle advisories must be a list")
        if not isinstance(raw_packages, list):
            raise SupplyChainBundleMalformedError("Bundle packages must be a list")
        if not isinstance(raw_policy_rules, list):
            raise SupplyChainBundleMalformedError("Bundle policyRules must be a list")
        if not isinstance(raw_source_hashes, list):
            raise SupplyChainBundleMalformedError("Bundle sourceHashes must be a list")
        bundle = SupplyChainBundle(
            advisories=tuple(
                SupplyChainBundleAdvisory.from_dict(item) for item in raw_advisories if isinstance(item, dict)
            ),
            bundle_version=_require_string(data, "bundleVersion"),
            expires_at=_require_string(data, "expiresAt"),
            feed_snapshot_hash=_require_string(data, "feedSnapshotHash"),
            generated_at=_require_string(data, "generatedAt"),
            key_id=_require_string(data, "keyId"),
            packages=tuple(SupplyChainBundlePackage.from_dict(item) for item in raw_packages if isinstance(item, dict)),
            policy_hash=_require_string(data, "policyHash"),
            policy_rules=tuple(
                SupplyChainBundlePolicyRule.from_dict(item) for item in raw_policy_rules if isinstance(item, dict)
            ),
            scoring_version=_require_string(data, "scoringVersion"),
            source_hashes=tuple(
                SupplyChainBundleSourceHash.from_dict(item) for item in raw_source_hashes if isinstance(item, dict)
            ),
            tier=_require_string(data, "tier"),
            workspace_id=_require_string(data, "workspaceId"),
        )
        if len(bundle.advisories) != len(raw_advisories):
            raise SupplyChainBundleMalformedError("Bundle advisories must contain only objects")
        if len(bundle.packages) != len(raw_packages):
            raise SupplyChainBundleMalformedError("Bundle packages must contain only objects")
        if len(bundle.policy_rules) != len(raw_policy_rules):
            raise SupplyChainBundleMalformedError("Bundle policyRules must contain only objects")
        if len(bundle.source_hashes) != len(raw_source_hashes):
            raise SupplyChainBundleMalformedError("Bundle sourceHashes must contain only objects")
        _ = (
            bundle.generated_at_timestamp,
            bundle.expires_at_timestamp,
            bundle.version_timestamp,
        )
        return bundle


@dataclass(frozen=True, slots=True)
class SupplyChainBundleResponse:
    """Signed supply-chain bundle response from Guard Cloud."""

    bundle: SupplyChainBundle
    payload_hash: str
    signature: str
    signature_algorithm: str
    verification_keys: tuple[SupplyChainVerificationKey, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "bundle": self.bundle.to_dict(),
            "payloadHash": self.payload_hash,
            "signature": self.signature,
            "signatureAlgorithm": self.signature_algorithm,
            "verificationKeys": [item.to_dict() for item in self.verification_keys],
        }
