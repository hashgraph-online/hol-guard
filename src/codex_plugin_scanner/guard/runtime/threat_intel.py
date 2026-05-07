"""HOL Guard threat intelligence bundle handling.

Provides typed dataclasses, signature verification, freshness checks,
rollback protection, and multi-source advisory matching for the
cloud advisory client subsystem.
"""

from __future__ import annotations

import base64
import json
import time
from dataclasses import dataclass
from typing import Final

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey

_BUNDLE_MAX_AGE_SECONDS: Final[int] = 86_400 * 7
_BUNDLE_CLOCK_SKEW_SECONDS: Final[int] = 300


class ThreatIntelError(Exception):
    """Base error for threat intel bundle validation failures."""


class BundleSignatureError(ThreatIntelError):
    """Bundle signature did not verify against the provided public key."""


class BundleExpiredError(ThreatIntelError):
    """Bundle freshness window has elapsed."""


class BundleRollbackError(ThreatIntelError):
    """Bundle version is older than the cached version — possible rollback attack."""


class BundleMalformedError(ThreatIntelError):
    """Bundle JSON is missing required fields or contains invalid types."""


@dataclass(frozen=True, slots=True)
class ThreatAdvisory:
    """Single advisory record inside a threat intelligence bundle."""

    advisory_id: str
    source: str
    severity: str
    title: str
    affected_type: str
    matcher: str
    recommendation: str

    def to_dict(self) -> dict[str, object]:
        return {
            "advisory_id": self.advisory_id,
            "source": self.source,
            "severity": self.severity,
            "title": self.title,
            "affected_type": self.affected_type,
            "matcher": self.matcher,
            "recommendation": self.recommendation,
        }

    @staticmethod
    def from_dict(data: dict[str, object]) -> ThreatAdvisory:
        def _str(key: str) -> str:
            val = data.get(key)
            if not isinstance(val, str) or not val.strip():
                raise BundleMalformedError(f"ThreatAdvisory missing required string field: {key!r}")
            return val

        return ThreatAdvisory(
            advisory_id=_str("advisory_id"),
            source=_str("source"),
            severity=_str("severity"),
            title=_str("title"),
            affected_type=_str("affected_type"),
            matcher=_str("matcher"),
            recommendation=_str("recommendation"),
        )


@dataclass(frozen=True, slots=True)
class ThreatIntelBundle:
    """Signed, versioned advisory bundle from the HOL Guard cloud."""

    version: int
    generated_at: float
    expires_at: float
    source: str
    signature: str
    advisories: tuple[ThreatAdvisory, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "version": self.version,
            "generated_at": self.generated_at,
            "expires_at": self.expires_at,
            "source": self.source,
            "signature": self.signature,
            "advisories": [a.to_dict() for a in self.advisories],
        }

    @staticmethod
    def from_dict(data: dict[str, object]) -> ThreatIntelBundle:
        def _int(key: str) -> int:
            val = data.get(key)
            if not isinstance(val, int):
                raise BundleMalformedError(f"ThreatIntelBundle missing required int field: {key!r}")
            return val

        def _float(key: str) -> float:
            val = data.get(key)
            if isinstance(val, (int, float)):
                return float(val)
            raise BundleMalformedError(f"ThreatIntelBundle missing required numeric field: {key!r}")

        def _str(key: str) -> str:
            val = data.get(key)
            if not isinstance(val, str) or not val.strip():
                raise BundleMalformedError(f"ThreatIntelBundle missing required string field: {key!r}")
            return val

        raw_advisories = data.get("advisories")
        if not isinstance(raw_advisories, list):
            raise BundleMalformedError("ThreatIntelBundle 'advisories' must be a list")

        parsed_advisories: list[ThreatAdvisory] = []
        for idx, item in enumerate(raw_advisories):
            if not isinstance(item, dict):
                raise BundleMalformedError(
                    f"ThreatIntelBundle advisory at index {idx} must be an object, got {type(item).__name__}"
                )
            parsed_advisories.append(ThreatAdvisory.from_dict(item))

        return ThreatIntelBundle(
            version=_int("version"),
            generated_at=_float("generated_at"),
            expires_at=_float("expires_at"),
            source=_str("source"),
            signature=_str("signature"),
            advisories=tuple(parsed_advisories),
        )


def _canonical_payload(bundle: ThreatIntelBundle) -> bytes:
    """Deterministic JSON payload used for signature computation.

    Signs only the stable fields — excludes `signature` itself.
    Timestamps are serialized as integers to avoid float precision
    differences across JSON implementations.
    """
    payload = {
        "version": bundle.version,
        "generated_at": int(bundle.generated_at),
        "expires_at": int(bundle.expires_at),
        "source": bundle.source,
        "advisories": [a.to_dict() for a in bundle.advisories],
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()


def verify_bundle_signature(bundle: ThreatIntelBundle, public_key_pem: bytes) -> None:
    """Verify the RSA-PSS signature on a bundle.

    Raises BundleSignatureError if the signature does not verify.
    """
    try:
        loaded_key = serialization.load_pem_public_key(public_key_pem)
    except (ValueError, TypeError) as exc:
        raise BundleSignatureError(f"Failed to load public key: {exc}") from exc

    if not isinstance(loaded_key, RSAPublicKey):
        raise BundleSignatureError("Public key must be RSA")

    try:
        sig_bytes = base64.b64decode(bundle.signature)
    except Exception as exc:
        raise BundleSignatureError(f"Signature is not valid base64: {exc}") from exc

    payload = _canonical_payload(bundle)
    try:
        loaded_key.verify(
            sig_bytes,
            payload,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256(),
        )
    except InvalidSignature as exc:
        raise BundleSignatureError("Bundle signature verification failed") from exc


def check_bundle_freshness(bundle: ThreatIntelBundle, now: float | None = None) -> None:
    """Raise BundleExpiredError if the bundle is outside its freshness window.

    Uses wall-clock time by default; pass `now` in tests for determinism.
    """
    ts = now if now is not None else time.time()
    if ts > bundle.expires_at + _BUNDLE_CLOCK_SKEW_SECONDS:
        raise BundleExpiredError(f"Bundle expired at {bundle.expires_at:.0f}, current time is {ts:.0f}")
    if ts < bundle.generated_at - _BUNDLE_CLOCK_SKEW_SECONDS:
        raise BundleExpiredError(
            f"Bundle generated_at {bundle.generated_at:.0f} is in the future (current time {ts:.0f})"
        )


def check_bundle_rollback(bundle: ThreatIntelBundle, cached_version: int) -> None:
    """Raise BundleRollbackError if the bundle version regresses.

    Protects against a server serving an older bundle to downgrade protections.
    """
    if bundle.version < cached_version:
        raise BundleRollbackError(f"Bundle version {bundle.version} is older than cached version {cached_version}")


def load_bundle_from_json(raw_json: str) -> ThreatIntelBundle:
    """Parse a raw JSON string into a ThreatIntelBundle.

    Raises BundleMalformedError on invalid JSON or schema violations.
    """
    try:
        data = json.loads(raw_json)
    except json.JSONDecodeError as exc:
        raise BundleMalformedError(f"Bundle JSON is invalid: {exc}") from exc

    if not isinstance(data, dict):
        raise BundleMalformedError("Bundle root must be a JSON object")

    return ThreatIntelBundle.from_dict(data)


def advisory_severity_rank(severity: str) -> int:
    """Numeric rank for severity comparison (higher = more severe)."""
    return {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}.get(severity.lower(), 0)
