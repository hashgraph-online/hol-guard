"""Supply-chain bundle verification keys and keyring loading.

Kept apart from the bundle payload models so callers that only read the
stored keyring do not load the bundle parsing and verification code.
"""

from __future__ import annotations

from dataclasses import dataclass

from .supply_chain_bundle_base import (
    _VERIFICATION_KEY_STATE_VALUES,
    SupplyChainBundleMalformedError,
    _optional_string,
    _parse_iso_timestamp,
    _require_string,
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
