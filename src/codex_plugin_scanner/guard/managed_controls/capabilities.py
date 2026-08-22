"""Capability negotiation for Extension-targeted Managed Controls."""

from __future__ import annotations

from dataclasses import dataclass

MANAGED_CONTROL_CAPABILITIES = frozenset(
    {
        "extension-catalog.v1",
        "extension-control-layer.v1",
        "policy-extension-targets.v1",
        "managed-controls-atomic-apply.v1",
    }
)


class CapabilityNegotiationError(ValueError):
    """Raised when a runtime cannot honor a required contract."""


def _positive_schema_version(value: object, *, label: str) -> int:
    if type(value) is not int or value <= 0:
        raise CapabilityNegotiationError(f"{label} must be a positive integer")
    return value


@dataclass(frozen=True, slots=True)
class RuntimeCapabilityAdvertisement:
    capabilities: frozenset[str]
    catalog_schema_version: int = 1
    extension_control_schema_version: int = 1

    @classmethod
    def from_values(
        cls,
        values: object,
        *,
        catalog_schema_version: int = 1,
        extension_control_schema_version: int = 1,
    ) -> "RuntimeCapabilityAdvertisement":
        if not isinstance(values, (list, tuple, set, frozenset)):
            raise CapabilityNegotiationError("capabilities must be a collection")
        if not all(isinstance(value, str) for value in values):
            raise CapabilityNegotiationError("capabilities must contain strings")
        capabilities = frozenset(values)
        return cls(
            capabilities=capabilities,
            catalog_schema_version=_positive_schema_version(
                catalog_schema_version,
                label="catalog schema version",
            ),
            extension_control_schema_version=_positive_schema_version(
                extension_control_schema_version,
                label="extension control schema version",
            ),
        )

    def require(self, required: frozenset[str]) -> None:
        missing = sorted(required - self.capabilities)
        if missing:
            raise CapabilityNegotiationError(
                f"runtime is missing required capabilities: {', '.join(missing)}"
            )

    @property
    def supports_managed_controls(self) -> bool:
        return MANAGED_CONTROL_CAPABILITIES <= self.capabilities
