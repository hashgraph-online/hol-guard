"""Construct declared hook capabilities."""

from .contract_models import CapabilityLocalHosted, HarnessEventCapability


def _capability(
    harness: str,
    event: str,
    transport: str,
    mode: str,
    declared_actions: tuple[str, ...],
    error_behavior: str,
    mandatory_compatibility: str,
    known_blind_spots: tuple[str, ...],
    source_reference: str,
    *,
    host_version_scope: str = "unknown",
    os_arch: str = "unknown",
    local_hosted: CapabilityLocalHosted = "local",
) -> HarnessEventCapability:
    """Create a source declaration row with conservative proof defaults."""

    return HarnessEventCapability(
        harness=harness,
        adapter=harness,
        host_version_scope=host_version_scope,
        os_arch=os_arch,
        local_hosted=local_hosted,  # type: ignore[arg-type]
        event=event,
        transport=transport,
        mode=mode,
        declared_actions=declared_actions,
        error_behavior=error_behavior,
        mandatory_compatibility=mandatory_compatibility,
        known_blind_spots=known_blind_spots,
        source_reference=source_reference,
    )
