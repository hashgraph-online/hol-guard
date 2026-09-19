"""Apply captured control authority to reads without inventing command matches."""

from __future__ import annotations

from collections.abc import Mapping

from .command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY
from .extension_control_authority import AuthorityHealth
from .extension_control_contract import ControlSurface
from .extension_control_resolver import resolve_extension_controls
from .extension_control_runtime import current_extension_control_snapshot


def sensitive_read_control_metadata() -> dict[str, object]:
    """A classified Read has no command observations, but Lockdown still applies."""
    snapshot = current_extension_control_snapshot()
    if snapshot is None or snapshot.health is AuthorityHealth.UNENROLLED:
        # No protected authority exists yet; retain the ordinary Read policy.
        return {}
    resolution = resolve_extension_controls(
        snapshot.layers,
        BUILT_IN_COMMAND_EXTENSION_REGISTRY,
        extension_ids=(),
        permission_ids=(),
        surface=ControlSurface.COMMAND_EVALUATION,
        authority_failure=snapshot.authority_failure,
    )
    if not resolution.blocked:
        return {}
    return {
        "command_action_floor": "block",
        "sensitive_read_control_floor": "block",
        "extension_control_resolution": {
            "blocked": True,
            "failures": [failure.code.value for failure in resolution.failures],
            "revision": snapshot.revision,
            "managed_revision": snapshot.managed_revision,
            "effective_digest": snapshot.effective_digest,
        },
    }


def sensitive_read_control_is_terminal(metadata: Mapping[str, object]) -> bool:
    """Observe and approvals cannot release captured Lockdown or invalid authority."""
    return metadata.get("sensitive_read_control_floor") == "block"
