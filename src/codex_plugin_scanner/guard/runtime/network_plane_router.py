"""Strict separation between Guard control-plane and workload networking."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import cast

from codex_plugin_scanner.guard.runtime.network_capability_contract import (
    ControlPlaneEscapeHatch,
    ControlPlaneRoute,
)
from codex_plugin_scanner.guard.runtime.network_policy_contract import require_digest, require_id


class NetworkPlane(str, Enum):
    GUARD_CONTROL = "guard-control"
    WORKLOAD = "workload"


@dataclass(frozen=True, slots=True)
class ControlPlaneRequest:
    installation_id: str
    executable_digest: str
    endpoint_digest: str
    route: ControlPlaneRoute
    plane: NetworkPlane = NetworkPlane.GUARD_CONTROL

    def __post_init__(self) -> None:
        require_id(self.installation_id, "installation_id")
        require_digest(self.executable_digest, "executable_digest")
        require_digest(self.endpoint_digest, "endpoint_digest")
        if not isinstance(cast(object, self.route), ControlPlaneRoute):
            raise ValueError("route must be exact")
        if self.plane is not NetworkPlane.GUARD_CONTROL:
            raise ValueError("control-plane requests must use the Guard control plane")


def escape_hatch_allows(
    hatch: ControlPlaneEscapeHatch,
    request: ControlPlaneRequest,
    *,
    now_epoch_ms: int,
) -> bool:
    """Authorize only an exact, current Guard control-plane request."""

    return (
        now_epoch_ms < hatch.expires_at_epoch_ms
        and request.plane is NetworkPlane.GUARD_CONTROL
        and request.installation_id == hatch.installation_id
        and request.executable_digest == hatch.executable_digest
        and request.endpoint_digest in hatch.endpoint_digests
        and request.route in hatch.routes
    )
