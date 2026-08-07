from __future__ import annotations

import pytest

from codex_plugin_scanner.guard.runtime.network_capability_contract import (
    ControlPlaneEscapeHatch,
    ControlPlaneRoute,
)
from codex_plugin_scanner.guard.runtime.network_plane_router import (
    ControlPlaneRequest,
    NetworkPlane,
    escape_hatch_allows,
)

_DIGEST = "a" * 64
_ENDPOINT = "b" * 64


def _hatch() -> ControlPlaneEscapeHatch:
    return ControlPlaneEscapeHatch(
        installation_id="install.alpha",
        routes=frozenset({ControlPlaneRoute.POLICY}),
        endpoint_digests=(_ENDPOINT,),
        executable_digest=_DIGEST,
        expires_at_epoch_ms=2_000,
    )


def _request() -> ControlPlaneRequest:
    return ControlPlaneRequest(
        installation_id="install.alpha",
        executable_digest=_DIGEST,
        endpoint_digest=_ENDPOINT,
        route=ControlPlaneRoute.POLICY,
    )


def test_escape_hatch_allows_only_exact_guard_control_plane_identity() -> None:
    assert escape_hatch_allows(_hatch(), _request(), now_epoch_ms=1_999)
    assert not escape_hatch_allows(_hatch(), _request(), now_epoch_ms=2_000)
    assert not escape_hatch_allows(
        _hatch(),
        ControlPlaneRequest(
            installation_id="install.alpha",
            executable_digest="c" * 64,
            endpoint_digest=_ENDPOINT,
            route=ControlPlaneRoute.POLICY,
        ),
        now_epoch_ms=1_000,
    )


def test_workload_cannot_be_constructed_as_control_plane_traffic() -> None:
    with pytest.raises(ValueError, match="Guard control plane"):
        _ = ControlPlaneRequest(
            installation_id="install.alpha",
            executable_digest=_DIGEST,
            endpoint_digest=_ENDPOINT,
            route=ControlPlaneRoute.POLICY,
            plane=NetworkPlane.WORKLOAD,
        )
