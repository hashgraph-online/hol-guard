from __future__ import annotations

import threading
from pathlib import Path

import pytest
from typing_extensions import override

from codex_plugin_scanner.guard.native_policy_snapshot_direct_lane_mcp_relay import (
    MCP_RELAY_BINDING_KEY,
    MCP_RELAY_VIEW_SCHEMA,
    NativePolicySnapshotMcpRelayMixin,
    extension_layers,
    mcp_relay_view,
)
from codex_plugin_scanner.guard.runtime.extension_control_authority import (
    AuthorityHealth,
    ExtensionControlAuthorityView,
)
from codex_plugin_scanner.guard.runtime.extension_control_contract import (
    CONTROL_SCHEMA_VERSION,
    ControlLayerKind,
    ExtensionControlLayer,
)
from codex_plugin_scanner.guard.runtime.extension_control_runtime import (
    ExtensionControlRuntime,
    ExtensionControlRuntimeSnapshot,
)

DIGEST = "a" * 64
LAYERS: list[object] = [{"kind": "local-admin", "global_lockdown": False, "controls": []}]


# A harness view as the native composer derives it; its shape is pinned in
# rust/crates/guard-runtime/src/policy_effective_views_tests.rs.
HARNESSES: dict[str, object] = {
    "codex": {
        "config": {"mode": "prompt", "harness_postures": {}},
        "hash_config": {"mode": "prompt", "sandbox_analysis": "off"},
    }
}


def test_the_view_needs_a_bound_harness_and_keeps_unreadable_layers_out() -> None:
    harnesses = dict(HARNESSES)

    assert mcp_relay_view({}, LAYERS) is None
    assert mcp_relay_view(None, LAYERS) is None
    assert mcp_relay_view(harnesses, LAYERS) == {
        "schema": MCP_RELAY_VIEW_SCHEMA,
        "harnesses": harnesses,
        "extension_layers": LAYERS,
    }
    assert mcp_relay_view(harnesses, None) == {"schema": MCP_RELAY_VIEW_SCHEMA, "harnesses": harnesses}


def _view(*layers: ExtensionControlLayer) -> ExtensionControlAuthorityView:
    return ExtensionControlAuthorityView(
        health=AuthorityHealth.PROTECTED, revision=1, catalog_digest=DIGEST, layers=layers
    )


def _runtime(*layers: ExtensionControlLayer) -> ExtensionControlRuntime:
    return ExtensionControlRuntime(_view(*layers))


def test_extension_layers_come_from_the_runtime_and_fail_closed_without_one() -> None:
    layer = ExtensionControlLayer(
        schema_version=CONTROL_SCHEMA_VERSION,
        kind=ControlLayerKind.LOCAL_ADMIN,
        catalog_digest=DIGEST,
        global_lockdown=False,
        controls=(),
    )

    class Broken(ExtensionControlRuntime):
        @override
        def current(self) -> ExtensionControlRuntimeSnapshot:
            raise RuntimeError("unreadable")

    class Store:
        def read_extension_control_authority_for_registry(self, _registry: object, **_kwargs) -> object:
            raise AssertionError("the view never reads the store")

    assert extension_layers(_runtime()) == []
    assert extension_layers(_runtime(layer)) == LAYERS
    assert extension_layers(None) is None
    assert extension_layers(Broken(_view())) is None
    assert extension_layers(Store()) is None


class _Publisher(NativePolicySnapshotMcpRelayMixin):
    def __init__(self, tmp_path: Path) -> None:
        self._condition = threading.Condition()
        self._publish_event = threading.Event()
        self.store = object()
        self._command_control_runtime: object | None = _runtime()
        self._compiled_mcp_relay_harnesses: dict[str, object] | None = dict(HARNESSES)
        self._direct_lane_ack_target: tuple[int, str] | None = (7, "digest")
        self.rebound = 0

    def _rebind_direct_lane(self) -> None:
        self.rebound += 1
        self._direct_lane_mcp_relay = None


def test_the_binding_carries_the_view_only_for_a_resident_that_accepts_it(tmp_path: Path) -> None:
    publisher = _Publisher(tmp_path)

    bound = publisher._with_mcp_relay_view({"generation": 1})
    assert bound is not None
    view = bound[MCP_RELAY_BINDING_KEY]
    assert isinstance(view, dict) and view["harnesses"] == HARNESSES
    assert publisher._with_mcp_relay_view(None) is None
    harnesses = publisher._compiled_mcp_relay_harnesses
    publisher._compiled_mcp_relay_harnesses = {}
    assert publisher._with_mcp_relay_view({"generation": 1}) == {"generation": 1}
    publisher._compiled_mcp_relay_harnesses = harnesses

    assert view["extension_layers"] == []
    publisher._command_control_runtime = None
    unlayered = publisher._with_mcp_relay_view({"generation": 1})
    assert unlayered is not None
    unlayered_view = unlayered[MCP_RELAY_BINDING_KEY]
    assert isinstance(unlayered_view, dict) and "extension_layers" not in unlayered_view
    publisher._command_control_runtime = _runtime()

    publisher._bind_mcp_relay_view(bound)
    assert publisher._direct_lane_mcp_relay == view
    publisher._bind_mcp_relay_view({"generation": 1})
    assert publisher._direct_lane_mcp_relay is None


@pytest.mark.parametrize("compiled", [None, {}])
def test_a_moved_view_rebinds_the_lane(tmp_path: Path, compiled: dict[str, object] | None) -> None:
    publisher = _Publisher(tmp_path)
    publisher._bind_mcp_relay_view(publisher._with_mcp_relay_view({}))
    publisher._recheck_direct_lane_mcp_relay()
    assert publisher.rebound == 0

    publisher._compiled_mcp_relay_harnesses = compiled
    publisher._recheck_direct_lane_mcp_relay()
    assert publisher.rebound == 1
    assert publisher._direct_lane_mcp_relay is None


def test_an_unbound_or_closed_lane_is_not_rechecked(tmp_path: Path) -> None:
    publisher = _Publisher(tmp_path)
    publisher._compiled_mcp_relay_harnesses = None
    publisher._recheck_direct_lane_mcp_relay()
    publisher._bind_mcp_relay_view(publisher._with_mcp_relay_view({}))
    publisher._direct_lane_ack_target = None
    publisher._recheck_direct_lane_mcp_relay()
    assert publisher.rebound == 0
