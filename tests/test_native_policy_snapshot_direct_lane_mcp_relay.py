from __future__ import annotations

import threading
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from typing import cast

import pytest
from typing_extensions import override

from codex_plugin_scanner.guard.config import GuardConfig
from codex_plugin_scanner.guard.native_policy_snapshot_direct_lane_mcp_relay import (
    MCP_RELAY_BINDING_KEY,
    MCP_RELAY_DECIDE_FEATURE,
    MCP_RELAY_VIEW_SCHEMA,
    REDACTION_LEVEL_KEY,
    NativePolicySnapshotMcpRelayMixin,
    extension_layers,
    harness_view,
    mcp_relay_view,
    uniform_harness_views,
    uniform_redaction_level,
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

FEATURES = (MCP_RELAY_DECIDE_FEATURE,)
DIGEST = "a" * 64
LAYERS: list[object] = [{"kind": "local-admin", "global_lockdown": False, "controls": []}]


def _config(tmp_path: Path, **fields: object) -> GuardConfig:
    return replace(GuardConfig(guard_home=tmp_path, workspace=None), **fields)


def test_a_harness_view_carries_the_proxy_config_and_hash_fields(tmp_path: Path) -> None:
    view = harness_view(_config(tmp_path, sandbox_analysis="on", managed_policy_hash="a" * 64), "codex")

    assert view is not None
    config = view["config"]
    hash_config = view["hash_config"]
    assert isinstance(config, dict) and isinstance(hash_config, dict)
    assert config["mode"] == GuardConfig(guard_home=tmp_path, workspace=None).mode
    assert set(config) == {
        "mode",
        "default_action",
        "artifact_actions",
        "publisher_actions",
        "harness_actions",
        "risk_actions",
        "harness_risk_actions",
        "harness_postures",
        "security_level",
        "protection_posture",
        "protection_posture_explicit",
        "managed_locked_settings",
    }
    # The posture override is the resolver's own input; the approval token the
    # proxy binds does not carry it, so it stays out of the hash fields.
    assert config["harness_postures"] == {}
    assert hash_config == {
        **{field: value for field, value in config.items() if field != "harness_postures"},
        "managed_policy_hash": "a" * 64,
        "managed_policy_status": "absent",
        "sandbox_analysis": "on",
    }


def test_a_per_harness_posture_changes_only_that_harness(tmp_path: Path) -> None:
    config = _config(tmp_path, harness_postures={"cursor": "watch"})

    assert harness_view(config, "cursor") != harness_view(config, "codex")
    assert harness_view(config, "codex") == harness_view(_config(tmp_path), "codex")


def test_a_harness_view_carries_only_its_own_posture_override(tmp_path: Path) -> None:
    config = _config(tmp_path, harness_postures={"cursor": "extra_careful"})

    cursor = harness_view(config, "cursor")
    codex = harness_view(config, "codex")

    assert cursor is not None and codex is not None
    assert cast("dict[str, object]", cursor["config"])["harness_postures"] == {"cursor": "extra_careful"}
    assert cast("dict[str, object]", codex["config"])["harness_postures"] == {}


def test_only_harnesses_every_config_agrees_on_are_bound(tmp_path: Path) -> None:
    home = _config(tmp_path)
    workspace = _config(tmp_path, harness_postures={"cursor": "watch"})

    assert set(uniform_harness_views([home])) == {"codex", "copilot", "cursor", "hermes", "opencode"}
    assert set(uniform_harness_views([home, workspace])) == {"codex", "copilot", "hermes", "opencode"}
    assert uniform_harness_views([]) == {}


def test_a_bound_harness_carries_the_redaction_level_every_config_agrees_on(tmp_path: Path) -> None:
    home = _config(tmp_path, receipt_redaction_level="partial")
    workspace = _config(tmp_path, receipt_redaction_level="none")

    bound = uniform_harness_views([home, _config(tmp_path, receipt_redaction_level="partial")])
    assert {view[REDACTION_LEVEL_KEY] for view in bound.values()} == {"partial"}  # type: ignore[index]
    assert uniform_redaction_level([home, workspace]) is None
    assert uniform_redaction_level([_config(tmp_path, receipt_redaction_level="secret")]) is None
    assert uniform_redaction_level([]) is None
    # A disagreement leaves the harnesses bound without the level, so only a
    # queued call defers.
    unlevelled = uniform_harness_views([home, workspace])
    assert set(unlevelled) == {"codex", "copilot", "cursor", "hermes", "opencode"}
    assert all(REDACTION_LEVEL_KEY not in view for view in unlevelled.values())  # type: ignore[operator]
    assert unlevelled["codex"] == harness_view(home, "codex")


def test_a_view_the_resident_would_read_differently_binds_nothing(tmp_path: Path) -> None:
    assert harness_view(_config(tmp_path, risk_actions={"network": 1.5}), "codex") is None
    assert harness_view(SimpleNamespace(), "codex") is None
    assert uniform_harness_views([_config(tmp_path, risk_actions={"network": 1.5})]) == {}


def test_the_view_needs_a_bound_harness_and_keeps_unreadable_layers_out(tmp_path: Path) -> None:
    harnesses = uniform_harness_views([_config(tmp_path)])

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
        self._compiled_mcp_relay_harnesses: dict[str, object] | None = uniform_harness_views([_config(tmp_path)])
        self._direct_lane_ack_target: tuple[int, str] | None = (7, "digest")
        self.rebound = 0

    def _rebind_direct_lane(self) -> None:
        self.rebound += 1
        self._direct_lane_mcp_relay = None


def test_the_binding_carries_the_view_only_for_a_resident_that_accepts_it(tmp_path: Path) -> None:
    publisher = _Publisher(tmp_path)

    bound = publisher._with_mcp_relay_view({"generation": 1}, FEATURES)
    assert bound is not None
    view = bound[MCP_RELAY_BINDING_KEY]
    assert isinstance(view, dict) and set(view["harnesses"]) == {"codex", "copilot", "cursor", "hermes", "opencode"}
    assert publisher._with_mcp_relay_view({"generation": 1}, ()) == {"generation": 1}
    assert publisher._with_mcp_relay_view(None, FEATURES) is None
    harnesses = publisher._compiled_mcp_relay_harnesses
    publisher._compiled_mcp_relay_harnesses = {}
    assert publisher._with_mcp_relay_view({"generation": 1}, FEATURES) == {"generation": 1}
    publisher._compiled_mcp_relay_harnesses = harnesses

    assert view["extension_layers"] == []
    publisher._command_control_runtime = None
    unlayered = publisher._with_mcp_relay_view({"generation": 1}, FEATURES)
    assert unlayered is not None
    unlayered_view = unlayered[MCP_RELAY_BINDING_KEY]
    assert isinstance(unlayered_view, dict) and "extension_layers" not in unlayered_view
    publisher._command_control_runtime = _runtime()

    publisher._bind_mcp_relay_view(bound, FEATURES)
    assert publisher._direct_lane_mcp_relay == view
    publisher._bind_mcp_relay_view(bound, ())
    assert publisher._direct_lane_mcp_relay is None


@pytest.mark.parametrize("compiled", [None, {}])
def test_a_moved_view_rebinds_the_lane(tmp_path: Path, compiled: dict[str, object] | None) -> None:
    publisher = _Publisher(tmp_path)
    publisher._bind_mcp_relay_view(publisher._with_mcp_relay_view({}, FEATURES), FEATURES)
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
    publisher._bind_mcp_relay_view(publisher._with_mcp_relay_view({}, FEATURES), FEATURES)
    publisher._direct_lane_ack_target = None
    publisher._recheck_direct_lane_mcp_relay()
    assert publisher.rebound == 0
