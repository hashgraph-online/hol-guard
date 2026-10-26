"""The tool-call view the resident decides a relayed MCP tool call with.

The Python MCP proxy evaluates a ``tools/call`` under ``config_for_harness``
of the Guard config it loaded, binds the approval hash to that config's
tool-call fields plus its managed-policy and sandbox fields, and hands the
extension-control layers the store verified to the tool policy. A resident
that decides such a call for the native relay needs the same three inputs, as
the daemon had them when it published. A harness is bound only when the home
and every settled workspace agree on its view, and the layers only when the
publisher's command-control runtime holds readable ones; anything else is
left out and the relay's call defers. A bound harness also carries the
receipt redaction level a queued call's silent inbox row is written with,
when every config agrees on it; without it only such a call defers.
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Mapping
from typing import TYPE_CHECKING, cast

from .native_policy_snapshot_codec import _validate_json_limits_v3
from .native_policy_snapshot_constants import NativePolicySnapshotError

if TYPE_CHECKING:
    from .native_policy_snapshot_publisher import NativePolicySnapshotPublisher

# The resident accepts the view below in its direct-lane binding.
MCP_RELAY_DECIDE_FEATURE = "mcp-relay-decide-v2"
MCP_RELAY_BINDING_KEY = "mcp_relay"
MCP_RELAY_VIEW_SCHEMA = "guard-mcp-relay-view.v2"
# The harnesses whose MCP proxy the relay replaces.
MCP_RELAY_HARNESSES = ("codex", "copilot", "cursor", "opencode")

# The field a bound harness carries its receipt redaction level in.
REDACTION_LEVEL_KEY = "receipt_redaction_level"
_REDACTION_LEVELS = frozenset({"full", "partial", "none"})
_MAX_VIEW_BYTES = 262_144
_MAX_SAFE_INTEGER = 2**53 - 1


def mcp_relay_bound(features: Iterable[str]) -> bool:
    return MCP_RELAY_DECIDE_FEATURE in set(features)


def _plain(value: object) -> bool:
    # Only values every encoder on the way reads identically: string keys,
    # no floats, safe integers.
    if value is None or isinstance(value, (bool, str)):
        return True
    if isinstance(value, int):
        return -_MAX_SAFE_INTEGER <= value <= _MAX_SAFE_INTEGER
    if isinstance(value, list):
        return all(_plain(item) for item in value)
    if isinstance(value, dict):
        return all(isinstance(key, str) and _plain(item) for key, item in value.items())
    return False


def _stable(value: object) -> object | None:
    """``value`` as the resident reads it, or ``None`` when it would differ."""

    try:
        encoded = json.dumps(value, ensure_ascii=False, allow_nan=False)
        decoded = json.loads(encoded)
        _validate_json_limits_v3(decoded)
    except (NativePolicySnapshotError, RecursionError, TypeError, ValueError, UnicodeError):
        return None
    if len(encoded.encode("utf-8")) > _MAX_VIEW_BYTES or not _plain(decoded):
        return None
    return decoded


def harness_view(config: object, harness: str) -> dict[str, object] | None:
    """The proxy's tool-call configuration and hash fields for one harness."""

    from .harness_posture import config_for_harness, harness_posture_override
    from .mcp_tool_calls import _tool_call_configuration  # pyright: ignore[reportPrivateUsage]

    try:
        effective = config_for_harness(config, harness)  # pyright: ignore[reportArgumentType]
        hash_config = {
            **_tool_call_configuration(effective),
            "managed_policy_hash": effective.managed_policy_hash,
            "managed_policy_status": effective.managed_policy_status,
            "sandbox_analysis": effective.sandbox_analysis,
        }
        # The resolver reads this harness's own posture override for the Extra
        # careful risk-action floor, which `config_for_harness` does not fold
        # into an explicit risk action. Only this harness's entry crosses: the
        # whole map would make every harness's view differ whenever any other
        # harness carries an override. It stays out of `hash_config` so the
        # approval token the relay binds is the one the proxy already binds.
        override = harness_posture_override(config, harness)  # pyright: ignore[reportArgumentType]
        configuration = {
            **_tool_call_configuration(effective),
            "harness_postures": {harness: override} if override is not None else {},
        }
    except (AttributeError, TypeError, ValueError):
        return None
    view = _stable({"config": configuration, "hash_config": hash_config})
    if not isinstance(view, dict):
        return None
    stable = cast(dict[str, dict[str, object]], view)
    return dict(stable) if isinstance(stable["config"].get("mode"), str) else None


def uniform_redaction_level(configs: Iterable[object]) -> str | None:
    """The receipt redaction level every compiled config resolves to."""

    levels = {getattr(config, "receipt_redaction_level", None) for config in configs}
    if len(levels) != 1:
        return None
    (level,) = levels
    return level if isinstance(level, str) and level in _REDACTION_LEVELS else None


def uniform_harness_views(configs: Iterable[object]) -> dict[str, object]:
    """The harness views every compiled config agrees on."""

    compiled = tuple(configs)
    harnesses: dict[str, object] = {}
    if not compiled:
        return harnesses
    level = uniform_redaction_level(compiled)
    for harness in MCP_RELAY_HARNESSES:
        views = [harness_view(config, harness) for config in compiled]
        bound = views[0]
        if bound is not None and all(view == bound for view in views[1:]):
            harnesses[harness] = bound if level is None else {**bound, REDACTION_LEVEL_KEY: level}
    return harnesses


def extension_layers(runtime: object) -> list[object] | None:
    """The extension-control layers the publisher last verified.

    They come from the command-control runtime the publisher compiled for the
    same binding, so the view never reads the store or its authority key.
    ``None`` when there is no runtime or its layers are unreadable.
    """

    from .native_mcp_extension_input import _layer_inputs  # pyright: ignore[reportPrivateUsage]
    from .runtime.extension_control_runtime import ExtensionControlRuntime

    if not isinstance(runtime, ExtensionControlRuntime):
        return None
    try:
        layers = _stable(_layer_inputs(tuple(runtime.current().layers)))
    except Exception:
        return None
    return cast(list[object], layers) if isinstance(layers, list) else None


def mcp_relay_view(harnesses: Mapping[str, object] | None, layers: list[object] | None) -> dict[str, object] | None:
    """The binding's view, or ``None`` when no harness is bound."""

    if not harnesses:
        return None
    view: dict[str, object] = {"schema": MCP_RELAY_VIEW_SCHEMA, "harnesses": dict(harnesses)}
    if layers is not None:
        view["extension_layers"] = list(layers)
    stable = _stable(view)
    return cast(dict[str, object], stable) if isinstance(stable, dict) else None


class NativePolicySnapshotMcpRelayMixin:
    """Bind the MCP relay view into the direct lane and rebind once it moves."""

    # The view the open lane bound.
    _direct_lane_mcp_relay: dict[str, object] | None = None

    def _current_mcp_relay_view(self) -> dict[str, object] | None:
        publisher = cast("NativePolicySnapshotPublisher", self)
        runtime = getattr(publisher, "_command_control_runtime", None)
        return mcp_relay_view(publisher._compiled_mcp_relay_harnesses, extension_layers(runtime))

    def _with_mcp_relay_view(
        self, binding: dict[str, object] | None, features: Iterable[str]
    ) -> dict[str, object] | None:
        """Add the view, for a resident that accepts it."""

        if binding is None or not mcp_relay_bound(features):
            return binding
        view = self._current_mcp_relay_view()
        return binding if view is None else {**binding, MCP_RELAY_BINDING_KEY: view}

    def _bind_mcp_relay_view(self, binding: object, features: Iterable[str]) -> None:
        """Record the view an ACKed binding carries, for the reconcile recheck."""

        view = binding.get(MCP_RELAY_BINDING_KEY) if isinstance(binding, Mapping) else None
        bound = mcp_relay_bound(features) and isinstance(view, Mapping)
        self._direct_lane_mcp_relay = dict(cast(Mapping[str, object], view)) if bound else None

    def _recheck_direct_lane_mcp_relay(self) -> None:
        """Rebind the lane once the view it carries moves.

        Each reconcile compiles the configs and the command-control runtime
        again, so the view is compared here.
        """

        publisher = cast("NativePolicySnapshotPublisher", self)
        bound = self._direct_lane_mcp_relay
        if bound is None or publisher._direct_lane_ack_target is None:
            return
        if self._current_mcp_relay_view() == bound:
            return
        publisher._rebind_direct_lane()
