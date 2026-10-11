"""Thin client for the native effective-policy composer.

Rust derives the effective policy from loaded Guard configuration fields,
folds per-harness posture floors into it, and composes several configs by the
lattice maximum. This module only extracts the plain configuration fields,
spawns the composer, and fails closed when it is unavailable. It never
recalculates a value.
"""

from __future__ import annotations

import copy
import json
import threading
import time
from collections import OrderedDict
from collections.abc import Iterable, Mapping
from typing import TYPE_CHECKING, Any, cast

from .native_policy_snapshot_constants import NativePolicySnapshotError
from .native_policy_snapshot_harness_postures import HARNESS_POSTURES_BINDING_KEY

if TYPE_CHECKING:
    from .config import GuardConfig
    from .native_runtime_values import NativeRuntimeIdentity

POLICY_EFFECTIVE_COMMAND = "policy-effective"
POLICY_EFFECTIVE_FEATURE = "native-policy-effective-v1"
POLICY_EFFECTIVE_SCHEMA = "guard-effective-policy.v1"
POLICY_EFFECTIVE_TIMEOUT_SECONDS = 10.0
_UNAVAILABLE = "native_policy_effective_unavailable"
_INVALID = "native_policy_effective_invalid"
# The composer is a pure function of one binary and its request. An unchanged
# request against that same digest must not respawn the runtime.
_MEMO_LIMIT = 32
_MEMO: OrderedDict[tuple[str, str, str], dict[str, Any]] = OrderedDict()
_MEMO_LOCK = threading.Lock()
_CONFIG_FIELDS = (
    "mode",
    "protection_posture",
    "protection_posture_explicit",
    "managed_locked_settings",
    "security_level",
    "default_action",
    "unknown_publisher_action",
    "changed_hash_action",
    "new_network_domain_action",
    "subprocess_action",
    "sandbox_analysis",
    "receipt_redaction_level",
    "risk_actions",
    "harness_risk_actions",
    "harness_actions",
    "publisher_actions",
    "artifact_actions",
    "mcp_tool_actions",
    "mcp_provider_actions",
    "mcp_provider_catalog_hash",
    HARNESS_POSTURES_BINDING_KEY,
)


def _config_fields(config: GuardConfig | Mapping[str, object]) -> dict[str, object]:
    """Plain field values, exactly as present on the config (absent stays absent)."""

    if isinstance(config, Mapping):
        return {name: config[name] for name in _CONFIG_FIELDS if name in config}
    return {name: getattr(config, name) for name in _CONFIG_FIELDS if hasattr(config, name)}


def _runtime_identity(deadline_monotonic: float) -> NativeRuntimeIdentity:
    from .native_runtime import native_runtime_status

    status = native_runtime_status(deadline_monotonic=deadline_monotonic)
    if (
        not status.available
        or not status.compatible
        or status.identity is None
        or status.capabilities is None
        or POLICY_EFFECTIVE_FEATURE not in status.capabilities.features
    ):
        raise NativePolicySnapshotError(_UNAVAILABLE)
    return status.identity


def _call(
    op: str,
    configs: Iterable[GuardConfig | Mapping[str, object]],
    *,
    guard_config: bool,
    deadline_monotonic: float | None = None,
) -> dict[str, Any]:
    from .native_runtime import _run_native_process

    request = {
        "schema": POLICY_EFFECTIVE_SCHEMA,
        "op": op,
        "guard_config": guard_config,
        "configs": [_config_fields(config) for config in configs],
    }
    try:
        text = json.dumps(request, separators=(",", ":"), default=_json_default)
    except (TypeError, ValueError) as error:
        raise NativePolicySnapshotError("native_policy_snapshot_policy_invalid") from error
    deadline = time.monotonic() + POLICY_EFFECTIVE_TIMEOUT_SECONDS
    if deadline_monotonic is not None:
        deadline = min(deadline, deadline_monotonic)
    if deadline - time.monotonic() <= 0:
        # An expired caller budget must neither probe nor spawn.
        raise NativePolicySnapshotError(_UNAVAILABLE)
    identity = _runtime_identity(deadline)
    path = identity.path
    # The path stays the same when a runtime is replaced in place. The digest
    # is what says the derivation tables changed.
    memo_key = (str(path), identity.sha256, text)
    with _MEMO_LOCK:
        cached = _MEMO.get(memo_key)
        if cached is not None:
            _MEMO.move_to_end(memo_key)
            return copy.deepcopy(cached)
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise NativePolicySnapshotError(_UNAVAILABLE)
    output = _run_native_process(
        path, (POLICY_EFFECTIVE_COMMAND, "--stdin"), input_text=text, timeout_seconds=remaining
    )
    if output is None:
        raise NativePolicySnapshotError(_UNAVAILABLE)
    try:
        response = json.loads(output)
    except ValueError as error:
        raise NativePolicySnapshotError(_INVALID) from error
    if not isinstance(response, dict):
        raise NativePolicySnapshotError(_INVALID)
    if response.get("ok") is not True:
        reason = response.get("error")
        raise NativePolicySnapshotError(reason if isinstance(reason, str) and reason else _INVALID)
    policy = response.get("policy")
    if not isinstance(policy, dict):
        raise NativePolicySnapshotError(_INVALID)
    with _MEMO_LOCK:
        _MEMO[memo_key] = copy.deepcopy(policy)
        while len(_MEMO) > _MEMO_LIMIT:
            _MEMO.popitem(last=False)
    return cast("dict[str, Any]", policy)


def _json_default(value: object) -> object:
    if isinstance(value, (set, frozenset, tuple)):
        return sorted(value, key=str) if not isinstance(value, tuple) else list(value)
    raise TypeError("unsupported configuration value")


def effective_native_policy_v3(
    config: GuardConfig | Mapping[str, object], *, deadline_monotonic: float | None = None
) -> dict[str, object]:
    """Bounded effective policy consumed by native hook decisions."""

    return cast(
        "dict[str, object]",
        _call(
            "effective",
            (config,),
            guard_config=not isinstance(config, Mapping),
            deadline_monotonic=deadline_monotonic,
        ),
    )


def compose_effective_native_policies(
    configs: tuple[GuardConfig | Mapping[str, object], ...],
    *,
    deadline_monotonic: float | None = None,
) -> dict[str, object]:
    """Compile home, workspace and managed configs into one native policy.

    The result carries the derived ``mode`` and the strictest per-harness
    postures beside the snapshot fields; neither reaches the Rust digest.
    """

    if not configs:
        raise NativePolicySnapshotError("native_policy_snapshot_policy_invalid")
    mappings = sum(isinstance(config, Mapping) for config in configs)
    if 0 < mappings < len(configs):
        # One request-wide derivation mode: a mixed tuple would silently drop
        # the loaded configs' risk floors, so refuse it.
        raise NativePolicySnapshotError("native_policy_snapshot_policy_invalid")
    return cast(
        "dict[str, object]",
        _call("compose", configs, guard_config=mappings == 0, deadline_monotonic=deadline_monotonic),
    )
