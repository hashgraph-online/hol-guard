"""The managed-policy view the daemon resolves Oh My Pi output mediation from.

After an Oh My Pi or Pi ``PostToolUse`` the daemon resolves structured output
mediation from the managed policy in Guard config. When nothing is required
it returns the edge response unchanged. A resident that answers such a hook
without the daemon needs the same managed-policy view, as the daemon had it
when it published; the resident resolves it itself. A view the resident
could not read exactly as the daemon's native query does is left out, so
such a hook defers to this daemon.
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Mapping

from .native_policy_snapshot_codec import _validate_json_limits_v3
from .native_policy_snapshot_constants import NativePolicySnapshotError

# The resident accepts the managed-policy view below in its direct-lane binding.
DIRECT_HOOK_STRUCTURED_OUTPUT_FEATURE = "hook-direct-structured-output-v1"
STRUCTURED_OUTPUT_BINDING_KEY = "structured_output_config"

_MAX_VIEW_BYTES = 65_536
_MAX_SAFE_INTEGER = 2**53 - 1


def structured_output_bound(features: Iterable[str]) -> bool:
    return DIRECT_HOOK_STRUCTURED_OUTPUT_FEATURE in set(features)


def _plain(value: object) -> bool:
    # Only values that every encoder on the way reads identically: string
    # keys (so no two keys can encode alike), no floats, safe integers.
    if value is None or isinstance(value, (bool, str)):
        return True
    if isinstance(value, int):
        return -_MAX_SAFE_INTEGER <= value <= _MAX_SAFE_INTEGER
    if isinstance(value, list):
        return all(_plain(item) for item in value)
    if isinstance(value, dict):
        return all(isinstance(key, str) and _plain(item) for key, item in value.items())
    return False


def structured_output_view(config: object) -> dict[str, object] | None:
    """The ``_config_wire`` the daemon sends its ``resolution`` query, or ``None``.

    The daemon encodes that query as JSON. A view that does not survive the
    same encoding unchanged, or that the snapshot codec would refuse, binds
    nothing, so the resident never resolves a different view.
    """

    from .runtime.structured_output_mediation import _config_wire

    try:
        view = _config_wire(config)
        encoded = json.dumps(view, ensure_ascii=False, allow_nan=False)
        size = len(encoded.encode("utf-8"))
        decoded = json.loads(encoded)
        _validate_json_limits_v3(decoded)
    except (NativePolicySnapshotError, RecursionError, TypeError, ValueError, UnicodeError):
        return None
    if size > _MAX_VIEW_BYTES or decoded != view or not _plain(decoded):
        return None
    return decoded


def uniform_structured_output_view(configs: Iterable[object]) -> dict[str, object] | None:
    """The managed-policy view every compiled config agrees on.

    Managed policy is machine-wide, so the home and every settled workspace
    resolve one view. A binding carries it only when they do.
    """

    views = [structured_output_view(config) for config in configs]
    if not views or views[0] is None or any(view != views[0] for view in views[1:]):
        return None
    return views[0]


def with_structured_output_view(
    binding: Mapping[str, object] | None,
    *,
    features: Iterable[str],
    view: Mapping[str, object] | None,
) -> dict[str, object] | None:
    """Add the managed-policy view, for a resident that accepts it."""

    if binding is None:
        return None
    bound = dict(binding)
    if view is not None and structured_output_bound(features):
        bound[STRUCTURED_OUTPUT_BINDING_KEY] = dict(view)
    return bound


def bound_structured_output_view(binding: object, features: Iterable[str]) -> dict[str, object] | None:
    """The view an ACKed binding carries, for the reconcile recheck."""

    if not isinstance(binding, Mapping) or not structured_output_bound(features):
        return None
    view = binding.get(STRUCTURED_OUTPUT_BINDING_KEY)
    return dict(view) if isinstance(view, Mapping) else None
