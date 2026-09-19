"""Compose validated configuration while retaining each action representation."""

from __future__ import annotations

from ..action_lattice import is_guard_action, most_restrictive_guard_action, normalize_guard_action

_MODE_STRENGTH = {"observe": 0, "prompt": 1, "enforce": 2}
_SELECTOR_MAPS = frozenset({"artifacts", "publishers", "harnesses", "risk_actions"})


def _action_selector_leaf(path: tuple[str, ...]) -> bool:
    return (len(path) == 2 and path[0] in _SELECTOR_MAPS) or (len(path) == 3 and path[0] == "harness_risk_actions")


def _action_value(value: object) -> object:
    if isinstance(value, dict):
        return value.get("action", value.get("default_action", value))
    return value


def _merge_metadata(local: dict[str, object], managed: dict[str, object]) -> dict[str, object]:
    merged = dict(local)
    for key, value in managed.items():
        prior = merged.get(key)
        merged[key] = _merge_metadata(prior, value) if isinstance(prior, dict) and isinstance(value, dict) else value
    return merged


def _compose_action_value(local: object, managed: object) -> object:
    # A missing local selector has no floor. A supplied unknown managed value
    # is not absence and must never erase a known local restriction.
    actions = [_action_value(managed)]
    if local is not None:
        actions.append(_action_value(local))
    winner = most_restrictive_guard_action(*actions, unknown_action="block")
    if not isinstance(local, dict) and not isinstance(managed, dict):
        return winner
    metadata = _merge_metadata(local if isinstance(local, dict) else {}, managed if isinstance(managed, dict) else {})
    metadata["action"] = winner
    if "default_action" in metadata:
        metadata["default_action"] = winner
    return metadata


def _merge_strongest_actions(local: object, managed: object, *, setting_path: tuple[str, ...] = ()) -> object:
    if _action_selector_leaf(setting_path):
        return _compose_action_value(local, managed)
    if isinstance(managed, dict):
        merged = dict(local) if isinstance(local, dict) else {}
        for key, value in managed.items():
            merged[key] = _merge_strongest_actions(merged.get(key), value, setting_path=(*setting_path, key))
        return merged
    if local is None:
        return normalize_guard_action(managed, unknown_action="block")
    if managed is None:
        return normalize_guard_action(local, unknown_action="block")
    return most_restrictive_guard_action(local, managed, unknown_action="block")


def _strongest_security_value(local: object, managed: object) -> object:
    if isinstance(local, str) and isinstance(managed, str):
        if is_guard_action(local) or is_guard_action(managed):
            return most_restrictive_guard_action(local, managed, unknown_action="block")
        if local in _MODE_STRENGTH and managed in _MODE_STRENGTH:
            return max((local, managed), key=_MODE_STRENGTH.__getitem__)
    return managed


def _is_action_setting_path(path: str) -> bool:
    parts = tuple(path.split("."))
    return any(part == "actions" or part.endswith(("_actions", "Actions")) for part in parts) or parts[-1].endswith(
        ("_action", "Action")
    )


def _compose_managed_value(local: object, managed: object, *, setting_path: tuple[str, ...] = ()) -> object:
    if _action_selector_leaf(setting_path):
        return _compose_action_value(local, managed)
    if isinstance(local, dict) and isinstance(managed, dict):
        composed = dict(local)
        for key, managed_value in managed.items():
            composed[key] = _compose_managed_value(composed.get(key), managed_value, setting_path=(*setting_path, key))
        return composed
    return _strongest_security_value(local, managed)
