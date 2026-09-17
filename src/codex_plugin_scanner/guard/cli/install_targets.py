"""Resolve which harnesses a Guard install or uninstall command targets."""

from __future__ import annotations

from collections.abc import Sequence

from ..adapters import get_adapter
from ..adapters.base import HarnessContext
from ..consumer import detect_all
from ..store import GuardStore


def _resolve_targets(
    command: str,
    requested_harness: str | Sequence[str] | None,
    install_all: bool,
    context: HarnessContext,
    store: GuardStore,
) -> list[str]:
    # Update flows reconnect several apps in one invocation; accept one or
    # many harness names while keeping the single-name contract unchanged.
    requested = [requested_harness] if isinstance(requested_harness, str) else requested_harness
    if requested and install_all:
        raise ValueError("Pass either a harness or --all, not both.")
    if requested and not install_all:
        targets: list[str] = []
        for item in requested:
            canonical = get_adapter(item).harness
            if canonical not in targets:
                targets.append(canonical)
        return targets
    if not install_all:
        action = "install" if command == "install" else "uninstall"
        suffix = " or --self" if command == "uninstall" else ""
        raise ValueError(f"Guard {action} requires a harness or --all{suffix}.")
    detected = {
        detection.harness
        for detection in detect_all(context)
        if detection.installed
        or detection.command_available
        or len(detection.config_paths) > 0
        or len(detection.artifacts) > 0
    }
    if command == "uninstall":
        detected.update(
            str(item.get("harness"))
            for item in store.list_managed_installs()
            if bool(item.get("active")) and isinstance(item.get("harness"), str)
        )
    targets = sorted(detected)
    if targets:
        return targets
    action = "install" if command == "install" else "remove"
    raise ValueError(f"No supported Guard harnesses detected for {action}; pass one explicitly or configure one first.")


def sole_harness_name(value: object) -> str | None:
    """Collapse the install parser's one-or-many harness argument.

    `install` accepts several harnesses per invocation; helpers that reason
    about a single requested harness read a single-element list as that name
    and anything larger as unspecified.
    """
    if isinstance(value, str):
        name = value.strip()
        return name or None
    if isinstance(value, (list, tuple)) and len(value) == 1 and isinstance(value[0], str):
        name = value[0].strip()
        return name or None
    return None


__all__ = ["_resolve_targets", "sole_harness_name"]
