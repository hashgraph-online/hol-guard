"""Helpers for Guard harness install and uninstall flows."""

from __future__ import annotations

from ..adapters import get_adapter
from ..adapters.base import HarnessContext
from ..consumer import detect_all
from ..store import GuardStore


def apply_managed_install(
    command: str,
    requested_harness: str | None,
    install_all: bool,
    context: HarnessContext,
    store: GuardStore,
    workspace: str | None,
    now: str,
) -> dict[str, object]:
    targets = _resolve_targets(command, requested_harness, install_all, context, store)
    active = command == "install"
    managed_installs: list[dict[str, object]] = []
    for harness in targets:
        adapter = get_adapter(harness)
        manifest = adapter.install(context) if active else adapter.uninstall(context)
        store.set_managed_install(harness, active, workspace, manifest, now)
        managed_install = store.get_managed_install(harness)
        if managed_install is not None:
            managed_installs.append(managed_install)
    payload: dict[str, object] = {
        "managed_installs": managed_installs,
        "auto_detected": requested_harness is None or install_all,
    }
    if len(managed_installs) == 1:
        payload["managed_install"] = managed_installs[0]
    return payload


def _resolve_targets(
    command: str,
    requested_harness: str | None,
    install_all: bool,
    context: HarnessContext,
    store: GuardStore,
) -> list[str]:
    if requested_harness is not None and install_all:
        raise ValueError("Pass either a harness or --all, not both.")
    if requested_harness is not None and not install_all:
        return [requested_harness]
    if not install_all:
        action = "install" if command == "install" else "uninstall"
        raise ValueError(f"Guard {action} requires a harness or --all.")
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
    raise ValueError(
        f"No supported harnesses were detected for Guard {action}. Pass a harness explicitly or configure one first."
    )


__all__ = ["apply_managed_install"]
