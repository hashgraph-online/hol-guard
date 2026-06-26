"""Dry-run helpers for Guard harness install flows."""

from __future__ import annotations

from ..adapters.base import HarnessContext
from ..store import GuardStore
from .install_commands import _resolve_targets, build_harness_setup_plan


def build_managed_install_plan(
    requested_harness: str | None,
    install_all: bool,
    context: HarnessContext,
    store: GuardStore,
) -> dict[str, object]:
    targets = _resolve_targets("install", requested_harness, install_all, context, store)
    plans = [build_harness_setup_plan("connect", harness, context, dry_run=True) for harness in targets]
    payload: dict[str, object] = {
        "dry_run": True,
        "setup_plans": plans,
        "auto_detected": requested_harness is None or install_all,
    }
    if len(plans) == 1:
        payload["setup_plan"] = plans[0]
        payload.update(plans[0])
    return payload


__all__ = ["build_managed_install_plan"]
