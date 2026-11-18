"""Test-side owner fields for the native harness install, uninstall and inventory operations.

The product callers pass the owner fields explicitly (see ``cli/native_managed_install.py``); a test that
installs one harness whole does the same through these functions.
"""

from __future__ import annotations

from codex_plugin_scanner.guard import native_harness_install_ops as _install_ops
from codex_plugin_scanner.guard import native_harness_ops as _ops
from codex_plugin_scanner.guard.harness_context import HarnessContext
from codex_plugin_scanner.guard.inventory_contract import (
    GuardAgentInventorySnapshot,
    inventory_snapshot_from_detection,
)
from codex_plugin_scanner.guard.native_harness_client import canonical_harness
from codex_plugin_scanner.guard.native_owned import owner_request


def _owner(harness: str, context: HarnessContext, op: str) -> dict[str, object]:
    return owner_request(context.guard_home, actor=f"adapter.{canonical_harness(harness)}.{op}")


def install(harness: str, context: HarnessContext, *, surface: str | None = None) -> dict[str, object]:
    return _install_ops.install(harness, context, owner=_owner(harness, context, "adapter_install"), surface=surface)


def prepare_install(harness: str, context: HarnessContext, *, surface: str | None = None) -> object:
    return _install_ops.prepare_install(harness, context, surface=surface)


def uninstall(harness: str, context: HarnessContext, *, surface: str | None = None) -> dict[str, object]:
    return _install_ops.uninstall(
        harness, context, owner=_owner(harness, context, "adapter_uninstall"), surface=surface
    )


def inventory_snapshot(
    harness: str,
    context: HarnessContext,
    *,
    generated_at: str,
    cisco_mcp_scan: str = "off",
    cisco_skill_scan: str = "off",
    cisco_timeout_seconds: float | None = None,
) -> GuardAgentInventorySnapshot:
    """A normalized inventory snapshot built from ``harness``'s detection."""
    from codex_plugin_scanner.guard.inventory_cisco import run_cisco_inventory_scans
    from codex_plugin_scanner.guard.native_context import bound_context_digest_home

    name = canonical_harness(harness)
    detection = _ops.detect(name, context)
    cisco_runs = run_cisco_inventory_scans(
        harness=name,
        context=context,
        detection=detection,
        mcp_mode=cisco_mcp_scan,
        skill_mode=cisco_skill_scan,
        timeout_seconds=cisco_timeout_seconds,
    )
    # Redaction asks the resident of this context's home.
    with bound_context_digest_home(getattr(context, "guard_home", None)):
        return inventory_snapshot_from_detection(
            detection,
            generated_at=generated_at,
            home_dir=context.home_dir,
            workspace_dir=context.workspace_dir,
            cisco_runs=cisco_runs,
        )
