"""Optional managed-control decorations for daemon API payloads."""

from __future__ import annotations

import json
from typing import Protocol

from ..runtime.command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY, CommandSafetyExtensionRegistry
from ..runtime.extension_control_authority import layers_to_json
from ..runtime.extension_control_resolver import compose_control_layers
from ..runtime.extension_control_runtime import ExtensionControlRuntimeSnapshot
from ..store_managed_controls_status import ManagedControlsStatusUnavailableError
from .extension_control_projection import build_effective_extension_control_projection


class ManagedControlsStatusStore(Protocol):
    def managed_controls_public_status(self, *, catalog_digest: str) -> dict[str, object] | None: ...

    def list_policy_decisions(self, harness: str | None = None) -> list[dict[str, object]]: ...


def _append_managed_controls_status(
    payload: dict[str, object],
    *,
    store: ManagedControlsStatusStore,
    catalog_digest: str,
) -> None:
    """Add optional status or a redacted diagnostic without failing the base API."""

    status_reader = getattr(store, "managed_controls_public_status", None)
    if not callable(status_reader):
        return
    try:
        status = status_reader(catalog_digest=catalog_digest)
    except ManagedControlsStatusUnavailableError:
        failures = payload.get("failures")
        if isinstance(failures, list):
            failures.append({"code": "managed-controls-status-unavailable"})
        return
    if status is not None:
        payload["managed_controls"] = status


def effective_controls_payload(
    registry: CommandSafetyExtensionRegistry,
    snapshot: ExtensionControlRuntimeSnapshot,
    store: ManagedControlsStatusStore,
) -> dict[str, object]:
    composed = compose_control_layers(snapshot.layers)
    payload: dict[str, object] = {
        "schema_version": "guard.daemon.extension-controls.v1",
        "health": snapshot.health.value,
        "revision": snapshot.revision,
        "catalog_digest": snapshot.catalog_digest,
        "global_lockdown": composed.global_lockdown,
        "controls": [
            {
                "target": {"kind": control.target.kind.value, "target_id": control.target.target_id},
                "state": control.state.value,
            }
            for control in composed.controls
        ],
        "layers": json.loads(layers_to_json(snapshot.layers)),
        "failures": [
            {
                "code": failure.code.value,
                **({"layer_kind": failure.layer_kind.value} if failure.layer_kind is not None else {}),
            }
            for failure in composed.failures
        ],
        "projection": build_effective_extension_control_projection(registry, snapshot),
    }
    _append_managed_controls_status(payload, store=store, catalog_digest=snapshot.catalog_digest)
    return payload


def managed_policy_rows(
    store: ManagedControlsStatusStore,
    harness: str | None,
) -> list[dict[str, object]]:
    """Annotate remote rows only from authenticated managed state."""

    items = store.list_policy_decisions(harness=harness)
    try:
        status = store.managed_controls_public_status(catalog_digest=BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest)
    except ManagedControlsStatusUnavailableError:
        return items
    if not isinstance(status, dict):
        return items
    authority_mode = status.get("authority_mode")
    if authority_mode not in {"personal-shared", "workspace-shared", "managed-restrictive"}:
        return items
    workspace_id = status.get("workspace_id")
    metadata: dict[str, object] = {"authority_mode": authority_mode}
    if isinstance(workspace_id, str) and workspace_id.strip():
        metadata["cloud_workspace_label"] = workspace_id.strip()[:160]
    return [{**item, **metadata} if item.get("source") == "policy-bundle" else item for item in items]
