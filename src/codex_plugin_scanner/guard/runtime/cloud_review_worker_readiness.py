"""Shared Cloud Review worker readiness used by CLI and dashboard settings."""

from __future__ import annotations

from collections.abc import Mapping


def cloud_review_workers_ready(worker: Mapping[str, object] | None) -> bool:
    if not isinstance(worker, Mapping):
        return False
    return (
        worker.get("status") != "restart_required"
        and worker.get("running") is True
        and worker.get("sync_running") is True
    )


def project_cloud_review_worker_refresh(worker: Mapping[str, object]) -> dict[str, object]:
    """Capability may be saved even when delivery workers are not yet ready."""

    restart_required = worker.get("status") == "restart_required"
    ready = cloud_review_workers_ready(worker)
    if restart_required:
        reason = "worker_restart_required"
        activation_status = "saved_retry_required"
    elif ready:
        reason = None
        activation_status = "ready"
    else:
        reason = "worker_retry_required"
        activation_status = "saved_retry_required"
    return {
        "capability_saved": True,
        "delivery_ready": ready,
        "enabled": ready,
        "reason": reason,
        "activation_status": activation_status,
        "worker": dict(worker),
    }


__all__ = ["cloud_review_workers_ready", "project_cloud_review_worker_refresh"]
