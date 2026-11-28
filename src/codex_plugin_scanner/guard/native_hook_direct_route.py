"""Choose the Rust direct-hook answer before the daemon edge fallback."""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import TYPE_CHECKING

from .native_hook_direct import native_hook_direct

if TYPE_CHECKING:
    from .hook_review.hook_worker_native import _HookWorkerNativeHost


def native_or_daemon_edge(
    worker: _HookWorkerNativeHost,
    *,
    payload: dict[str, object],
    harness: str,
    event_name: str,
    default_harness: str,
    home_dir: Path,
    guard_home: Path,
    workspace: Path | None,
    deadline: float | None,
    policy_snapshot: Mapping[str, object] | None,
    recording_only: bool,
    defer_accepted_recording: bool,
    claim_saved_approval: bool,
) -> tuple[dict[str, object] | None, bool]:
    """Return a direct Rust edge, or the established daemon edge fallback."""

    direct_edge = (
        native_hook_direct(
            harness=harness,
            guard_home=guard_home,
            payload=payload,
            workspace=workspace,
            home_dir=home_dir,
            deadline=deadline,
        )
        if claim_saved_approval
        else None
    )
    if direct_edge is not None and direct_edge.get("outcome") != "defer":
        return direct_edge, True
    edge = worker._review_raw_hook_native(
        payload=payload,
        harness=harness,
        event=event_name,
        guard_home=guard_home,
        home_dir=home_dir,
        cwd=workspace,
        source_ref_external_allowed=default_harness.strip().lower().replace("_", "-") in {"pi", "omp"},
        observe_mode=recording_only,
        deadline=deadline,
        policy_snapshot=policy_snapshot,
        local_cli_rules=True,
        observe_local_cli=True,
        record_receipt=(
            not defer_accepted_recording
            and callable(getattr(worker.activity_writer, "submit_native_decision_receipt", None))
        ),
        containment_sink=True,
    )
    return edge, False


__all__ = ["native_or_daemon_edge"]
