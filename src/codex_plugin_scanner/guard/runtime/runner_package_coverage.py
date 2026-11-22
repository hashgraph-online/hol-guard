"""Package manager coverage reported with the Guard Cloud runtime session."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from ..harness_context import HarnessContext
from ..shims import package_shim_cloud_coverage
from ..store import GuardStore
from . import runner_native_sync as _sync

_SUMMARY_KEYS = ("sync_summary", "runtime_session_summary", "supply_chain_bundle_summary")


def cloud_package_manager_coverage(
    store: GuardStore,
    *,
    workspace: str,
    generated_at: str,
) -> dict[str, object]:
    """The package shim coverage for ``workspace``, with how stale the synced intel is."""

    coverage = package_shim_cloud_coverage(
        HarnessContext(
            home_dir=Path.home(),
            workspace_dir=Path(workspace),
            guard_home=store.guard_home,
        ),
        generated_at=generated_at,
    )
    # The three summaries come from one snapshot so a sync committing in
    # between cannot pair an old summary with a new one.
    summaries = store.sync_payload_snapshot(*_SUMMARY_KEYS)
    coverage["staleIntel"] = _sync.stale_intel(
        tuple(summaries.values()),
        generated_at=generated_at,
        now=datetime.now(timezone.utc).isoformat(),
    )
    return coverage


__all__ = ["cloud_package_manager_coverage"]
