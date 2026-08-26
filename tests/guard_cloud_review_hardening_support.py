from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.runtime.exact_cloud_review import enable_exact_cloud_review
from codex_plugin_scanner.guard.store import GuardStore
from tests.guard_exact_cloud_review_support import (
    add_review_request,
    connected_exact_review_store,
    exact_review_job,
    remote_approval,
    review_request,
)


def exact_job_store(tmp_path: Path, *, request_id: str) -> tuple[GuardStore, dict[str, object]]:
    store = connected_exact_review_store(tmp_path)
    request = review_request(request_id)
    add_review_request(store, request)
    enable_exact_cloud_review(store)
    job = exact_review_job(
        store,
        remote_approval(store, request_id, receipt_id=f"{request_id}-receipt"),
    )
    job.update(
        {
            "resultContractVersion": "guard-cloud-review-command-result-v2",
            "serverResolvedBinding": {"localRequestId": request_id},
        }
    )
    return store, job


def harness_context(tmp_path: Path) -> HarnessContext:
    return HarnessContext(home_dir=tmp_path, workspace_dir=tmp_path, guard_home=tmp_path / "guard-home")


def sync_auth(store: GuardStore, *, access_token: str) -> dict[str, object]:
    binding = store.get_review_event_oauth_binding()
    assert binding is not None
    return {
        "access_token": access_token,
        "sync_url": "https://guard.example/api/guard/receipts/sync",
        **binding,
    }


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


__all__ = ["exact_job_store", "harness_context", "now", "sync_auth"]
