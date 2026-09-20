"""Persisted review consent and authority survive a new Python process.

The subprocess uses the real Store, read-only status projection and signed exact
application. Signing keys and OAuth credentials are synthetic and use the test
file-backed keyring. Worker refresh is explicitly unavailable: this does not
prove a running daemon, installed runtime, remote delivery or live sign-in.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

from codex_plugin_scanner.guard.daemon import cloud_review_settings as settings
from codex_plugin_scanner.guard.models import PolicyDecision
from codex_plugin_scanner.guard.runtime import cloud_review_status as status_module
from codex_plugin_scanner.guard.runtime import exact_cloud_review as exact
from codex_plugin_scanner.guard.store import GuardStore
from tests.guard_exact_cloud_review_support import (
    add_review_request,
    connected_exact_review_store,
    remote_approval,
    review_request,
)


def _child_status() -> None:
    home = Path(sys.argv[1])
    application = None
    if len(sys.argv) == 3:
        approval = json.loads(Path(sys.argv[2]).read_text(encoding="utf-8"))
        store = GuardStore(home)
        try:
            resolution = exact.apply_exact_cloud_review(store, remote_approval=approval)
            application = resolution.request_id
        except exact.ExactCloudReviewError as error:
            application = str(error)
    status = status_module.cloud_review_status(home, allow_system_keyring=True)
    keys = (
        "connected",
        "consent_enabled",
        "reason",
        "delivery_ready",
        "delivery_readiness_reason",
        "activation_error",
        "workspace_id",
        "source",
        "worker",
    )
    print(
        json.dumps(
            {
                "pid": os.getpid(),
                "status_module": str(Path(status_module.__file__).resolve()),
                "status": {key: status[key] for key in keys},
                "application": application,
            },
        ),
    )


def _new_process(store: GuardStore, approval_file: Path | None = None) -> dict[str, object]:
    checkout = Path(__file__).resolve().parents[1]
    command = [
        sys.executable,
        "-c",
        "from tests.test_cloud_review_lifecycle_process import _child_status; _child_status()",
        str(store.guard_home),
    ]
    if approval_file is not None:
        command.append(str(approval_file))
    result = subprocess.run(
        command,
        cwd=checkout,
        env={**os.environ, "PYTHONPATH": os.pathsep.join((str(checkout / "src"), str(checkout)))},
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
    )
    payload = json.loads(result.stdout)
    assert isinstance(payload, dict)
    assert isinstance(payload["pid"], int) and payload["pid"] != os.getpid()
    assert payload["status_module"] == str(Path(status_module.__file__).resolve())
    status = payload["status"]
    assert isinstance(status, dict)
    assert status["connected"] is True
    assert (status["workspace_id"], status["source"]) == ("workspace-1", "default")
    assert status["worker"] == {"running": None, "sync_running": None, "observed_at": None}
    return payload


def _durable_authority(store: GuardStore) -> dict[str, tuple[tuple[object, ...], ...]]:
    tables = (
        "approval_requests",
        "guard_exact_cloud_review_receipts",
        "guard_local_once_approvals",
        "policy_decisions",
        "guard_review_outbox_events",
        "guard_review_outbox_request_sequences",
    )
    with store._connect() as connection:
        return {
            table: tuple(tuple(row) for row in connection.execute(f"select * from {table} order by rowid"))
            for table in tables
        }


def test_new_process_observes_saved_failure_and_revocation_without_erasing_authority(tmp_path: Path) -> None:
    store = connected_exact_review_store(tmp_path)
    store.upsert_policy(
        PolicyDecision(harness="codex", scope="artifact", action="block", artifact_id="synthetic:retained"),
        datetime.now(timezone.utc).isoformat(),
    )
    policy_before = store.list_policy_decisions()
    credentials_before = store.get_oauth_local_credentials(allow_primary=False)
    for request_id in ("process-resolved", "process-pending"):
        add_review_request(store, review_request(request_id))
    initial = _durable_authority(store)
    missing = _new_process(store)["status"]
    assert isinstance(missing, dict)
    assert missing["consent_enabled"] is False
    assert missing["reason"] == "cloud_review_capability_missing"
    assert _durable_authority(store) == initial

    refreshes: list[bool] = []

    def unavailable_workers() -> dict[str, object]:
        refreshes.append(True)
        return {"running": False, "sync_running": False}

    def change(action: str) -> dict[str, object]:
        return settings.change_cloud_review_settings(
            store,
            {
                "action": action,
                "confirm": f"cloud-review.{action}",
                "workspace_id": "workspace-1",
                "source": "default",
            },
            refresh_workers=unavailable_workers,
        )

    enabled = change("enable")
    capability = store.get_sync_payload(exact.EXACT_CLOUD_REVIEW_CAPABILITY_STATE_KEY)
    assert isinstance(capability, dict)
    assert enabled["consent_enabled"] is True and enabled["delivery_ready"] is False
    for action in ("enable", "retry_delivery"):
        repeated = change(action)
        assert repeated["consent_enabled"] is True
        assert repeated["activation_error"] == "worker_refresh_failed"
        assert store.get_sync_payload(exact.EXACT_CLOUD_REVIEW_CAPABILITY_STATE_KEY) == capability
    assert len(store.list_events(event_name="cloud_review.exact_capability_issued")) == 1

    resolved_file = tmp_path / "signed-resolved.json"
    resolved_file.write_text(
        json.dumps(remote_approval(store, "process-resolved", receipt_id="process-resolved-receipt")),
        encoding="utf-8",
    )
    resolved_file.chmod(0o600)
    pending_file = tmp_path / "signed-pending.json"
    pending_file.write_text(
        json.dumps(remote_approval(store, "process-pending", receipt_id="process-pending-receipt")),
        encoding="utf-8",
    )
    pending_file.chmod(0o600)
    applied = _new_process(store, resolved_file)
    assert applied["application"] == "process-resolved"
    assert store.has_exact_cloud_review_receipt("process-resolved-receipt")
    resolved_before = store.get_approval_request("process-resolved")
    assert isinstance(resolved_before, dict) and resolved_before["status"] == "resolved"
    enabled_status = applied["status"]
    assert isinstance(enabled_status, dict)
    assert enabled_status["consent_enabled"] is True
    assert enabled_status["activation_error"] == "worker_refresh_failed"
    assert enabled_status["delivery_ready"] is False
    assert enabled_status["delivery_readiness_reason"] == "worker_refresh_failed"

    before_disable = _durable_authority(store)
    disabled = change("disable")
    assert disabled["consent_enabled"] is False
    assert refreshes == [True] * 4
    assert store.get_sync_payload(exact.EXACT_CLOUD_REVIEW_CAPABILITY_STATE_KEY) is None
    revocation = exact._verify(store, store.get_sync_payload(exact.EXACT_CLOUD_REVIEW_REVOCATION_STATE_KEY))
    assert revocation["capabilityDigest"] == exact._capability_digest(exact._verify(store, capability))
    before_rejection = _durable_authority(store)
    assert before_rejection == before_disable
    rejected = _new_process(store, pending_file)
    # Disable removes the personal capability; explicit revocation separately
    # fences the managed-admin path (covered by its existing authority suite).
    assert rejected["application"] == "cloud_review_capability_missing"
    disabled_status = rejected["status"]
    assert isinstance(disabled_status, dict)
    assert disabled_status["consent_enabled"] is False
    assert disabled_status["reason"] == "cloud_review_capability_missing"
    assert disabled_status["delivery_ready"] is False
    assert disabled_status["delivery_readiness_reason"] == "cloud_review_capability_missing"
    assert _durable_authority(store) == before_rejection
    assert store.get_approval_request("process-resolved") == resolved_before
    pending = store.get_approval_request("process-pending")
    assert isinstance(pending, dict) and pending["status"] == "pending"
    assert not store.has_exact_cloud_review_receipt("process-pending-receipt")
    assert store.list_policy_decisions() == policy_before
    assert store.get_oauth_local_credentials(allow_primary=False) == credentials_before
    assert len(store.list_events(event_name="cloud_review.exact_used")) == 1
