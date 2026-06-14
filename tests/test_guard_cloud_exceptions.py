"""Cloud exception DTO persistence and API coverage (HGLP046-HGLP060)."""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.cloud_exceptions import (
    build_cloud_exceptions_from_policy_bundle,
    build_cloud_exceptions_from_sync_payload,
    cloud_exception_from_mapping,
    list_active_cloud_exceptions,
)
from codex_plugin_scanner.guard.daemon.server import GuardDaemonServer
from codex_plugin_scanner.guard.runtime.runner import _persist_cloud_exceptions
from codex_plugin_scanner.guard.store import GuardStore


def _sample_sync_exception(*, exception_id: str = "artifact:codex:demo") -> dict[str, object]:
    return {
        "exceptionId": exception_id,
        "scope": "artifact",
        "harness": "codex",
        "artifactId": "codex:project:demo",
        "owner": "owner@example.com",
        "approver": "approver@example.com",
        "reason": "Temporary allow for demo artifact",
        "expiresAt": "2099-01-01T00:00:00Z",
        "sourceReceiptId": "receipt_demo_001",
    }


def test_cloud_exception_dto_includes_required_fields() -> None:
    parsed = cloud_exception_from_mapping(_sample_sync_exception())
    assert parsed is not None
    payload = parsed.to_dict()
    for key in (
        "id",
        "effect",
        "scope",
        "harness",
        "owner",
        "approver",
        "expiry",
        "source_receipt_id",
        "bundle_hash",
        "ack_status",
        "last_used_at",
    ):
        assert key in payload


def test_expired_cloud_exceptions_are_not_active() -> None:
    expired = cloud_exception_from_mapping(
        {
            **_sample_sync_exception(exception_id="expired:1"),
            "expiresAt": "2020-01-01T00:00:00Z",
        }
    )
    assert expired is not None
    active = list_active_cloud_exceptions([expired], now="2026-01-01T00:00:00+00:00")
    assert active == []


def test_persist_cloud_exceptions_stores_separate_from_policy_decisions(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "home")
    serialized = _persist_cloud_exceptions(
        store,
        sync_exceptions=[_sample_sync_exception()],
        now="2026-06-13T00:00:00Z",
    )
    assert len(serialized) == 1
    listed = store.list_cloud_exceptions()
    assert len(listed) == 1
    assert listed[0]["id"] == "artifact:codex:demo"
    assert listed[0]["last_used_at"] is None
    policy_rows = store.list_policy_decisions()
    assert all(row.get("source") != "cloud-sync" for row in policy_rows)


def test_policy_bundle_cloud_exceptions_are_loaded(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "home")
    bundle = {
        "bundleHash": "sha256:demo",
        "cloudExceptions": [
            {
                "exceptionId": "bundle:1",
                "effect": "allow",
                "scope": "harness",
                "harness": "codex",
                "owner": "owner@example.com",
                "expiresAt": "2099-01-01T00:00:00Z",
            }
        ],
        "acknowledgements": [],
    }
    items = build_cloud_exceptions_from_policy_bundle(bundle, device_id="device-1")
    assert len(items) == 1
    assert items[0].bundle_hash == "sha256:demo"
    _persist_cloud_exceptions(store, policy_bundle=bundle, now="2026-06-13T00:00:00Z")
    assert store.list_cloud_exceptions(harness="codex")


def test_sync_payload_builder_deduplicates_by_id() -> None:
    items = build_cloud_exceptions_from_sync_payload(
        [_sample_sync_exception(), _sample_sync_exception(exception_id="artifact:codex:other")]
    )
    assert len(items) == 2
