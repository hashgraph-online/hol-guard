"""Delivery retries preserve consent identity unless renewal is explicit."""

from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from codex_plugin_scanner.cli import _build_parser
from codex_plugin_scanner.guard.cli import commands_dispatch_cloud_review as cli
from codex_plugin_scanner.guard.daemon.cloud_review_settings import change_cloud_review_settings
from codex_plugin_scanner.guard.runtime.exact_cloud_review import EXACT_CLOUD_REVIEW_CAPABILITY_STATE_KEY
from tests.guard_exact_cloud_review_support import add_review_request, connected_exact_review_store, review_request
from tests.test_guard_cloud_review_settings import _payload, _refresh


def test_cli_renewal_requires_an_explicit_option() -> None:
    parser = _build_parser("hol-guard", program_mode="combined")
    assert parser.parse_args(["guard", "cloud-review", "enable"]).renew is False
    assert parser.parse_args(["guard", "cloud-review", "enable", "--renew"]).renew is True


def test_connect_delivery_retry_keeps_capability_and_pending_request(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = connected_exact_review_store(tmp_path)
    add_review_request(store, review_request("retry-current"))
    ready = False
    monkeypatch.setattr(
        cli,
        "_refresh_cloud_review_worker",
        lambda _home: {"status": "refreshed", "running": True, "sync_running": ready},
    )

    def connect() -> dict[str, object]:
        return cli.apply_connect_time_cloud_review_consent(
            args=argparse.Namespace(enable_cloud_review=True),
            store=store,
            guard_home=store.guard_home,
            payload={"status": "connected"},
            exit_code=0,
        )

    first = connect()
    original = store.get_sync_payload(EXACT_CLOUD_REVIEW_CAPABILITY_STATE_KEY)
    assert first["cloud_review"]["enabled"] is False
    ready = True
    second = connect()
    assert second["cloud_review"]["enabled"] is True
    assert store.get_sync_payload(EXACT_CLOUD_REVIEW_CAPABILITY_STATE_KEY) == original
    assert store.get_approval_request("retry-current")["status"] == "pending"
    assert len(store.list_events(event_name="cloud_review.exact_capability_issued")) == 1


def test_cli_retry_keeps_nonce_and_explicit_renewal_replaces_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    store = connected_exact_review_store(tmp_path)
    monkeypatch.setattr(
        cli,
        "_refresh_cloud_review_worker",
        lambda _home: {"status": "refreshed", "running": True, "sync_running": True},
    )

    def enable(*, renew: bool = False) -> int:
        return cli._run_guard_cloud_review_command(
            argparse.Namespace(cloud_review_command="enable", expires_in_days=30, renew=renew, json=True),
            guard_home=store.guard_home,
            store=store,
        )

    assert enable() == 0
    original = store.get_sync_payload(EXACT_CLOUD_REVIEW_CAPABILITY_STATE_KEY)
    assert enable() == 0
    assert store.get_sync_payload(EXACT_CLOUD_REVIEW_CAPABILITY_STATE_KEY) == original
    assert enable(renew=True) == 0
    assert store.get_sync_payload(EXACT_CLOUD_REVIEW_CAPABILITY_STATE_KEY) != original
    capsys.readouterr()


def test_dashboard_concurrent_retries_issue_one_capability(tmp_path: Path) -> None:
    store = connected_exact_review_store(tmp_path)

    def enable() -> dict[str, object]:
        return change_cloud_review_settings(store, _payload(), refresh_workers=_refresh)

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(lambda _index: enable(), range(2)))
    assert all(result["enabled"] is True for result in results)
    assert len(store.list_events(event_name="cloud_review.exact_capability_issued")) == 1
    original = store.get_sync_payload(EXACT_CLOUD_REVIEW_CAPABILITY_STATE_KEY)
    change_cloud_review_settings(store, _payload(renew_consent=True), refresh_workers=_refresh)
    assert store.get_sync_payload(EXACT_CLOUD_REVIEW_CAPABILITY_STATE_KEY) != original
