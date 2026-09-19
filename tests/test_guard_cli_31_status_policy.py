"""Guard CLI status policy behavior."""

from __future__ import annotations

import json

from codex_plugin_scanner.cli import main
from codex_plugin_scanner.guard.store import GuardStore
from tests.guard_cli_cloud_support import (
    _digest_only_status_policy_bundle,
    _seed_guard_cloud,
    _signed_status_policy_bundle,
)
from tests.guard_cli_test_fixtures import (
    _isolate_codex_runtime_marker as _isolate_codex_runtime_marker,
)
from tests.guard_cli_test_fixtures import (
    _use_legacy_update_context as _use_legacy_update_context,
)


class TestGuardCli:
    def test_guard_status_reports_cloud_policy_bundle_version(self, tmp_path, capsys):
        home_dir = tmp_path / "home"
        store = GuardStore(home_dir)
        now = "2026-05-01T00:00:00Z"
        _seed_guard_cloud(store)
        policy_bundle = _signed_status_policy_bundle()
        store.set_sync_payload(
            "policy_bundle",
            policy_bundle,
            now,
        )
        store.set_sync_payload(
            "policy_bundle_last_error",
            {"reason": "auth_expired"},
            now,
        )

        rc = main(["guard", "status", "--home", str(home_dir), "--json"])
        payload = json.loads(capsys.readouterr().out)

        assert rc == 0
        assert payload["cloud_policy_bundle_version"] == "policy-2026-05-01.3"
        assert payload["cloud_policy_bundle_hash"] == policy_bundle["bundleHash"]
        assert payload["cloud_policy_rollout_state"] == "enforcing"
        assert payload["cloud_policy_sync_error"] == "auth_expired"

    def test_guard_status_does_not_mask_current_auth_failure_with_stale_sync_success(self, tmp_path, capsys):
        home_dir = tmp_path / "home"
        store = GuardStore(home_dir)
        _seed_guard_cloud(store)
        store.set_sync_payload(
            "sync_summary",
            {"synced_at": "2026-05-01T00:00:00Z", "receipts_stored": 1},
            "2026-05-01T00:00:00Z",
        )
        store.set_sync_payload(
            "headless_app_sync_summary",
            {"status": "auth_expired"},
            "2026-05-01T01:00:00Z",
        )

        rc = main(["guard", "status", "--home", str(home_dir), "--json"])
        payload = json.loads(capsys.readouterr().out)

        assert rc == 0
        assert payload["cloud_state"] == "local_only"
        assert "repair" in str(payload["cloud_state_detail"]).lower()
        assert payload["last_sync_at"] == "2026-05-01T00:00:00Z"

    def test_guard_status_rejects_digest_only_cached_bundle_metadata(self, tmp_path, capsys):
        home_dir = tmp_path / "home"
        store = GuardStore(home_dir)
        now = "2026-05-01T00:00:00Z"
        _seed_guard_cloud(store)
        store.set_sync_payload("policy_bundle", _digest_only_status_policy_bundle(), now)
        store.set_sync_payload("policy_bundle_last_error", {"reason": "auth_expired"}, now)

        rc = main(["guard", "status", "--home", str(home_dir), "--json"])
        payload = json.loads(capsys.readouterr().out)

        assert rc == 0
        assert payload["cloud_policy_bundle_version"] is None
        assert payload["cloud_policy_bundle_hash"] is None
        assert payload["cloud_policy_rollout_state"] is None
        assert payload["cloud_policy_sync_error"] == "unsupported_signature_algorithm"

    def test_guard_status_explains_local_only_policy_state(self, tmp_path, capsys):
        home_dir = tmp_path / "home"

        rc = main(["guard", "status", "--home", str(home_dir), "--json"])
        payload = json.loads(capsys.readouterr().out)

        assert rc == 0
        assert payload["cloud_state"] == "local_only"
        assert "this machine" in str(payload["cloud_state_detail"]).lower()
