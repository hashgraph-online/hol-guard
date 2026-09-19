"""Guard CLI sync refresh behavior."""

from __future__ import annotations

import pytest

from codex_plugin_scanner.guard.cli import commands as guard_commands_module
from codex_plugin_scanner.guard.store import GuardStore
from tests.guard_cli_cloud_support import _disable_oauth_persistence_assert, _seed_guard_cloud
from tests.guard_cli_test_fixtures import (
    _isolate_codex_runtime_marker as _isolate_codex_runtime_marker,
)
from tests.guard_cli_test_fixtures import (
    _use_legacy_update_context as _use_legacy_update_context,
)


class TestGuardCli:
    def test_refresh_cloud_policy_bundle_records_auth_expired_reason(self, tmp_path, monkeypatch):
        home_dir = tmp_path / "home"
        _disable_oauth_persistence_assert(monkeypatch)
        store = GuardStore(home_dir)
        _seed_guard_cloud(store)

        def _fail_auth(_store: GuardStore, **_kwargs: object) -> dict[str, object]:
            raise guard_commands_module.GuardSyncAuthorizationExpiredError(
                "Guard authorization expired. Run `hol-guard connect` to sign in again."
            )

        monkeypatch.setattr(guard_commands_module, "sync_supply_chain_bundle", _fail_auth)

        guard_commands_module._refresh_cloud_policy_bundle(store, bundle_only=True)

        assert store.get_sync_payload("policy_bundle_last_error") == {
            "reason": "auth_expired",
            "message": "Guard authorization expired. Run `hol-guard connect` to sign in again.",
        }

    @pytest.mark.parametrize(
        "rejection_reason",
        ["bundle_version_downgrade", "inactive_rollout_state"],
    )
    def test_refresh_cloud_policy_bundle_preserves_bundle_rejection_reason(
        self,
        tmp_path,
        monkeypatch,
        rejection_reason,
    ):
        home_dir = tmp_path / "home"
        _disable_oauth_persistence_assert(monkeypatch)
        store = GuardStore(home_dir)
        _seed_guard_cloud(store)

        def _bundle_rejected(current_store: GuardStore, **_kwargs: object) -> dict[str, object]:
            current_store.set_sync_payload(
                "policy_bundle_last_error",
                {"reason": rejection_reason},
                "2026-04-09T00:00:00Z",
            )
            return {"synced": True}

        monkeypatch.setattr(
            guard_commands_module,
            "_resolve_guard_sync_auth_context",
            lambda _store: {
                "access_token": "token",
                "sync_url": "https://hol.org/api/guard/receipts/sync",
            },
        )
        monkeypatch.setattr(
            guard_commands_module,
            "sync_supply_chain_bundle",
            _bundle_rejected,
        )

        guard_commands_module._refresh_cloud_policy_bundle(store, bundle_only=True)

        assert store.get_sync_payload("policy_bundle_last_error") == {
            "reason": rejection_reason,
        }

    def test_refresh_cloud_policy_bundle_preserves_bundle_hash_mismatch_reason(self, tmp_path, monkeypatch):
        home_dir = tmp_path / "home"
        _disable_oauth_persistence_assert(monkeypatch)
        store = GuardStore(home_dir)
        _seed_guard_cloud(store)

        def _bundle_rejected(current_store: GuardStore, **_kwargs: object) -> dict[str, object]:
            current_store.set_sync_payload(
                "policy_bundle_last_error",
                {"reason": "bundle_hash_mismatch"},
                "2026-04-09T00:00:00Z",
            )
            return {"synced": True}

        monkeypatch.setattr(
            guard_commands_module,
            "sync_supply_chain_bundle",
            _bundle_rejected,
        )

        guard_commands_module._refresh_cloud_policy_bundle(store, bundle_only=True)

        assert store.get_sync_payload("policy_bundle_last_error") == {
            "reason": "bundle_hash_mismatch",
        }

    def test_refresh_cloud_policy_bundle_clears_non_bundle_errors_after_success(self, tmp_path, monkeypatch):
        home_dir = tmp_path / "home"
        _disable_oauth_persistence_assert(monkeypatch)
        store = GuardStore(home_dir)
        _seed_guard_cloud(store)
        store.set_sync_payload(
            "policy_bundle_last_error",
            {"reason": "sync_failed", "message": "stale error"},
            "2026-04-09T00:00:00Z",
        )

        monkeypatch.setattr(
            guard_commands_module,
            "_resolve_guard_sync_auth_context",
            lambda _store: {
                "access_token": "token",
                "sync_url": "https://hol.org/api/guard/receipts/sync",
            },
        )
        monkeypatch.setattr(
            guard_commands_module,
            "sync_supply_chain_bundle",
            lambda _store, **_kwargs: {"synced_at": "2026-04-09T00:00:00Z"},
        )

        guard_commands_module._refresh_cloud_policy_bundle(store, bundle_only=True)

        assert store.get_sync_payload("policy_bundle_last_error") == {}

    def test_refresh_cloud_policy_bundle_skips_receipt_sync_for_protect_latency(self, tmp_path, monkeypatch):
        home_dir = tmp_path / "home"
        _disable_oauth_persistence_assert(monkeypatch)
        store = GuardStore(home_dir)
        _seed_guard_cloud(store)

        def _unexpected_receipt_sync(_store: GuardStore, **_kwargs: object) -> dict[str, object]:
            raise AssertionError("sync_receipts should not run during protect-time bundle refresh")

        def _unexpected_cloud_state_sync(_store: GuardStore, **_kwargs: object) -> dict[str, object]:
            raise AssertionError("sync_supply_chain_cloud_state should not run during protect-time bundle refresh")

        monkeypatch.setattr(guard_commands_module, "sync_receipts", _unexpected_receipt_sync)
        monkeypatch.setattr(guard_commands_module, "sync_supply_chain_cloud_state", _unexpected_cloud_state_sync)
        monkeypatch.setattr(
            guard_commands_module,
            "sync_supply_chain_bundle",
            lambda _store, **_kwargs: {"synced_at": "2026-04-09T00:00:00Z"},
        )

        guard_commands_module._refresh_cloud_policy_bundle(store, bundle_only=True)
