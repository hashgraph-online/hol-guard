"""Tests for multi-source connection profile support."""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.store import GuardStore
from codex_plugin_scanner.guard.store_base import _normalize_source_name


class TestNormalizeSourceName:
    def test_default_returns_default(self):
        assert _normalize_source_name("default") == "default"

    def test_empty_returns_default(self):
        assert _normalize_source_name("") == "default"
        assert _normalize_source_name("   ") == "default"

    def test_lowercases(self):
        assert _normalize_source_name("Staging") == "staging"
        assert _normalize_source_name("PROD") == "prod"

    def test_strips_whitespace(self):
        assert _normalize_source_name("  staging  ") == "staging"

    def test_allows_hyphens_and_underscores(self):
        assert _normalize_source_name("my-staging") == "my-staging"
        assert _normalize_source_name("test_env") == "test_env"

    def test_rejects_spaces(self):
        with pytest.raises(ValueError, match="Invalid source name"):
            _normalize_source_name("staging env")

    def test_rejects_special_chars(self):
        with pytest.raises(ValueError, match="Invalid source name"):
            _normalize_source_name("staging!")

    def test_rejects_leading_hyphen(self):
        with pytest.raises(ValueError, match="Invalid source name"):
            _normalize_source_name("-staging")

    def test_rejects_too_long(self):
        with pytest.raises(ValueError, match="64 characters"):
            _normalize_source_name("a" * 65)


class TestGuardStoreSourceNamespacing:
    """Verify that different source names produce isolated credential storage."""

    def test_default_source_uses_unnamespaced_keys(self, tmp_path):
        store = GuardStore(tmp_path / "default")
        assert store._oauth_local_credentials_state_key == "oauth_local_credentials"
        assert store._guard_source == "default"

    def test_named_source_uses_namespaced_keys(self, tmp_path):
        store = GuardStore(tmp_path / "staging", source="staging")
        assert store._oauth_local_credentials_state_key == "oauth_local_credentials:staging"
        assert store._guard_source == "staging"

    def test_different_sources_have_different_state_keys(self, tmp_path):
        store_a = GuardStore(tmp_path / "a", source="production")
        store_b = GuardStore(tmp_path / "b", source="staging")
        assert store_a._oauth_local_credentials_state_key != store_b._oauth_local_credentials_state_key

    def test_different_sources_have_different_secret_refs(self, tmp_path):
        store_a = GuardStore(tmp_path / "a", source="production")
        store_b = GuardStore(tmp_path / "b", source="staging")
        assert store_a._oauth_local_credentials_ref != store_b._oauth_local_credentials_ref

    def test_same_source_same_guard_home_produces_same_ref(self, tmp_path):
        store_a = GuardStore(tmp_path / "shared", source="staging")
        store_b = GuardStore(tmp_path / "shared", source="staging")
        assert store_a._oauth_local_credentials_ref == store_b._oauth_local_credentials_ref

    def test_invalid_source_raises(self, tmp_path):
        with pytest.raises(ValueError, match="Invalid source name"):
            GuardStore(tmp_path / "bad", source="invalid name!")


class TestMultiSourceCredentials:
    """Verify that credentials stored under one source are isolated from another."""

    @staticmethod
    def _store_credentials(store: GuardStore, issuer: str, client_id: str) -> None:
        from codex_plugin_scanner.guard.cli.oauth_client import generate_dpop_key_pair

        dpop = generate_dpop_key_pair()
        store.set_oauth_local_credentials(
            issuer=issuer,
            client_id=client_id,
            refresh_token=f"refresh-{client_id}",
            dpop_private_key_pem=dpop.private_key_pem,
            dpop_public_jwk=dpop.public_jwk,
            dpop_public_jwk_thumbprint=dpop.public_jwk_thumbprint,
            now="2026-01-01T00:00:00+00:00",
        )

    def test_default_and_staging_are_isolated(self, tmp_path):
        store_default = GuardStore(tmp_path / "shared")
        store_staging = GuardStore(tmp_path / "shared", source="staging")

        # Store credentials under default
        self._store_credentials(store_default, "https://hol.org", "client-default")

        # Store credentials under staging
        self._store_credentials(store_staging, "https://hol.org", "client-staging")

        # Verify isolation
        default_creds = store_default.get_oauth_local_credentials()
        staging_creds = store_staging.get_oauth_local_credentials()

        assert default_creds is not None
        assert staging_creds is not None
        assert default_creds["client_id"] == "client-default"
        assert staging_creds["client_id"] == "client-staging"
        assert default_creds["issuer"] == "https://hol.org"
        assert staging_creds["issuer"] == "https://hol.org"

    def test_list_oauth_sources_returns_all(self, tmp_path):
        store_default = GuardStore(tmp_path / "shared")
        store_staging = GuardStore(tmp_path / "shared", source="staging")

        self._store_credentials(store_default, "https://hol.org", "client-default")
        self._store_credentials(store_staging, "https://hol.org", "client-staging")

        # Use a third store to list all sources (source param doesn't matter for listing)
        store_list = GuardStore(tmp_path / "shared")
        sources = store_list.list_oauth_sources()

        assert len(sources) == 2
        source_names = {s["source"] for s in sources}
        assert source_names == {"default", "staging"}

    def test_disconnect_only_clears_one_source(self, tmp_path):
        store_default = GuardStore(tmp_path / "shared")
        store_staging = GuardStore(tmp_path / "shared", source="staging")

        self._store_credentials(store_default, "https://hol.org", "client-default")
        self._store_credentials(store_staging, "https://hol.org", "client-staging")

        # Clear staging
        store_staging.delete_sync_payload(store_staging._oauth_local_credentials_state_key)

        # Default should still be there
        default_creds = store_default.get_oauth_local_credentials()
        assert default_creds is not None
        assert default_creds["client_id"] == "client-default"

        # Staging should be gone
        staging_creds = store_staging.get_oauth_local_credentials()
        assert staging_creds is None

