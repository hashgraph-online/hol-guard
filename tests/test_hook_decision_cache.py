"""Tests for the hook decision cache wrapper."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.config import GuardConfig
from codex_plugin_scanner.guard.runtime.hook_decision_cache import (
    HookDecisionCache,
    SOURCE_CACHE_SCANNER_NAME,
    SOURCE_CACHE_VERSION,
    SourceReadCacheMaterial,
    hook_config_fingerprint,
)
from codex_plugin_scanner.guard.store import GuardStore


def _material(**overrides: object) -> SourceReadCacheMaterial:
    defaults: dict[str, object] = {
        "kind": "source-read-v1",
        "harness": "pi",
        "event_name": "PostToolUse",
        "workspace_hash": "ws-hash-abc",
        "realpath": "/workspace/src/foo.ts",
        "stat_dev": 1,
        "stat_ino": 2,
        "stat_size": 100,
        "stat_mtime_ns": 1760000000000,
        "content_sha256": "abc123",
        "output_sha256": "abc123",
        "scanner_version": "hook-content-v1:rulehash",
        "source_classifier_version": "source-paths-v1",
        "policy_fingerprint": "policy-hash-123",
        "config_fingerprint": "config-hash-123",
    }
    defaults.update(overrides)
    return SourceReadCacheMaterial(**defaults)  # type: ignore[arg-type]


@pytest.fixture()
def store(tmp_path: Path) -> GuardStore:
    return GuardStore(tmp_path / "guard-home")


@pytest.fixture()
def cache(store: GuardStore) -> HookDecisionCache:
    return HookDecisionCache(store)


class TestSourceReadCacheMaterial:
    def test_frozen_dataclass(self) -> None:
        material = _material()
        try:
            material.harness = "codex"  # type: ignore[misc]
        except AttributeError:
            pass
        else:
            raise AssertionError("SourceReadCacheMaterial should be frozen")


class TestSourceTargetId:
    def test_same_material_returns_same_target_id(self, cache: HookDecisionCache) -> None:
        m = _material()
        assert cache.source_target_id(m) == cache.source_target_id(m)

    def test_different_harness_different_target_id(self, cache: HookDecisionCache) -> None:
        m1 = _material(harness="pi")
        m2 = _material(harness="codex")
        assert cache.source_target_id(m1) != cache.source_target_id(m2)

    def test_different_realpath_different_target_id(self, cache: HookDecisionCache) -> None:
        m1 = _material(realpath="/ws/src/a.ts")
        m2 = _material(realpath="/ws/src/b.ts")
        assert cache.source_target_id(m1) != cache.source_target_id(m2)


class TestSourceInputHash:
    def test_same_material_returns_same_input_hash(self, cache: HookDecisionCache) -> None:
        m = _material()
        assert cache.source_input_hash(m) == cache.source_input_hash(m)

    def test_content_hash_change_causes_different_hash(self, cache: HookDecisionCache) -> None:
        m1 = _material(content_sha256="aaa")
        m2 = _material(content_sha256="bbb")
        assert cache.source_input_hash(m1) != cache.source_input_hash(m2)

    def test_policy_fingerprint_change_causes_different_hash(self, cache: HookDecisionCache) -> None:
        m1 = _material(policy_fingerprint="policy-aaa")
        m2 = _material(policy_fingerprint="policy-bbb")
        assert cache.source_input_hash(m1) != cache.source_input_hash(m2)

    def test_config_fingerprint_change_causes_different_hash(self, cache: HookDecisionCache) -> None:
        m1 = _material(config_fingerprint="config-aaa")
        m2 = _material(config_fingerprint="config-bbb")
        assert cache.source_input_hash(m1) != cache.source_input_hash(m2)

    def test_scanner_version_change_causes_different_hash(self, cache: HookDecisionCache) -> None:
        m1 = _material(scanner_version="v1")
        m2 = _material(scanner_version="v2")
        assert cache.source_input_hash(m1) != cache.source_input_hash(m2)

    def test_stat_change_causes_different_hash(self, cache: HookDecisionCache) -> None:
        m1 = _material(stat_size=100, stat_mtime_ns=1000)
        m2 = _material(stat_size=200, stat_mtime_ns=2000)
        assert cache.source_input_hash(m1) != cache.source_input_hash(m2)


class TestCacheGetSave:
    def test_cache_miss_returns_none(self, cache: HookDecisionCache) -> None:
        m = _material()
        assert cache.get_source_read(m) is None

    def test_cache_save_then_get_returns_payload(self, cache: HookDecisionCache) -> None:
        m = _material()
        payload = {
            "decision": "allow_original",
            "reason_code": "source_full_scan_allow",
            "content_sha256": "abc123",
            "output_sha256": "abc123",
            "bytes_scanned": 100,
            "scanner_version": "hook-content-v1:rulehash",
            "source_classifier_version": "source-paths-v1",
        }
        cache.save_source_read(m, payload, now="2025-01-01T00:00:00+00:00")
        result = cache.get_source_read(m)
        assert result is not None
        assert result["decision"] == "allow_original"
        assert result["reason_code"] == "source_full_scan_allow"

    def test_cache_miss_on_content_hash_change(self, cache: HookDecisionCache) -> None:
        m1 = _material(content_sha256="aaa")
        payload = {"decision": "allow_original"}
        cache.save_source_read(m1, payload, now="2025-01-01T00:00:00+00:00")
        m2 = _material(content_sha256="bbb")
        assert cache.get_source_read(m2) is None

    def test_cache_miss_on_policy_fingerprint_change(self, cache: HookDecisionCache) -> None:
        m1 = _material(policy_fingerprint="policy-aaa")
        cache.save_source_read(m1, {"decision": "allow_original"}, now="2025-01-01T00:00:00+00:00")
        m2 = _material(policy_fingerprint="policy-bbb")
        assert cache.get_source_read(m2) is None

    def test_cache_miss_on_config_fingerprint_change(self, cache: HookDecisionCache) -> None:
        m1 = _material(config_fingerprint="config-aaa")
        cache.save_source_read(m1, {"decision": "allow_original"}, now="2025-01-01T00:00:00+00:00")
        m2 = _material(config_fingerprint="config-bbb")
        assert cache.get_source_read(m2) is None

    def test_cache_miss_on_scanner_version_change(self, cache: HookDecisionCache) -> None:
        m1 = _material(scanner_version="v1")
        cache.save_source_read(m1, {"decision": "allow_original"}, now="2025-01-01T00:00:00+00:00")
        m2 = _material(scanner_version="v2")
        assert cache.get_source_read(m2) is None

    def test_cached_payload_never_contains_raw_file_content(self, cache: HookDecisionCache) -> None:
        m = _material()
        payload = {
            "decision": "allow_original",
            "content_sha256": "abc123",
        }
        cache.save_source_read(m, payload, now="2025-01-01T00:00:00+00:00")
        result = cache.get_source_read(m)
        assert result is not None
        # The payload should only contain metadata, never raw content.
        for key, value in result.items():
            assert not isinstance(value, str) or "raw_content" not in key
            assert "file_text" not in key
            assert "file_content" not in key


class TestHookConfigFingerprint:
    def test_same_config_returns_same_fingerprint(self, tmp_path: Path) -> None:
        config = GuardConfig(guard_home=tmp_path, workspace=tmp_path)
        fp1 = hook_config_fingerprint(config)
        fp2 = hook_config_fingerprint(config)
        assert fp1 == fp2
        assert len(fp1) == 64

    def test_different_mode_different_fingerprint(self, tmp_path: Path) -> None:
        c1 = GuardConfig(guard_home=tmp_path, workspace=tmp_path, mode="prompt")
        c2 = GuardConfig(guard_home=tmp_path, workspace=tmp_path, mode="block")
        assert hook_config_fingerprint(c1) != hook_config_fingerprint(c2)

    def test_different_default_action_different_fingerprint(self, tmp_path: Path) -> None:
        c1 = GuardConfig(guard_home=tmp_path, workspace=tmp_path, default_action="warn")
        c2 = GuardConfig(guard_home=tmp_path, workspace=tmp_path, default_action="block")
        assert hook_config_fingerprint(c1) != hook_config_fingerprint(c2)

    def test_different_risk_actions_different_fingerprint(self, tmp_path: Path) -> None:
        c1 = GuardConfig(guard_home=tmp_path, workspace=tmp_path, risk_actions={"high": "warn"})
        c2 = GuardConfig(guard_home=tmp_path, workspace=tmp_path, risk_actions={"high": "block"})
        assert hook_config_fingerprint(c1) != hook_config_fingerprint(c2)


class TestPolicyFingerprint:
    def test_same_store_returns_same_fingerprint(self, store: GuardStore) -> None:
        fp1 = store.policy_fingerprint(harness="pi", workspace="/workspace")
        fp2 = store.policy_fingerprint(harness="pi", workspace="/workspace")
        assert fp1 == fp2
        assert len(fp1) == 64

    def test_different_harness_different_fingerprint(self, store: GuardStore) -> None:
        fp1 = store.policy_fingerprint(harness="pi", workspace="/workspace")
        fp2 = store.policy_fingerprint(harness="codex", workspace="/workspace")
        assert fp1 != fp2

    def test_different_workspace_different_fingerprint(self, store: GuardStore) -> None:
        fp1 = store.policy_fingerprint(harness="pi", workspace="/workspace1")
        fp2 = store.policy_fingerprint(harness="pi", workspace="/workspace2")
        assert fp1 != fp2

    def test_none_workspace_returns_fingerprint(self, store: GuardStore) -> None:
        fp = store.policy_fingerprint(harness="pi", workspace=None)
        assert len(fp) == 64
