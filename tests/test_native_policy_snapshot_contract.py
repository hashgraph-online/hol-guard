"""Contract and policy-composition tests for native snapshots."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
from pathlib import Path

import pytest

import codex_plugin_scanner.guard.native_policy_snapshot as snapshot_module
from codex_plugin_scanner.guard.native_policy_snapshot import (
    POLICY_SNAPSHOT_INTEGRITY_DOMAIN,
    POLICY_SNAPSHOT_VERIFIER_DERIVATION_DOMAIN,
    build_policy_snapshot_v3,
    derive_native_policy_verifier_key,
    provision_native_policy_verifier_key,
)

from .native_policy_snapshot_test_fixtures import _config

# Split modules are implementation containers; the compatibility façade imports
# their test functions so the historical test path keeps identical collection.
__test__ = False


@pytest.mark.skipif(os.name != "nt", reason="Windows path aliases are platform-specific")
def test_windows_scope_aliases_share_one_digest_identity() -> None:
    normal = snapshot_module._normalize_scope_text_v3(r"C:\Users\Guard\State")
    assert normal == r"c:\users\guard\state"
    assert snapshot_module._normalize_scope_text_v3(r"\\?\C:\Users\Guard\State") == normal
    assert snapshot_module._normalize_scope_text_v3(r"\\?\UNC\Server\Share\State\\") == (
        snapshot_module._normalize_scope_text_v3(r"\\server\share\state")
    )


def test_policy_merge_never_downgrades_enforcing_posture_to_watch() -> None:
    protected = {**_config(), "mode": "enforce", "protection_posture": "protected"}
    watch = {**_config(), "mode": "observe", "protection_posture": "watch"}

    merged = snapshot_module._merge_effective_native_policies((protected, watch))

    assert merged["protection_posture"] == "protected"
    assert merged["mode"] == "enforce"

    claude_alias = {
        **_config(),
        "harness_actions": {"claude": "review"},
        "harness_risk_actions": {"claude": {"execution": "review"}},
    }
    claude_canonical = {
        **_config(),
        "harness_actions": {"claude-code": "block"},
        "harness_risk_actions": {"claude-code": {"execution": "block"}},
    }
    alias_merged = snapshot_module._merge_effective_native_policies((claude_alias, claude_canonical))

    assert alias_merged["harness_actions"] == {"claude": "block", "claude-code": "block"}
    assert alias_merged["harness_risk_actions"] == {
        "claude": {"execution": "block"},
        "claude-code": {"execution": "block"},
    }


def test_v3_builder_derives_and_provisions_verifier_before_snapshot_push(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir()
    master = b"m" * 32
    expected = hmac.new(master, POLICY_SNAPSHOT_VERIFIER_DERIVATION_DOMAIN, hashlib.sha256).digest()
    assert derive_native_policy_verifier_key(master) == expected

    key_path = provision_native_policy_verifier_key(guard_home, master)
    assert key_path.read_bytes() == expected
    if os.name != "nt":
        assert key_path.stat().st_mode & 0o077 == 0

    snapshot = build_policy_snapshot_v3(
        config=_config(),
        guard_home=guard_home,
        runtime_identity="a" * 64,
        rule_digest="b" * 64,
        verifier_key=expected,
        generation=1,
        issued_at_ms=100,
        expires_at_ms=200,
    )
    signing = dict(snapshot)
    integrity = signing.pop("integrity")
    assert isinstance(integrity, dict)
    expected_mac = hmac.new(
        expected,
        POLICY_SNAPSHOT_INTEGRITY_DOMAIN
        + json.dumps(signing, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode(),
        hashlib.sha256,
    ).hexdigest()
    assert integrity["mac"] == expected_mac
    assert master not in key_path.read_bytes()
