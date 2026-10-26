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


# Vectors recorded from the removed Python builder; the resident must reproduce
# them byte for byte so digests and MACs stay stable across the authority move.
_PARITY_VECTORS = (
    (
        {},
        "enforce",
        "461e7371b4e23f68a2e384062faaa021fcc1e7cb8b789c96f6f124a65487cd07",
        "ffb0b31f12fe507a2ae3d0f808e37c7da91706fcebc6977c5c02a9855098be4b",
        "77170173a94cf54c25eabf94b66d5ee379cb7822292003828f8e8e778af570fb",
    ),
    (
        {"mode": "observe"},
        "observe",
        "461e7371b4e23f68a2e384062faaa021fcc1e7cb8b789c96f6f124a65487cd07",
        "b792e5c8aa606db99a87d4663bfbc1ff20ca5a609abf23d8d7c88e9b1e30dcc7",
        "c370fb4960883ef685ad6ce6d5b68a6f18081b7c6e2f52a4060c175b7c56e033",
    ),
    (
        {"protection_posture": "watch"},
        "observe",
        "798d0ad10339b633b38824de633d6f32f94278ef5b6a46e5e04840b8734ab464",
        "04e3d39f788fc5dd0ea6029a7f2559dfab9b5a290dd0b3f34f83f56869bc210a",
        "1b1b0460e9c62c21992c25573f962d7f43871cf48effc8a6a2dfb6e881cfd934",
    ),
)


@pytest.mark.parametrize(("overrides", "mode", "config_digest", "policy_digest", "mac"), _PARITY_VECTORS)
def test_resident_build_reproduces_recorded_python_digests_and_mac(
    native_hook_force: Path,
    overrides: dict[str, object],
    mode: str,
    config_digest: str,
    policy_digest: str,
    mac: str,
) -> None:
    from codex_plugin_scanner.guard.native_policy_snapshot_business_bridge import build_native_business_snapshot

    key = bytes(range(32))
    request: dict[str, object] = {
        "schema": "guard-native-policy-build.v1",
        "version": 1,
        "verifier_key": list(key),
        "generation": 3,
        "runtime_identity": "a" * 64,
        "rule_digest": "b" * 64,
        "mode": mode,
        "scope_contract": {
            "schema": "guard-native-scope.v1",
            "kind": "guard-home",
            "scope_digest": "c" * 64,
            "workspace_binding": "request-source",
        },
        "effective_policy": snapshot_module.effective_native_policy_v3({**_config(), **overrides}),
        "issued_at_ms": 1000,
        "expires_at_ms": 2000,
    }

    built = build_native_business_snapshot(request)

    assert built["config_digest"] == config_digest
    assert built["policy_digest"] == policy_digest
    assert built["integrity"]["mac"] == mac  # type: ignore[index]
    assert snapshot_module.snapshot_mac_matches_v3(built, key)
    tampered = {**built, "generation": 4}
    assert not snapshot_module.snapshot_mac_matches_v3(tampered, key)


def test_mac_check_fails_closed_on_malformed_integrity_blocks() -> None:
    key = bytes(range(32))
    for integrity in (None, {}, {"mac": 7}, {"mac": "\u00e9" * 64}, {"mac": "A" * 64}, {"mac": "0" * 63}):
        assert not snapshot_module.snapshot_mac_matches_v3({"generation": 1, "integrity": integrity}, key)


def test_mac_check_requires_exact_integrity_metadata() -> None:
    key = bytes(range(32))
    unsigned = {"generation": 1}
    mac = snapshot_module._snapshot_integrity_mac_v3(unsigned, key)
    key_id = snapshot_module.native_policy_verifier_key_id(key)
    good = {"algorithm": "hmac-sha256", "key_id": key_id, "mac": mac}
    assert snapshot_module.snapshot_mac_matches_v3({**unsigned, "integrity": good}, key)
    for forged in (
        {**good, "algorithm": "hmac-sha512"},
        {**good, "key_id": "0" * 64},
        {"mac": mac},
        {**good, "extra": "x"},
    ):
        assert not snapshot_module.snapshot_mac_matches_v3({**unsigned, "integrity": forged}, key)
