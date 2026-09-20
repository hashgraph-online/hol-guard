"""Current secret fingerprints use the constant-time comparison primitive."""

from __future__ import annotations

import hashlib
import hmac
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard import store_base as base
from codex_plugin_scanner.guard import store_base_values as values


@pytest.mark.parametrize("candidate", ["fixture-key-鍵", "different-fixture-key"])
def test_current_scrypt_fingerprint_uses_compare_digest_for_match_and_mismatch(
    monkeypatch: pytest.MonkeyPatch, candidate: str
) -> None:
    expected = base._secret_fingerprint("fixture-key-鍵")
    comparisons = []

    def compare_digest(actual: str, stored: str) -> bool:
        comparisons.append((actual, stored))
        return hmac.compare_digest(actual, stored)

    monkeypatch.setattr(values, "hmac", SimpleNamespace(compare_digest=compare_digest))
    assert base._secret_matches_hash(candidate, expected) is (candidate == "fixture-key-鍵")
    assert len(comparisons) == 1
    actual, stored = comparisons[0]
    assert stored == expected
    assert actual.startswith("scrypt$")
    assert len(actual) == len(stored) == 71
    assert actual.isascii() and stored.isascii()


@pytest.mark.parametrize(
    "expected",
    [
        "",
        "scrypt$",
        "scrypt$" + "0" * 63,
        "scrypt$" + "0" * 65,
        "scrypt$" + "A" * 64,
        "scrypt$" + "g" * 64,
        "scrypt$" + "0" * 63 + "\n",
        "scrypt$" + "0" * 63 + "é",
        "scrypt$" + "0" * 63 + "\ud800",
        "scrypt$" + "\uff10" * 64,
        "pbkdf2-sha256$" + "0" * 64,
        hashlib.sha256(b"fixture-key").hexdigest(),
    ],
)
def test_malformed_and_legacy_hashes_stay_false_without_comparing_secret_material(
    monkeypatch: pytest.MonkeyPatch, expected: str
) -> None:
    def unexpected(*_args: object) -> None:
        pytest.fail("invalid stored format must not enter secret derivation or comparison")

    monkeypatch.setattr(base, "_secret_fingerprint", unexpected)
    monkeypatch.setattr(values, "hmac", SimpleNamespace(compare_digest=unexpected))
    assert base._secret_matches_hash("fixture-key", expected) is False
