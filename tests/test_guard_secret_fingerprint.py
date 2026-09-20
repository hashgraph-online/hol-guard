"""Current secret-fingerprint comparison and malformed-domain regressions."""

from __future__ import annotations

import pytest

from codex_plugin_scanner.guard import store_base as base
from codex_plugin_scanner.guard import store_base_values as values


@pytest.mark.parametrize("comparison", ("match", "first", "last", "short", "long"))
def test_secret_fingerprint_uses_constant_time_comparison(comparison: str, monkeypatch: pytest.MonkeyPatch) -> None:
    value = "synthetic-secret-\u00e9"
    expected = base._secret_fingerprint(value)
    candidate = expected
    if comparison in {"first", "last"}:
        index = len(base._SECRET_FINGERPRINT_PREFIX) if comparison == "first" else len(expected) - 1
        changed = "0" if expected[index] != "0" else "1"
        candidate = expected[:index] + changed + expected[index + 1 :]
    elif comparison == "short":
        candidate = expected[:-1]
    elif comparison == "long":
        candidate = expected + "0"
    calls: list[tuple[str, str]] = []
    original_compare = values.hmac.compare_digest

    def observe_compare(actual: str, supplied: str) -> bool:
        calls.append((actual, supplied))
        return original_compare(actual, supplied)

    monkeypatch.setattr(values.hmac, "compare_digest", observe_compare)
    assert base._secret_matches_hash(value, candidate) is (comparison == "match")
    assert calls == ([] if comparison in {"short", "long"} else [(expected, candidate)])


@pytest.mark.parametrize("malformation", ("non_ascii", "surrogate"))
def test_non_ascii_secret_fingerprint_is_rejected_without_error(malformation: str) -> None:
    suffix = "\u00e9" if malformation == "non_ascii" else "\ud800"
    assert base._secret_matches_hash("synthetic-secret", base._SECRET_FINGERPRINT_PREFIX + suffix) is False


@pytest.mark.parametrize("expected", ("", "a" * 64, "sha256$" + "a" * 64))
def test_unsupported_secret_fingerprint_is_rejected_before_hashing(
    expected: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    def unexpected_hash(_value: str) -> str:
        raise AssertionError("Unsupported fingerprint format must not hash secret material")

    monkeypatch.setattr(base, "_secret_fingerprint", unexpected_hash)
    assert base._secret_matches_hash("synthetic-secret", expected) is False
