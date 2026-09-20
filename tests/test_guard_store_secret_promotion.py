"""Promoting secrets retains exact string values and backend failure tolerance."""

from __future__ import annotations

import hmac
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard import store_base_secret_backends as backends
from codex_plugin_scanner.guard.store_base import FallbackSecretStore


class _SecretBackend:
    def __init__(self, value: str | None, *, fail_get: bool = False, fail_set: bool = False) -> None:
        self.value = value
        self.fail_get = fail_get
        self.fail_set = fail_set
        self.writes: list[tuple[str, str]] = []

    def get_secret(self, secret_id: str) -> str | None:
        del secret_id
        if self.fail_get:
            raise RuntimeError("unavailable backend")
        return self.value

    def set_secret(self, secret_id: str, value: str) -> None:
        self.writes.append((secret_id, value))
        if self.fail_set:
            raise RuntimeError("unavailable backend")
        self.value = value

    def delete_secret(self, secret_id: str) -> None:
        del secret_id
        self.value = None


@pytest.mark.parametrize("value", ["example-value", "", "café", "🔒", "\ud800", "\x00"])
@pytest.mark.parametrize("matches", [True, False])
def test_promotion_compares_complete_encoded_values_and_preserves_exact_secret(
    monkeypatch: pytest.MonkeyPatch, value: str, matches: bool
) -> None:
    stored = value if matches else value + "-changed"
    primary = _SecretBackend(stored)
    fallback = _SecretBackend("fallback-value")
    comparisons: list[tuple[bytes, bytes]] = []

    def compare(left: bytes, right: bytes) -> bool:
        comparisons.append((left, right))
        return hmac.compare_digest(left, right)

    monkeypatch.setattr(backends, "hmac", SimpleNamespace(compare_digest=compare))
    store = FallbackSecretStore(primary, fallback)
    store.promote_secret("example-id", value)

    assert comparisons == [(stored.encode("utf-8", "surrogatepass"), value.encode("utf-8", "surrogatepass"))]
    assert primary.value == value
    assert primary.writes == ([] if matches else [("example-id", value)])
    assert fallback.value == "fallback-value" and fallback.writes == []


@pytest.mark.parametrize("fail_get", [False, True])
@pytest.mark.parametrize("fail_set", [False, True])
def test_missing_or_failed_primary_lookup_keeps_best_effort_promotion(fail_get: bool, fail_set: bool) -> None:
    primary = _SecretBackend(None, fail_get=fail_get, fail_set=fail_set)
    fallback = _SecretBackend("fallback-value")
    store = FallbackSecretStore(primary, fallback)

    store.promote_secret("example-id", "new-value")

    assert primary.writes == [("example-id", "new-value")]
    assert primary.value == (None if fail_set else "new-value")
    assert fallback.value == "fallback-value" and fallback.writes == []


def test_visually_equivalent_unicode_values_are_not_normalized() -> None:
    primary = _SecretBackend("café")
    store = FallbackSecretStore(primary, _SecretBackend(None))

    store.promote_secret("example-id", "cafe\u0301")

    assert primary.writes == [("example-id", "cafe\u0301")]
