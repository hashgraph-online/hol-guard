from __future__ import annotations

import pytest

from codex_plugin_scanner.guard import store_base as store
from codex_plugin_scanner.guard import store_base_secret_backends as backends


class _Backend:
    def __init__(self, value: str | None, *, read_error: bool = False, write_error: bool = False) -> None:
        self.value = value
        self.read_error = read_error
        self.write_error = write_error
        self.reads: list[str] = []
        self.writes: list[tuple[str, str]] = []

    def get_secret(self, secret_id: str) -> str | None:
        self.reads.append(secret_id)
        if self.read_error:
            raise RuntimeError("read failed")
        return self.value

    def set_secret(self, secret_id: str, value: str) -> None:
        self.writes.append((secret_id, value))
        if self.write_error:
            raise RuntimeError("write failed")
        self.value = value

    def delete_secret(self, secret_id: str) -> None:
        self.value = None


@pytest.mark.parametrize(
    "kind",
    [
        "equal_ascii",
        "different_prefix",
        "different_suffix",
        "different_length",
        "equal_unicode",
        "different_unicode",
        "equal_surrogate",
        "different_surrogate",
        "equal_empty",
        "different_empty",
    ],
)
def test_promote_secret_compares_encoded_values(kind: str, monkeypatch: pytest.MonkeyPatch) -> None:
    existing, requested, changed = {
        "equal_ascii": ("secret", "secret", False),
        "different_prefix": ("secret", "xecret", True),
        "different_suffix": ("secret", "secrex", True),
        "different_length": ("secret", "secrets", True),
        "equal_unicode": ("caf\u00e9", "caf\u00e9", False),
        "different_unicode": ("caf\u00e9", "cafe\u0301", True),
        "equal_surrogate": ("\ud800", "\ud800", False),
        "different_surrogate": ("\ud800", "\ud801", True),
        "equal_empty": ("", "", False),
        "different_empty": ("", "secret", True),
    }[kind]
    original_compare = backends.hmac.compare_digest
    observed: list[tuple[bytes, bytes]] = []

    def compare(left: bytes, right: bytes) -> bool:
        observed.append((left, right))
        return original_compare(left, right)

    monkeypatch.setattr(backends.hmac, "compare_digest", compare)
    primary = _Backend(existing)
    fallback = _Backend("fallback")
    secret_store = store.FallbackSecretStore(primary, fallback)

    assert secret_store.promote_secret("id", requested) is None

    assert observed == [
        (existing.encode("utf-8", errors="surrogatepass"), requested.encode("utf-8", errors="surrogatepass"))
    ]
    assert primary.reads == ["id"]
    assert primary.writes == ([("id", requested)] if changed else [])
    assert primary.value == requested
    assert fallback.reads == fallback.writes == []
    assert fallback.value == "fallback"


@pytest.mark.parametrize("read_error", [False, True])
def test_promote_missing_secret_preserves_primary_write(read_error: bool, monkeypatch: pytest.MonkeyPatch) -> None:
    def unexpected_compare(_left: bytes, _right: bytes) -> bool:
        raise AssertionError("missing primary secret must not be compared")

    monkeypatch.setattr(backends.hmac, "compare_digest", unexpected_compare)
    primary = _Backend(None, read_error=read_error)
    fallback = _Backend("fallback")

    assert store.FallbackSecretStore(primary, fallback).promote_secret("id", "secret") is None

    assert primary.reads == ["id"]
    assert primary.writes == [("id", "secret")]
    assert primary.value == "secret"
    assert fallback.reads == fallback.writes == []


def test_promote_secret_preserves_write_failure_behavior() -> None:
    primary = _Backend("old", write_error=True)
    fallback = _Backend("fallback")

    assert store.FallbackSecretStore(primary, fallback).promote_secret("id", "new") is None

    assert primary.reads == ["id"]
    assert primary.writes == [("id", "new")]
    assert primary.value == "old"
    assert fallback.reads == fallback.writes == []
