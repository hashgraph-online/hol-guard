"""Retained copies cannot silently select an older or unavailable marker."""

from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard.native_business_source_retention import (
    read_retained_business_source_anchor,
    write_retained_business_source_anchor,
)
from codex_plugin_scanner.guard.native_policy_snapshot_constants import NativePolicySnapshotError
from codex_plugin_scanner.guard.store_base import FallbackSecretStore


class MemoryCopy:
    def __init__(self, value=None, *, unavailable=False, discard_write=False):
        self.value = value
        self.unavailable = unavailable
        self.discard_write = discard_write

    def get_secret(self, reference):
        if self.unavailable:
            raise RuntimeError("private backend failure must not escape")
        return self.value

    def set_secret(self, reference, value):
        if self.unavailable:
            raise RuntimeError("private write failure must not escape")
        if not self.discard_write:
            self.value = value


def _store(primary, fallback):
    return SimpleNamespace(
        _policy_integrity_secret_store=FallbackSecretStore(primary, fallback),
        _build_scoped_secret_ref=lambda prefix: prefix + ":synthetic-home",
    )


@pytest.mark.parametrize("primary,fallback", [(None, "old"), ("new", "old"), ("old", None)])
def test_missing_and_conflicting_copies_cannot_restore_an_old_source(primary, fallback):
    with pytest.raises(NativePolicySnapshotError, match="native_business_source_retention_conflict"):
        read_retained_business_source_anchor(_store(MemoryCopy(primary), MemoryCopy(fallback)))


def test_unavailable_copy_is_not_treated_as_fresh_or_fallback_only():
    with pytest.raises(NativePolicySnapshotError, match="native_business_source_retention_unavailable") as failure:
        read_retained_business_source_anchor(_store(MemoryCopy(unavailable=True), MemoryCopy()))
    assert "private backend failure" not in str(failure.value)


def test_partial_success_cannot_claim_durable_retention():
    store = _store(MemoryCopy("old"), MemoryCopy("old", discard_write=True))
    with pytest.raises(NativePolicySnapshotError, match="native_business_source_retention_conflict"):
        write_retained_business_source_anchor(store, b"new")


def test_success_requires_readback_from_both_existing_backends():
    store = _store(MemoryCopy(), MemoryCopy())
    assert read_retained_business_source_anchor(store) is None
    write_retained_business_source_anchor(store, b"bounded-fixture-marker")
    assert read_retained_business_source_anchor(store) == b"bounded-fixture-marker"
