"""Canonical compilation keeps exact bytes with bounded immutable reuse."""

from __future__ import annotations

import json

import pytest

from codex_plugin_scanner.guard import store_extension_control_manifest as manifest
from codex_plugin_scanner.guard.runtime import command_matcher_contracts as contracts
from codex_plugin_scanner.guard.runtime.command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY


def _uncached_key(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


@pytest.mark.parametrize(
    "values",
    [
        frozenset(("plain", "\n", '"', "\\", "é", "😀", "\0", "--flag")),
        frozenset((None, False, 7, 2.5, "7", "false")),
        frozenset(("x" * 256, "x" * 257, "y" * 1000)),
    ],
)
def test_set_order_retains_exact_json_order(values: frozenset[object]) -> None:
    contracts._encoded_short_string.cache_clear()
    expected = sorted(values, key=_uncached_key)
    assert contracts.canonical_contract_value(values) == expected
    assert contracts.canonical_contract_value(values) == expected


def test_mutable_values_are_encoded_again_after_change() -> None:
    value: dict[str, object] = {"items": ["first"]}
    first = contracts._set_sort_key(value)
    value["items"] = ["second"]
    assert contracts._set_sort_key(value) == _uncached_key(value)
    assert contracts._set_sort_key(value) != first


def test_sort_key_cache_is_bounded_and_excludes_long_or_nonplain_strings() -> None:
    class StringSubclass(str):
        pass

    contracts._encoded_short_string.cache_clear()
    for index in range(600):
        value = f"flag-{index}"
        assert contracts._set_sort_key(value) == _uncached_key(value)
    assert contracts._encoded_short_string.cache_info().currsize == 512
    before = contracts._encoded_short_string.cache_info()
    for value in ("x" * 257, StringSubclass("subclass"), 7, None):
        assert contracts._set_sort_key(value) == _uncached_key(value)
    assert contracts._encoded_short_string.cache_info() == before


def test_all_packaged_target_fingerprints_match_uncached_compilation(monkeypatch: pytest.MonkeyPatch) -> None:
    contracts._encoded_short_string.cache_clear()
    optimized = manifest._build_catalog_target_manifest(BUILT_IN_COMMAND_EXTENSION_REGISTRY)
    assert optimized
    with monkeypatch.context() as patch:
        patch.setattr(contracts, "_set_sort_key", _uncached_key)
        reference = manifest._build_catalog_target_manifest(BUILT_IN_COMMAND_EXTENSION_REGISTRY)
    assert optimized == reference
