"""Phase 11 JavaScript semver regression tests."""

from __future__ import annotations

from codex_plugin_scanner.guard.runtime.js_semver import version_matches_js_selector
from codex_plugin_scanner.guard.runtime.supply_chain_package_eval import _exact_version


def test_version_matches_js_selector_preserves_prerelease_ordering() -> None:
    assert version_matches_js_selector("1.2.3-beta.1", "1.2.3-beta.1")
    assert not version_matches_js_selector("1.2.3-beta.1", "1.2.3")
    assert not version_matches_js_selector("1.2.3-beta.1", ">=1.2.3")
    assert version_matches_js_selector("1.2.3", ">=1.2.3")


def test_exact_version_ignores_all_js_source_prefixes() -> None:
    assert _exact_version("github:hashgraph-online/hol-guard") is None
    assert _exact_version("gitlab:hashgraph-online/hol-guard") is None
    assert _exact_version("bitbucket:hashgraph-online/hol-guard") is None
