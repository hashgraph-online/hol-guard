from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard.runtime.extension_control_authority import (
    AuthorityHealth,
    ExtensionControlAuthorityView,
)
from codex_plugin_scanner.guard.runtime.runner import (
    _managed_controls_lkg_capabilities,
    _managed_controls_negotiated_capabilities,
)
from codex_plugin_scanner.guard.store import GuardStore
from tests.test_managed_controls_activation_integration import _CAPABILITIES, _activate, _bundle


def test_candidate_capabilities_require_current_response_and_lkg_is_exact(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for name in (
        "GUARD_EXTENSION_CATALOG_SYNC_V1",
        "GUARD_POLICY_EXTENSION_TARGETS_V1",
        "GUARD_MANAGED_EXTENSION_CONTROLS_V1",
        "GUARD_MANAGED_CONTROLS_ATOMIC_APPLY_V1",
    ):
        monkeypatch.setenv(name, "true")
    store = GuardStore(tmp_path / "guard-home")
    bundle = _bundle()
    assert _activate(store, bundle) is True
    assert _managed_controls_negotiated_capabilities(store, None) == frozenset()
    negotiated = _managed_controls_negotiated_capabilities(
        store,
        {"managedControlsCapabilities": [*sorted(_CAPABILITIES), "unknown.v9"]},
    )
    assert negotiated == _CAPABILITIES
    assert _managed_controls_lkg_capabilities(store, bundle) == _CAPABILITIES
    different = dict(bundle)
    different["bundleHash"] = "sha256:" + "e" * 64
    assert _managed_controls_lkg_capabilities(store, different) == frozenset()


def test_current_and_lkg_negotiation_withhold_authority_capabilities_when_unprotected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for name in (
        "GUARD_EXTENSION_CATALOG_SYNC_V1",
        "GUARD_POLICY_EXTENSION_TARGETS_V1",
        "GUARD_MANAGED_EXTENSION_CONTROLS_V1",
        "GUARD_MANAGED_CONTROLS_ATOMIC_APPLY_V1",
    ):
        monkeypatch.setenv(name, "true")
    store = GuardStore(tmp_path / "guard-home")
    bundle = _bundle()
    assert _activate(store, bundle) is True
    unavailable = ExtensionControlAuthorityView(AuthorityHealth.UNENROLLED, 0, "", ())
    monkeypatch.setattr(store, "read_extension_control_authority_for_registry", lambda _registry: unavailable)
    current = _managed_controls_negotiated_capabilities(
        store,
        {"managedControlsCapabilities": sorted(_CAPABILITIES)},
    )
    assert current == frozenset()
    assert _managed_controls_lkg_capabilities(store, bundle) == frozenset()
