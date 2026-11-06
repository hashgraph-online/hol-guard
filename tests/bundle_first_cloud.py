"""Force bundle-first evaluation in integration tests that seed offline bundles."""

from __future__ import annotations

from typing import Any

import pytest

from codex_plugin_scanner.guard.cli import commands as commands_module
from tests.test_guard_supply_chain_evaluator import (
    _force_cloud_fallback,
    _force_unpaid_entitlement,
)


def _use_seeded_supply_chain_bundle(*args: Any, **kwargs: Any) -> None:
    """Keep offline-bundle integration tests hermetic and deterministic."""

    del args, kwargs


@pytest.fixture
def bundle_first_cloud(monkeypatch: pytest.MonkeyPatch) -> None:
    _force_cloud_fallback(monkeypatch)
    _force_unpaid_entitlement(monkeypatch)
    monkeypatch.setattr(
        commands_module,
        "sync_supply_chain_bundle",
        _use_seeded_supply_chain_bundle,
    )
