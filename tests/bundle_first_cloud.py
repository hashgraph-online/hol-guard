"""Force bundle-first evaluation in integration tests that seed offline bundles."""

from __future__ import annotations

import pytest

from tests.test_guard_supply_chain_evaluator import _force_cloud_fallback


@pytest.fixture
def bundle_first_cloud(monkeypatch: pytest.MonkeyPatch) -> None:
    _force_cloud_fallback(monkeypatch)
