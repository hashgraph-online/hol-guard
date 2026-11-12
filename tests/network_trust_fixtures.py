"""Test isolation for the reused default TLS context."""

from __future__ import annotations

from collections.abc import Iterator

import pytest


@pytest.fixture(autouse=True)
def _fresh_default_ssl_context() -> Iterator[None]:
    """Keep a reused TLS context from crossing tests that stub trust sources."""
    from codex_plugin_scanner.guard.mdm.network_trust import reset_default_ssl_context_cache

    reset_default_ssl_context_cache()
    yield
    reset_default_ssl_context_cache()
