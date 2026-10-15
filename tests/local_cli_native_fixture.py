"""Run local CLI and MCP grant and contributed MCP decisions through a keyed compiled resident.

The grant decision is native-authoritative: the resident reads ``guard.db``
and answers, and refuses to serve a home that holds no policy verifier key.
Tests that build a real ``GuardStore`` under a temp home enrol that home's own
verifier key before each native call, then close the resident on teardown.
"""

from __future__ import annotations

import atexit
import shutil
import tempfile
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest

from .native_runtime_fixtures import _resolve_native_hook_runtime

_TEST_GUARD_HOME: list[Path] = []
_SCRATCH_GUARD_HOME: list[Path] = []


def _scratch_guard_home() -> Path:
    """Create the shared scratch home on first use and remove it at exit."""

    if not _SCRATCH_GUARD_HOME:
        home = Path(tempfile.mkdtemp(prefix="native-guard-home-"))
        atexit.register(shutil.rmtree, home, ignore_errors=True)
        _SCRATCH_GUARD_HOME.append(home)
    return _SCRATCH_GUARD_HOME[0]


def native_test_guard_home() -> Path:
    """The per-test Guard home that synthetic stores hand the native resident.

    A fresh home per test keeps each resident's restart budget independent.
    Stores built outside a test share one scratch home, created on demand.
    """

    return _TEST_GUARD_HOME[0] if _TEST_GUARD_HOME else _scratch_guard_home()


_KEYED_HOMES: set[Path] = set()


def ensure_keyed_home(guard_home: Path) -> None:
    """Enrol the home's own verifier key before its first native decision."""

    from codex_plugin_scanner.guard.native_policy_snapshot_publisher import provision_native_verifier_key_for_store
    from codex_plugin_scanner.guard.store import GuardStore

    if guard_home not in _KEYED_HOMES:
        provision_native_verifier_key_for_store(GuardStore(guard_home))
        _KEYED_HOMES.add(guard_home)


@pytest.fixture(autouse=True)
def native_local_cli_grant_resident(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Iterator[None]:
    from codex_plugin_scanner.guard import local_cli_grant_decision
    from codex_plugin_scanner.guard.native_resident_client import close_native_residents

    monkeypatch.setenv("HOL_GUARD_NATIVE", "force")
    monkeypatch.setenv("HOL_GUARD_NATIVE_BINARY", str(_resolve_native_hook_runtime()))
    homes = _KEYED_HOMES
    homes.clear()
    _TEST_GUARD_HOME[:] = [tmp_path / "native-guard-home"]

    def keyed(native: Callable[..., Any]) -> Callable[..., Any]:
        """Wrap a native grant call so its home holds a verifier key first."""

        def call(*, guard_home: Path, **kwargs: Any) -> Any:
            ensure_keyed_home(guard_home)
            return native(guard_home=guard_home, **kwargs)

        return call

    monkeypatch.setattr(
        local_cli_grant_decision, "native_local_cli_grant", keyed(local_cli_grant_decision.native_local_cli_grant)
    )
    yield
    for home in tuple(homes):
        close_native_residents(home)
    homes.clear()
    _TEST_GUARD_HOME.clear()
