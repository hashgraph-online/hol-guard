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
    from codex_plugin_scanner.guard import local_cli_grant_decision, local_cli_hook
    from codex_plugin_scanner.guard.daemon import hook_native_local_cli
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
    native_hook = local_cli_hook.native_local_cli_hook

    def keyed_hook(store: Any, **kwargs: Any) -> Any:
        ensure_keyed_home(store.guard_home)
        return native_hook(store, **kwargs)

    monkeypatch.setattr(local_cli_hook, "native_local_cli_hook", keyed_hook)
    rule_verdict = hook_native_local_cli._rule_verdict

    def keyed_rule_verdict(store: Any, *args: Any) -> Any:
        ensure_keyed_home(store.guard_home)
        return rule_verdict(store, *args)

    monkeypatch.setattr(hook_native_local_cli, "_rule_verdict", keyed_rule_verdict)
    yield
    for home in tuple(homes):
        close_native_residents(home)
    homes.clear()
    _TEST_GUARD_HOME.clear()


def review_rule_verdict(
    store: Any, *, command: str, cwd: Path, home_dir: Path, mode: str = "review"
) -> tuple[str, str | None] | None:
    """The resident's custom-rule verdict for ``command``, or ``None`` when no rule applies.

    ``review`` checks a non-recognition review; ``allowed`` checks a command
    the native runtime allowed.
    """

    from codex_plugin_scanner.guard.daemon import hook_native_local_cli

    if mode == "allowed":
        native_result: dict[str, object] = {"decision": "allow", "policy_action": "allow", "minimum_action": "allow"}
    else:
        native_result = {
            "decision": "ask",
            "policy_action": "review",
            "minimum_action": "review",
            "reason_code": "native_command_review_required",
            "reason": "Review",
            "action": {"action_type": "shell"},
        }
    payload = {"tool_input": {"command": command}, "cwd": str(cwd)}
    answer = hook_native_local_cli._rule_verdict(store, mode, payload, native_result, cwd, home_dir)
    return None if answer is None or answer[0] == "none" else answer
