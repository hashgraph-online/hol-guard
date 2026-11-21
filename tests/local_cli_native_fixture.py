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
from collections.abc import Iterator
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
    from codex_plugin_scanner.guard.native_resident_client import close_native_residents

    from . import runtime_wrapper_support

    monkeypatch.setenv("HOL_GUARD_NATIVE", "force")
    monkeypatch.setenv("HOL_GUARD_NATIVE_BINARY", str(_resolve_native_hook_runtime()))
    homes = _KEYED_HOMES
    homes.clear()
    _TEST_GUARD_HOME[:] = [tmp_path / "native-guard-home"]

    native_hook = runtime_wrapper_support.native_local_cli_hook

    def keyed_hook(store: Any, **kwargs: Any) -> Any:
        ensure_keyed_home(store.guard_home)
        return native_hook(store, **kwargs)

    monkeypatch.setattr(runtime_wrapper_support, "native_local_cli_hook", keyed_hook)
    yield
    for home in tuple(homes):
        close_native_residents(home)
    homes.clear()
    _TEST_GUARD_HOME.clear()


def review_rule_verdict(
    store: Any,
    *,
    command: str,
    cwd: Path,
    home_dir: Path,
    mode: str = "review",
    native_result: dict[str, object] | None = None,
    input_key: str = "tool_input",
) -> tuple[str, str | None] | None:
    """The resident's custom-rule verdict for ``command``, or ``None`` when no rule applies.

    ``review`` checks a non-recognition review; ``allowed`` checks a command
    the native runtime allowed. ``native_result`` replaces the mode's default
    verdict.
    """

    import os
    from uuid import uuid4

    from codex_plugin_scanner.guard.native_execution import _resident_request

    if native_result is None and mode == "allowed":
        native_result = {"decision": "allow", "policy_action": "allow", "minimum_action": "allow"}
    elif native_result is None:
        native_result = {
            "decision": "ask",
            "policy_action": "review",
            "minimum_action": "review",
            "reason_code": "native_command_review_required",
            "reason": "Review",
            "action": {"action_type": "shell"},
        }
    ensure_keyed_home(store.guard_home)
    request_id = f"hook-local-cli-rule-{uuid4().hex}"
    response = _resident_request(
        operation="hook_local_cli_rule",
        request={
            "schema": "guard-hook-local-cli-rule-request.v1",
            "request_id": request_id,
            "store_path": str(store.path),
            "guard_home": str(store.guard_home),
            "mode": mode,
            "payload": {input_key: {"command": command}, "cwd": str(cwd)},
            "native_result": native_result,
            "workspace": str(cwd),
            "home_dir": str(home_dir),
            "user_home": str(Path.home()),
            "env": dict(os.environ),
        },
        guard_home=store.guard_home,
        timeout_seconds=5.0,
        required_feature="hook-local-cli-rule-v1",
        response_schema="guard-hook-local-cli-rule-result.v1",
    )
    if response is None or response.get("request_id") != request_id or response.get("verdict") == "none":
        return None
    name = response.get("name")
    return str(response["verdict"]), name if isinstance(name, str) else None
