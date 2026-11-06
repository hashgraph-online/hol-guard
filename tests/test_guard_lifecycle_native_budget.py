"""A lifecycle command has to wait for native authority, not fail fast.

Enforcement runs on every tool call and can afford to degrade, so its digest
budget is tight. An install runs once, pays for a runtime nothing has started
yet, and has nowhere to fall back to: a Windows tester watched one abort on
``native_mcp_server_identity_unavailable`` and the identical second run
succeed. These pin the budget those commands run under, and the reason the
failure carries when it still happens.
"""

from __future__ import annotations

import hashlib
import json
import time
from argparse import Namespace
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from codex_plugin_scanner.guard import native_context, native_context_budget
from codex_plugin_scanner.guard.cli import commands_router
from codex_plugin_scanner.guard.native_runtime import (
    NativeRuntimeCapabilities,
    NativeRuntimeIdentity,
    NativeRuntimeStatus,
)
from codex_plugin_scanner.guard.runtime import mcp_protection

_FEATURES = (
    "resident-protocol-v2",
    "native-resident-client-v1",
    "native-resident-lifecycle-v1",
    "context-digest-v1",
)


@pytest.fixture(autouse=True)
def _own_budget() -> Iterator[None]:
    """Keep each test's floor to itself.

    The dispatch resets its own floor, and these tests reset the ones they
    bind by hand. This is the backstop for the case neither covers: a test
    that fails part-way through leaves the floor bound, and every later test
    in the shard then measures a budget it never asked for.
    """

    token = native_context_budget._BOUND_TIMEOUT_FLOOR.set(None)
    try:
        yield
    finally:
        native_context_budget._BOUND_TIMEOUT_FLOOR.reset(token)


def _status() -> NativeRuntimeStatus:
    return NativeRuntimeStatus(
        mode="force",
        available=True,
        compatible=True,
        reason="ok",
        identity=NativeRuntimeIdentity(path=Path("/runtime/hol-guard-runtime"), size=1, mtime_ns=1, sha256="ab" * 32),
        capabilities=NativeRuntimeCapabilities(
            protocol_version=2,
            runtime_version="0.0.0",
            rule_digest="cd" * 32,
            build_sha="ef" * 32,
            target="test",
            features=_FEATURES,
        ),
    )


def _ok_result(request: dict[str, object]) -> bytes:
    canonical = json.dumps(request, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)
    return json.dumps(
        {
            "schema": "guard-context-digest-result.v1",
            "request_id": request["request_id"],
            "request_sha256": hashlib.sha256(canonical.encode("utf-8")).hexdigest(),
            "status": "ok",
            "code": "ok",
            "digest": "00" * 32,
        }
    ).encode("utf-8")


def _prime(monkeypatch: pytest.MonkeyPatch) -> list[float]:
    """Capture how long each outgoing request was given, in seconds."""

    granted: list[float] = []
    monkeypatch.setattr(native_context, "native_runtime_status", lambda: _status())
    monkeypatch.setattr(native_context, "ensure_resident_prerequisite", lambda _home: True)
    monkeypatch.setattr(native_context, "_isolated_environment", lambda: {})
    monkeypatch.setattr(native_context, "native_resident_client_ready", lambda _executable, _home: True)

    def _client(*_args: Any, **kwargs: Any) -> bytes | None:
        granted.append(float(kwargs["deadline_monotonic"]) - time.monotonic())
        return _ok_result(json.loads(kwargs["payload"])["request"])

    monkeypatch.setattr(native_context, "native_resident_client_request", _client)
    return granted


def _digest(guard_home: Path, argv: str, **kwargs: float) -> object:
    return native_context.native_context_digest("launch_argv_digest", {"argv": [argv]}, guard_home=guard_home, **kwargs)


def test_enforcement_keeps_the_tight_budget(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    granted = _prime(monkeypatch)
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir()

    assert _digest(guard_home, "hot")

    assert granted[0] < native_context._TIMEOUT_SECONDS + 0.5


def test_a_lifecycle_command_gives_a_cold_runtime_room_to_answer(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    granted = _prime(monkeypatch)
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir()
    token = native_context.bind_context_digest_lifecycle_budget()
    try:
        assert _digest(guard_home, "install")
    finally:
        native_context.reset_context_digest_budget(token)

    assert granted[0] > native_context_budget._LIFECYCLE_TIMEOUT_SECONDS - 0.5


def test_the_floor_applies_to_a_caller_that_pinned_the_steady_state_budget(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The hot path's own constant is what makes a lifecycle call fail early."""

    granted = _prime(monkeypatch)
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir()
    token = native_context.bind_context_digest_lifecycle_budget()
    try:
        assert _digest(guard_home, "pinned", timeout_seconds=native_context._TIMEOUT_SECONDS)
    finally:
        native_context.reset_context_digest_budget(token)

    assert granted[0] > native_context_budget._LIFECYCLE_TIMEOUT_SECONDS - 0.5


def test_the_floor_never_shortens_a_longer_budget(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    granted = _prime(monkeypatch)
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir()
    token = native_context.bind_context_digest_lifecycle_budget()
    try:
        assert _digest(guard_home, "generous", timeout_seconds=30.0)
    finally:
        native_context.reset_context_digest_budget(token)

    assert granted[0] > 29.0


def test_the_floor_does_not_revive_a_call_its_caller_disabled(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    granted = _prime(monkeypatch)
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir()
    token = native_context.bind_context_digest_lifecycle_budget()
    try:
        assert _digest(guard_home, "disabled", timeout_seconds=0.0) is None
    finally:
        native_context.reset_context_digest_budget(token)

    assert granted == []


def test_the_budget_does_not_outlive_the_command(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    granted = _prime(monkeypatch)
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir()
    token = native_context.bind_context_digest_lifecycle_budget()
    native_context.reset_context_digest_budget(token)

    assert _digest(guard_home, "after")

    assert granted[0] < native_context._TIMEOUT_SECONDS + 0.5


def _route(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, command: str, handler_name: str) -> float | None:
    """Run one prestore command and report the budget its handler saw."""

    seen: list[float | None] = []
    monkeypatch.setattr(commands_router, "resolve_guard_home", lambda _override: tmp_path / "guard-home")
    monkeypatch.setattr(commands_router, "_resolve_guard_workspace", lambda _args, **_kwargs: None)
    monkeypatch.setattr(commands_router, "enforce_lifecycle_gate", lambda *_args, **_kwargs: None)

    def _handler(_args: Namespace, **_kwargs: object) -> int:
        seen.append(native_context_budget._BOUND_TIMEOUT_FLOOR.get())
        return 0

    monkeypatch.setattr(commands_router, handler_name, _handler, raising=False)
    args = Namespace(
        guard_command=command,
        guard_home=None,
        home=None,
        workspace=None,
        grok_executable=None,
        source="default",
        json=True,
    )
    assert commands_router.run_guard_command(args) == 0
    return seen[0]


def test_a_protection_lifecycle_command_runs_under_the_longer_budget(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    assert _route(monkeypatch, tmp_path, "update", "_run_guard_update_command") == (
        native_context_budget._LIFECYCLE_TIMEOUT_SECONDS
    )


def test_an_ordinary_command_does_not(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    assert _route(monkeypatch, tmp_path, "trust", "_run_guard_trust_command") is None


def test_a_lifecycle_command_does_not_widen_the_next_command_in_the_process(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """One dispatch must not leave enforcement running on the longer budget."""

    _route(monkeypatch, tmp_path, "update", "_run_guard_update_command")

    assert _route(monkeypatch, tmp_path, "trust", "_run_guard_trust_command") is None


def test_the_install_error_names_why_native_authority_was_unavailable(monkeypatch: pytest.MonkeyPatch) -> None:
    """An aborted install leaves the person nothing but this string to act on."""

    monkeypatch.setattr(mcp_protection, "context_mcp_identity", lambda _kind, _request: None)
    monkeypatch.setattr(
        mcp_protection, "native_context_failure_reason", lambda: "native_context_digest_prerequisite_unavailable"
    )

    with pytest.raises(ValueError) as error:
        mcp_protection.build_mcp_server_identity(
            config_path="/home/tester/.codex/config.toml",
            command="hol-guard",
            args=(),
            transport="stdio",
        )

    assert str(error.value) == ("native_mcp_server_identity_unavailable:native_context_digest_prerequisite_unavailable")


def test_the_floor_is_bound_before_the_command_resolves_a_guard_home(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An install reaches native authority long before it has a home to bind.

    Binding the floor partway down the dispatch covers only the handlers below
    that point. Everything an install does on the way there — resolving the
    home, standing up the store — runs on the hot path's budget, which is the
    budget that aborted one on a cold runtime.
    """

    seen: list[float | None] = []

    def _resolve(_override: object) -> Path:
        seen.append(native_context_budget._BOUND_TIMEOUT_FLOOR.get())
        return tmp_path / "guard-home"

    monkeypatch.setattr(commands_router, "resolve_guard_home", _resolve)
    monkeypatch.setattr(commands_router, "_resolve_guard_workspace", lambda _args, **_kwargs: None)
    monkeypatch.setattr(commands_router, "enforce_lifecycle_gate", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(commands_router, "_run_guard_update_command", lambda _args, **_kwargs: 0, raising=False)

    assert _dispatch(commands_router, "update") == 0
    assert seen == [native_context_budget._LIFECYCLE_TIMEOUT_SECONDS]


def test_a_command_that_fails_still_gives_the_floor_back(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A raising handler must not leave enforcement on the longer budget.

    The dispatch is not the only thing in the process: a daemon and a hook
    worker run commands one after another, and a failed install leaving its
    floor bound widens every tool call they enforce afterwards.
    """

    monkeypatch.setattr(commands_router, "resolve_guard_home", lambda _override: tmp_path / "guard-home")
    monkeypatch.setattr(commands_router, "_resolve_guard_workspace", lambda _args, **_kwargs: None)
    monkeypatch.setattr(commands_router, "enforce_lifecycle_gate", lambda *_args, **_kwargs: None)

    def _raise(_args: Namespace, **_kwargs: object) -> int:
        raise RuntimeError("install failed")

    monkeypatch.setattr(commands_router, "_run_guard_update_command", _raise, raising=False)

    with pytest.raises(RuntimeError):
        _dispatch(commands_router, "update")

    assert native_context_budget._BOUND_TIMEOUT_FLOOR.get() is None


def test_an_early_handler_command_never_sees_a_lifecycle_floor(monkeypatch: pytest.MonkeyPatch) -> None:
    """`hol-guard mcp` returns above the home resolution and stays on its budget."""

    seen: list[float | None] = []

    def _handler(_args: Namespace, **_kwargs: object) -> int:
        seen.append(native_context_budget._BOUND_TIMEOUT_FLOOR.get())
        return 0

    monkeypatch.setattr(commands_router, "_run_guard_mcp_command", _handler, raising=False)

    assert _dispatch(commands_router, "mcp") == 0
    assert seen == [None]


def _dispatch(router: Any, command: str) -> int:
    """Run one command through the real entry point with the usual arguments."""

    return router.run_guard_command(
        Namespace(
            guard_command=command,
            guard_home=None,
            home=None,
            workspace=None,
            grok_executable=None,
            source="default",
            json=True,
        )
    )


def test_a_refused_identity_request_names_the_code_the_runtime_sent(monkeypatch: pytest.MonkeyPatch) -> None:
    """An error-status answer is not the same as no answer at all.

    The runtime replied and said why. Dropping its code leaves the aborted
    install reporting bare unavailability, which reads as a missing runtime —
    the one thing that did not happen here.
    """

    monkeypatch.setattr(
        native_context,
        "native_context_digest",
        lambda *_args, **_kwargs: {"status": "error", "code": "native_mcp_identity_request_invalid"},
    )
    token = native_context._LAST_DIGEST_FAILURE.set(None)

    with pytest.raises(ValueError) as error:
        mcp_protection.build_mcp_server_identity(
            config_path="/home/tester/.codex/config.toml",
            command="hol-guard",
            args=(),
            transport="stdio",
        )

    native_context._LAST_DIGEST_FAILURE.reset(token)

    assert str(error.value) == "native_mcp_server_identity_unavailable:native_mcp_identity_request_invalid"
