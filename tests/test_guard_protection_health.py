"""What the runtime reports about each protection fact.

What each fact proves, and whether the signals add up to a protected machine,
belong to the native runtime (`guard_command::protection_health_facts` and
`guard_command::protection_health`), pinned in `rust/crates/guard-command/`.
What this module owes is the facts themselves, so these tests stand in for the
transport and read the request the runtime built.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import approvals as approvals_module
from codex_plugin_scanner.guard.models import GuardRuntimeState
from codex_plugin_scanner.guard.native_protection_health import NativeProtectionHealthError
from codex_plugin_scanner.guard.runtime import protection_health_runtime
from codex_plugin_scanner.guard.store import GuardStore

_NOW = datetime(2026, 7, 19, 15, 0, tzinfo=timezone.utc)


def test_runtime_state_brackets_ipv6_approval_center_origin() -> None:
    state = GuardRuntimeState(
        session_id="session-ipv6",
        daemon_host="::1",
        daemon_port=5474,
        started_at=_NOW.isoformat(),
        last_heartbeat_at=_NOW.isoformat(),
    )
    assert state.to_dict()["approval_center_url"] == "http://[::1]:5474"


@dataclass(frozen=True)
class _ActivityHealth:
    dropped_event_count: int
    persistence_error_count: int
    active_error_count: int


class _Store:
    def __init__(self, *, count: int = 1, active_errors: int = 0) -> None:
        self._count: int = count
        self._health: _ActivityHealth = _ActivityHealth(0, 0, active_errors)

    def count_command_activities(self) -> int:
        return self._count

    def get_command_activity_persistence_health(self) -> _ActivityHealth:
        return self._health


class _BrokenStore:
    def count_command_activities(self) -> int:
        raise RuntimeError("store unavailable")

    def get_command_activity_persistence_health(self) -> _ActivityHealth:
        raise RuntimeError("store unavailable")


@pytest.fixture
def collect(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Callable[..., dict[str, object]]:
    """Collect the facts the runtime sent, without reaching a resident."""

    def _collect(
        *,
        store: protection_health_runtime.ProtectionHealthStore | None = None,
        installs: Sequence[Mapping[str, object]] = (),
        trust: Mapping[str, object] | None = None,
        runtime_state: Mapping[str, object] | None = None,
        hook_verification: Mapping[str, bool] | None = None,
    ) -> dict[str, object]:
        recorded: dict[str, object] = {}

        def _record(facts: Mapping[str, object], *, guard_home: Path) -> dict[str, object]:
            recorded.update(facts)
            recorded["guard_home"] = guard_home
            return {}

        monkeypatch.setattr(protection_health_runtime, "protection_health_report", _record)
        protection_health_runtime.build_runtime_protection_health(
            store=store or _Store(),
            guard_home=tmp_path / "guard-home",
            runtime_state=runtime_state,
            managed_installs=list(installs),
            hook_verification=hook_verification,
            trust_status=trust or {},
            now=_NOW,
        )
        return recorded

    return _collect


def test_every_fact_the_resident_reads_is_sent(collect: Callable[..., dict[str, object]], tmp_path: Path) -> None:
    containment = {"schema_version": "guard.containment-health.v1"}
    facts = collect(
        store=_Store(count=38_102, active_errors=0),
        installs=[{"harness": "codex", "active": True}],
        trust={"runtime_protection": "protected", "remembered_rules": "enforced", "other": "x"},
        runtime_state={
            "registration_status": "registered",
            "last_heartbeat_at": _NOW.isoformat(),
            "containment_health": containment,
            "session_id": "session",
        },
        hook_verification={"codex": True},
    )
    assert facts == {
        "now": "2026-07-19T15:00:00+00:00",
        "managed_installs": [{"harness": "codex", "active": True}],
        "hook_verification": {"codex": True},
        "daemon": {
            "registration_status": "registered",
            "last_heartbeat_at": "2026-07-19T15:00:00+00:00",
            "containment_health": containment,
        },
        "remembered_rules": "enforced",
        "runtime_protection": "protected",
        "decision_stream": {"active_error_count": 0, "activity_count": 38_102},
        "guard_home": tmp_path / "guard-home",
    }


def test_absent_facts_are_sent_as_absent(collect: Callable[..., dict[str, object]]) -> None:
    facts = collect(store=_BrokenStore())
    assert facts["daemon"] is None
    assert facts["hook_verification"] is None
    assert facts["managed_installs"] == []
    assert facts["remembered_rules"] is None
    assert facts["runtime_protection"] is None
    # A store that cannot report its counters is unavailable, never healthy.
    assert facts["decision_stream"] is None


def test_installs_send_only_their_identity_and_activity(collect: Callable[..., dict[str, object]]) -> None:
    installs: list[dict[str, object]] = [
        {
            "harness": f"app-{index}",
            "active": True,
            "workspace": f"/private/workspace/{index}",
            "raw_command": f"secret-command-{index}",
            "manifest": {"path": "/secret"},
        }
        for index in range(3)
    ]
    installs.append({"harness": "../../private", "active": "yes"})

    facts = collect(installs=list(reversed(installs)))

    serialized = repr(facts["managed_installs"])
    assert "/private/workspace" not in serialized
    assert "secret-command" not in serialized
    assert "/secret" not in serialized
    # An install the resident would not count is not sent.
    assert facts["managed_installs"] == [
        {"harness": "app-0", "active": True},
        {"harness": "app-1", "active": True},
        {"harness": "app-2", "active": True},
    ]


def test_stale_and_repeated_installs_stay_within_the_request_limit(
    collect: Callable[..., dict[str, object]],
) -> None:
    installs: list[dict[str, object]] = []
    installs.extend({"harness": "codex", "active": True} for _ in range(20_000))
    installs.extend({"harness": f"old-{index}", "active": False} for index in range(20_000))
    installs.extend(({"harness": "x" * 65, "active": True}, {"harness": "x" * 64, "active": True}))
    installs.append({"harness": 7, "active": True})

    facts = collect(installs=installs)

    assert facts["managed_installs"] == [
        {"harness": "codex", "active": True},
        {"harness": "x" * 64, "active": True},
    ]


def test_canonical_managed_install_supersedes_legacy_alias() -> None:
    installs = [
        {"harness": "claude", "active": True, "manifest": {}},
        {"harness": "claude-code", "active": True, "manifest": {"canonical": True}},
    ]

    assert approvals_module._canonical_managed_installs_for_health(installs) == [
        {"harness": "claude-code", "active": True, "manifest": {"canonical": True}}
    ]

    active_alias = [
        {"harness": "claude", "active": True, "manifest": {"alias": True}},
        {"harness": "claude-code", "active": False, "manifest": {"canonical": True}},
    ]
    assert approvals_module._canonical_managed_installs_for_health(active_alias) == [
        {"harness": "claude-code", "active": True, "manifest": {"alias": True}}
    ]


def test_cursor_attestation_unavailable_is_unproven_not_inactive(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = GuardStore(tmp_path / "guard-home")
    installs = [{"harness": "cursor", "active": True, "manifest": {}}]
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.cursor_hook_health.cursor_runtime_hooks_verified",
        lambda _context: None,
    )
    assert approvals_module._live_hook_verification(installs, store) == {}


def test_an_unreachable_runtime_leaves_the_snapshot_without_a_verdict(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    def unreachable(**_kwargs: object) -> dict[str, object]:
        raise NativeProtectionHealthError("native_protection_health_report_unavailable")

    monkeypatch.setattr(approvals_module, "build_runtime_protection_health", unreachable)
    snapshot = approvals_module.build_runtime_snapshot(
        store=GuardStore(tmp_path / "guard-home"),
        approval_center_url=None,
    )

    assert snapshot["protection_health"] is None
    # A machine with no runtime row reads as "setup" before the report is even
    # asked for. The state an unreachable runtime leaves behind is the one a
    # registered machine falls to, and that is the headline resolver's own
    # branch: an empty protection state is never rendered as protection.
    assert (
        approvals_module._resolve_runtime_headline_state(
            pending_count=0,
            runtime_state={"session_id": "session"},
            protection_state="",
        )
        == "degraded"
    )
