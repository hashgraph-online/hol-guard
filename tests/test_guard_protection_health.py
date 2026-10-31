"""What the runtime proves about each protection check.

Whether a set of signals adds up to a protected machine belongs to the native
runtime (`guard_command::protection_health`), and is pinned by
`rust/crates/guard-command/tests/`. What this module owes is the signals
themselves, so these tests stand in for the transport and read the request the
runtime built rather than evaluating it a second time.
"""

from __future__ import annotations

import hashlib
import itertools
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import approvals as approvals_module
from codex_plugin_scanner.guard.models import GuardRuntimeState
from codex_plugin_scanner.guard.native_protection_health import NativeProtectionHealthError
from codex_plugin_scanner.guard.runtime import protection_health_runtime
from codex_plugin_scanner.guard.runtime.containment_contract import ContainmentBackend
from codex_plugin_scanner.guard.runtime.containment_health import (
    CONTAINMENT_POLICY_CONTRACT_DIGEST,
    ContainmentHealthEvidence,
)
from codex_plugin_scanner.guard.runtime.protection_health import (
    PROTECTION_CHECK_IDS,
    ProtectionCheckStatus,
    ProtectionSignal,
)
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
    def __init__(self, *, count: int, dropped: int, errors: int, active_errors: int) -> None:
        self._count: int = count
        self._health: _ActivityHealth = _ActivityHealth(dropped, errors, active_errors)

    def count_command_activities(self) -> int:
        return self._count

    def get_command_activity_persistence_health(self) -> _ActivityHealth:
        return self._health


def _containment_evidence() -> dict[str, object]:
    fingerprint = hashlib.sha256(b"stable").hexdigest()
    return ContainmentHealthEvidence(
        backend=ContainmentBackend.MACOS_SANDBOX,
        backend_digest=hashlib.sha256(b"backend").hexdigest(),
        policy_contract_digest=CONTAINMENT_POLICY_CONTRACT_DIGEST,
        daemon_fingerprint=fingerprint,
        runtime_fingerprint=fingerprint,
        probe_at=_NOW.isoformat(),
        probe_enforced=True,
    ).to_dict()


@dataclass(frozen=True)
class _Collected:
    """The request the runtime built, as the resident would have received it."""

    signals: Mapping[str, ProtectionSignal]
    harness_signals: Mapping[str, ProtectionSignal]

    def row(self, check_id: str) -> tuple[str, str]:
        signal = self.signals[check_id]
        return signal.status.value, signal.reason_code

    def harness(self, name: str) -> tuple[str, str]:
        signal = self.harness_signals[name]
        return signal.status.value, signal.reason_code

    def all_pass(self) -> bool:
        return all(signal.status is ProtectionCheckStatus.PASS for signal in self.signals.values())


@pytest.fixture
def collect(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Callable[..., _Collected]:
    """Collect the signals the runtime produced, without reaching a resident."""

    def _collect(
        *,
        installs: Sequence[Mapping[str, object]] | None = None,
        trust: Mapping[str, object] | None = None,
        dropped: int = 0,
        errors: int = 0,
        active_errors: int | None = None,
        activity_count: int = 1,
        runtime_state: Mapping[str, object] | None = None,
        hook_verification: Mapping[str, bool] | None = None,
    ) -> _Collected:
        recorded: dict[str, Mapping[str, ProtectionSignal]] = {}

        def _record(
            signals: Mapping[str, ProtectionSignal],
            *,
            harness_signals: Mapping[str, ProtectionSignal],
            guard_home: Path,
        ) -> dict[str, object]:
            recorded["signals"] = dict(signals)
            recorded["harness_signals"] = dict(harness_signals)
            return {}

        monkeypatch.setattr(protection_health_runtime, "protection_health_report", _record)
        if runtime_state is None:
            runtime_state = {
                "last_heartbeat_at": _NOW.isoformat(),
                "containment_health": _containment_evidence(),
            }
        protection_health_runtime.build_runtime_protection_health(
            store=_Store(
                count=activity_count,
                dropped=dropped,
                errors=errors,
                active_errors=(1 if dropped > 0 or errors > 0 else 0) if active_errors is None else active_errors,
            ),
            guard_home=tmp_path / "guard-home",
            runtime_state=runtime_state,
            managed_installs=list(installs or []),
            hook_verification=hook_verification,
            trust_status=trust or {},
            now=_NOW,
        )
        return _Collected(recorded["signals"], recorded["harness_signals"])

    return _collect


def test_every_check_the_report_needs_is_produced(collect: Callable[..., _Collected]) -> None:
    collected = collect(installs=[{"harness": "codex", "active": True}])
    assert set(collected.signals) == set(PROTECTION_CHECK_IDS)


def test_missing_positive_proofs_never_produce_an_all_passing_signal_set(
    collect: Callable[..., _Collected],
) -> None:
    for active, runtime_protection, remembered_rules, dropped, errors in itertools.product(
        (False, True),
        ("protected", "degraded", "unknown"),
        ("enforced", "disabled_degraded", "unknown"),
        (0, 1),
        (0, 1),
    ):
        collected = collect(
            installs=[{"harness": "codex", "active": active}],
            trust={"runtime_protection": runtime_protection, "remembered_rules": remembered_rules},
            dropped=dropped,
            errors=errors,
        )
        # Without every required proof the grammar can only call this degraded,
        # which `guard_protection_health_truth_table.rs` pins exhaustively.
        assert not collected.all_pass()


def test_repaired_live_state_ignores_historical_evidence_errors(
    collect: Callable[..., _Collected],
) -> None:
    collected = collect(
        installs=[{"harness": "codex", "active": True}],
        trust={"runtime_protection": "protected", "remembered_rules": "enforced"},
        dropped=12_338,
        errors=12_338,
        active_errors=0,
        activity_count=38_102,
        hook_verification={"codex": True},
    )
    assert collected.row("rule_packs")[0] == "pass"
    assert collected.row("decision_stream") == ("pass", "decision_stream_healthy")
    assert collected.row("tamper_checks")[0] == "pass"
    assert collected.all_pass()


def test_fresh_evidence_store_is_ready_before_first_command(
    collect: Callable[..., _Collected],
) -> None:
    collected = collect(
        installs=[{"harness": "codex", "active": True}],
        trust={"runtime_protection": "protected", "remembered_rules": "enforced"},
        active_errors=0,
        activity_count=0,
        hook_verification={"codex": True},
    )
    assert collected.row("decision_stream") == ("pass", "decision_stream_ready")
    assert collected.all_pass()


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


def test_signals_distinguish_failed_and_unproven_facts(
    collect: Callable[..., _Collected],
) -> None:
    active = collect(
        installs=[{"harness": "codex", "active": True}],
        trust={"runtime_protection": "protected", "remembered_rules": "enforced"},
    )
    assert active.row("daemon")[0] == "pass"
    assert active.row("harness_hooks") == ("unknown", "hook_attestation_unavailable")
    assert active.row("decision_plane_compatibility")[0] == "pass"
    assert active.row("sandbox")[0] == "pass"

    degraded = collect(
        installs=[{"harness": "codex", "active": False}],
        trust={"runtime_protection": "degraded", "remembered_rules": "disabled_degraded"},
        dropped=1,
    )
    assert degraded.row("harness_hooks") == ("fail", "no_managed_harness")
    assert degraded.row("tamper_checks")[0] == "fail"
    assert degraded.row("decision_stream")[0] == "fail"


def test_inactive_duplicate_rows_do_not_override_an_active_install(
    collect: Callable[..., _Collected],
) -> None:
    for installs in (
        [{"harness": "codex", "active": False}, {"harness": "codex", "active": True}],
        [{"harness": "codex", "active": True}, {"harness": "codex", "active": False}],
    ):
        collected = collect(installs=installs)
        assert list(collected.harness_signals) == ["codex"]
        assert collected.harness("codex") == ("unknown", "hook_attestation_unavailable")


def test_inactive_historical_rows_do_not_degrade_verified_active_hooks(
    collect: Callable[..., _Collected],
) -> None:
    collected = collect(
        installs=[
            {"harness": "pi", "active": False},
            {"harness": "cursor", "active": True},
        ],
        trust={"runtime_protection": "protected", "remembered_rules": "enforced"},
        hook_verification={"cursor": True},
    )

    assert list(collected.harness_signals) == ["cursor"]
    assert collected.harness("cursor") == ("pass", "hooks_verified")
    assert collected.all_pass()


def test_stale_or_invalid_runtime_rows_never_prove_daemon_health(
    collect: Callable[..., _Collected],
) -> None:
    stale = collect(runtime_state={"last_heartbeat_at": (_NOW - timedelta(seconds=31)).isoformat()})
    invalid = collect(runtime_state={"last_heartbeat_at": "not-a-time"})
    assert stale.row("daemon") == ("fail", "daemon_heartbeat_stale")
    assert invalid.row("daemon") == ("unknown", "daemon_heartbeat_invalid")


def test_harness_signals_carry_only_a_stable_identity(
    collect: Callable[..., _Collected],
) -> None:
    installs: list[dict[str, object]] = [
        {
            "harness": f"app-{index}",
            "active": True,
            "workspace": f"/private/workspace/{index}",
            "raw_command": f"secret-command-{index}",
        }
        for index in range(120)
    ]
    installs.append({"harness": "../../private", "active": True, "workspace": "/secret"})

    collected = collect(installs=installs)

    assert "../../private" not in collected.harness_signals
    serialized = repr(collected)
    assert "/private/" not in serialized
    assert "secret-command" not in serialized
    # How many of these the report may name is the native runtime's bound, and
    # `guard_protection_health_truth_table.rs` pins it at a hundred.
    assert len(collected.harness_signals) == 120


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
