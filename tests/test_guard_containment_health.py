from __future__ import annotations

import hashlib
from collections.abc import Mapping
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import cast

import pytest

import codex_plugin_scanner.guard.native_execution as native_execution
import codex_plugin_scanner.guard.runtime.containment_health as containment_health_module
from codex_plugin_scanner.guard.runtime import protection_health_runtime
from codex_plugin_scanner.guard.runtime.containment_contract import ContainmentBackend
from codex_plugin_scanner.guard.runtime.containment_health import (
    CONTAINMENT_POLICY_CONTRACT_DIGEST,
    ContainmentHealthEvidence,
    containment_health_signals,
    probe_containment_health,
)
from codex_plugin_scanner.guard.runtime.protection_health import ProtectionSignal

_NOW = datetime(2026, 7, 19, 15, 0, tzinfo=timezone.utc)


class _Health:
    dropped_event_count: int = 0
    persistence_error_count: int = 0


class _Store:
    def count_command_activities(self) -> int:
        return 1

    def get_command_activity_persistence_health(self) -> _Health:
        return _Health()


def _evidence(**overrides: object) -> ContainmentHealthEvidence:
    digest = hashlib.sha256(b"stable").hexdigest()
    values: dict[str, object] = {
        "backend": ContainmentBackend.MACOS_SANDBOX,
        "backend_digest": hashlib.sha256(b"backend").hexdigest(),
        "policy_contract_digest": CONTAINMENT_POLICY_CONTRACT_DIGEST,
        "daemon_fingerprint": digest,
        "runtime_fingerprint": digest,
        "probe_at": _NOW.isoformat(),
        "probe_enforced": True,
    }
    values.update(overrides)
    return ContainmentHealthEvidence(
        backend=cast(ContainmentBackend, values["backend"]),
        backend_digest=cast(str, values["backend_digest"]),
        policy_contract_digest=cast(str, values["policy_contract_digest"]),
        daemon_fingerprint=cast(str, values["daemon_fingerprint"]),
        runtime_fingerprint=cast(str, values["runtime_fingerprint"]),
        probe_at=cast(str, values["probe_at"]),
        probe_enforced=cast(bool, values["probe_enforced"]),
    )


def _runtime_signals(evidence: object) -> dict[str, ProtectionSignal]:
    """The signals the runtime produced for this evidence.

    Whether they add up to a protected machine is the native runtime's answer,
    pinned in `rust/crates/guard-command/tests/`, so the transport is stood in
    for here rather than evaluated a second time.
    """

    recorded: dict[str, ProtectionSignal] = {}

    def _record(
        signals: Mapping[str, ProtectionSignal],
        *,
        harness_signals: Mapping[str, ProtectionSignal],
        guard_home: Path,
    ) -> dict[str, object]:
        recorded.update(signals)
        return {}

    original = protection_health_runtime.protection_health_report
    protection_health_runtime.protection_health_report = _record
    try:
        protection_health_runtime.build_runtime_protection_health(
            store=_Store(),
            # Never read: the resident the path would reach is stood in for.
            guard_home=Path("guard-home"),
            runtime_state={"last_heartbeat_at": _NOW.isoformat(), "containment_health": evidence},
            managed_installs=[{"harness": "codex", "active": True}],
            trust_status={},
            now=_NOW,
        )
    finally:
        protection_health_runtime.protection_health_report = original
    return recorded


def test_compatible_health_proves_only_the_containment_owned_checks() -> None:
    evidence = _evidence()
    signals = containment_health_signals(evidence.to_dict(), now=_NOW)

    assert set(signals) == {
        "policy_engine",
        "decision_plane_compatibility",
        "containment_compatibility",
        "sandbox",
    }
    assert all(signal.status.value == "pass" for signal in signals.values())

    produced = _runtime_signals(evidence.to_dict())
    assert produced["daemon"].status.value == "pass"
    assert produced["containment_compatibility"].status.value == "pass"
    assert produced["sandbox"].reason_code == "containment_backend_enforced"
    # No managed hook is attested here, so the grammar cannot call this
    # protected; `guard_protection_health_truth_table.rs` pins that.
    assert produced["harness_hooks"].status.value != "pass"


def test_unsupported_platform_probe_returns_explicit_fail_closed_health(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    daemon_fingerprint = hashlib.sha256(b"windows-daemon").hexdigest()
    monkeypatch.setattr(containment_health_module.sys, "platform", "win32")

    evidence = probe_containment_health(
        daemon_fingerprint=daemon_fingerprint,
        guard_home=tmp_path / "guard-home",
    )
    signals = containment_health_signals(evidence.to_dict(), now=datetime.now(timezone.utc))

    assert evidence.backend is ContainmentBackend.UNSUPPORTED
    assert evidence.backend_digest == hashlib.sha256(b"unavailable:unsupported").hexdigest()
    assert evidence.probe_enforced is False
    assert {signal.reason_code for signal in signals.values()} == {"unsupported_platform"}


def test_unsupported_reason_takes_precedence_over_probe_failure() -> None:
    evidence = _evidence(backend=ContainmentBackend.UNSUPPORTED, probe_enforced=False)

    signals = containment_health_signals(evidence.to_dict(), now=_NOW)

    assert {signal.reason_code for signal in signals.values()} == {"unsupported_platform"}


@pytest.mark.parametrize(
    ("overrides", "reason"),
    (
        ({"backend": ContainmentBackend.UNSUPPORTED}, "unsupported_platform"),
        ({"probe_enforced": False}, "containment_probe_failed"),
        ({"probe_at": (_NOW - timedelta(minutes=6)).isoformat()}, "containment_probe_stale"),
        ({"probe_at": (_NOW + timedelta(seconds=6)).isoformat()}, "containment_probe_future"),
        ({"policy_contract_digest": hashlib.sha256(b"other").hexdigest()}, "policy_version_mismatch"),
        ({"runtime_fingerprint": hashlib.sha256(b"drift").hexdigest()}, "daemon_runtime_drift"),
    ),
)
def test_faults_fail_closed_and_surface_degraded(
    overrides: dict[str, object],
    reason: str,
) -> None:
    evidence = _evidence(**overrides)
    signals = containment_health_signals(evidence.to_dict(), now=_NOW)
    produced = _runtime_signals(evidence.to_dict())

    assert all(signal.status.value == "fail" for signal in signals.values())
    assert {signal.reason_code for signal in signals.values()} == {reason}
    # Each containment check reaches the report as the failure it is.
    for check_id, signal in signals.items():
        assert produced[check_id] == signal


def test_daemon_drift_has_an_explicit_daemon_failure() -> None:
    evidence = _evidence(runtime_fingerprint=hashlib.sha256(b"drift").hexdigest())
    daemon = _runtime_signals(evidence.to_dict())["daemon"]

    assert (daemon.status.value, daemon.reason_code) == ("fail", "daemon_runtime_drift")


def test_missing_or_malformed_health_is_blocking_not_unknown() -> None:
    for value in (None, {}, {"schema_version": "future"}, ["not", "a", "mapping"]):
        signals = containment_health_signals(value, now=_NOW)
        assert all(signal.status.value == "fail" for signal in signals.values())


def test_health_mapping_is_strict_and_privacy_safe(tmp_path: Path) -> None:
    evidence = _evidence()
    serialized = repr(evidence.to_dict())
    assert str(tmp_path) not in serialized
    with pytest.raises(ValueError, match="fields"):
        _ = ContainmentHealthEvidence.from_mapping({**evidence.to_dict(), "raw_command": "secret"})


def test_probe_consumes_resident_evidence_without_recomputing_it(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    daemon_fingerprint = hashlib.sha256(b"resident-daemon").hexdigest()
    payload = _evidence(
        backend=ContainmentBackend.LINUX_BWRAP,
        probe_enforced=True,
        daemon_fingerprint=daemon_fingerprint,
        runtime_fingerprint=daemon_fingerprint,
    ).to_dict()
    seen: dict[str, object] = {}

    def fake_probe(*, daemon_fingerprint: str, guard_home: Path) -> dict[str, object]:
        seen["daemon_fingerprint"] = daemon_fingerprint
        seen["guard_home"] = guard_home
        return payload

    monkeypatch.setattr(native_execution, "containment_health_probe_native", fake_probe)

    evidence = probe_containment_health(
        daemon_fingerprint=daemon_fingerprint,
        guard_home=tmp_path / "guard-home",
    )

    assert seen == {
        "daemon_fingerprint": daemon_fingerprint,
        "guard_home": tmp_path / "guard-home",
    }
    assert evidence.to_dict() == payload


def test_probe_fails_closed_when_the_resident_cannot_answer(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setattr(
        native_execution,
        "containment_health_probe_native",
        lambda **_kwargs: None,
    )

    with pytest.raises(RuntimeError, match="native_containment_health_probe_unavailable"):
        _ = probe_containment_health(
            daemon_fingerprint=hashlib.sha256(b"no-resident").hexdigest(),
            guard_home=tmp_path / "guard-home",
        )
