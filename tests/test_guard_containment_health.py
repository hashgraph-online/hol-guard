from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from pathlib import Path
from typing import cast

import pytest

import codex_plugin_scanner.guard.native_execution as native_execution
import codex_plugin_scanner.guard.native_protection_health as native_protection_health
import codex_plugin_scanner.guard.runtime.containment_health as containment_health_module
from codex_plugin_scanner.guard.runtime.containment_contract import ContainmentBackend
from codex_plugin_scanner.guard.runtime.containment_health import (
    CONTAINMENT_POLICY_CONTRACT_DIGEST,
    ContainmentHealthEvidence,
    containment_health_signals,
    probe_containment_health,
)
from codex_plugin_scanner.guard.runtime.protection_health import ProtectionCheckStatus, ProtectionSignal

_NOW = datetime(2026, 7, 19, 15, 0, tzinfo=timezone.utc)


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

    assert evidence.backend is ContainmentBackend.UNSUPPORTED
    assert evidence.backend_digest == hashlib.sha256(b"unavailable:unsupported").hexdigest()
    assert evidence.probe_enforced is False
    # What unsupported evidence proves is the resident's, pinned in
    # `guard_command::protection_health_facts`.


def test_containment_signals_are_the_resident_report_rows(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    sent: list[dict[str, object]] = []

    def report(facts: dict[str, object], *, guard_home: Path) -> dict[str, object]:
        sent.append({**facts, "guard_home": guard_home})
        return {
            "checks": [
                {"check_id": "harness_hooks", "status": "fail", "reason_code": "no_managed_harness"},
                {"check_id": "daemon", "status": "unknown", "reason_code": "daemon_heartbeat_unavailable"},
                {"check_id": "policy_engine", "status": "pass", "reason_code": "policy_engine_compatible"},
                {"check_id": "sandbox", "status": "fail", "reason_code": "containment_probe_failed"},
            ]
        }

    monkeypatch.setattr(native_protection_health, "protection_health_report", report)
    evidence = _evidence().to_dict()

    signals = containment_health_signals(evidence, now=_NOW, guard_home=tmp_path)

    assert signals == {
        "policy_engine": ProtectionSignal(ProtectionCheckStatus.PASS, "policy_engine_compatible"),
        "sandbox": ProtectionSignal(ProtectionCheckStatus.FAIL, "containment_probe_failed"),
    }
    assert sent == [
        {
            "now": _NOW.isoformat(),
            "managed_installs": [],
            "hook_verification": None,
            "daemon": {"registration_status": None, "last_heartbeat_at": None, "containment_health": evidence},
            "remembered_rules": None,
            "runtime_protection": None,
            "decision_stream": None,
            "guard_home": tmp_path,
        }
    ]


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
