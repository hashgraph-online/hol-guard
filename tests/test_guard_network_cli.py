from __future__ import annotations

import argparse
from collections.abc import Callable
from dataclasses import replace
from pathlib import Path
from typing import cast

import pytest

from codex_plugin_scanner.guard.cli import commands_dispatch_local, network_status_command
from codex_plugin_scanner.guard.cli.commands_parser import add_guard_parser
from codex_plugin_scanner.guard.config import GuardConfig
from codex_plugin_scanner.guard.daemon.client import (
    GuardDaemonRequestError,
    GuardDaemonResponseSchemaError,
    GuardDaemonTimeoutError,
    GuardDaemonTransportError,
)
from codex_plugin_scanner.guard.daemon.server import GuardDaemonServer
from codex_plugin_scanner.guard.runtime.network_capability_contract import default_platform_profiles
from codex_plugin_scanner.guard.runtime.network_policy_contract import EnforcementGrade
from codex_plugin_scanner.guard.runtime.network_status import (
    NetworkStatusSchemaError,
    build_network_status,
    validate_network_status,
)
from codex_plugin_scanner.guard.runtime.network_supervisor import NetworkSupervisor, NetworkSupervisorHealth
from codex_plugin_scanner.guard.runtime.provider_recovery import RecoveryPhase
from codex_plugin_scanner.guard.store import GuardStore


def _parse(arguments: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command")
    add_guard_parser(subparsers)
    return parser.parse_args(arguments)


def _run_network_status(
    monkeypatch: pytest.MonkeyPatch,
    *,
    response: dict[str, object] | None = None,
    error: Exception | None = None,
) -> dict[str, object]:
    emitted: list[tuple[str, object, bool]] = []

    class Client:
        def network_status(self) -> dict[str, object]:
            if error is not None:
                raise error
            assert response is not None
            return response

    def load_client(_guard_home: Path, *, identity_timeout: float) -> Client:
        assert identity_timeout == 0.05
        return Client()

    monkeypatch.setattr(
        commands_dispatch_local,
        "_emit",
        lambda title, payload, as_json: emitted.append((title, payload, as_json)),
        raising=False,
    )
    monkeypatch.setattr(
        network_status_command,
        "load_running_guard_surface_daemon_client",
        load_client,
    )
    args = _parse(["guard", "network", "status", "--json"])

    result = commands_dispatch_local._run_guard_network_command(
        args,
        guard_home=Path("/guard-home"),
        config=GuardConfig(
            guard_home=Path("/guard-home"),
            workspace=None,
            new_network_domain_action="block",
        ),
    )

    assert result == 0
    title, raw_payload, as_json = emitted.pop()
    assert title == "network"
    assert as_json is True
    assert isinstance(raw_payload, dict)
    return raw_payload


def test_network_status_uses_authenticated_daemon_truth(monkeypatch: pytest.MonkeyPatch) -> None:
    daemon_status = build_network_status(platform_name="darwin")
    payload = _run_network_status(monkeypatch, response=daemon_status)

    assert payload["schema"] == "guard.network-status.v1"
    assert payload["status_source"] == "daemon"
    backends = cast(list[dict[str, object]], payload["backends"])
    assert tuple(item["backend_id"] for item in backends) == ("macos.observe",)
    assert all(item["production_ready"] is False for item in backends)
    assert payload["legacy_domain_policy"] == {"action": "deny", "sandbox_required": False}


def test_network_status_reads_live_authenticated_daemon(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    guard_home = tmp_path / "guard-home"
    daemon = GuardDaemonServer(GuardStore(guard_home), host="127.0.0.1", port=0)
    emitted: list[dict[str, object]] = []
    monkeypatch.setattr(
        commands_dispatch_local,
        "_emit",
        lambda _title, payload, _as_json: emitted.append(cast(dict[str, object], payload)),
        raising=False,
    )
    daemon.start()
    try:
        result = commands_dispatch_local._run_guard_network_command(
            _parse(["guard", "network", "status", "--json"]),
            guard_home=guard_home,
            config=GuardConfig(
                guard_home=guard_home,
                workspace=None,
                new_network_domain_action="review",
            ),
        )
    finally:
        daemon.stop()

    assert result == 0
    assert emitted[0]["status_source"] == "daemon"
    assert emitted[0]["reason_code"] == "no-verified-installed-backend"
    assert emitted[0]["legacy_domain_policy"] == {
        "action": "approve",
        "sandbox_required": False,
    }


@pytest.mark.parametrize(
    ("error", "reason_code"),
    (
        (GuardDaemonTimeoutError("private timeout detail"), "daemon-timeout"),
        (GuardDaemonTransportError("private socket detail"), "daemon-transport-unavailable"),
        (GuardDaemonResponseSchemaError("private JSON detail"), "daemon-schema-invalid"),
        (
            GuardDaemonRequestError("private auth detail", status=401),
            "daemon-authentication-failed",
        ),
        (GuardDaemonRequestError("private request detail", status=500), "daemon-request-failed"),
    ),
)
def test_network_status_failure_is_privacy_safe_and_never_claims_static_protection(
    monkeypatch: pytest.MonkeyPatch,
    error: Exception,
    reason_code: str,
) -> None:
    payload = _run_network_status(monkeypatch, error=error)

    assert payload["status_source"] == "fallback"
    assert payload["reason_code"] == reason_code
    assert payload["effective_grade"] == "unavailable"
    assert payload["protection_active"] is False
    assert payload["backends"] == []
    assert payload["legacy_domain_policy"] == {"action": "deny", "sandbox_required": False}
    assert "private" not in str(payload)


def test_network_status_rejects_inconsistent_daemon_protection(monkeypatch: pytest.MonkeyPatch) -> None:
    daemon_status = build_network_status(platform_name="darwin")
    daemon_status["protection_active"] = True

    payload = _run_network_status(monkeypatch, response=daemon_status)

    assert payload["status_source"] == "fallback"
    assert payload["reason_code"] == "daemon-schema-invalid"
    assert payload["backends"] == []


@pytest.mark.parametrize(
    "mutate",
    (
        lambda payload: payload.update(effective_grade="invented-grade"),
        lambda payload: cast(list[dict[str, object]], payload["backends"])[0].update(
            verified=True,
            installed=False,
        ),
        lambda payload: cast(dict[str, object], payload["supervisor"]).update(phase="invented-phase"),
        lambda payload: cast(dict[str, object], payload["supervisor"]).update(permits_enforcement=True),
    ),
)
def test_network_status_validator_rejects_enum_nested_and_invariant_corruption(
    mutate: Callable[[dict[str, object]], None],
) -> None:
    status = build_network_status(
        platform_name="darwin",
        supervisor_health=NetworkSupervisor().health(now_epoch_ms=1),
    )
    mutate(status)

    with pytest.raises(NetworkStatusSchemaError):
        validate_network_status(status)


def test_network_status_validator_projects_only_privacy_safe_v1_fields() -> None:
    status = build_network_status(
        platform_name="darwin",
        legacy_domain_action="warn",
        supervisor_health=NetworkSupervisor().health(now_epoch_ms=1),
    )
    status["secret_token"] = "must-not-escape"
    cast(list[dict[str, object]], status["backends"])[0]["local_path"] = "/private/user"
    cast(dict[str, object], status["supervisor"])["raw_error"] = "private failure"
    cast(dict[str, object], status["legacy_domain_policy"])["private_note"] = "private policy"

    projected = validate_network_status(status)

    assert "must-not-escape" not in str(projected)
    assert "/private/user" not in str(projected)
    assert "private failure" not in str(projected)
    assert "private policy" not in str(projected)
    assert projected["legacy_domain_policy"] == {
        "action": "approve",
        "sandbox_required": False,
    }


@pytest.mark.parametrize(
    "legacy_policy",
    (
        {"action": "invented", "sandbox_required": False},
        {"action": "approve", "sandbox_required": "false"},
        "approve",
    ),
)
def test_malformed_daemon_legacy_policy_fails_safe(
    monkeypatch: pytest.MonkeyPatch,
    legacy_policy: object,
) -> None:
    status = build_network_status(platform_name="darwin")
    status["legacy_domain_policy"] = legacy_policy

    payload = _run_network_status(monkeypatch, response=status)

    assert payload["status_source"] == "fallback"
    assert payload["reason_code"] == "daemon-schema-invalid"
    assert payload["backends"] == []
    assert payload["legacy_domain_policy"] == {"action": "deny", "sandbox_required": False}


def test_sensitive_reason_text_is_rejected_instead_of_forwarded(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    status = build_network_status(platform_name="darwin")
    status["reason_code"] = "token: private-value"

    payload = _run_network_status(monkeypatch, response=status)

    assert payload["reason_code"] == "daemon-schema-invalid"
    assert "private-value" not in str(payload)


def _active_network_status(*, production_ready: bool) -> dict[str, object]:
    status = build_network_status(platform_name="linux")
    backend = cast(list[dict[str, object]], status["backends"])[0]
    backend.update(
        installed=True,
        verified=True,
        active=True,
        production_ready=production_ready,
        effective_grade="proxy-only",
    )
    status.update(
        effective_grade="proxy-only",
        protection_active=True,
        supervisor={
            "phase": "healthy",
            "backend_id": backend["backend_id"],
            "backend_digest": "a" * 64,
            "effective_grade": "proxy-only",
            "healthy_until_epoch_ms": 2_000_000_000_000,
            "retry_attempt": 0,
            "next_retry_seconds": 0.0,
            "permits_enforcement": True,
            "independently_observed": False,
        },
    )
    return status


def test_non_production_backend_can_never_claim_active_protection() -> None:
    with pytest.raises(NetworkStatusSchemaError, match="production ready"):
        validate_network_status(_active_network_status(production_ready=False))


def test_effective_grade_cannot_exceed_advertised_maximum() -> None:
    status = _active_network_status(production_ready=True)
    backend = cast(list[dict[str, object]], status["backends"])[0]
    backend["effective_grade"] = "destination-enforced"
    status["effective_grade"] = "destination-enforced"
    cast(dict[str, object], status["supervisor"])["effective_grade"] = "destination-enforced"

    with pytest.raises(NetworkStatusSchemaError, match="advertised grade"):
        validate_network_status(status)


def test_zero_production_ready_backends_remain_truthfully_inactive() -> None:
    projected = validate_network_status(build_network_status(platform_name="darwin"))

    assert projected["protection_active"] is False
    assert projected["effective_grade"] == "unavailable"
    assert all(backend["production_ready"] is False for backend in cast(list[dict[str, object]], projected["backends"]))


@pytest.mark.parametrize(("production_ready", "expected_active"), ((False, False), (True, True)))
def test_producer_and_validator_agree_on_backend_readiness(
    production_ready: bool,
    expected_active: bool,
) -> None:
    profile = replace(default_platform_profiles()[0], production_ready=production_ready)
    health = NetworkSupervisorHealth(
        phase=RecoveryPhase.HEALTHY,
        backend_id=profile.backend_id,
        backend_digest="a" * 64,
        effective_grade=profile.maximum_grade,
        healthy_until_epoch_ms=4_000_000_000_000,
        retry_attempt=0,
        next_retry_seconds=0.0,
    )

    projected = validate_network_status(
        build_network_status(profiles=(profile,), supervisor_health=health, platform_name="linux")
    )

    assert projected["protection_active"] is expected_active
    assert projected["effective_grade"] == (profile.maximum_grade.value if expected_active else "unavailable")


def test_backend_health_above_profile_maximum_fails_closed() -> None:
    profile = replace(default_platform_profiles()[0], production_ready=True)
    health = NetworkSupervisorHealth(
        phase=RecoveryPhase.HEALTHY,
        backend_id=profile.backend_id,
        backend_digest="a" * 64,
        effective_grade=EnforcementGrade.DESTINATION_ENFORCED,
        healthy_until_epoch_ms=4_000_000_000_000,
        retry_attempt=0,
        next_retry_seconds=0.0,
    )

    projected = validate_network_status(
        build_network_status(profiles=(profile,), supervisor_health=health, platform_name="linux")
    )

    assert projected["protection_active"] is False
    assert projected["effective_grade"] == "unavailable"


@pytest.mark.parametrize(
    "supervisor_update",
    (
        {"backend_digest": None},
        {"healthy_until_epoch_ms": 999},
        {"next_retry_seconds": float("nan")},
        {"next_retry_seconds": float("inf")},
        {"independently_observed": True},
    ),
)
def test_active_network_status_requires_fresh_consistent_supervisor_proof(
    supervisor_update: dict[str, object],
) -> None:
    status = _active_network_status(production_ready=True)
    cast(dict[str, object], status["supervisor"]).update(supervisor_update)

    with pytest.raises(NetworkStatusSchemaError):
        validate_network_status(status, now_epoch_ms=1_000)


def test_inactive_backend_cannot_claim_an_enforcing_grade() -> None:
    status = build_network_status(platform_name="linux")
    backend = cast(list[dict[str, object]], status["backends"])[0]
    backend["effective_grade"] = "proxy-only"

    with pytest.raises(NetworkStatusSchemaError, match=r"inactive.*cannot enforce"):
        validate_network_status(status)


def test_observed_grade_must_match_observed_backend_truth() -> None:
    status = build_network_status(platform_name="linux")
    backend = cast(list[dict[str, object]], status["backends"])[0]
    backend.update(observed=True, effective_grade="observe")
    status.update(independently_observed=True, independently_observed_grade="destination-enforced")

    with pytest.raises(NetworkStatusSchemaError, match="observer grade"):
        validate_network_status(status)


def test_consistent_observe_only_backend_is_accepted() -> None:
    status = build_network_status(platform_name="linux")
    backend = cast(list[dict[str, object]], status["backends"])[0]
    backend.update(observed=True, effective_grade="observe")
    status.update(independently_observed=True, independently_observed_grade="observe")

    projected = validate_network_status(status)

    assert projected["independently_observed_grade"] == "observe"


def test_partial_supervisor_fails_safe_before_projection() -> None:
    status = _active_network_status(production_ready=True)
    cast(dict[str, object], status["supervisor"]).pop("backend_id")

    with pytest.raises(NetworkStatusSchemaError, match="incomplete"):
        validate_network_status(status)


def test_one_supervisor_cannot_prove_multiple_active_backends() -> None:
    status = _active_network_status(production_ready=True)
    first = cast(list[dict[str, object]], status["backends"])[0]
    second = dict(first)
    second["backend_id"] = "linux.secondary"
    cast(list[dict[str, object]], status["backends"]).append(second)

    with pytest.raises(NetworkStatusSchemaError, match="one active backend"):
        validate_network_status(status)


def test_network_parser_defaults_to_status(monkeypatch: pytest.MonkeyPatch) -> None:
    emitted: list[tuple[str, object, bool]] = []
    monkeypatch.setattr(
        commands_dispatch_local,
        "_emit",
        lambda title, payload, as_json: emitted.append((title, payload, as_json)),
        raising=False,
    )
    args = _parse(["guard", "network", "--json"])

    assert commands_dispatch_local._run_guard_network_command(args) == 0
    assert emitted[0][0] == "network"
