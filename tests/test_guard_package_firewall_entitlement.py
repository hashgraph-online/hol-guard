"""Tests for package-firewall entitlement helpers."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import cast

import pytest

from codex_plugin_scanner.guard import package_firewall_entitlement as entitlement_module
from codex_plugin_scanner.guard.native_hook_artifact_compose import (
    NativeHookComposeError,
    NativeHookComposeValidationError,
)
from codex_plugin_scanner.guard.package_firewall_entitlement import (
    PACKAGE_FIREWALL_RUNTIME_UNAVAILABLE_REASON,
    build_oauth_package_firewall_entitlement,
    package_firewall_access,
    package_firewall_entitlement_or_denied,
    reconcile_connect_state_with_oauth_entitlement,
)
from codex_plugin_scanner.guard.store import GuardStore


def test_package_firewall_access_is_answered_by_the_resident(monkeypatch: pytest.MonkeyPatch) -> None:
    """One question carries the whole entitlement and returns every projection.

    Which actions a lapsed or unproven entitlement still leaves available is
    the resident's call now; the shared composition vectors own that table.
    A request that needs the action table, the offered actions, the block copy
    and one operation's verdict asks once, not once per projection.
    """

    asked: list[dict[str, object]] = []

    def answer(kind: str, fields: dict[str, object], *, guard_home: Path | None) -> dict[str, object]:
        asked.append({"kind": kind, "fields": dict(fields), "guard_home": guard_home})
        return {
            "action_states": {"repair": "available"},
            "available_actions": ["status", "repair"],
            "block": {"code": "paid_guard_cloud_required", "message": "Upgrade.", "status": 402},
            "operation_allowed": True,
        }

    monkeypatch.setattr(entitlement_module, "native_hook_compose", answer)
    entitlement = {"allowed": False, "reason": "guard_cloud_reconnect_required"}
    home = Path("/guard-home")

    access = package_firewall_access(
        entitlement,
        operation="repair",
        has_installed_managers=True,
        guard_home=home,
    )

    assert access.operation_allowed is True
    assert access.action_states == {"repair": "available"}
    assert access.available_actions == ["status", "repair"]
    assert access.block == (402, "paid_guard_cloud_required", "Upgrade.")

    assert [question["kind"] for question in asked] == ["package_firewall_access"]
    assert asked[0]["fields"] == {
        "entitlement": entitlement,
        "has_installed_managers": True,
        "operation": "repair",
    }
    assert asked[0]["guard_home"] == home


def test_package_firewall_access_without_an_operation_reads_only_the_projections(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A caller that names no operation still asks once and gets no verdict."""

    asked: list[dict[str, object]] = []

    def answer(kind: str, fields: dict[str, object], *, guard_home: Path | None) -> dict[str, object]:
        asked.append({"kind": kind, "fields": dict(fields), "guard_home": guard_home})
        return {
            "action_states": {"install": "paid_required"},
            "available_actions": ["status", "education", "cli_fallback"],
            "block": {"code": "paid_guard_cloud_required", "message": "Upgrade.", "status": 402},
            "operation_allowed": None,
        }

    monkeypatch.setattr(entitlement_module, "native_hook_compose", answer)

    access = package_firewall_access({"allowed": False, "reason": "paid_guard_cloud_required"})

    assert access.operation_allowed is False
    assert access.action_states == {"install": "paid_required"}
    assert [question["fields"]["operation"] for question in asked] == [None]


def test_an_unavailable_resident_does_not_decide_package_firewall_access(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def unavailable(kind: str, fields: dict[str, object], *, guard_home: Path | None) -> dict[str, object]:
        raise NativeHookComposeError("native_hook_artifact_compose_unavailable")

    monkeypatch.setattr(entitlement_module, "native_hook_compose", unavailable)

    with pytest.raises(NativeHookComposeError):
        package_firewall_access(
            {"allowed": True, "reason": "paid_entitlement_active"},
            operation="install",
            has_installed_managers=True,
        )


def test_build_oauth_package_firewall_entitlement_preserves_team_tier() -> None:
    entitlement = build_oauth_package_firewall_entitlement(
        {
            "guard_local_entitlement": {
                "plan_id": "team",
                "tier": "team",
                "supply_chain_firewall": True,
                "expires_at": "2026-06-30T00:00:00.000Z",
            }
        },
        now=datetime(2026, 5, 31, tzinfo=timezone.utc),
    )

    assert entitlement == {
        "plan_id": "team",
        "supply_chain_entitlement_expires_at": "2026-06-30T00:00:00.000Z",
        "supply_chain_firewall": True,
        "supply_chain_plan_id": "team",
    }


def test_build_oauth_package_firewall_entitlement_consumes_solo_plan_identity() -> None:
    entitlement = build_oauth_package_firewall_entitlement(
        {
            "guard_local_entitlement": {
                "plan_id": "solo",
                "tier": "solo",
                "supply_chain_firewall": False,
                "expires_at": "2026-09-07T00:00:00.000Z",
            }
        },
        now=datetime(2026, 8, 7, tzinfo=timezone.utc),
    )

    assert entitlement == {
        "plan_id": "solo",
        "supply_chain_entitlement_expires_at": "2026-09-07T00:00:00.000Z",
        "supply_chain_firewall": False,
        "supply_chain_plan_id": "solo",
    }


def test_build_oauth_package_firewall_entitlement_keeps_legacy_paid_alias_compatible() -> None:
    entitlement = build_oauth_package_firewall_entitlement(
        {
            "guard_local_entitlement": {
                "plan_id": "paid",
                "tier": "paid",
                "expires_at": "2026-09-07T00:00:00.000Z",
            }
        },
        now=datetime(2026, 8, 7, tzinfo=timezone.utc),
    )

    assert entitlement == {
        "plan_id": "paid",
        "supply_chain_entitlement_expires_at": "2026-09-07T00:00:00.000Z",
        "supply_chain_firewall": True,
        "supply_chain_plan_id": "paid",
    }


def test_reconcile_connect_state_clears_stale_sync_not_available_for_paid_oauth(
    tmp_path: Path,
) -> None:
    store = GuardStore(tmp_path / "guard-home")
    now = "2026-05-31T09:00:00.000Z"
    store.record_guard_connect_pairing_completed(
        sync_url="https://hol.org/api/guard/receipts/sync",
        allowed_origin="https://hol.org",
        now=now,
    )
    store.record_latest_guard_connect_sync_result(
        status="connected",
        milestone="sync_not_available",
        now=now,
        reason="Guard sync requires a Pro or Team plan.",
    )
    store.set_oauth_local_credentials(
        issuer="https://hol.org",
        client_id="guard-local-daemon",
        refresh_token="refresh-token",
        dpop_private_key_pem=(
            "-----BEGIN " + "PRIVATE KEY-----\nMC4CAQAwBQYDK2VuBCIEIA==\n-----END PRIVATE KEY-----\n"
        ),
        dpop_public_jwk={"kty": "OKP", "crv": "Ed25519", "x": "test"},
        dpop_public_jwk_thumbprint="thumbprint-1",
        supply_chain_plan_id="team",
        supply_chain_firewall=True,
        supply_chain_entitlement_expires_at="2026-06-30T00:00:00.000Z",
        workspace_id="workspace-1",
        now=now,
    )

    reconciled = reconcile_connect_state_with_oauth_entitlement(store, now=now)

    assert reconciled is not None
    assert reconciled.get("milestone") == "first_sync_pending"
    effective = store.get_effective_guard_connect_state(now=now)
    assert isinstance(effective, dict)
    assert effective.get("milestone") == "first_sync_pending"


def test_reconcile_connect_state_ignores_non_sync_not_available_milestones(
    tmp_path: Path,
) -> None:
    store = GuardStore(tmp_path / "guard-home")
    now = "2026-05-31T09:00:00.000Z"
    store.record_guard_connect_pairing_completed(
        sync_url="https://hol.org/api/guard/receipts/sync",
        allowed_origin="https://hol.org",
        now=now,
    )

    assert reconcile_connect_state_with_oauth_entitlement(store, now=now) is None


def test_reconcile_connect_state_ignores_missing_oauth_credentials(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    now = "2026-05-31T09:00:00.000Z"
    store.record_guard_connect_pairing_completed(
        sync_url="https://hol.org/api/guard/receipts/sync",
        allowed_origin="https://hol.org",
        now=now,
    )
    store.record_latest_guard_connect_sync_result(
        status="connected",
        milestone="sync_not_available",
        now=now,
        reason="Guard sync requires a Pro or Team plan.",
    )

    assert reconcile_connect_state_with_oauth_entitlement(store, now=now) is None


def test_reconcile_connect_state_ignores_free_oauth_plan(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    now = "2026-05-31T09:00:00.000Z"
    store.record_guard_connect_pairing_completed(
        sync_url="https://hol.org/api/guard/receipts/sync",
        allowed_origin="https://hol.org",
        now=now,
    )
    store.record_latest_guard_connect_sync_result(
        status="connected",
        milestone="sync_not_available",
        now=now,
        reason="Guard sync requires a Pro or Team plan.",
    )
    store.set_oauth_local_credentials(
        issuer="https://hol.org",
        client_id="guard-local-daemon",
        refresh_token="refresh-token",
        dpop_private_key_pem=(
            "-----BEGIN " + "PRIVATE KEY-----\nMC4CAQAwBQYDK2VuBCIEIA==\n-----END PRIVATE KEY-----\n"
        ),
        dpop_public_jwk={"kty": "OKP", "crv": "Ed25519", "x": "test"},
        dpop_public_jwk_thumbprint="thumbprint-1",
        supply_chain_plan_id="free",
        supply_chain_firewall=False,
        supply_chain_entitlement_expires_at="2026-06-30T00:00:00.000Z",
        workspace_id="workspace-1",
        now=now,
    )

    assert reconcile_connect_state_with_oauth_entitlement(store, now=now) is None


def test_the_cli_block_payload_fails_closed_when_the_resident_cannot_compose(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The CLI answers `unavailable` rather than raising out of the command.

    Nothing is offered in that reply: the composition is the authority, so a
    request it could not answer is refused instead of being rebuilt from the
    entitlement dict.
    """

    from codex_plugin_scanner.guard.cli.commands_support_workspace import _package_firewall_block_payload

    def unavailable(kind: str, fields: dict[str, object], *, guard_home: Path | None) -> dict[str, object]:
        raise NativeHookComposeError("native_hook_artifact_compose_unavailable")

    monkeypatch.setattr(entitlement_module, "native_hook_compose", unavailable)

    status, payload = _package_firewall_block_payload(
        entitlement={"allowed": False, "reason": "paid_guard_cloud_required"},
        has_installed_managers=True,
        operation="install",
    )

    assert status == 503
    assert payload["error"] == "package_firewall_authority_unavailable"
    assert payload["operation"] == "install"
    assert payload["available_actions"] == []


@pytest.mark.parametrize("error", [NativeHookComposeError("unavailable"), NativeHookComposeValidationError("bad")])
def test_a_runtime_that_cannot_answer_entitles_nothing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    error: Exception,
) -> None:
    """A gating caller reads a denial, never an allow it worked out itself."""

    class _Rows:
        """The rows the question is built from, with no runtime behind them."""

        guard_home = str(tmp_path)

        def get_sync_payload(self, name: str) -> None:
            return None

        def get_effective_guard_connect_state(self, *, now: str) -> None:
            return None

        def get_cloud_sync_profile(self) -> None:
            return None

        def get_oauth_local_credential_health(self) -> None:
            return None

    def refuse(*args: object, **kwargs: object) -> dict[str, object]:
        raise error

    monkeypatch.setattr(entitlement_module, "native_hook_compose", refuse)
    entitlement = package_firewall_entitlement_or_denied(cast("GuardStore", _Rows()))

    assert entitlement["allowed"] is False
    assert entitlement["reason"] == PACKAGE_FIREWALL_RUNTIME_UNAVAILABLE_REASON
