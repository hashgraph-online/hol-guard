from __future__ import annotations

from types import SimpleNamespace

from codex_plugin_scanner.guard.cli.commands_dispatch_desktop import (
    _presentation_projection,
    build_desktop_bootstrap_payload,
)
from codex_plugin_scanner.guard.config import update_guard_settings
from codex_plugin_scanner.guard.presentation_mode import resolve_presentation_mode


def test_desktop_bootstrap_old_core_fallback_is_everyday_and_not_writable() -> None:
    payload = build_desktop_bootstrap_payload(
        status_payload={"runtime_status": "offline", "managed_harnesses": 0, "harnesses": []},
        pending_requests=[],
        approval_history=[],
        receipts=[],
        core_version="3.2.0",
    )
    assert payload["presentation"] == {
        "mode": "everyday",
        "source": "default",
        "explicit": False,
        "canWrite": False,
        "schemaVersion": 1,
        "revision": 0,
        "diagnostic": "presentation_not_supported_by_core",
    }


def test_desktop_projection_is_core_authoritative() -> None:
    config = SimpleNamespace(
        presentation_mode="technical",
        presentation_mode_explicit=True,
        presentation_schema_version=1,
        presentation_revision=7,
    )
    assert _presentation_projection(config) == {
        "mode": "technical",
        "source": "local-explicit",
        "explicit": True,
        "canWrite": True,
        "schemaVersion": 1,
        "revision": 7,
        "diagnostic": None,
    }


def test_explicit_presentation_preference_can_be_cleared_without_revision_drift(tmp_path) -> None:
    guard_home = tmp_path / "guard"
    guard_home.mkdir()
    first = update_guard_settings(guard_home, {"presentation_mode": "technical"}, skip_approval_gate=True)
    assert first.presentation_mode_explicit is True
    cleared = update_guard_settings(
        guard_home,
        {"presentation_mode_explicit": False, "presentation_revision": first.presentation_revision},
        skip_approval_gate=True,
    )
    assert cleared.presentation_mode == "technical"
    assert cleared.presentation_mode_explicit is False
    assert cleared.presentation_revision == first.presentation_revision + 1
    no_op = update_guard_settings(
        guard_home,
        {"presentation_mode_explicit": False, "presentation_revision": cleared.presentation_revision},
        skip_approval_gate=True,
    )
    assert no_op.presentation_revision == cleared.presentation_revision


def test_invalid_local_value_and_cloud_profile_keep_core_dashboard_parity() -> None:
    resolved = resolve_presentation_mode(local_value="future", local_explicit=False, cloud_profile="technical")
    assert resolved.value == "technical"
    assert resolved.source == "cloud-profile"
    assert resolved.diagnostic == "unknown_presentation_mode_fell_back_to_everyday"
