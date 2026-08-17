"""Protection posture load, dual-write, and known-bad auto-stop."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path

from codex_plugin_scanner.guard.config import (
    load_guard_config,
    resolve_risk_action,
    update_guard_settings,
)
from codex_plugin_scanner.guard.protection_posture import (
    apply_posture_confidence,
    derive_protection_posture,
    dual_write_from_posture,
)


def _write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def test_implicit_legacy_config_keeps_balanced_maps(tmp_path: Path) -> None:
    guard_home = tmp_path / ".hol-guard"
    _write_text(guard_home / "config.toml", 'mode = "prompt"\nsecurity_level = "balanced"\n')
    config = load_guard_config(guard_home)
    assert config.protection_posture == "protected"
    assert config.protection_posture_explicit is False
    assert resolve_risk_action(config, "network_egress", harness="codex") == "warn"
    assert resolve_risk_action(config, "package_script", harness="codex") == "warn"
    assert resolve_risk_action(config, "credential_exfiltration", harness="codex") == "require-reapproval"


def test_observe_mode_derives_watch(tmp_path: Path) -> None:
    guard_home = tmp_path / ".hol-guard"
    _write_text(guard_home / "config.toml", 'mode = "observe"\nsecurity_level = "balanced"\n')
    config = load_guard_config(guard_home)
    assert config.protection_posture == "watch"
    assert config.protection_posture_explicit is False
    assert resolve_risk_action(config, "network_egress", harness="codex") == "warn"


def test_strict_derives_extra_careful(tmp_path: Path) -> None:
    guard_home = tmp_path / ".hol-guard"
    _write_text(guard_home / "config.toml", 'mode = "enforce"\nsecurity_level = "strict"\n')
    config = load_guard_config(guard_home)
    assert config.protection_posture == "extra_careful"
    assert config.protection_posture_explicit is False
    assert resolve_risk_action(config, "network_egress", harness="codex") == "require-reapproval"


def test_full_settings_blob_with_explicit_flag_persists_protected(tmp_path: Path) -> None:
    guard_home = tmp_path / ".hol-guard"
    loaded = update_guard_settings(
        guard_home,
        {
            "mode": "prompt",
            "security_level": "balanced",
            "protection_posture": "protected",
            "protection_posture_explicit": True,
        },
    )
    assert loaded.protection_posture_explicit is True
    assert resolve_risk_action(loaded, "network_egress", harness="codex") == "allow"


def test_explicit_protected_uses_posture_maps(tmp_path: Path) -> None:
    guard_home = tmp_path / ".hol-guard"
    updated = update_guard_settings(guard_home, {"protection_posture": "protected"})
    loaded = load_guard_config(guard_home)
    config_text = (guard_home / "config.toml").read_text(encoding="utf-8")
    assert updated.protection_posture == "protected"
    assert updated.protection_posture_explicit is True
    assert updated.mode == "enforce"
    assert updated.security_level == "balanced"
    assert loaded.protection_posture == "protected"
    assert 'protection_posture = "protected"' in config_text
    assert 'mode = "enforce"' in config_text
    assert resolve_risk_action(loaded, "network_egress", harness="codex") == "allow"
    assert resolve_risk_action(loaded, "package_script", harness="codex") == "require-reapproval"
    assert resolve_risk_action(loaded, "guard_bypass", harness="codex") == "block"
    assert resolve_risk_action(loaded, "encoded_exfiltration", harness="codex") == "block"


def test_explicit_extra_careful_asks_for_network(tmp_path: Path) -> None:
    guard_home = tmp_path / ".hol-guard"
    loaded = update_guard_settings(guard_home, {"protection_posture": "extra_careful"})
    assert loaded.mode == "enforce"
    assert loaded.security_level == "strict"
    assert resolve_risk_action(loaded, "network_egress", harness="codex") == "require-reapproval"
    assert resolve_risk_action(loaded, "cloud_advisory", harness="codex") == "require-reapproval"
    assert resolve_risk_action(loaded, "mcp_dangerous_tool", harness="codex") == "require-reapproval"


def test_watch_dual_writes_observe_and_keeps_level(tmp_path: Path) -> None:
    guard_home = tmp_path / ".hol-guard"
    update_guard_settings(guard_home, {"security_level": "strict"})
    loaded = update_guard_settings(guard_home, {"protection_posture": "watch"})
    assert loaded.mode == "observe"
    assert loaded.security_level == "strict"
    assert loaded.protection_posture == "watch"
    assert loaded.watch_auto_revert_hours == 24


def test_legacy_security_level_stays_implicit(tmp_path: Path) -> None:
    guard_home = tmp_path / ".hol-guard"
    loaded = update_guard_settings(guard_home, {"security_level": "paranoid"})
    assert loaded.protection_posture == "extra_careful"
    assert loaded.protection_posture_explicit is False
    assert resolve_risk_action(loaded, "network_egress", harness="codex") == "block"
    assert "protection_posture" not in (guard_home / "config.toml").read_text(encoding="utf-8")


def test_legacy_observe_does_not_persist_watch(tmp_path: Path) -> None:
    guard_home = tmp_path / ".hol-guard"
    loaded = update_guard_settings(guard_home, {"mode": "observe"})
    assert loaded.mode == "observe"
    assert loaded.protection_posture == "watch"
    assert loaded.protection_posture_explicit is False


def test_settings_echo_does_not_persist_derived_posture(tmp_path: Path) -> None:
    guard_home = tmp_path / ".hol-guard"
    loaded = update_guard_settings(
        guard_home,
        {
            "mode": "prompt",
            "security_level": "balanced",
            "protection_posture": "protected",
        },
    )
    assert loaded.protection_posture_explicit is False
    assert resolve_risk_action(loaded, "network_egress", harness="codex") == "warn"


def test_settings_save_blob_with_explicit_watch_stamps_entered_at(tmp_path: Path) -> None:
    guard_home = tmp_path / ".hol-guard"
    loaded = update_guard_settings(
        guard_home,
        {
            "mode": "observe",
            "security_level": "balanced",
            "risk_actions": {},
            "protection_posture": "watch",
            "protection_posture_explicit": True,
        },
    )
    assert loaded.protection_posture == "watch"
    assert loaded.protection_posture_explicit is True
    assert loaded.mode == "observe"
    assert loaded.watch_entered_at is not None


def test_settings_save_blob_with_explicit_protected_uses_posture_maps(tmp_path: Path) -> None:
    guard_home = tmp_path / ".hol-guard"
    loaded = update_guard_settings(
        guard_home,
        {
            "mode": "enforce",
            "security_level": "balanced",
            "risk_actions": {},
            "protection_posture": "protected",
            "protection_posture_explicit": True,
        },
    )
    assert loaded.protection_posture_explicit is True
    assert resolve_risk_action(loaded, "network_egress", harness="codex") == "allow"
    assert resolve_risk_action(loaded, "package_script", harness="codex") == "require-reapproval"


def test_mode_prompt_does_not_clear_explicit_protected(tmp_path: Path) -> None:
    guard_home = tmp_path / ".hol-guard"
    update_guard_settings(guard_home, {"protection_posture": "protected"})
    loaded = update_guard_settings(guard_home, {"mode": "prompt"})
    assert loaded.protection_posture == "protected"
    assert loaded.mode == "prompt"


def test_invalid_posture_falls_back_on_load(tmp_path: Path) -> None:
    guard_home = tmp_path / ".hol-guard"
    _write_text(guard_home / "config.toml", 'protection_posture = "yolo"\nmode = "prompt"\n')
    config = load_guard_config(guard_home)
    assert config.protection_posture == "protected"
    assert config.protection_posture_explicit is False


def test_invalid_posture_rejected_on_update(tmp_path: Path) -> None:
    guard_home = tmp_path / ".hol-guard"
    try:
        update_guard_settings(guard_home, {"protection_posture": "yolo"})
    except ValueError as exc:
        assert "protection posture" in str(exc).lower()
    else:
        raise AssertionError("expected invalid posture to raise")


def test_custom_risk_override_still_wins(tmp_path: Path) -> None:
    guard_home = tmp_path / ".hol-guard"
    update_guard_settings(guard_home, {"protection_posture": "protected"})
    loaded = update_guard_settings(guard_home, {"risk_actions": {"network_egress": "block"}})
    assert resolve_risk_action(loaded, "network_egress", harness="codex") == "block"
    assert resolve_risk_action(loaded, "package_script", harness="codex") == "require-reapproval"


def test_relaxed_implicit_maps_stay_warn(tmp_path: Path) -> None:
    guard_home = tmp_path / ".hol-guard"
    _write_text(guard_home / "config.toml", 'mode = "prompt"\nsecurity_level = "relaxed"\n')
    config = load_guard_config(guard_home)
    assert config.protection_posture == "protected"
    assert resolve_risk_action(config, "guard_bypass", harness="codex") == "warn"
    assert resolve_risk_action(config, "credential_exfiltration", harness="codex") == "warn"


def test_derive_and_dual_write_tables() -> None:
    assert derive_protection_posture("observe", "balanced") == "watch"
    assert derive_protection_posture("prompt", "balanced") == "protected"
    assert derive_protection_posture("enforce", "strict") == "extra_careful"
    assert derive_protection_posture("enforce", "paranoid") == "extra_careful"
    assert derive_protection_posture("prompt", "gentle") == "protected"
    assert dual_write_from_posture("protected") == ("enforce", "balanced")
    assert dual_write_from_posture("extra_careful") == ("enforce", "strict")
    assert dual_write_from_posture("watch", current_security_level="balanced") == ("observe", "balanced")


def test_confidence_stop_only_when_explicit_and_strong() -> None:
    asked = apply_posture_confidence(
        posture="protected",
        explicit=True,
        risk_class="credential_exfiltration",
        action="require-reapproval",
        confidence=None,
    )
    stopped = apply_posture_confidence(
        posture="protected",
        explicit=True,
        risk_class="credential_exfiltration",
        action="require-reapproval",
        confidence="strong",
    )
    implicit = apply_posture_confidence(
        posture="protected",
        explicit=False,
        risk_class="credential_exfiltration",
        action="require-reapproval",
        confidence="strong",
    )
    always = apply_posture_confidence(
        posture="protected",
        explicit=True,
        risk_class="guard_bypass",
        action="require-reapproval",
        confidence=None,
    )
    assert asked == "require-reapproval"
    assert stopped == "block"
    assert implicit == "require-reapproval"
    assert always == "block"


def test_managed_security_level_lock_keeps_level_maps(tmp_path: Path) -> None:
    guard_home = tmp_path / ".hol-guard"
    loaded = update_guard_settings(guard_home, {"protection_posture": "protected"})
    locked = replace(
        loaded,
        security_level="paranoid",
        managed_locked_settings=("security_level",),
        protection_posture_explicit=True,
    )
    assert resolve_risk_action(locked, "network_egress", harness="codex") == "block"
    assert resolve_risk_action(locked, "local_secret_read", harness="codex") == "block"


def test_watch_auto_revert_hours_round_trip(tmp_path: Path) -> None:
    guard_home = tmp_path / ".hol-guard"
    loaded = update_guard_settings(guard_home, {"watch_auto_revert_hours": 0})
    assert loaded.watch_auto_revert_hours == 0
    loaded = update_guard_settings(guard_home, {"watch_auto_revert_hours": 48})
    assert loaded.watch_auto_revert_hours == 48


def test_watch_auto_reverts_after_entered_timestamp(tmp_path: Path) -> None:
    from datetime import datetime, timedelta, timezone

    from codex_plugin_scanner.guard.config import maybe_auto_revert_watch

    guard_home = tmp_path / ".hol-guard"
    loaded = update_guard_settings(guard_home, {"protection_posture": "watch", "watch_auto_revert_hours": 24})
    assert loaded.protection_posture == "watch"
    assert loaded.watch_entered_at is not None
    later = datetime.now(timezone.utc) + timedelta(hours=25)
    reverted = maybe_auto_revert_watch(guard_home, now=later)
    assert reverted.protection_posture == "protected"
    assert reverted.mode == "enforce"


def test_watch_auto_revert_accepts_naive_entered_at(tmp_path: Path) -> None:
    from datetime import datetime, timedelta, timezone

    from codex_plugin_scanner.guard.config import maybe_auto_revert_watch, watch_should_auto_revert

    guard_home = tmp_path / ".hol-guard"
    loaded = update_guard_settings(guard_home, {"protection_posture": "watch", "watch_auto_revert_hours": 24})
    naive = loaded.watch_entered_at.replace("+00:00", "") if loaded.watch_entered_at else "2020-01-01T00:00:00"
    naive_config = replace(loaded, watch_entered_at=naive)
    later = datetime.now(timezone.utc) + timedelta(hours=25)
    assert watch_should_auto_revert(naive_config, now=later) is True
    reverted = maybe_auto_revert_watch(guard_home, now=later)
    assert reverted.protection_posture == "protected"


def test_explicit_protected_survives_mode_lock_overlay(tmp_path: Path) -> None:
    from types import SimpleNamespace

    from codex_plugin_scanner.guard.config import _reapply_managed_config

    guard_home = tmp_path / ".hol-guard"
    loaded = update_guard_settings(guard_home, {"protection_posture": "protected"})
    locked = replace(
        loaded,
        managed_policy=SimpleNamespace(settings={"mode": "enforce"}, locked_settings=frozenset({"mode"})),
        managed_locked_settings=("mode",),
    )
    overlaid = _reapply_managed_config(locked)
    assert overlaid.protection_posture_explicit is True
    assert resolve_risk_action(overlaid, "package_script", harness="codex") == "require-reapproval"


def test_level_change_on_explicit_posture_returns_to_level_maps(tmp_path: Path) -> None:
    guard_home = tmp_path / ".hol-guard"
    update_guard_settings(guard_home, {"protection_posture": "protected"})
    loaded = update_guard_settings(
        guard_home,
        {
            "mode": "enforce",
            "security_level": "strict",
            "protection_posture": "protected",
            "protection_posture_explicit": True,
        },
    )
    assert loaded.protection_posture_explicit is False
    assert loaded.security_level == "strict"
    assert resolve_risk_action(loaded, "network_egress", harness="codex") == "require-reapproval"
    assert resolve_risk_action(loaded, "mcp_dangerous_tool", harness="codex") == "block"


def test_watch_forces_observe_even_when_mode_is_in_payload(tmp_path: Path) -> None:
    guard_home = tmp_path / ".hol-guard"
    loaded = update_guard_settings(
        guard_home,
        {
            "protection_posture": "watch",
            "protection_posture_explicit": True,
            "mode": "prompt",
            "security_level": "balanced",
        },
    )
    assert loaded.mode == "observe"
    assert loaded.protection_posture == "watch"


def test_runtime_policy_reads_signal_confidence_from_artifact_metadata(tmp_path: Path) -> None:
    from codex_plugin_scanner.guard.cli.commands_support_runtime_policy import (
        _apply_explicit_posture_action,
    )
    from codex_plugin_scanner.guard.models import GuardArtifact

    guard_home = tmp_path / ".hol-guard"
    config = update_guard_settings(guard_home, {"protection_posture": "protected"})
    artifact = GuardArtifact(
        artifact_id="codex:project:tool-action:exfil",
        name="exfil",
        harness="codex",
        artifact_type="tool_action_request",
        source_scope="project",
        config_path="/workspace/repo/.guard/config.toml",
        metadata={
            "risk_signals": [{"confidence": "strong", "category": "secret"}],
        },
    )
    action = _apply_explicit_posture_action(config, artifact, "credential_exfiltration", "require-reapproval")
    assert action == "block"


def test_managed_mode_lock_overrides_watch_payload() -> None:
    from codex_plugin_scanner.guard.mdm.contracts import MDM_POLICY_SCHEMA_VERSION, ManagedPolicy
    from codex_plugin_scanner.guard.mdm.policy import apply_managed_policy

    policy = ManagedPolicy(
        schema_version=MDM_POLICY_SCHEMA_VERSION,
        settings={"mode": "enforce"},
        locked_settings=frozenset({"mode"}),
    )
    composed = apply_managed_policy(
        {"mode": "observe", "protection_posture": "watch", "security_level": "balanced"},
        policy,
    )
    assert composed["mode"] == "enforce"


def test_managed_watch_auto_revert_lock_keeps_hours() -> None:
    from codex_plugin_scanner.guard.mdm.contracts import MDM_POLICY_SCHEMA_VERSION, ManagedPolicy
    from codex_plugin_scanner.guard.mdm.policy import apply_managed_policy

    policy = ManagedPolicy(
        schema_version=MDM_POLICY_SCHEMA_VERSION,
        settings={"watch_auto_revert_hours": 24},
        locked_settings=frozenset({"watch_auto_revert_hours"}),
    )
    composed = apply_managed_policy({"watch_auto_revert_hours": 0}, policy)
    assert composed["watch_auto_revert_hours"] == 24
