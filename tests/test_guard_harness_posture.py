"""Per-harness protection posture: config, MDM locks, auto-revert, native carrier."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

import codex_plugin_scanner.guard.config as config_module
from codex_plugin_scanner.guard.config import (
    editable_guard_settings,
    load_guard_config,
    maybe_auto_revert_watch,
    resolve_risk_action,
    update_guard_settings,
)
from codex_plugin_scanner.guard.harness_posture import (
    config_for_harness,
    effective_harness_posture,
    harness_is_recording_only,
    harness_posture_summary,
    protection_settings_payload,
)
from codex_plugin_scanner.guard.mdm.contracts import ManagedPolicy, ManagedPolicyState
from codex_plugin_scanner.guard.native_policy_snapshot_harness_postures import (
    posture_risk_overlay,
    read_harness_postures_sidecar,
    recording_only_for_binding,
    write_harness_postures_sidecar,
)
from codex_plugin_scanner.guard.store import GuardStore


def _managed(settings: dict[str, object], locked: set[str]) -> ManagedPolicyState:
    policy = ManagedPolicy(
        schema_version="1",
        settings=settings,
        locked_settings=frozenset(locked),
        content_hash="a" * 64,
    )
    return ManagedPolicyState("active", "machine-policy-fixture", policy=policy)


def test_unset_harness_inherits_global_posture(tmp_path: Path) -> None:
    guard_home = tmp_path / ".hol-guard"
    config = update_guard_settings(guard_home, {"protection_posture": "protected"})
    assert config.harness_postures in (None, {})
    assert effective_harness_posture(config, "codex") == "protected"
    assert harness_is_recording_only(config, "codex") is False


def test_harness_watch_is_recording_only_for_that_harness_only(tmp_path: Path) -> None:
    guard_home = tmp_path / ".hol-guard"
    config = update_guard_settings(guard_home, {"harness_postures": {"codex": "watch"}})
    assert config.harness_postures == {"codex": "watch"}
    assert config.harness_watch_entered_at is not None and "codex" in config.harness_watch_entered_at
    assert harness_is_recording_only(config, "codex") is True
    assert harness_is_recording_only(config, "claude-code") is False
    assert config.protection_posture == "protected"
    reloaded = load_guard_config(guard_home)
    assert reloaded.harness_postures == {"codex": "watch"}


def test_harness_override_is_merge_patch_and_null_clears(tmp_path: Path) -> None:
    guard_home = tmp_path / ".hol-guard"
    update_guard_settings(guard_home, {"harness_postures": {"codex": "watch", "claude-code": "extra_careful"}})
    config = update_guard_settings(guard_home, {"harness_postures": {"codex": None}})
    assert config.harness_postures == {"claude-code": "extra_careful"}
    assert "codex" not in (config.harness_watch_entered_at or {})
    config = update_guard_settings(guard_home, {"harness_postures": {"claude-code": "inherit"}})
    assert not config.harness_postures


def test_invalid_harness_posture_is_rejected(tmp_path: Path) -> None:
    guard_home = tmp_path / ".hol-guard"
    with pytest.raises(ValueError):
        update_guard_settings(guard_home, {"harness_postures": {"codex": "off"}})


def test_reselecting_watch_refreshes_entered_at(tmp_path: Path) -> None:
    guard_home = tmp_path / ".hol-guard"
    first = update_guard_settings(guard_home, {"harness_postures": {"codex": "watch"}})
    config_path = guard_home / "config.toml"
    stale = (datetime.now(timezone.utc) - timedelta(hours=20)).isoformat()
    text = config_path.read_text(encoding="utf-8").replace(first.harness_watch_entered_at["codex"], stale)
    config_path.write_text(text, encoding="utf-8")
    assert load_guard_config(guard_home).harness_watch_entered_at["codex"] == stale
    second = update_guard_settings(guard_home, {"harness_postures": {"codex": "watch"}})
    assert second.harness_watch_entered_at["codex"] != stale


def test_harness_watch_auto_reverts_to_inherit_after_window(tmp_path: Path) -> None:
    guard_home = tmp_path / ".hol-guard"
    update_guard_settings(guard_home, {"harness_postures": {"codex": "watch", "cursor": "watch"}})
    assert maybe_auto_revert_watch(guard_home).harness_postures == {"codex": "watch", "cursor": "watch"}
    later = datetime.now(timezone.utc) + timedelta(hours=25)
    reverted = maybe_auto_revert_watch(guard_home, now=later)
    assert not reverted.harness_postures
    assert reverted.protection_posture == "protected"


def test_harness_watch_auto_revert_disabled_with_zero_hours(tmp_path: Path) -> None:
    guard_home = tmp_path / ".hol-guard"
    update_guard_settings(guard_home, {"watch_auto_revert_hours": 0, "harness_postures": {"codex": "watch"}})
    later = datetime.now(timezone.utc) + timedelta(hours=500)
    assert maybe_auto_revert_watch(guard_home, now=later).harness_postures == {"codex": "watch"}


def test_extra_careful_override_strengthens_risk_actions(tmp_path: Path) -> None:
    guard_home = tmp_path / ".hol-guard"
    config = update_guard_settings(
        guard_home, {"protection_posture": "protected", "harness_postures": {"codex": "extra_careful"}}
    )
    assert resolve_risk_action(config, "network_egress", harness="codex") == "require-reapproval"
    assert resolve_risk_action(config, "network_egress", harness="claude-code") != "require-reapproval"


def test_config_for_harness_applies_override_and_noops_without_one(tmp_path: Path) -> None:
    guard_home = tmp_path / ".hol-guard"
    config = update_guard_settings(guard_home, {"harness_postures": {"codex": "watch"}})
    scoped = config_for_harness(config, "codex")
    assert scoped.mode == "observe" and scoped.protection_posture == "watch"
    assert config_for_harness(config, "claude-code") is config


def test_managed_lock_discards_local_weakening_overrides(tmp_path: Path) -> None:
    guard_home = tmp_path / ".hol-guard"
    update_guard_settings(guard_home, {"harness_postures": {"codex": "watch", "cursor": "extra_careful"}})
    locked = load_guard_config(
        guard_home, managed_policy_state=_managed({"protection_posture": "protected"}, {"protection_posture"})
    )
    assert locked.harness_postures == {"cursor": "extra_careful"}
    assert harness_is_recording_only(locked, "codex") is False
    assert editable_guard_settings(locked)["harness_postures_locked"] is True


def test_managed_lock_rejects_local_watch_write(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    guard_home = tmp_path / ".hol-guard"
    state = _managed({"protection_posture": "protected"}, {"protection_posture"})
    monkeypatch.setattr(config_module, "load_managed_policy", lambda: state)
    config = update_guard_settings(guard_home, {"harness_postures": {"codex": "extra_careful"}})
    assert config.harness_postures == {"codex": "extra_careful"}
    with pytest.raises(ValueError):
        update_guard_settings(guard_home, {"harness_postures": {"codex": "watch"}})
    with pytest.raises(ValueError):
        update_guard_settings(guard_home, {"harness_postures": {"codex": "protected"}})


def test_managed_harness_postures_lock_replaces_local_map(tmp_path: Path) -> None:
    guard_home = tmp_path / ".hol-guard"
    update_guard_settings(guard_home, {"harness_postures": {"codex": "watch"}})
    locked = load_guard_config(
        guard_home,
        managed_policy_state=_managed({"harness_postures": {"cursor": "extra_careful"}}, {"harness_postures"}),
    )
    assert locked.harness_postures == {"cursor": "extra_careful"}


def test_status_summary_lists_overrides_and_effective_watch(tmp_path: Path) -> None:
    guard_home = tmp_path / ".hol-guard"
    config = update_guard_settings(guard_home, {"harness_postures": {"codex": "watch"}})
    summary = harness_posture_summary(config)
    assert summary["harness_postures"] == {"codex": "watch"}
    assert summary["harnesses_in_watch"] == ["codex"]


def test_settings_set_protection_payload_for_harness_and_inherit() -> None:
    assert protection_settings_payload("watch", harness="codex", inherit=False) == {
        "harness_postures": {"codex": "watch"}
    }
    assert protection_settings_payload(None, harness="codex", inherit=True) == {"harness_postures": {"codex": None}}
    assert protection_settings_payload("watch", harness=None, inherit=False)["protection_posture"] == "watch"


def test_recording_only_for_binding_semantics() -> None:
    assert recording_only_for_binding(None, "codex") is False
    assert recording_only_for_binding({"mode": "observe"}, "codex") is True
    assert recording_only_for_binding({"mode": "enforce"}, "codex") is False
    enforce_with_watch = {"mode": "enforce", "harness_postures": {"codex": "watch"}}
    assert recording_only_for_binding(enforce_with_watch, "codex") is True
    assert recording_only_for_binding(enforce_with_watch, "claude-code") is False
    observe_with_protected = {"mode": "observe", "harness_postures": {"codex": "protected"}}
    assert recording_only_for_binding(observe_with_protected, "codex") is False
    assert recording_only_for_binding(observe_with_protected, "claude-code") is True
    assert recording_only_for_binding({"mode": "enforce", "harness_postures": {"codex": "bogus"}}, "codex") is False


def test_posture_overlay_only_strengthens(tmp_path: Path) -> None:
    guard_home = tmp_path / ".hol-guard"
    watch_global = update_guard_settings(
        guard_home, {"protection_posture": "watch", "harness_postures": {"codex": "protected", "cursor": "watch"}}
    )
    overlay = posture_risk_overlay({}, watch_global)
    assert overlay["codex"]["local_secret_read"] == "require-reapproval"
    assert "cursor" not in overlay
    protected_global = update_guard_settings(
        guard_home, {"protection_posture": "protected", "harness_postures": {"codex": "watch", "cursor": "protected"}}
    )
    assert posture_risk_overlay({}, protected_global) == {}


def test_sidecar_is_bound_to_generation_and_digest_and_authenticated(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    store._policy_integrity_secret_material(create=True)
    digest = "d" * 64
    write_harness_postures_sidecar(store, generation=3, policy_digest=digest, postures={"codex": "watch"})
    assert read_harness_postures_sidecar(store, generation=3, policy_digest=digest) == {"codex": "watch"}
    assert read_harness_postures_sidecar(store, generation=4, policy_digest=digest) == {}
    assert read_harness_postures_sidecar(store, generation=3, policy_digest="e" * 64) == {}

    sidecar = tmp_path / "guard-home" / "native-runtime" / "harness-postures-v1.json"
    document = json.loads(sidecar.read_text(encoding="utf-8"))
    document["harness_postures"] = {"codex": "watch", "claude-code": "watch"}
    sidecar.write_text(json.dumps(document), encoding="utf-8")
    assert read_harness_postures_sidecar(store, generation=3, policy_digest=digest) == {}


def test_sidecar_without_postures_removes_stale_file(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    store._policy_integrity_secret_material(create=True)
    digest = "d" * 64
    write_harness_postures_sidecar(store, generation=1, policy_digest=digest, postures={"codex": "watch"})
    write_harness_postures_sidecar(store, generation=2, policy_digest=digest, postures={})
    assert read_harness_postures_sidecar(store, generation=1, policy_digest=digest) == {}
    assert not (tmp_path / "guard-home" / "native-runtime" / "harness-postures-v1.json").exists()


def test_full_settings_save_keeps_global_watch_timer(tmp_path: Path) -> None:
    guard_home = tmp_path / ".hol-guard"
    first = update_guard_settings(guard_home, {"protection_posture": "watch"})
    assert first.watch_entered_at is not None
    config_path = guard_home / "config.toml"
    stale = (datetime.now(timezone.utc) - timedelta(hours=20)).isoformat()
    config_path.write_text(
        config_path.read_text(encoding="utf-8").replace(first.watch_entered_at, stale), encoding="utf-8"
    )
    dashboard_save = {
        "mode": "observe",
        "security_level": first.security_level,
        "protection_posture": "watch",
        "protection_posture_explicit": True,
        "watch_auto_revert_hours": 12,
    }
    assert update_guard_settings(guard_home, dashboard_save).watch_entered_at == stale
    assert update_guard_settings(guard_home, {"protection_posture": "watch"}).watch_entered_at != stale


def test_extra_careful_override_floors_app_risk_actions(tmp_path: Path) -> None:
    guard_home = tmp_path / ".hol-guard"
    config = update_guard_settings(
        guard_home,
        {
            "protection_posture": "protected",
            "harness_postures": {"codex": "extra_careful"},
            "harness_risk_actions": {"codex": {"network_egress": "allow"}},
        },
    )
    assert resolve_risk_action(config, "network_egress", harness="codex") == "require-reapproval"


def test_failed_sidecar_write_binds_no_overrides(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    import codex_plugin_scanner.guard.native_policy_snapshot_harness_postures as sidecar_module

    store = GuardStore(tmp_path / "guard-home")
    store._policy_integrity_secret_material(create=True)
    digest = "d" * 64
    assert write_harness_postures_sidecar(store, generation=1, policy_digest=digest, postures={"codex": "watch"}) == {
        "codex": "watch"
    }

    def _fail(*_args: object, **_kwargs: object) -> None:
        raise OSError("disk full")

    monkeypatch.setattr(sidecar_module, "_write_private_file", _fail)
    assert write_harness_postures_sidecar(store, generation=2, policy_digest=digest, postures={"codex": "watch"}) == {}
    assert read_harness_postures_sidecar(store, generation=2, policy_digest=digest) == {}
