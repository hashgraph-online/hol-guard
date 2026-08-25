from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard.runtime.custom_extension_continuity import (
    CUSTOM_EXTENSION_CONTINUITY_FIELD,
    CUSTOM_EXTENSION_CONTINUITY_SCHEMA,
    CustomExtensionContinuityError,
    apply_verified_custom_extension_continuity,
    continuity_state_for_local_items,
    record_local_custom_extension_mutation,
)
from codex_plugin_scanner.guard.runtime.local_cli_commands import LocalCliCommand
from codex_plugin_scanner.guard.runtime.local_cli_identity import UnlistedCliIdentity
from codex_plugin_scanner.guard.store import GuardStore

_NOW = "2026-08-25T16:00:00Z"
_FUTURE = "2026-08-25T17:00:00Z"
_LATER = "2026-08-25T18:00:00Z"


def _identity(
    *,
    kind: str = "executable",
    identity_hash: str = "a" * 64,
    cli_id: str = "local-cli.release-tool-12345678",
) -> UnlistedCliIdentity:
    return UnlistedCliIdentity(
        cli_id=cli_id,
        name="release-tool.py" if kind == "script" else "release-tool",
        kind="script" if kind == "script" else "executable",
        identity_hash=identity_hash,
        example_label="release-tool",
        interpreter_name="python3" if kind == "script" else None,
    )


def _observe(
    store: GuardStore,
    identity: UnlistedCliIdentity,
    *,
    surface: str = "cli",
    source_path: str | None = None,
    commands: tuple[str, ...] = ("deploy",),
) -> None:
    store.record_local_cli_observation(
        identity,
        seen_at=_NOW,
        source_path=source_path,
        surface=surface,
        help_status="ok",
        server_identity_hash=identity.identity_hash if surface == "mcp" else None,
    )
    store.replace_local_cli_commands(
        identity.cli_id,
        tuple(LocalCliCommand(command, command, command, f"{command} safely") for command in commands),
    )


def _bundle(
    identity: UnlistedCliIdentity,
    *,
    state: str = "allowed",
    identity_hash: str | None = None,
    expires_at: str = _FUTURE,
    revision: int = 1,
    commands: dict[str, str] | None = None,
) -> dict[str, object]:
    return {
        "payload": {
            CUSTOM_EXTENSION_CONTINUITY_FIELD: {
                "schemaVersion": CUSTOM_EXTENSION_CONTINUITY_SCHEMA,
                "revision": revision,
                "observedAt": _NOW,
                "expiresAt": expires_at,
                "items": [
                    {
                        "cliId": identity.cli_id,
                        "identityHash": identity_hash or identity.identity_hash,
                        "settings": {
                            "state": state,
                            "commands": commands if commands is not None else {"deploy": "allow"},
                        },
                    }
                ],
            }
        }
    }


@pytest.mark.parametrize(("kind", "surface"), (("executable", "cli"), ("script", "cli"), ("executable", "mcp")))
def test_signed_continuity_applies_only_to_exact_observed_executable_script_and_mcp_identity(
    tmp_path: Path,
    kind: str,
    surface: str,
) -> None:
    store = GuardStore(tmp_path / "guard-home")
    identity = _identity(kind=kind)
    _observe(store, identity, surface=surface)
    result = apply_verified_custom_extension_continuity(store, _bundle(identity), now=_NOW)
    assert result["items"][identity.cli_id]["status"] == "applied"
    assert store.read_local_cli_grant(identity.cli_id)["state"] == "allowed"
    assert store.read_local_cli_command_states(identity.cli_id) == {"deploy": "allow"}
    events = store.list_events(event_name="custom_extension_continuity/applied")
    assert events and str(events[0]["payload"]).find("source_path") == -1


def test_missing_local_observation_stays_pending_and_does_not_create_authority(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    identity = _identity()
    result = apply_verified_custom_extension_continuity(store, _bundle(identity), now=_NOW)
    assert result["items"][identity.cli_id]["status"] == "pending_observation"
    assert store.read_local_cli_grant(identity.cli_id) is None


def test_changed_identity_is_refused_without_replacing_local_setting(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    identity = _identity()
    _observe(store, identity)
    result = apply_verified_custom_extension_continuity(
        store,
        _bundle(identity, identity_hash="b" * 64),
        now=_NOW,
    )
    assert result["items"][identity.cli_id]["status"] == "changed_identity"
    assert store.read_local_cli_grant(identity.cli_id) is None


@pytest.mark.parametrize("forbidden", ("command", "sourcePath", "code", "downloadUrl"))
def test_continuity_contract_never_accepts_code_or_launch_material(tmp_path: Path, forbidden: str) -> None:
    store = GuardStore(tmp_path / "guard-home")
    identity = _identity()
    payload = _bundle(identity)
    field = payload["payload"][CUSTOM_EXTENSION_CONTINUITY_FIELD]
    field["items"][0][forbidden] = "do-not-run"
    with pytest.raises(CustomExtensionContinuityError, match="unsupported fields"):
        apply_verified_custom_extension_continuity(store, payload, now=_NOW)
    assert store.read_local_cli_grant(identity.cli_id) is None


def test_local_removal_keeps_file_and_blocks_same_cloud_revision_recreation(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    source = tmp_path / "release-tool.py"
    source.write_text("print('still local')", encoding="utf-8")
    identity = _identity(kind="script")
    _observe(store, identity, source_path=str(source))
    apply_verified_custom_extension_continuity(store, _bundle(identity), now=_NOW)
    record_local_custom_extension_mutation(
        store,
        identity=identity,
        state="unset",
        expected_revision=store.read_local_cli_revision(),
        command_states={},
        now=_NOW,
    )
    result = apply_verified_custom_extension_continuity(store, _bundle(identity), now=_NOW)
    assert result["items"][identity.cli_id]["status"] == "removed"
    assert store.read_local_cli_grant(identity.cli_id) is None
    assert source.read_text(encoding="utf-8") == "print('still local')"


@pytest.mark.parametrize(
    ("local_state", "local_commands"),
    (("blocked", {"deploy": "block"}), ("allowed", {"deploy": "block"})),
)
def test_local_state_and_command_overrides_survive_same_cloud_revision_until_superseded(
    tmp_path: Path,
    local_state: str,
    local_commands: dict[str, str],
) -> None:
    store = GuardStore(tmp_path / "guard-home")
    identity = _identity()
    _observe(store, identity)
    apply_verified_custom_extension_continuity(store, _bundle(identity), now=_NOW)
    record_local_custom_extension_mutation(
        store,
        identity=identity,
        state=local_state,
        expected_revision=store.read_local_cli_revision(),
        command_states=local_commands,
        now=_NOW,
    )
    replayed = apply_verified_custom_extension_continuity(store, _bundle(identity), now=_NOW)
    assert replayed["items"][identity.cli_id]["status"] == "locally_overridden"
    assert store.read_local_cli_grant(identity.cli_id)["state"] == local_state
    assert store.read_local_cli_command_states(identity.cli_id) == local_commands
    assert store.list_events(event_name="custom_extension_continuity/locally_overridden")

    superseded = apply_verified_custom_extension_continuity(store, _bundle(identity, revision=2), now=_NOW)
    assert superseded["items"][identity.cli_id]["status"] == "applied"
    assert store.read_local_cli_grant(identity.cli_id)["state"] == "allowed"
    assert store.read_local_cli_command_states(identity.cli_id) == {"deploy": "allow"}
    assert store.get_sync_payload("custom_extension_continuity_local_removals") == {}


def test_stale_and_offline_state_keep_last_known_good_local_setting(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    identity = _identity()
    _observe(store, identity)
    apply_verified_custom_extension_continuity(store, _bundle(identity), now=_NOW)
    stale = apply_verified_custom_extension_continuity(
        store,
        _bundle(identity, state="blocked", expires_at=_FUTURE, revision=2),
        now=_LATER,
    )
    assert stale["items"][identity.cli_id]["status"] == "stale"
    assert store.read_local_cli_grant(identity.cli_id)["state"] == "allowed"
    offline = continuity_state_for_local_items(store, now=_LATER)
    assert offline[identity.cli_id]["status"] == "stale"


def test_fresh_signed_bundle_removal_marks_state_without_deleting_local_authority(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    identity = _identity()
    _observe(store, identity)
    apply_verified_custom_extension_continuity(store, _bundle(identity), now=_NOW)
    removed = apply_verified_custom_extension_continuity(store, {"payload": {}}, now=_NOW)
    assert removed["items"][identity.cli_id]["status"] == "removed"
    assert store.read_local_cli_grant(identity.cli_id)["state"] == "allowed"


def test_replayed_or_changed_revision_cannot_replace_newer_settings(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    identity = _identity()
    _observe(store, identity)
    apply_verified_custom_extension_continuity(store, _bundle(identity, revision=2), now=_NOW)
    with pytest.raises(CustomExtensionContinuityError, match="backwards"):
        apply_verified_custom_extension_continuity(store, _bundle(identity, state="blocked", revision=1), now=_NOW)
    with pytest.raises(CustomExtensionContinuityError, match="payload changed"):
        apply_verified_custom_extension_continuity(store, _bundle(identity, state="blocked", revision=2), now=_NOW)
    assert store.read_local_cli_grant(identity.cli_id)["state"] == "allowed"


def test_invalid_later_item_leaves_zero_mutation_after_restart(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard-home"
    store = GuardStore(guard_home)
    first = _identity()
    second = _identity(identity_hash="b" * 64, cli_id="local-cli.audit-tool-12345678")
    _observe(store, first)
    _observe(store, second)
    observation = _bundle(first)
    field = observation["payload"][CUSTOM_EXTENSION_CONTINUITY_FIELD]
    field["items"].append(
        {
            "cliId": second.cli_id,
            "identityHash": second.identity_hash,
            "settings": {"state": "blocked", "commands": {"unobserved": "block"}},
        }
    )

    with pytest.raises(CustomExtensionContinuityError, match="unobserved command"):
        apply_verified_custom_extension_continuity(store, observation, now=_NOW)

    restarted = GuardStore(guard_home)
    assert restarted.read_local_cli_revision() == 0
    assert restarted.read_local_cli_grant(first.cli_id) is None
    assert restarted.read_local_cli_grant(second.cli_id) is None
    assert restarted.get_sync_payload("custom_extension_continuity") is None
    assert restarted.list_events(event_name="custom_extension_continuity/applied") == []


def test_signed_settings_exactly_replace_prior_command_states_without_touching_unrelated_grants(
    tmp_path: Path,
) -> None:
    store = GuardStore(tmp_path / "guard-home")
    identity = _identity()
    unrelated = _identity(identity_hash="c" * 64, cli_id="local-cli.unrelated-12345678")
    _observe(store, identity, commands=("deploy", "audit"))
    _observe(store, unrelated)
    store.upsert_local_cli_grant(
        identity=unrelated,
        state="blocked",
        expected_revision=0,
        updated_at=_NOW,
        command_states={"deploy": "block"},
    )

    apply_verified_custom_extension_continuity(
        store,
        _bundle(identity, commands={"deploy": "allow", "audit": "block"}),
        now=_NOW,
    )
    assert store.read_local_cli_revision() == 2
    assert store.read_local_cli_command_states(identity.cli_id) == {"deploy": "allow", "audit": "block"}

    apply_verified_custom_extension_continuity(
        store,
        _bundle(identity, state="blocked", revision=2, commands={"deploy": "block"}),
        now=_NOW,
    )
    assert store.read_local_cli_revision() == 3
    assert store.read_local_cli_grant(identity.cli_id)["state"] == "blocked"
    assert store.read_local_cli_command_states(identity.cli_id) == {"deploy": "block"}

    apply_verified_custom_extension_continuity(
        store,
        _bundle(identity, state="allowed", revision=3, commands={}),
        now=_NOW,
    )
    assert store.read_local_cli_revision() == 4
    assert store.read_local_cli_grant(identity.cli_id)["state"] == "allowed"
    assert store.read_local_cli_command_states(identity.cli_id) == {}
    assert store.read_local_cli_grant(unrelated.cli_id)["state"] == "blocked"
    assert store.read_local_cli_command_states(unrelated.cli_id) == {"deploy": "block"}


@pytest.mark.parametrize("failure_stage", ("after_authority", "after_sync_state", "after_event"))
def test_local_removal_is_crash_atomic_and_same_revision_cannot_recreate_after_retry(
    tmp_path: Path,
    failure_stage: str,
) -> None:
    guard_home = tmp_path / "guard-home"
    initial = GuardStore(guard_home)
    identity = _identity()
    _observe(initial, identity)
    apply_verified_custom_extension_continuity(initial, _bundle(identity), now=_NOW)

    class FaultyStore(GuardStore):
        def _custom_extension_continuity_transaction_boundary(self, stage: str) -> None:
            if stage == failure_stage:
                raise RuntimeError("simulated process failure")

    faulty = FaultyStore(guard_home)
    with pytest.raises(RuntimeError, match="simulated process failure"):
        record_local_custom_extension_mutation(
            faulty,
            identity=identity,
            state="unset",
            expected_revision=faulty.read_local_cli_revision(),
            command_states={},
            now=_NOW,
        )

    restarted = GuardStore(guard_home)
    assert restarted.read_local_cli_grant(identity.cli_id)["state"] == "allowed"
    assert restarted.get_sync_payload("custom_extension_continuity_local_removals") in (None, {})
    assert restarted.get_sync_payload("custom_extension_continuity")["items"][identity.cli_id]["status"] == "applied"

    record_local_custom_extension_mutation(
        restarted,
        identity=identity,
        state="unset",
        expected_revision=restarted.read_local_cli_revision(),
        command_states={},
        now=_NOW,
    )
    after_successful_restart = GuardStore(guard_home)
    result = apply_verified_custom_extension_continuity(
        after_successful_restart,
        _bundle(identity),
        now=_NOW,
    )
    assert result["items"][identity.cli_id]["status"] == "removed"
    assert after_successful_restart.read_local_cli_grant(identity.cli_id) is None


def test_same_revision_local_unset_tombstone_injected_after_preflight_blocks_old_cloud_apply(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    guard_home = tmp_path / "guard-home"
    store = GuardStore(guard_home)
    identity = _identity()
    _observe(store, identity)
    original_transaction = store.apply_custom_extension_continuity_transaction
    injected = False

    def _inject_tombstone(**kwargs):
        nonlocal injected
        if not injected:
            injected = True
            concurrent = GuardStore(guard_home)
            concurrent.set_sync_payload(
                "custom_extension_continuity_local_removals",
                {
                    identity.cli_id: {
                        "identity_hash": identity.identity_hash,
                        "cloud_revision": 1,
                        "removed_at": _NOW,
                    }
                },
                _NOW,
            )
        return original_transaction(**kwargs)

    monkeypatch.setattr(store, "apply_custom_extension_continuity_transaction", _inject_tombstone)
    with pytest.raises(CustomExtensionContinuityError, match="authority changed"):
        apply_verified_custom_extension_continuity(store, _bundle(identity), now=_NOW)

    restarted = GuardStore(guard_home)
    assert restarted.read_local_cli_revision() == 0
    assert restarted.read_local_cli_grant(identity.cli_id) is None
    assert restarted.get_sync_payload("custom_extension_continuity") is None
    result = apply_verified_custom_extension_continuity(restarted, _bundle(identity), now=_NOW)
    assert result["items"][identity.cli_id]["status"] == "removed"
    assert restarted.read_local_cli_grant(identity.cli_id) is None


def test_observation_hash_change_after_preflight_aborts_old_identity_apply(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    guard_home = tmp_path / "guard-home"
    store = GuardStore(guard_home)
    identity = _identity()
    changed = _identity(identity_hash="b" * 64)
    _observe(store, identity)
    original_transaction = store.apply_custom_extension_continuity_transaction
    injected = False

    def _change_observation(**kwargs):
        nonlocal injected
        if not injected:
            injected = True
            concurrent = GuardStore(guard_home)
            concurrent.record_local_cli_observation(changed, seen_at=_NOW, help_status="ok")
        return original_transaction(**kwargs)

    monkeypatch.setattr(store, "apply_custom_extension_continuity_transaction", _change_observation)
    with pytest.raises(CustomExtensionContinuityError, match="authority changed"):
        apply_verified_custom_extension_continuity(store, _bundle(identity), now=_NOW)

    restarted = GuardStore(guard_home)
    assert restarted.read_local_cli_revision() == 0
    assert restarted.read_local_cli_grant(identity.cli_id) is None
    assert restarted.get_sync_payload("custom_extension_continuity") is None
    result = apply_verified_custom_extension_continuity(restarted, _bundle(identity), now=_NOW)
    assert result["items"][identity.cli_id]["status"] == "changed_identity"
    assert restarted.read_local_cli_grant(identity.cli_id) is None
