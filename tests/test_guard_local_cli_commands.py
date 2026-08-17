from __future__ import annotations

from pathlib import Path

from codex_plugin_scanner.guard.local_cli_trust import matching_local_cli_grant, utc_now
from codex_plugin_scanner.guard.runtime.local_cli_commands import LocalCliCommand
from codex_plugin_scanner.guard.runtime.local_cli_identity import identify_unlisted_cli
from codex_plugin_scanner.guard.store import GuardStore


def _identity(tmp_path: Path):
    script = tmp_path / "ship.py"
    script.write_text("print('ok')\n", encoding="utf-8")
    identity = identify_unlisted_cli(f"python3 {script} deploy", cwd=tmp_path, home_dir=tmp_path)
    assert identity is not None
    return script, identity


def test_legacy_allow_without_catalog_still_allows(tmp_path: Path) -> None:
    home = tmp_path / "home"
    home.mkdir()
    store = GuardStore(home)
    script, identity = _identity(tmp_path)
    store.record_local_cli_observation(identity, seen_at=utc_now())
    store.upsert_local_cli_grant(identity=identity, state="allowed", expected_revision=0, updated_at=utc_now())
    matched = matching_local_cli_grant(
        store=store,
        command=f"python3 {script} deploy",
        cwd=tmp_path,
        home_dir=tmp_path,
        current_action="review",
    )
    assert matched is not None
    assert matched[1] == "allowed"


def test_recommended_command_does_not_override_review(tmp_path: Path) -> None:
    home = tmp_path / "home"
    home.mkdir()
    store = GuardStore(home)
    script, identity = _identity(tmp_path)
    store.record_local_cli_observation(identity, seen_at=utc_now())
    store.replace_local_cli_commands(
        identity.cli_id,
        (
            LocalCliCommand("root", "ship.py", "ship.py", "root"),
            LocalCliCommand("deploy", "deploy", "deploy", "Ship it"),
            LocalCliCommand("other", "Other commands", "ship.py …", "other"),
        ),
    )
    store.upsert_local_cli_grant(identity=identity, state="allowed", expected_revision=0, updated_at=utc_now())
    matched = matching_local_cli_grant(
        store=store,
        command=f"python3 {script} deploy",
        cwd=tmp_path,
        home_dir=tmp_path,
        current_action="review",
    )
    assert matched is None


def test_allowed_subcommand_overrides_review(tmp_path: Path) -> None:
    home = tmp_path / "home"
    home.mkdir()
    store = GuardStore(home)
    script, identity = _identity(tmp_path)
    store.record_local_cli_observation(identity, seen_at=utc_now())
    store.replace_local_cli_commands(
        identity.cli_id,
        (
            LocalCliCommand("root", "ship.py", "ship.py", "root"),
            LocalCliCommand("deploy", "deploy", "deploy", "Ship it"),
            LocalCliCommand("other", "Other commands", "ship.py …", "other"),
        ),
    )
    store.upsert_local_cli_grant(identity=identity, state="allowed", expected_revision=0, updated_at=utc_now())
    store.upsert_local_cli_command_states(identity.cli_id, {"deploy": "allow"})
    matched = matching_local_cli_grant(
        store=store,
        command=f"python3 {script} deploy --yes",
        cwd=tmp_path,
        home_dir=tmp_path,
        current_action="review",
    )
    assert matched is not None
    assert matched[1] == "allowed"


def test_blocked_subcommand_blocks_review(tmp_path: Path) -> None:
    home = tmp_path / "home"
    home.mkdir()
    store = GuardStore(home)
    script, identity = _identity(tmp_path)
    store.record_local_cli_observation(identity, seen_at=utc_now())
    store.replace_local_cli_commands(
        identity.cli_id,
        (
            LocalCliCommand("root", "ship.py", "ship.py", "root"),
            LocalCliCommand("deploy", "deploy", "deploy", "Ship it"),
            LocalCliCommand("other", "Other commands", "ship.py …", "other"),
        ),
    )
    store.upsert_local_cli_grant(identity=identity, state="allowed", expected_revision=0, updated_at=utc_now())
    store.upsert_local_cli_command_states(identity.cli_id, {"deploy": "block"})
    matched = matching_local_cli_grant(
        store=store,
        command=f"python3 {script} deploy",
        cwd=tmp_path,
        home_dir=tmp_path,
        current_action="review",
    )
    assert matched is not None
    assert matched[1] == "blocked"
