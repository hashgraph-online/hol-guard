from __future__ import annotations

import pytest

from codex_plugin_scanner.guard.daemon.local_cli_profiles_api import (
    annotate_cli_profiles,
    ensure_profile_catalog,
    merge_profile_commands,
    seeded_profile_cli_id,
    seeded_profile_items,
)
from codex_plugin_scanner.guard.runtime.custom_extension_profiles import (
    KNOWN_CLI_PROFILES,
    WRANGLER_PROFILE,
    profile_for_executable,
)
from codex_plugin_scanner.guard.runtime.local_cli_commands import (
    MAX_LOCAL_CLI_COMMANDS,
    OTHER_COMMAND_ID,
    ROOT_COMMAND_ID,
    LocalCliCommand,
    default_local_cli_commands,
    is_local_cli_command_id,
    match_command_id,
)
from codex_plugin_scanner.guard.runtime.local_cli_identity import catalog_owned_executables, is_local_cli_id


@pytest.mark.parametrize("profile", KNOWN_CLI_PROFILES, ids=lambda profile: profile.profile_id)
def test_profile_command_tree_is_valid(profile) -> None:
    ids = [entry.command.command_id for entry in profile.commands]

    assert len(ids) == len(set(ids))
    assert ROOT_COMMAND_ID not in ids and OTHER_COMMAND_ID not in ids
    assert len(ids) + 2 <= MAX_LOCAL_CLI_COMMANDS
    for entry in profile.commands:
        assert is_local_cli_command_id(entry.command.command_id)
        assert entry.command.parent_id is None or entry.command.parent_id in ids
    assert is_local_cli_id(seeded_profile_cli_id(profile))
    assert not profile.executables & catalog_owned_executables()


def test_wrangler_suggestions_leave_writes_to_guard_and_allow_reads_only() -> None:
    suggested = WRANGLER_PROFILE.suggested_states()

    # CLI commands cannot store an explicit review rule; inherit keeps them on
    # Guard's default review for commands it cannot prove read-only.
    assert set(suggested.values()) <= {"inherit", "allow"}
    for command_id in ("deploy", "versions.deploy", "secret.put", "d1.execute", "r2.object.delete", "login"):
        assert suggested[command_id] == "inherit"
    for command_id in ("whoami", "deployments.list", "d1.list", "kv.key.list"):
        assert suggested[command_id] == "allow"
    assert suggested["d1"] == "inherit"


@pytest.mark.parametrize(
    ("tokens", "expected"),
    [
        (("d1", "migrations", "apply"), "d1.migrations.apply"),
        (("kv", "key", "get", "x"), "kv.key"),
        (("versions", "secret", "put", "TOKEN"), "versions.secret.put"),
        (("kv:namespace", "list"), OTHER_COMMAND_ID),
        ((), ROOT_COMMAND_ID),
    ],
)
def test_wrangler_tokens_match_profile_ids(tokens: tuple[str, ...], expected: str) -> None:
    commands = merge_profile_commands("wrangler", default_local_cli_commands("wrangler"))

    assert match_command_id(tokens, commands) == expected


def test_profile_for_executable_accepts_windows_shims() -> None:
    assert profile_for_executable("wrangler.CMD") is WRANGLER_PROFILE
    assert profile_for_executable("wrangle") is None
    assert profile_for_executable(None) is None


def test_merge_profile_commands_keeps_profile_first_and_discovered_extras() -> None:
    discovered = (
        *default_local_cli_commands("wrangler"),
        LocalCliCommand(command_id="deploy", name="deploy", usage="wrangler deploy", description="help text"),
        LocalCliCommand(command_id="hyperdrive", name="hyperdrive", usage="wrangler hyperdrive", description=""),
    )

    merged = merge_profile_commands("wrangler", discovered)
    ids = [command.command_id for command in merged]

    assert ids[0] == ROOT_COMMAND_ID and ids[-1] == OTHER_COMMAND_ID
    assert ids.count("deploy") == 1
    deploy = next(command for command in merged if command.command_id == "deploy")
    assert deploy.description == "Deploy the Worker to Cloudflare."
    assert "hyperdrive" in ids
    assert merge_profile_commands("gh", discovered) == discovered


def test_apply_cli_profiles_seeds_placeholder_when_wrangler_unseen() -> None:
    other = {"cli_id": "local-cli.gh-1234abcd", "name": "gh", "surface": "cli", "commands": []}

    assert annotate_cli_profiles([other]) == [other]
    [seeded] = seeded_profile_items([other], authority_revision=7)

    assert seeded["cli_id"] == "local-cli.profile-wrangler"
    assert seeded["seeded"] is True and seeded["installed"] is False
    assert seeded["state"] == "unset" and seeded["suggestable"] is False
    assert seeded["authority_revision"] == 7
    assert len(str(seeded["identity_hash"])) == 64
    commands = seeded["commands"]
    assert isinstance(commands, list)
    by_id = {command["command_id"]: command for command in commands}
    assert by_id[ROOT_COMMAND_ID]["state"] == "inherit" and "suggested_state" not in by_id[ROOT_COMMAND_ID]
    assert by_id["whoami"]["suggested_state"] == "allow"
    assert by_id["deploy"]["state"] == "inherit"


def test_apply_cli_profiles_annotates_detected_wrangler_without_placeholder() -> None:
    detected = {
        "cli_id": "local-cli.wrangler-1234abcd",
        "name": "wrangler",
        "surface": "cli",
        "commands": [{"command_id": "deploy", "state": "allow"}, {"command_id": "root", "state": "inherit"}],
    }
    mcp = {"cli_id": "local-cli.mcp-1234abcd", "name": "wrangler", "surface": "mcp", "commands": []}

    items = annotate_cli_profiles([detected, mcp])

    assert [item["cli_id"] for item in items] == ["local-cli.wrangler-1234abcd", "local-cli.mcp-1234abcd"]
    assert seeded_profile_items(items, authority_revision=1) == []
    annotated = items[0]
    assert annotated["brand"] == "cloudflare" and annotated["display_name"] == "Cloudflare Wrangler"
    commands = annotated["commands"]
    assert isinstance(commands, list)
    assert commands[:2] == [
        {"command_id": "deploy", "state": "allow", "suggested_state": "inherit"},
        {"command_id": "root", "state": "inherit"},
    ]
    by_id = {command["command_id"]: command for command in commands}
    assert by_id["whoami"]["state"] == "inherit" and by_id["whoami"]["suggested_state"] == "allow"
    assert len(by_id) == len(commands)
    assert "profile_id" not in items[1]
    assert detected["commands"][0] == {"command_id": "deploy", "state": "allow"}


def test_detected_wrangler_without_stored_commands_gets_profile_suggestions() -> None:
    detected = {"cli_id": "local-cli.wrangler-1234abcd", "name": "wrangler", "surface": "cli", "commands": []}

    [annotated] = annotate_cli_profiles([detected])

    commands = annotated["commands"]
    assert isinstance(commands, list)
    by_id = {command["command_id"]: command for command in commands}
    assert by_id["whoami"]["suggested_state"] == "allow"
    assert by_id["deploy"]["state"] == "inherit"


class _CatalogStore:
    def __init__(self, commands: tuple[LocalCliCommand, ...]) -> None:
        self.commands = commands
        self.writes = 0

    def read_local_cli_command_catalog(self, cli_id: str) -> list[LocalCliCommand]:
        return list(self.commands)

    def replace_local_cli_commands(self, cli_id: str, commands: tuple[LocalCliCommand, ...]) -> None:
        self.commands = commands
        self.writes += 1


def test_ensure_profile_catalog_stores_profile_commands_once() -> None:
    extra = LocalCliCommand(command_id="hyperdrive", name="hyperdrive", usage="wrangler hyperdrive", description="")
    store = _CatalogStore((*default_local_cli_commands("wrangler"), extra))

    ensure_profile_catalog(store, "local-cli.wrangler-1234abcd", "wrangler")  # type: ignore[arg-type]
    ensure_profile_catalog(store, "local-cli.wrangler-1234abcd", "wrangler")  # type: ignore[arg-type]
    ensure_profile_catalog(store, "local-cli.gh-1234abcd", "gh")  # type: ignore[arg-type]

    ids = {command.command_id for command in store.commands}
    assert store.writes == 1
    assert {"whoami", "deploy", "hyperdrive", ROOT_COMMAND_ID, OTHER_COMMAND_ID} <= ids
