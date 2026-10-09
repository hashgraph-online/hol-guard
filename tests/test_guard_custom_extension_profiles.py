from __future__ import annotations

import pytest

from codex_plugin_scanner.guard.daemon.local_cli_profiles_api import (
    annotate_cli_profiles,
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


def test_wrangler_suggestions_review_writes_and_allow_reads_only() -> None:
    suggested = WRANGLER_PROFILE.suggested_states()

    for command_id in ("deploy", "versions.deploy", "secret.put", "d1.execute", "r2.object.delete", "login"):
        assert suggested[command_id] == "review"
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
    assert by_id["deploy"]["suggested_state"] == "review"
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
    assert annotated["commands"] == [
        {"command_id": "deploy", "state": "allow", "suggested_state": "review"},
        {"command_id": "root", "state": "inherit"},
    ]
    assert "profile_id" not in items[1]
    assert detected["commands"][0] == {"command_id": "deploy", "state": "allow"}
