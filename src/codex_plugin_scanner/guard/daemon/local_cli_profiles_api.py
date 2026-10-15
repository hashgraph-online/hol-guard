"""Apply curated CLI profiles to custom extension list and recognize payloads."""

from __future__ import annotations

import hashlib
import re
from collections.abc import Iterable, Mapping, Sequence

from ..runtime.custom_extension_profiles import (
    KNOWN_CLI_PROFILES,
    KnownCliProfile,
    profile_for_executable,
)
from ..runtime.local_cli_commands import (
    OTHER_COMMAND_ID,
    ROOT_COMMAND_ID,
    LocalCliCommand,
    merge_discovered_commands,
)
from ..runtime.local_cli_runner import runner_name, runner_target

SEEDED_PROFILE_PREFIX = "local-cli.profile-"
_VERSION_OR_TAG = re.compile(r"[A-Za-z0-9.^~<>=*+_-]+")


def seeded_profile_cli_id(profile: KnownCliProfile) -> str:
    return f"{SEEDED_PROFILE_PREFIX}{profile.profile_id}"


def merge_profile_commands(tool_name: str, discovered: Sequence[LocalCliCommand]) -> tuple[LocalCliCommand, ...]:
    """Fill the catalog with curated profile commands after help-discovered ones.

    Discovered commands go first so the catalog limit never evicts them; the
    profile only fills the remaining slots.
    """

    profile = profile_for_executable(tool_name)
    if profile is None:
        return tuple(discovered)
    return merge_discovered_commands(tool_name, (*discovered, *profile.local_cli_commands()))


def profiled_cli_package_launch(tokens: Sequence[str]) -> bool:
    """Return True when a package runner directly launches a profiled CLI.

    ``npx wrangler`` is a CLI call, not an MCP server; probing it over stdio
    would spawn the CLI and then reject the paste as a built-in launcher.
    Selector forms (``npx --package wrangler other``) and scoped packages
    (``@other/wrangler``) are not the profiled CLI, so they keep MCP discovery.
    """

    if not tokens:
        return False
    runner = runner_name(tokens[0])
    target = runner_target(runner, tuple(tokens[1:])) if runner is not None else None
    if target is None:
        return False
    package_name, _, version_spec = target.rpartition("@") if target.rfind("@") > 0 else (target, "", "")
    # ``wrangler@npm:other`` or a URL spec can install a different package.
    if version_spec and not _VERSION_OR_TAG.fullmatch(version_spec):
        return False
    return profile_for_executable(package_name) is not None


_MCP_CLI_ID_PREFIX = "local-cli.mcp-"
_DEFAULT_COMMAND_IDS = frozenset({ROOT_COMMAND_ID, OTHER_COMMAND_ID})


def profile_catalog_seed(cli_id: str, tool_name: str) -> tuple[LocalCliCommand, ...]:
    """Return the curated catalog to store for a profiled CLI, or nothing.

    CLIs detected from hook traffic have no stored commands yet, and saving a
    rule for an unknown command id is rejected. The apply transaction stores
    this seed only while the catalog holds just the default commands, so
    existing commands and the rules covering them are never replaced. MCP
    servers are skipped: their name comes from user config.
    """

    if cli_id.startswith(_MCP_CLI_ID_PREFIX):
        return ()
    profile = profile_for_executable(tool_name)
    if profile is None:
        return ()
    return merge_discovered_commands(tool_name, profile.local_cli_commands())


def is_default_catalog(command_ids: Iterable[object]) -> bool:
    """True when a catalog holds no commands beyond the default root and other."""

    return all(command_id in _DEFAULT_COMMAND_IDS for command_id in command_ids)


def annotate_cli_profiles(items: list[dict[str, object]]) -> list[dict[str, object]]:
    """Copy profile metadata and suggested command states onto matching CLI items."""

    annotated: list[dict[str, object]] = []
    for item in items:
        profile = _item_profile(item)
        annotated.append(item if profile is None else _annotated(item, profile))
    return annotated


def seeded_profile_items(items: list[dict[str, object]], *, authority_revision: int) -> list[dict[str, object]]:
    """Return setup rows for profiles with no matching listed CLI yet.

    Seeded rows are kept out of ``items`` because they have no stored
    observation or grant; they only open the trust-gated add flow.
    """

    matched = {profile.profile_id for item in items if (profile := _item_profile(item)) is not None}
    return [
        _seeded_item(profile, authority_revision=authority_revision)
        for profile in KNOWN_CLI_PROFILES
        if profile.profile_id not in matched
    ]


def _item_profile(item: dict[str, object]) -> KnownCliProfile | None:
    if item.get("surface") != "cli":
        return None
    return profile_for_executable(item.get("name"))


def _annotated(item: dict[str, object], profile: KnownCliProfile) -> dict[str, object]:
    suggested = profile.suggested_states()
    commands = item.get("commands")
    annotated = dict(item)
    annotated.update(profile_id=profile.profile_id, brand=profile.brand, display_name=profile.display_name)
    listed = [command for command in commands if isinstance(command, dict)] if isinstance(commands, list) else []
    known = {command.get("command_id") for command in listed}
    if is_default_catalog(known):
        # Match the seed the apply transaction stores, so every shown
        # suggestion can be saved. Stored catalogs are shown as they are.
        seed = profile_catalog_seed(str(item.get("cli_id") or ""), str(item.get("name") or ""))
        by_id = {command.get("command_id"): command for command in listed}
        listed = [by_id.get(command.command_id) or command.to_dict() for command in seed]
    annotated["commands"] = [_with_suggestion(command, suggested) for command in listed]
    return annotated


def _with_suggestion(command: object, suggested: Mapping[str, str]) -> object:
    if not isinstance(command, dict):
        return command
    state = suggested.get(str(command.get("command_id")))
    return command if state is None else {**command, "suggested_state": state}


def _seeded_item(profile: KnownCliProfile, *, authority_revision: int) -> dict[str, object]:
    executable = sorted(profile.executables)[0]
    commands = merge_discovered_commands(executable, profile.local_cli_commands())
    suggested = profile.suggested_states()
    return {
        "cli_id": seeded_profile_cli_id(profile),
        "identity_hash": hashlib.sha256(f"hol-guard:seeded-profile:{profile.profile_id}".encode()).hexdigest(),
        "kind": "executable",
        "name": executable,
        "interpreter_name": None,
        "example_label": executable,
        "observed_count": 0,
        "last_seen_at": None,
        "source_path": None,
        "help_status": None,
        "surface": "cli",
        "server_identity_hash": None,
        "source_label": None,
        "state": "unset",
        "stale": False,
        "grant_revision": None,
        "authority_revision": authority_revision,
        "suggestion_score": 0,
        "suggestable": False,
        "seeded": True,
        "installed": False,
        "profile_id": profile.profile_id,
        "brand": profile.brand,
        "display_name": profile.display_name,
        "commands": [_with_suggestion(command.to_dict(), suggested) for command in commands],
    }


__all__ = [
    "SEEDED_PROFILE_PREFIX",
    "annotate_cli_profiles",
    "is_default_catalog",
    "merge_profile_commands",
    "profile_catalog_seed",
    "seeded_profile_cli_id",
    "seeded_profile_items",
]
