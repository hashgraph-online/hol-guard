"""Apply curated CLI profiles to custom extension list and recognize payloads."""

from __future__ import annotations

import hashlib
from collections.abc import Mapping, Sequence
from typing import TYPE_CHECKING

from ..runtime.custom_extension_profiles import (
    KNOWN_CLI_PROFILES,
    KnownCliProfile,
    profile_for_executable,
)
from ..runtime.local_cli_commands import LocalCliCommand, merge_discovered_commands

if TYPE_CHECKING:
    from ..store import GuardStore

SEEDED_PROFILE_PREFIX = "local-cli.profile-"


def seeded_profile_cli_id(profile: KnownCliProfile) -> str:
    return f"{SEEDED_PROFILE_PREFIX}{profile.profile_id}"


def merge_profile_commands(tool_name: str, discovered: Sequence[LocalCliCommand]) -> tuple[LocalCliCommand, ...]:
    """Put curated profile commands ahead of help-discovered ones for known CLIs."""

    profile = profile_for_executable(tool_name)
    if profile is None:
        return tuple(discovered)
    return merge_discovered_commands(tool_name, (*profile.local_cli_commands(), *discovered))


_MCP_CLI_ID_PREFIX = "local-cli.mcp-"


def ensure_profile_catalog(store: GuardStore, cli_id: str, tool_name: str) -> None:
    """Store a profiled CLI's curated commands so suggested rules can be saved.

    CLIs detected from hook traffic have no stored commands yet, and saving a
    rule for an unknown command id is rejected. MCP servers are skipped: their
    name comes from user config, and merging CLI commands would crowd out
    their tools and drop saved tool rules.
    """

    if cli_id.startswith(_MCP_CLI_ID_PREFIX):
        return
    profile = profile_for_executable(tool_name)
    if profile is None:
        return
    existing = store.read_local_cli_command_catalog(cli_id)
    known = {command.command_id for command in existing}
    if all(entry.command.command_id in known for entry in profile.commands):
        return
    store.replace_local_cli_commands(cli_id, merge_profile_commands(tool_name, existing))


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
    missing = [entry.command.to_dict() for entry in profile.commands if entry.command.command_id not in known]
    annotated["commands"] = [_with_suggestion(command, suggested) for command in (*listed, *missing)]
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
    "ensure_profile_catalog",
    "merge_profile_commands",
    "seeded_profile_cli_id",
    "seeded_profile_items",
]
