"""Curated command trees for popular CLIs offered as custom extensions.

The native runtime owns the profiles and the executable lookup
(``cli_profiles.rs``); this module carries its answer as typed rows. A profile
only describes commands and suggests a starting rule for each one, so a
runtime that cannot answer offers no profile rather than a guessed one.
"""

from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
from typing import cast

from .local_cli_commands import LocalCliCommand, LocalCliCommandState

_KIND = "cli_profiles"


@dataclass(frozen=True, slots=True)
class ProfileCommand:
    command: LocalCliCommand
    suggested_state: LocalCliCommandState = "inherit"


@dataclass(frozen=True, slots=True)
class KnownCliProfile:
    profile_id: str
    display_name: str
    brand: str
    homepage: str
    executables: frozenset[str]
    commands: tuple[ProfileCommand, ...]

    def suggested_states(self) -> dict[str, LocalCliCommandState]:
        return {entry.command.command_id: entry.suggested_state for entry in self.commands}

    def local_cli_commands(self) -> tuple[LocalCliCommand, ...]:
        return tuple(entry.command for entry in self.commands)


def _profile(row: dict[str, object]) -> KnownCliProfile:
    commands = cast("list[dict[str, object]]", row["commands"])
    return KnownCliProfile(
        profile_id=str(row["profile_id"]),
        display_name=str(row["display_name"]),
        brand=str(row["brand"]),
        homepage=str(row["homepage"]),
        executables=frozenset(str(name) for name in cast("list[object]", row["executables"])),
        commands=tuple(
            ProfileCommand(
                LocalCliCommand(
                    command_id=str(command["command_id"]),
                    name=str(command["name"]),
                    usage=str(command["usage"]),
                    description=str(command["description"]),
                    parent_id=cast("str | None", command["parent_id"]),
                ),
                cast("LocalCliCommandState", command["suggested_state"]),
            )
            for command in commands
        ),
    )


@lru_cache(maxsize=1)
def _profiles() -> tuple[KnownCliProfile, ...]:
    from ..native_runner_authority import native_runner_authority

    rows = native_runner_authority(_KIND, {}).get("profiles")
    return tuple(_profile(row) for row in cast("list[dict[str, object]]", rows))


def known_cli_profiles() -> tuple[KnownCliProfile, ...]:
    """Every curated profile, or none while the runtime cannot answer (never cached)."""

    from ..native_runner_authority import NativeRunnerAuthorityError

    try:
        return _profiles()
    except (NativeRunnerAuthorityError, KeyError, TypeError):
        return ()


@lru_cache(maxsize=256)
def _profile_id(name: str) -> str | None:
    from ..native_runner_authority import native_runner_authority

    profile_id = native_runner_authority(_KIND, {"executable": name}).get("profile_id")
    return profile_id if isinstance(profile_id, str) else None


def profile_for_executable(name: object) -> KnownCliProfile | None:
    if not isinstance(name, str):
        return None
    from ..native_runner_authority import NativeRunnerAuthorityError

    try:
        profile_id = _profile_id(name)
    except NativeRunnerAuthorityError:
        return None
    return next((profile for profile in known_cli_profiles() if profile.profile_id == profile_id), None)


__all__ = [
    "KnownCliProfile",
    "ProfileCommand",
    "known_cli_profiles",
    "profile_for_executable",
]
