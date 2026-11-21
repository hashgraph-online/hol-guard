"""Curated command trees for popular CLIs offered as custom extensions.

The native runtime owns the profiles and the executable lookup
(``cli_profiles.rs``); this module carries its answer as typed rows. A profile
only describes commands and suggests a starting rule for each one, so a
runtime that cannot answer offers no profile rather than a guessed one.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
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


@lru_cache(maxsize=4)
def _profiles(guard_home: Path | None = None) -> tuple[KnownCliProfile, ...]:
    from ..native_runner_authority import native_runner_authority

    rows = native_runner_authority(_KIND, {}, guard_home=guard_home).get("profiles")
    return tuple(_profile(row) for row in cast("list[dict[str, object]]", rows))


def known_cli_profiles() -> tuple[KnownCliProfile, ...]:
    """Every curated profile, or none while the runtime cannot answer (never cached)."""

    from ..native_runner_authority import NativeRunnerAuthorityError

    try:
        return _profiles()
    except (NativeRunnerAuthorityError, KeyError, TypeError):
        return ()


# A listing is answered in chunks no longer than the runtime accepts.
_LOOKUP_CHUNK = 1024


class CliProfileUnavailableError(RuntimeError):
    """The runtime could not say which names launch a profiled CLI."""


def profiles_for_executables(
    names: Sequence[object], *, guard_home: Path | None = None
) -> tuple[KnownCliProfile | None, ...]:
    """The profile each name launches, in one runtime call per chunk.

    Raises ``CliProfileUnavailableError`` when the runtime cannot answer, so a
    caller that must not guess can tell an outage from a name with no profile.
    ``guard_home`` is the home whose resident answers.
    """

    from ..native_runner_authority import NativeRunnerAuthorityError, native_runner_authority

    unique = list(dict.fromkeys(name for name in names if isinstance(name, str)))
    found: dict[str, str | None] = {}
    try:
        for offset in range(0, len(unique), _LOOKUP_CHUNK):
            chunk = unique[offset : offset + _LOOKUP_CHUNK]
            ids = native_runner_authority(_KIND, {"executables": chunk}, guard_home=guard_home).get("profile_ids")
            if not isinstance(ids, list) or len(ids) != len(chunk):
                raise CliProfileUnavailableError(_KIND)
            found.update(zip(chunk, (value if isinstance(value, str) else None for value in ids), strict=True))
        by_id = {profile.profile_id: profile for profile in _profiles(guard_home)} if any(found.values()) else {}
    except (NativeRunnerAuthorityError, KeyError, TypeError) as error:
        raise CliProfileUnavailableError(_KIND) from error
    return tuple(by_id.get(found.get(name) or "") if isinstance(name, str) else None for name in names)


def profile_for_executable(name: object) -> KnownCliProfile | None:
    """The profile ``name`` launches, or none while the runtime cannot answer."""

    try:
        return profiles_for_executables([name])[0]
    except CliProfileUnavailableError:
        return None


__all__ = [
    "CliProfileUnavailableError",
    "KnownCliProfile",
    "ProfileCommand",
    "known_cli_profiles",
    "profile_for_executable",
    "profiles_for_executables",
]
