"""Load the commands of a command-line tool Guard has only seen in use.

Tools Guard notices while it reviews agent commands are recorded by name and
identity, but their ``--help`` is never read, so they list no commands to
allow or block. This module reads that help on the operator's request, with
the same probe the Add custom extension flow uses, under tighter conditions:

* a program is found on ``PATH`` by its bare name. A script, or a file named
  like one (``deploy.sh``), is never looked up by name: it is read at the file
  an agent launched, which the hook records, or at the file a paused command
  of Guard's still names. Only a tool Guard never saw launched asks the
  operator for its full path, as Add custom extension does;
* either way, only when the file found today is the same one Guard recorded:
  the same id and identity hash. A replaced or edited file is not probed;
* new commands are merged onto the stored ones, so a probe can never remove a
  command or the choice the operator already made for it, and a failed probe
  changes nothing;
* nothing is written when the stored tool changed while its help was read, or
  when the operator cancelled first. Once writing starts, a cancel no longer
  applies, so a job that stored commands never reports itself cancelled.
"""

from __future__ import annotations

import re
import shlex
import threading
from collections.abc import Callable, Iterable, Mapping
from pathlib import Path
from typing import TYPE_CHECKING, NamedTuple, Protocol

from ..local_cli_errors import LocalCliCatalogLimitError
from ..local_cli_trust import utc_now
from ..runtime.local_cli_commands import MAX_LOCAL_CLI_COMMANDS, LocalCliCommand
from ..runtime.local_cli_identity import UnlistedCliIdentity, recognize_operator_cli
from .local_cli_api_contract import LocalCliApiError
from .local_cli_profiles_api import merge_profile_commands
from .mcp_discovery_jobs import DiscoveryStageError, begin_commit

if TYPE_CHECKING:
    from ..store import GuardStore


class DiscoverCommands(Protocol):
    def __call__(
        self,
        command: str,
        identity: UnlistedCliIdentity,
        cwd: Path,
        home_dir: Path,
        guard_home: Path,
        *,
        cancel: threading.Event | None = None,
    ) -> tuple[tuple[LocalCliCommand, ...], str, str | None]: ...


_BARE_PROGRAM_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$")
_SCRIPT_SUFFIXES = frozenset(
    {
        ".bash",
        ".bat",
        ".cmd",
        ".fish",
        ".js",
        ".mjs",
        ".cjs",
        ".ts",
        ".pl",
        ".ps1",
        ".py",
        ".rb",
        ".sh",
        ".zsh",
    }
)


class ReloadTarget(NamedTuple):
    """A recorded tool, the command Guard reads its --help through, and the file it runs."""

    identity: UnlistedCliIdentity
    command: str
    path: str | None = None


_MAX_PATH_LENGTH = 4096


def verified_cli_for_reload(
    item: Mapping[str, object],
    *,
    home_dir: Path,
    path: object = None,
    launched_paths: Callable[[], Iterable[str]] = tuple,
) -> ReloadTarget:
    """Return the stored tool's identity, re-derived from where it runs, or refuse.

    ``path`` is the operator's. Without it Guard tries the file it recorded an
    agent launching, then ``launched_paths`` (files its paused commands name,
    read only when needed), and finds a plain program by name on ``PATH``.
    No process starts here. Refusals carry a message the dashboard shows as is.
    """

    name = item.get("name")
    label = name if isinstance(name, str) and name else "this tool"
    if path is not None:
        return _verified_at_path(item, label, path, home_dir=home_dir)
    if (
        item.get("kind") != "executable"
        or not isinstance(name, str)
        or _BARE_PROGRAM_NAME.fullmatch(name) is None
        or Path(name).suffix.lower() in _SCRIPT_SUFFIXES
    ):
        launched = _verified_at_launch(item, label, launched_paths, home_dir=home_dir)
        if launched is None:
            raise LocalCliApiError(
                400,
                "cli_reload_needs_path",
                f"Guard has not seen where {label} is saved yet. It learns the path the next time an agent "
                "runs it, or enter its full path now.",
            )
        return launched
    try:
        return _verified_on_path(item, name, label, home_dir=home_dir)
    except LocalCliApiError as missed:
        # Guard's PATH can miss a program the agent ran from its own PATH. The
        # file Guard saw launched replaces that refusal only when it verifies;
        # otherwise the PATH refusal is the accurate one to show.
        try:
            launched = _verified_at_launch(item, label, launched_paths, home_dir=home_dir)
        except LocalCliApiError:
            raise missed from None
        if launched is None:
            raise
        return launched


def _verified_at_launch(
    item: Mapping[str, object],
    label: str,
    launched_paths: Callable[[], Iterable[str]],
    *,
    home_dir: Path,
) -> ReloadTarget | None:
    """The first file Guard saw launched that is still the recorded tool, or ``None``.

    A file that is there but changed refuses, so the operator learns why
    instead of being asked for a path Guard already knows.
    """

    changed: LocalCliApiError | None = None
    for candidate in _launch_candidates(item, launched_paths):
        try:
            return _verified_at_path(item, label, candidate, home_dir=home_dir)
        except LocalCliApiError as refused:
            if refused.code == "cli_identity_changed" and changed is None:
                changed = refused
    if changed is not None:
        raise changed
    return None


def _launch_candidates(item: Mapping[str, object], launched_paths: Callable[[], Iterable[str]]) -> Iterable[str]:
    recorded = item.get("source_path")
    tried: set[str] = set()
    if isinstance(recorded, str) and Path(recorded).is_absolute():
        tried.add(recorded)
        yield recorded
    for candidate in launched_paths():
        if candidate not in tried:
            tried.add(candidate)
            yield candidate


def _verified_on_path(item: Mapping[str, object], name: str, label: str, *, home_dir: Path) -> ReloadTarget:
    identity, _, _ = recognize_operator_cli(name, cwd=home_dir, home_dir=home_dir)
    if identity is None:
        # Guard's PATH can differ from the agent shell's, so a missing tool is
        # not evidence that it was removed.
        raise LocalCliApiError(
            409,
            "cli_not_on_guard_path",
            f"Guard cannot find {name} on its own PATH, which can differ from your agent's. "
            "Enter its full path to load its commands.",
        )
    _require_recorded(item, identity, label, found_on="Guard finds on its PATH")
    return ReloadTarget(identity, name)


def _verified_at_path(item: Mapping[str, object], label: str, path: object, *, home_dir: Path) -> ReloadTarget:
    if (
        not isinstance(path, str)
        or not path.strip()
        or len(path) > _MAX_PATH_LENGTH
        or any(character in path for character in "\x00\r\n")
    ):
        raise LocalCliApiError(400, "cli_path_invalid", f"Enter the full path to {label}.")
    location = path.strip()
    if not (location.startswith("/") or location.startswith("~/") or Path(location).is_absolute()):
        raise LocalCliApiError(
            400,
            "cli_path_invalid",
            f"Enter the full path to {label}, starting with / or ~/.",
        )
    # Quoting keeps a path with spaces whole, but would also stop ``~`` from
    # expanding, so the home directory is filled in first.
    resolved = str(home_dir / location[2:]) if location.startswith("~/") else location
    command = shlex.quote(resolved)
    interpreter = item.get("interpreter_name")
    if item.get("kind") == "script" and isinstance(interpreter, str) and interpreter:
        # A script recorded through its interpreter keeps that launch, or it
        # would be found again as a different tool.
        command = f"{shlex.quote(interpreter)} {command}"
    identity, _, _ = recognize_operator_cli(command, cwd=home_dir, home_dir=home_dir)
    if identity is None:
        raise LocalCliApiError(
            400,
            "cli_path_not_found",
            f"Guard cannot find a program it can run at {location}. Check the path and try again.",
        )
    _require_recorded(item, identity, label, found_on="at this path")
    return ReloadTarget(identity, command, resolved)


def _require_recorded(item: Mapping[str, object], identity: UnlistedCliIdentity, label: str, *, found_on: str) -> None:
    if (
        identity.kind != item.get("kind")
        or identity.runner is not None
        or identity.cli_id != item.get("cli_id")
        or identity.identity_hash != item.get("identity_hash")
    ):
        raise LocalCliApiError(
            409,
            "cli_identity_changed",
            f"The {label} {found_on} is not the one Guard recorded. It is another file, or it has changed "
            "since Guard last saw it.",
        )


def load_cli_commands(
    store: GuardStore,
    target: ReloadTarget,
    *,
    discover: DiscoverCommands,
    home_dir: Path,
    guard_home: Path,
    cancel: threading.Event,
) -> None:
    """Read the target's --help and add any new commands to its catalog."""

    identity = target.identity
    # The probe re-resolves the command and only runs a program whose id, kind
    # and identity hash still match, so a binary swapped after the check
    # above is not run.
    # A cancel also stops the probe from starting any further --help runs.
    commands, help_status, _ = discover(target.command, identity, home_dir, home_dir, guard_home, cancel=cancel)
    if cancel.is_set():
        return
    if help_status == "failed":
        raise DiscoveryStageError("cli_help_unreadable")
    stored = next((item for item in store.list_local_cli_items() if item.get("cli_id") == identity.cli_id), None)
    if stored is None or stored.get("identity_hash") != identity.identity_hash:
        # The tool was found again as a different program while its help was
        # read. These commands describe the old one.
        raise DiscoveryStageError("cli_identity_changed")
    if not begin_commit(cancel):
        return
    try:
        store.merge_local_cli_commands(
            identity.cli_id,
            merge_profile_commands(identity.name, commands),
            limit=MAX_LOCAL_CLI_COMMANDS,
        )
    except LocalCliCatalogLimitError:
        raise DiscoveryStageError("catalog_limit_reached") from None
    store.record_local_cli_observation(
        identity,
        seen_at=utc_now(),
        # The file whose help was read, so the next load needs no path either.
        source_path=target.path,
        help_status=help_status,
        surface="cli",
    )
