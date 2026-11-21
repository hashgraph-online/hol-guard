"""``hol-guard codebases add`` and ``hol-guard codebases list``.

``add`` admits a folder for background checks, as choosing it under Supply Chain,
then Workspaces in ``hol-guard dashboard`` does: the daemon checks it and receipt
sync sends the result to Guard Cloud's Codebases page. There is no ``remove``:
a command an agent can run may widen what Guard checks but never narrow it, so
pausing a codebase stays in the dashboard.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import TYPE_CHECKING, TextIO

if TYPE_CHECKING:
    from ..config import GuardConfig
    from ..store import GuardStore
    from ..workspace_assessment_store import WorktreeKeys

_ADMISSION_ERRORS: dict[str, str] = {
    "workspace_root_missing": "That folder does not exist.",
    "workspace_root_not_directory": "That path is not a folder.",
    "workspace_snapshot_native_unavailable": (
        "Guard's native runtime is not available on this machine, so it cannot check codebases. "
        "Run `hol-guard doctor` to repair it."
    ),
}


def configure_codebases_parser(guard_subparsers: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    from ...argparse_utils import FriendlyArgumentParser
    from .commands_parser_helpers import _add_guard_common_args

    parser = guard_subparsers.add_parser("codebases", help="Add codebases for Guard to check in the background")
    _add_guard_common_args(parser)
    parser.add_argument("--json", action="store_true")
    subparsers = parser.add_subparsers(dest="codebases_command", required=True, parser_class=FriendlyArgumentParser)
    add_parser = subparsers.add_parser(
        "add",
        help="Check a codebase in the background and send the results to Guard Cloud",
    )
    add_parser.add_argument(
        "path",
        nargs="?",
        help="Folder to check (default: the Git repository holding the current folder, or the current folder)",
    )
    list_parser = subparsers.add_parser("list", help="List the codebases Guard checks on this machine")
    for subparser in (add_parser, list_parser):
        options = len(subparser._actions)
        _add_guard_common_args(subparser)
        subparser.add_argument("--json", action="store_true")
        # The options are accepted on either side of the subcommand. argparse copies every
        # subparser default over the parent's namespace, so an option given before
        # `add`/`list` would be reset unless the repeated options leave absent values unset.
        for action in subparser._actions[options:]:
            action.default = argparse.SUPPRESS


def default_codebase_root(start: Path) -> Path:
    """The nearest folder at or above ``start`` holding ``.git``, else ``start``."""

    for folder in (start, *start.parents):
        if (folder / ".git").exists():
            return folder
    return start


def _write(stream: TextIO | None, payload: dict[str, object], text: str, *, as_json: bool) -> None:
    target = stream or sys.stdout
    target.write(json.dumps(payload, sort_keys=True) + "\n" if as_json else text + "\n")


def _checks_off_note(config: GuardConfig | None) -> str | None:
    if config is None or config.workspace_assessment_enabled:
        return None
    return "Background checks are turned off in Guard settings (workspace_assessment_enabled), so none will run."


def _admitted(store: GuardStore, root: Path) -> WorktreeKeys | None:
    """Return the keys of the worktree at ``root`` when someone already added it and it is still checked.

    An install-made admission does not count: adding it again makes it manual, so
    removing that install later leaves it checked. Neither does an older worktree
    that used to live at the same folder.
    """

    from .. import workspace_assessment_worker as worker
    from ..native_workspace_snapshot import WorkspaceSnapshotError
    from ..workspace_assessment_admissions import is_manual_admission
    from ..workspace_assessment_store import WorktreeKeys

    if not root.is_dir():
        return None
    try:
        snapshot = worker.workspace_snapshot(root, mode="stat")
    except WorkspaceSnapshotError:
        return None
    keys = WorktreeKeys(snapshot.codebase_key, snapshot.worktree_key)
    return keys if is_manual_admission(store, keys, root=str(root)) else None


def _add(args: argparse.Namespace, store: GuardStore, config: GuardConfig | None, stream: TextIO | None) -> int:
    from ..workspace_assessment_worker import WorkspaceAdmissionError, admit_workspace

    as_json = bool(getattr(args, "json", False))
    raw = getattr(args, "path", None)
    requested = Path(raw).expanduser().absolute() if raw else default_codebase_root(Path.cwd())
    root = requested.resolve() if requested.exists() else requested
    note = _checks_off_note(config)
    follow_up = (
        "Guard checks it in the background on this machine. The result appears on the Codebases page "
        "in Guard Cloud after the next sync (`hol-guard sync`)."
    )
    existing = _admitted(store, root)
    if existing is not None:
        # A repeat leaves the admission and its queue alone instead of queueing another check.
        payload: dict[str, object] = {
            "added": False,
            "already_checked": True,
            "root": str(root),
            "codebase_key": existing.codebase_key,
            "worktree_key": existing.worktree_key,
        }
        lines = [f"Guard already checks {root}.", follow_up]
    else:
        try:
            admitted = admit_workspace(store, str(root))
        except WorkspaceAdmissionError as error:
            message = _ADMISSION_ERRORS.get(error.code, f"Guard could not read that folder ({error.code}).")
            _write(
                stream, {"added": False, "error": error.code, "message": message}, f"Error: {message}", as_json=as_json
            )
            return 1
        payload = {"added": True, "already_checked": False, "root": str(root), **admitted}
        lines = [f"Added {root}.", follow_up]
    if note:
        lines.append(note)
        payload["warning"] = note
    _write(stream, payload, "\n".join(lines), as_json=as_json)
    return 0


_RUN_STATES: dict[str, str] = {
    "queued": "checking",
    "running": "checking",
    "failed": "last check failed",
    "partial": "partly checked",
}


def _check_state(item: dict[str, object], latest: dict[str, object] | None) -> str:
    if item["paused"]:
        return "paused"
    if latest is None:
        return "waiting to check"
    state = _RUN_STATES.get(str(latest.get("state")))
    if state is not None:
        return state
    return "changed since last check" if item["stale"] else "up to date"


def _list(args: argparse.Namespace, store: GuardStore, config: GuardConfig | None, stream: TextIO | None) -> int:
    from ..workspace_assessment_reads import latest_runs, list_worktrees

    latest = {(run["codebase_key"], run["worktree_key"]): run for run in latest_runs(store)}
    worktrees = [
        {**item, "check_state": _check_state(item, latest.get((item["codebase_key"], item["worktree_key"])))}
        for item in list_worktrees(store)
    ]
    note = _checks_off_note(config)
    payload: dict[str, object] = {"codebases": worktrees}
    if note:
        payload["warning"] = note
    if not worktrees:
        text = "Guard checks no codebases on this machine. Add one with `hol-guard codebases add` from its folder."
    else:
        rows = [f"  {item['root']}  ({item['check_state']})" for item in worktrees]
        text = "Codebases Guard checks on this machine:\n" + "\n".join(rows)
    if note:
        text += "\n" + note
    _write(stream, payload, text, as_json=bool(getattr(args, "json", False)))
    return 0


def run_codebases_command(
    args: argparse.Namespace,
    *,
    store: GuardStore,
    config: GuardConfig | None = None,
    output_stream: TextIO | None = None,
    **_: object,
) -> int:
    if getattr(args, "codebases_command", None) == "add":
        return _add(args, store, config, output_stream)
    return _list(args, store, config, output_stream)


__all__ = ["configure_codebases_parser", "default_codebase_root", "run_codebases_command"]
