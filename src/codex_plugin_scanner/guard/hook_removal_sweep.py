"""Find and strip Guard-owned hook handlers from harness config files.

The per-harness adapters remove what Guard recorded at install time. This
sweep is the backstop for hooks the store no longer knows about (a lost state
directory, a half-finished update, an older Guard version): it scans each known
harness config file for hook handlers whose command carries a Guard signature
and removes only those handlers. Handlers that are not Guard's are preserved.

The native runtime's ``hook-removal-sweep`` command discovers the candidate
files, matches the signatures, and rewrites the files.
Only JSON and TOML files are rewritten, and a TOML edit is kept only when the
re-parsed file equals the pruned payload.
"""

from __future__ import annotations

import os
from collections.abc import Collection, Mapping
from dataclasses import dataclass, field
from pathlib import Path

from .harness_context import HarnessContext
from .mdm.runtime_request import runtime_answer

_FEATURE = "native-hook-removal-sweep-v1"
_DISCOVERY_FEATURE = "native-hook-removal-discovery-v1"
_PLAN_FEATURE = "native-hook-removal-plan-v1"
_REPORT_FEATURE = "native-hook-removal-report-v1"
_BACKUP_FEATURE = "native-hook-removal-backup-v1"
_COMMAND = "hook-removal-sweep"
_SCHEMA = "hook-removal-sweep.v1"
_OUTPUT_LIMIT = 4 * 1024 * 1024
_TIMEOUT_SECONDS = 60.0


class BackupError(OSError):
    """A config file could not be backed up, so its harness must not be edited."""


class SweepUnavailableError(OSError):
    """The native runtime could not scan or rewrite the hook files."""


@dataclass(frozen=True)
class SweepFileResult:
    path: Path
    removed: int = 0
    wrote: bool = False
    error: str | None = None
    event_names: tuple[str, ...] = ()


@dataclass
class SweepTotals:
    files: list[SweepFileResult] = field(default_factory=list)

    @property
    def removed(self) -> int:
        return sum(item.removed for item in self.files)


def _runtime(request: Mapping[str, object], *, feature: str = _FEATURE) -> dict[str, object]:
    answer = runtime_answer(
        feature,
        _COMMAND,
        {"schema": _SCHEMA, **request},
        output_limit=_OUTPUT_LIMIT,
        timeout_seconds=_TIMEOUT_SECONDS,
    )
    if answer is None:
        raise SweepUnavailableError("native hook sweep unavailable")
    return answer


def _answer(request: Mapping[str, object], key: str, *, feature: str = _FEATURE) -> object:
    answer = _runtime(request, feature=feature)
    if key not in answer:
        raise SweepUnavailableError("native hook sweep unavailable")
    return answer[key]


def _result(value: object) -> SweepFileResult:
    if not isinstance(value, dict):
        raise SweepUnavailableError("native hook sweep answer malformed")
    path = value.get("path")
    removed = value.get("removed")
    wrote = value.get("wrote")
    error = value.get("error")
    events = value.get("event_names")
    if (
        not isinstance(path, str)
        or not isinstance(removed, int)
        or isinstance(removed, bool)
        or removed < 0
        or not isinstance(wrote, bool)
        or (error is not None and not isinstance(error, str))
        or not isinstance(events, list)
        or not all(isinstance(name, str) for name in events)
    ):
        raise SweepUnavailableError("native hook sweep answer malformed")
    return SweepFileResult(path=Path(path), removed=removed, wrote=wrote, error=error, event_names=tuple(events))


def sweep_config_file(path: Path, *, dry_run: bool) -> SweepFileResult:
    """Remove Guard hook handlers from one file.

    Raises ``SweepUnavailableError`` when the native runtime cannot answer.
    """

    return _result(_answer({"op": "sweep-file", "path": str(path.absolute()), "dry_run": dry_run}, "file"))


def _roots(context: HarnessContext) -> dict[str, object]:
    workspace = context.workspace_dir
    return {
        "home": str(context.home_dir.absolute()),
        "workspace": str(workspace.absolute()) if workspace is not None else None,
    }


def _scope(harness: str, context: HarnessContext) -> dict[str, object]:
    return {"harness": harness, **_roots(context)}


def removal_plans(context: HarnessContext, harnesses: tuple[str, ...], active: set[str]) -> list[object]:
    plan = {**_roots(context), "harnesses": list(harnesses), "active": sorted(active)}
    rows = _answer({"op": "plan", "plan": plan}, "plans", feature=_PLAN_FEATURE)
    if not isinstance(rows, list):
        raise SweepUnavailableError("native hook removal plan malformed")
    return rows


def removal_report(context: HarnessContext, outcomes: list[dict[str, object]]) -> dict[str, object]:
    """Read the runtime's post-removal verification and counts."""
    answer = _runtime(
        {"op": "report", "report": {**_roots(context), "outcomes": outcomes}},
        feature=_REPORT_FEATURE,
    )
    if (
        set(answer) != {"status", "remaining", "removed_hook_count", "affected_harness_count"}
        or answer.get("status") not in ("removed", "partial")
        or not isinstance(answer.get("remaining"), list)
        or any(
            not isinstance(count, int) or isinstance(count, bool) or count < 0
            for count in (answer.get("removed_hook_count"), answer.get("affected_harness_count"))
        )
    ):
        raise SweepUnavailableError("native hook removal report malformed")
    return answer


def harness_hook_files(harness: str, context: HarnessContext) -> tuple[Path, ...]:
    """Existing regular JSON/TOML config files that may hold hooks for ``harness``."""

    files = _answer({"op": "files", "scope": _scope(harness, context)}, "files", feature=_DISCOVERY_FEATURE)
    if not isinstance(files, list) or not all(isinstance(item, str) for item in files):
        raise SweepUnavailableError("native hook sweep answer malformed")
    return tuple(Path(item) for item in files)


def sweep_harness(harness: str, context: HarnessContext, *, dry_run: bool) -> SweepTotals:
    """Sweep every candidate file for ``harness``.

    A symlinked config is never edited through the link: its hooks come back
    as ``symlink_not_followed``, counted as found in a dry run.
    """

    request = {"op": "sweep", "dry_run": dry_run, "scope": _scope(harness, context)}
    files = _answer(request, "files", feature=_DISCOVERY_FEATURE)
    if not isinstance(files, list):
        raise SweepUnavailableError("native hook sweep answer malformed")
    return SweepTotals(files=[_result(item) for item in files])


def _entries(value: object, keys: frozenset[str]) -> list[dict[str, str]]:
    if not isinstance(value, list):
        raise SweepUnavailableError("native hook sweep answer malformed")
    entries: list[dict[str, str]] = []
    for item in value:
        if not isinstance(item, dict) or set(item) != keys or not all(isinstance(text, str) for text in item.values()):
            raise SweepUnavailableError("native hook sweep answer malformed")
        entries.append({str(key): str(text) for key, text in item.items()})
    return entries


_BACKUP_KEYS = frozenset({"harness", "original_path", "backup_path"})


def backup_harness_files(
    backup_dir: Path, harness: str, files: tuple[Path, ...], *, skip: Collection[str]
) -> list[dict[str, str]]:
    """Copy each existing file of ``harness`` that ``skip`` does not name.

    Returns one entry per copy, with the copied bytes' ``sha256``. Raises
    ``BackupError`` when any file cannot be copied (the runtime removes this
    harness's copies again).
    """

    request = {
        "op": "backup",
        "backup_dir": str(backup_dir),
        "harness": harness,
        "candidates": [str(path) for path in files],
        "skip": sorted(skip),
    }
    answer = _runtime(request, feature=_BACKUP_FEATURE)
    if answer.get("outcome") == "error":
        raise BackupError(str(answer.get("error", "backup_failed")))
    if answer.get("outcome") != "ok":
        raise SweepUnavailableError("native hook sweep answer malformed")
    return _entries(answer.get("entries"), _BACKUP_KEYS | {"sha256"})


def finalize_backups(
    backup_dir: Path, entries: list[dict[str, str]], *, stamp: str
) -> tuple[Path | None, list[dict[str, str]]]:
    """Keep copies of files that changed, drop the rest, and write the manifest.

    Without a runtime answer every copy that still exists is kept, since
    nothing proved its file unchanged. The runtime may have removed some
    copies before the answer was lost, so the report lists only the copies
    still on disk.
    """

    request = {"op": "finalize-backups", "backup_dir": str(backup_dir), "stamp": stamp, "entries": entries}
    try:
        answer = _runtime(request, feature=_BACKUP_FEATURE)
        kept = _entries(answer.get("files"), _BACKUP_KEYS)
    except SweepUnavailableError:
        kept = [{key: entry[key] for key in _BACKUP_KEYS} for entry in entries if os.path.lexists(entry["backup_path"])]
        return (backup_dir if kept else None), kept
    directory = answer.get("backup_dir")
    return (Path(directory) if isinstance(directory, str) else None), kept


__all__ = [
    "BackupError",
    "SweepFileResult",
    "SweepTotals",
    "SweepUnavailableError",
    "backup_harness_files",
    "finalize_backups",
    "harness_hook_files",
    "removal_plans",
    "removal_report",
    "sweep_config_file",
    "sweep_harness",
]
