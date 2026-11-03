"""Write, and put back, the one settings entry that adds Cloud actions to an AI tool.

`apply_host_config` writes the file a preview rendered, and only if the file
still holds the bytes that preview read: AI tools such as Claude Code rewrite
their settings while they run, and a change made after the preview must not be
overwritten. Before writing it keeps a copy of the previous file in the Guard
home. The new file is written beside the old one and moved into place in one
step, then read back; if it does not read back as rendered, the previous file
is put back.

`restore_host_config` undoes the most recent write for an AI tool. While the
file still holds exactly what Guard wrote, the earlier copy is put back as it
was. AI tools change their own settings files as they run, so when the file
has changed since, only Guard's entry is put back as it was (or removed) and
everything else edited since stays; if Guard's entry itself was changed,
nothing is touched.

A settings file that is a link is refused: Guard would otherwise write
wherever the link points.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import stat
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from ..daemon.atomic_replace import replace_file
from .cloud_actions_host_config import HostConfigPlan, read_settings_bytes, render_entry_undo

_BACKUP_FORMAT = "guard.cloud-actions.settings-backup.v1"
_KEEP_BACKUPS = 10
_NEW_FILE_MODE = 0o600
_PRIVATE_DIR_MODE = 0o700
# Recorded as `after_sha256` when Guard's failed write left no file behind.
_ABSENT = "absent"


class HostConfigWriteError(Exception):
    """The settings file was not changed; `reason` says why."""

    def __init__(self, reason: str, message: str) -> None:
        super().__init__(message)
        self.reason = reason


@dataclass(frozen=True, slots=True)
class HostConfigBackup:
    """What Guard changed in one settings file, and the copy that undoes it."""

    ai_tool: str
    path: Path
    url: str
    replaced_entry: bool
    existed: bool
    mode: int | None
    before_sha256: str | None
    after_sha256: str
    record_file: Path
    copy_file: Path | None


def backups_dir(guard_home: Path, ai_tool: str) -> Path:
    return guard_home / "cloud-actions" / "settings-backups" / ai_tool


def apply_host_config(plan: HostConfigPlan, *, guard_home: Path) -> HostConfigBackup:
    """Write `plan.after` to `plan.path` if the file is still as previewed."""

    if not plan.changes or plan.after is None:
        raise ValueError("Only a plan that changes the file can be applied.")
    path = plan.path
    _refuse_link(path)
    current = _read(path)
    if current != plan.before:
        raise _changed_since_preview(path)
    try:
        mode = _file_mode(path) if current is not None else None
    except OSError as error:
        raise HostConfigWriteError("unreadable", f"{path} could not be read ({error.strerror or 'error'}).") from None
    backup = _save_backup(plan, guard_home=guard_home, mode=mode)
    published = False
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = _write_temporary(path, plan.after, _NEW_FILE_MODE if mode is None else mode)
        try:
            # Read again right before the move: the window for a lost edit is
            # the move itself.
            if _read(path) != plan.before:
                raise _changed_since_preview(path)
            _publish(temporary, path, create=plan.before is None)
            published = True
        finally:
            temporary.unlink(missing_ok=True)
        _sync_directory(path.parent)
        if _read(path) != plan.after:
            raise HostConfigWriteError("write_not_verified", f"{path} did not read back as written.")
    except BaseException as error:
        # An interrupt can land after the move but before it was noted; the
        # file then already holds the new settings and must be put back too.
        # Guard's own refusals happen before any move, so they never count.
        if not published and not isinstance(error, HostConfigWriteError):
            published = _holds(path, plan.after)
        if published and not _put_back(backup, plan.before):
            # The copy is the only way back now, so it stays for `restore`, and the
            # record now names what is on disk so restore puts the whole file back.
            _record_left_behind(backup)
            raise HostConfigWriteError(
                "put_back_failed",
                f"{path} did not read back as written, and Guard could not put the earlier file back. "
                f"Guard kept its copy; run `hol-guard cloud-actions ai-tools restore {plan.ai_tool}`.",
            ) from None
        _discard_backup(backup)
        if isinstance(error, OSError):
            raise HostConfigWriteError(
                "write_failed", f"{path} could not be written ({error.strerror or 'error'})."
            ) from None
        raise
    _prune_backups(backups_dir(guard_home, plan.ai_tool))
    return backup


@dataclass(frozen=True, slots=True)
class HostConfigRestore:
    """`scope` is "file" when the whole earlier file was put back, "entry" when only Guard's entry was."""

    path: Path
    removed_file: bool
    scope: Literal["file", "entry"]
    entry_removed: bool


def restore_host_config(ai_tool: str, *, path: Path, guard_home: Path) -> HostConfigRestore | None:
    """Undo Guard's most recent write to `path`; None when there is nothing to undo."""

    backup = _latest_backup(backups_dir(guard_home, ai_tool), path)
    if backup is None:
        return None
    _refuse_link(path)
    current = _read(path)
    before = _read_copy(backup)
    try:
        if current is None and backup.after_sha256 == _ABSENT:
            # A failed write removed the file; recreate the earlier one.
            if before is not None:
                temporary = _write_temporary(path, before, backup.mode or _NEW_FILE_MODE)
                try:
                    _publish(temporary, path, create=True)
                finally:
                    temporary.unlink(missing_ok=True)
                _sync_directory(path.parent)
            result = HostConfigRestore(
                path=path, removed_file=False, scope="file", entry_removed=not backup.replaced_entry
            )
        elif current is not None and _sha256(current) == backup.after_sha256:
            if before is None:
                if _read(path) != current:
                    raise _changed_since_preview(path)
                path.unlink()
                _sync_directory(path.parent)
            else:
                _write_exact(path, before, mode=backup.mode or _NEW_FILE_MODE, expected=current)
            result = HostConfigRestore(
                path=path, removed_file=before is None, scope="file", entry_removed=not backup.replaced_entry
            )
        else:
            result = _undo_entry(backup, current=current, before=before)
    except OSError as error:
        raise HostConfigWriteError(
            "write_failed", f"{path} could not be put back ({error.strerror or 'error'})."
        ) from None
    _discard_backup(backup)
    return result


def _undo_entry(backup: HostConfigBackup, *, current: bytes | None, before: bytes | None) -> HostConfigRestore:
    """Put back only Guard's entry in a file the AI tool or the user has changed since."""

    path = backup.path
    try:
        if current is None:
            raise ValueError("missing")
        restored, entry_removed = render_entry_undo(
            backup.ai_tool, current=current, written_url=backup.url, prior=before
        )
    except ValueError:
        raise HostConfigWriteError(
            "changed_since_apply",
            f"The hol-guard-cloud entry in {path} changed after Guard wrote it, so Guard will not change it. "
            "Edit or remove that entry yourself if you no longer want it.",
        ) from None
    _write_exact(path, restored, mode=_file_mode(path), expected=current)
    return HostConfigRestore(path=path, removed_file=False, scope="entry", entry_removed=entry_removed)


def _changed_since_preview(path: Path) -> HostConfigWriteError:
    return HostConfigWriteError(
        "changed_since_preview",
        f"{path} changed after Guard read it, so nothing was written. Run the command again.",
    )


def _refuse_link(path: Path) -> None:
    if path.is_symlink():
        raise HostConfigWriteError(
            "settings_file_is_link",
            f"{path} is a link. Guard changes only a regular file; add the entry to the file it points to yourself.",
        )


def _read(path: Path) -> bytes | None:
    try:
        return read_settings_bytes(path)
    except ValueError as error:
        raise HostConfigWriteError("unreadable", str(error)) from None


def _holds(path: Path, payload: bytes) -> bool:
    try:
        return _read(path) == payload
    except (OSError, HostConfigWriteError):
        return False


def _file_mode(path: Path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _write_temporary(path: Path, payload: bytes, mode: int) -> Path:
    descriptor, name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".guard-tmp", dir=path.parent)
    temporary = Path(name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            fchmod = getattr(os, "fchmod", None)
            if fchmod is not None:
                fchmod(handle.fileno(), mode)
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise
    if getattr(os, "fchmod", None) is None:
        os.chmod(temporary, mode)
    return temporary


def _publish(temporary: Path, path: Path, *, create: bool) -> None:
    if not create:
        replace_file(temporary, path)
        return
    # A hard link fails if the file appeared since the check, so a file
    # another program just created is never replaced. Without hard links
    # there is no such guarantee, so nothing is written.
    try:
        os.link(temporary, path)
    except FileExistsError:
        raise _changed_since_preview(path) from None
    except OSError as error:
        raise HostConfigWriteError(
            "write_failed",
            f"{path} could not be created safely ({error.strerror or 'error'}), so nothing was written. "
            "Add the entry yourself from the preview.",
        ) from None


def _write_exact(path: Path, payload: bytes, *, mode: int, expected: bytes) -> None:
    temporary = _write_temporary(path, payload, mode)
    try:
        if _read(path) != expected:
            raise _changed_since_preview(path)
        replace_file(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)
    _sync_directory(path.parent)


def _put_back(backup: HostConfigBackup, before: bytes | None) -> bool:
    """Put the previewed file back; False when it could not be confirmed."""

    try:
        if before is None:
            backup.path.unlink(missing_ok=True)
        else:
            temporary = _write_temporary(backup.path, before, backup.mode or _NEW_FILE_MODE)
            try:
                replace_file(temporary, backup.path)
            finally:
                temporary.unlink(missing_ok=True)
        _sync_directory(backup.path.parent)
        return _read(backup.path) == before
    except (OSError, HostConfigWriteError):
        return False


def _sync_directory(directory: Path) -> None:
    if os.name == "nt":
        return
    with contextlib.suppress(OSError):
        descriptor = os.open(directory, os.O_RDONLY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)


def _private_dir(directory: Path) -> None:
    directory.mkdir(parents=True, exist_ok=True, mode=_PRIVATE_DIR_MODE)
    if os.name != "nt":
        # Owner-only access: the folder holds copies of AI tool settings files.
        # nosemgrep: python.lang.security.audit.insecure-file-permissions.insecure-file-permissions
        os.chmod(directory, _PRIVATE_DIR_MODE)


def _save_backup(plan: HostConfigPlan, *, guard_home: Path, mode: int | None) -> HostConfigBackup:
    if plan.after is None:
        raise ValueError("Only a plan that changes the file can be applied.")
    directory = backups_dir(guard_home, plan.ai_tool)
    try:
        _private_dir(directory)
        stem = f"{time.time_ns():020d}-{os.getpid()}"
        copy_file = None
        if plan.before is not None:
            copy_file = directory / f"{stem}.before"
            _write_private(copy_file, plan.before)
        record_file = directory / f"{stem}.json"
        backup = HostConfigBackup(
            ai_tool=plan.ai_tool,
            path=_absolute(plan.path),
            url=plan.url,
            replaced_entry=plan.action == "update",
            existed=plan.before is not None,
            mode=mode,
            before_sha256=None if plan.before is None else _sha256(plan.before),
            after_sha256=_sha256(plan.after),
            record_file=record_file,
            copy_file=copy_file,
        )
        _write_record(backup, after_sha256=backup.after_sha256)
    except OSError as error:
        raise HostConfigWriteError(
            "backup_failed",
            f"Guard could not keep a copy of {plan.path} ({error.strerror or 'error'}), so nothing was written.",
        ) from None
    return backup


def _record_left_behind(backup: HostConfigBackup) -> None:
    """Point the kept record at the bytes a failed write left, so `restore` replaces the whole file."""

    with contextlib.suppress(OSError, HostConfigWriteError):
        on_disk = _read(backup.path)
        _write_record(backup, after_sha256=_ABSENT if on_disk is None else _sha256(on_disk))


def _write_record(backup: HostConfigBackup, *, after_sha256: str) -> None:
    record = {
        "format": _BACKUP_FORMAT,
        "ai_tool": backup.ai_tool,
        "path": str(backup.path),
        "url": backup.url,
        "replaced_entry": backup.replaced_entry,
        "existed": backup.existed,
        "mode": backup.mode,
        "before_sha256": backup.before_sha256,
        "after_sha256": after_sha256,
        "copy": None if backup.copy_file is None else backup.copy_file.name,
    }
    _write_private(backup.record_file, (json.dumps(record, sort_keys=True) + "\n").encode())


def _write_private(path: Path, payload: bytes) -> None:
    temporary = _write_temporary(path, payload, _NEW_FILE_MODE)
    try:
        replace_file(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)
    _sync_directory(path.parent)


def _discard_backup(backup: HostConfigBackup) -> None:
    with contextlib.suppress(OSError):
        backup.record_file.unlink(missing_ok=True)
        if backup.copy_file is not None:
            backup.copy_file.unlink(missing_ok=True)


def _records(directory: Path) -> list[Path]:
    try:
        return sorted(directory.glob("*.json"))
    except OSError:
        return []


def _load_backup(record_file: Path) -> HostConfigBackup | None:
    try:
        raw: object = json.loads(record_file.read_bytes())
    except (OSError, ValueError):
        return None
    if not isinstance(raw, dict) or raw.get("format") != _BACKUP_FORMAT:
        return None
    path, url, copy, mode = raw.get("path"), raw.get("url"), raw.get("copy"), raw.get("mode")
    after, before = raw.get("after_sha256"), raw.get("before_sha256")
    if not isinstance(path, str) or not isinstance(url, str) or not isinstance(after, str):
        return None
    if not isinstance(raw.get("ai_tool"), str):
        return None
    if copy is not None and (not isinstance(copy, str) or Path(copy).name != copy):
        return None
    return HostConfigBackup(
        ai_tool=str(raw["ai_tool"]),
        path=Path(path),
        url=url,
        replaced_entry=raw.get("replaced_entry") is True,
        existed=raw.get("existed") is True,
        mode=mode if isinstance(mode, int) and 0 <= mode <= 0o7777 else None,
        before_sha256=before if isinstance(before, str) else None,
        after_sha256=after,
        record_file=record_file,
        copy_file=None if copy is None else record_file.parent / copy,
    )


def _absolute(path: Path) -> Path:
    # Same file, same key: `--home ./x` and its absolute spelling find one record.
    return Path(os.path.abspath(path))


def _latest_backup(directory: Path, path: Path) -> HostConfigBackup | None:
    wanted = _absolute(path)
    for record_file in reversed(_records(directory)):
        backup = _load_backup(record_file)
        if backup is None:
            # A newer record that cannot be read may be the change to undo.
            raise HostConfigWriteError(
                "backup_unreadable",
                f"Guard's record {record_file} is damaged, so nothing was changed. "
                "Check that file, or remove it to undo earlier changes.",
            )
        if _absolute(backup.path) == wanted:
            return backup
    return None


def _read_copy(backup: HostConfigBackup) -> bytes | None:
    if not backup.existed:
        return None
    try:
        payload = backup.copy_file.read_bytes() if backup.copy_file is not None else None
    except OSError:
        payload = None
    if payload is None or _sha256(payload) != backup.before_sha256:
        raise HostConfigWriteError(
            "backup_unreadable",
            f"Guard's copy of the earlier {backup.path} is missing or damaged, so nothing was changed.",
        )
    return payload


def _prune_backups(directory: Path) -> None:
    records = _records(directory)
    for record_file in records[: max(0, len(records) - _KEEP_BACKUPS)]:
        backup = _load_backup(record_file)
        if backup is not None:
            _discard_backup(backup)
        else:
            with contextlib.suppress(OSError):
                record_file.unlink()


__all__ = [
    "HostConfigBackup",
    "HostConfigRestore",
    "HostConfigWriteError",
    "apply_host_config",
    "backups_dir",
    "restore_host_config",
]
