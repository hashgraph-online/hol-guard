"""Explicit integration writes with preflight, per-file replacement, and rollback."""

from __future__ import annotations

import os
import shutil
import stat
import tempfile
from pathlib import Path

from .errors import BuilderError
from .io import checked_path, read_bytes
from .kit import MAX_ARTIFACT_BYTES, Kit
from .repository_edits import conflict
from .repository_plan import Change, IntegrationPlan, plan_repository

LOCK_NAME = ".hol-guard-extension-authoring.lock"


def _check_before(root: Path, change: Change, *, expected: bytes | None = None, after: bool = False) -> None:
    target = checked_path(root / change.path)
    wanted = expected if after else change.before
    if wanted is None:
        if target.exists():
            raise conflict("A planned new file appeared after inspection; no files will be overwritten.")
    elif not target.exists() or read_bytes(target, limit=MAX_ARTIFACT_BYTES) != wanted:
        raise conflict("A destination file changed after inspection; regenerate the integration plan.")


def _stage_file(path: Path, content: bytes, mode: int) -> None:
    with path.open("xb") as stream:
        stream.write(content)
        stream.flush()
        os.fsync(stream.fileno())
    os.chmod(path, mode)


def _create_parents(root: Path, parent: Path, created: list[Path]) -> None:
    missing: list[Path] = []
    current = checked_path(parent)
    while current != root and not current.exists():
        missing.append(current)
        current = current.parent
    if not current.is_dir():
        raise conflict("A planned output parent is not a directory.")
    for directory in reversed(missing):
        checked_path(directory)
        directory.mkdir()
        created.append(directory)


def _rollback(
    plan: IntegrationPlan,
    completed: list[Change],
    staging: Path,
    modes: dict[str, int],
    created: list[Path],
) -> bool:
    complete = True
    for index, change in enumerate(reversed(completed)):
        try:
            _check_before(plan.root, change, expected=change.after, after=True)
            target = checked_path(plan.root / change.path)
            if change.before is None:
                target.unlink()
            else:
                restore = staging / f"rollback-{index}"
                _stage_file(restore, change.before, modes[change.path])
                os.replace(restore, target)
        except (OSError, BuilderError):
            # Do not overwrite a concurrent human edit while restoring our writes.
            complete = False
    for directory in reversed(created):
        try:
            checked_path(directory).rmdir()
        except (OSError, BuilderError):
            if directory.exists():
                complete = False
    return complete


def _write_plan(plan: IntegrationPlan) -> None:
    changes = [change for change in plan.changes if change.before != change.after]
    if not changes:
        return
    for change in plan.changes:
        _check_before(plan.root, change)
    staging = Path(tempfile.mkdtemp(prefix=".hol-guard-stage-", dir=plan.root))
    completed: list[Change] = []
    created: list[Path] = []
    modes: dict[str, int] = {}
    staged: dict[str, Path] = {}
    try:
        for index, change in enumerate(changes):
            target = checked_path(plan.root / change.path)
            mode = stat.S_IMODE(target.stat().st_mode) if change.before is not None else 0o644
            modes[change.path] = mode
            staged[change.path] = staging / str(index)
            _stage_file(staged[change.path], change.after, mode)
        # Publish the ownership record last. This improves crash recovery without
        # claiming that multiple filesystem replacements form one atomic commit.
        ordered = sorted(changes, key=lambda change: (change.path.endswith("/record.json"), change.path))
        for change in ordered:
            target = plan.root / change.path
            _create_parents(plan.root, target.parent, created)
            _check_before(plan.root, change)
            os.replace(staged[change.path], checked_path(target))
            completed.append(change)
    except (OSError, BuilderError, KeyboardInterrupt) as exc:
        restored = _rollback(plan, completed, staging, modes, created)
        if isinstance(exc, KeyboardInterrupt) and restored:
            raise
        message = (
            "Integration could not complete; completed writes were rolled back."
            if restored
            else (
                "Integration stopped and rollback encountered a concurrent edit or I/O error; "
                "inspect Git status before retrying."
            )
        )
        raise BuilderError("apply_write" if restored else "apply_rollback", message, conflict=True) from exc
    finally:
        shutil.rmtree(staging)


def apply_kit(
    kit: Kit,
    repository: Path,
    *,
    write: bool = False,
    expected_plan: str | None = None,
) -> dict[str, object]:
    if not write:
        plan = plan_repository(kit, repository)
        result = plan.to_dict()
        if expected_plan is not None and result["planDigest"] != expected_plan:
            raise conflict("The integration plan no longer matches the inspected digest.")
        return {**result, "written": False}
    root = checked_path(repository)
    if not root.is_dir():
        raise BuilderError("repository_directory", "The destination must be an existing HOL Guard checkout.")
    lock = checked_path(root / LOCK_NAME)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(lock, flags, 0o600)
    except OSError as exc:
        raise conflict(
            "Cannot acquire the authoring lock; another operation or a stale lock requires inspection."
        ) from exc
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(b"Guard extension authoring is in progress. Inspect the writer before removing this lock.\n")
        plan = plan_repository(kit, root)
        result = plan.to_dict()
        if expected_plan is not None and result["planDigest"] != expected_plan:
            raise conflict("The integration plan no longer matches the inspected digest.")
        _write_plan(plan)
        return {**result, "written": True}
    finally:
        checked_path(lock).unlink()
