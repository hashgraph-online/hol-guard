"""Copilot lifecycle state I/O; the native ``copilot_lifecycle_state`` kind decides what to trust."""

from __future__ import annotations

import errno
import json
import os
import stat
import time
from collections.abc import Callable, Iterable, Iterator, Mapping
from contextlib import ExitStack, contextmanager
from functools import wraps
from hashlib import sha256
from pathlib import Path
from typing import BinaryIO, Protocol

from .....path_support import resolves_within_root
from .....safe_output import write_text_atomic_no_follow
from ....daemon.file_locking import try_lock_daemon_file
from ....mdm.file_lock import release_file_lock
from ...adapter_safe_output import write_text_at_authorized_path
from ...adapter_state_integrity import (
    adapter_state_is_authenticated,
    authenticate_adapter_state,
    authenticated_adapter_path,
)
from ...base import HarnessContext, _ensure_path_within_root, _json_payload

CopilotStateEntry = tuple[Path, Path, Path, dict[str, object]]
PathFactory = Callable[[Path, HarnessContext], Path]
_LIFECYCLE_LOCK_TIMEOUT_SECONDS = 30.0
_LIFECYCLE_LOCK_POLL_SECONDS = 0.05
_WINDOWS_LOCK_CONTENTION_ERRORS = {32, 33}


class CopilotLifecycleAdapter(Protocol):
    def _target_mcp_paths(self, context: HarnessContext) -> tuple[Path, ...]: ...

    def _config_path(self, context: HarnessContext) -> Path: ...

    def _hook_path(self, context: HarnessContext) -> Path | None: ...

    def _uninstall_targets(self, context: HarnessContext) -> list[tuple[Path, Path, Path]]: ...


def _canonical_lifecycle_target(target_path: Path) -> str:
    try:
        return os.path.normcase(str(target_path.resolve()))
    except (OSError, RuntimeError) as error:
        raise OSError("Unable to canonicalize the Copilot lifecycle target.") from error


def _copilot_lifecycle_lock_directory(context: HarnessContext) -> Path:
    lock_directory = context.guard_home / "managed" / "copilot"
    _ensure_path_within_root(context.guard_home, lock_directory, label="Copilot lifecycle lock")
    lock_directory.mkdir(parents=True, exist_ok=True)
    _ensure_path_within_root(context.guard_home, lock_directory, label="Copilot lifecycle lock")
    try:
        metadata = lock_directory.lstat()
    except OSError as error:
        raise OSError("Unable to validate the Copilot lifecycle lock directory.") from error
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise OSError("Copilot lifecycle lock directory is not a regular directory")
    return lock_directory


def _copilot_lifecycle_lock_path(context: HarnessContext, target_path: Path) -> Path:
    target = _canonical_lifecycle_target(target_path)
    digest = sha256(target.encode("utf-8")).hexdigest()[:12]
    return _copilot_lifecycle_lock_directory(context) / f"{digest}.lifecycle.lock"


def _copilot_lifecycle_lock_identity(lock_path: Path) -> tuple[int, int] | None:
    try:
        metadata = lock_path.lstat()
    except FileNotFoundError:
        return None
    except OSError as error:
        raise OSError("Unable to inspect the Copilot lifecycle lock.") from error
    if stat.S_ISLNK(metadata.st_mode):
        raise OSError("Copilot lifecycle lock must not be a symbolic link")
    if not stat.S_ISREG(metadata.st_mode):
        raise OSError("Copilot lifecycle lock is not a regular file")
    return metadata.st_dev, metadata.st_ino


def _windows_lock_contention(error: OSError) -> bool:
    winerror = getattr(error, "winerror", None)
    if winerror is not None:
        return winerror in _WINDOWS_LOCK_CONTENTION_ERRORS
    return error.errno in {errno.EACCES, errno.EAGAIN, errno.EDEADLK}


def _try_copilot_lifecycle_lock(handle: BinaryIO) -> bool:
    if os.name != "nt":
        return try_lock_daemon_file(handle)
    import msvcrt

    handle.seek(0)
    if os.fstat(handle.fileno()).st_size == 0:
        handle.write(b"0")
        handle.flush()
    handle.seek(0)
    try:
        msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
    except OSError as error:
        if _windows_lock_contention(error):
            return False
        raise
    return True


@contextmanager
def copilot_lifecycle_lock(context: HarnessContext, target_path: Path) -> Iterator[None]:
    """Serialize one Copilot lifecycle path across processes and threads."""

    lock_path = _copilot_lifecycle_lock_path(context, target_path)
    prior_identity = _copilot_lifecycle_lock_identity(lock_path)
    flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(lock_path, flags, 0o600)
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise OSError("Copilot lifecycle lock is not a regular file")
        current_identity = _copilot_lifecycle_lock_identity(lock_path)
        opened_identity = metadata.st_dev, metadata.st_ino
        if (
            current_identity is None
            or current_identity != opened_identity
            or (prior_identity is not None and prior_identity != current_identity)
        ):
            raise OSError("Copilot lifecycle lock changed while opening")
        with os.fdopen(descriptor, "a+b") as handle:
            descriptor = -1
            deadline = time.monotonic() + _LIFECYCLE_LOCK_TIMEOUT_SECONDS
            while True:
                try:
                    acquired = _try_copilot_lifecycle_lock(handle)
                except OSError as error:
                    raise OSError("Unable to acquire the Copilot lifecycle lock.") from error
                if acquired:
                    break
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError("Timed out waiting for the Copilot lifecycle lock.")
                time.sleep(min(_LIFECYCLE_LOCK_POLL_SECONDS, remaining))
            try:
                yield
            finally:
                release_file_lock(handle)
    finally:
        if descriptor >= 0:
            os.close(descriptor)


@contextmanager
def copilot_lifecycle_scope(context: HarnessContext) -> Iterator[None]:
    """Serialize lifecycle state discovery for one Guard home."""

    scope_path = context.guard_home / "managed" / "copilot" / ".lifecycle.scope"
    with copilot_lifecycle_lock(context, scope_path):
        yield


@contextmanager
def copilot_lifecycle_target_locks(context: HarnessContext, target_paths: Iterable[Path]) -> Iterator[None]:
    """Acquire target locks in a stable order for multi-file installs."""

    paths = sorted({_canonical_lifecycle_target(path): path for path in target_paths}.items())
    with ExitStack() as stack:
        for _resolved, path in paths:
            stack.enter_context(copilot_lifecycle_lock(context, path))
        yield


@contextmanager
def copilot_lifecycle_locks(context: HarnessContext, target_paths: Iterable[Path]) -> Iterator[None]:
    """Serialize one Guard-home Copilot operation and its recorded targets.

    This coordinates Guard operations that share ``context.guard_home``. A
    different Guard home is a separate authority and does not coordinate
    concurrent writes to the same harness configuration.
    """

    with copilot_lifecycle_scope(context), copilot_lifecycle_target_locks(context, target_paths):
        yield


def copilot_lifecycle_install(method: Callable[..., dict[str, object]]) -> Callable[..., dict[str, object]]:
    @wraps(method)
    def wrapped(adapter: CopilotLifecycleAdapter, context: HarnessContext) -> dict[str, object]:
        target_paths = adapter._target_mcp_paths(context)
        lock_paths = (*target_paths, adapter._config_path(context))
        managed_hook_path = adapter._hook_path(context)
        if managed_hook_path is not None:
            lock_paths += (managed_hook_path,)
        with copilot_lifecycle_locks(context, lock_paths):
            return method(adapter, context)

    return wrapped


def copilot_lifecycle_uninstall(method: Callable[..., dict[str, object]]) -> Callable[..., dict[str, object]]:
    @wraps(method)
    def wrapped(adapter: CopilotLifecycleAdapter, context: HarnessContext) -> dict[str, object]:
        target_paths = adapter._target_mcp_paths(context)
        lock_paths = (*target_paths, adapter._config_path(context))
        managed_hook_path = adapter._hook_path(context)
        if managed_hook_path is not None:
            lock_paths += (managed_hook_path,)
        with copilot_lifecycle_scope(context):
            recorded_targets = adapter._uninstall_targets(context)
            recorded_paths = (*lock_paths, *(target for _state, target, _backup in recorded_targets))
            with copilot_lifecycle_target_locks(context, recorded_paths):
                return method(adapter, context)

    return wrapped


def _target_identity(target_path: Path) -> tuple[int, int] | None:
    try:
        metadata = target_path.lstat()
    except OSError:
        return None
    if not stat.S_ISREG(metadata.st_mode):
        return None
    return metadata.st_dev, metadata.st_ino


def _target_matches_payload(
    target_path: Path,
    target_payload: str,
    expected_identity: tuple[int, int] | None,
) -> bool:
    if expected_identity is None or _target_identity(target_path) != expected_identity:
        return False
    try:
        return target_path.read_bytes() == target_payload.encode("utf-8")
    except OSError:
        return False


def copilot_state_payload(
    context: HarnessContext,
    *,
    target_path: Path,
    backup_path: Path,
    state_path: Path,
    scope: str,
    create_key: bool = True,
) -> dict[str, object]:
    return authenticate_adapter_state(
        context.guard_home,
        harness="copilot",
        create_key=create_key,
        payload={
            "managed_config_path": str(target_path.resolve()),
            "backup_path": str(backup_path.resolve()),
            "scope": scope,
            "workspace_dir": str(context.workspace_dir.resolve()) if context.workspace_dir is not None else None,
        },
    )


def write_copilot_state(
    context: HarnessContext,
    *,
    target_path: Path,
    backup_path: Path,
    state_path: Path,
    scope: str,
) -> None:
    payload = copilot_state_payload(
        context, target_path=target_path, backup_path=backup_path, state_path=state_path, scope=scope
    )
    write_text_atomic_no_follow(state_path, json.dumps(payload, indent=2) + "\n")


def commit_copilot_target_and_state(
    context: HarnessContext,
    *,
    target_path: Path,
    target_payload: str,
    original_text: str | None,
    backup_path: Path,
    state_path: Path,
    scope: str,
) -> None:
    """Commit backup, target, and state as one recoverable lifecycle transaction.

    Rollback is conditional: it restores only while the target still has the
    identity and bytes written by this transaction. If an external writer
    changes the target, the edit is preserved and the backup remains available
    for recovery. Lifecycle locks coordinate Guard operations sharing one
    ``guard_home``; unrelated writers are outside that cooperative boundary.
    """

    preserve_existing_backup = copilot_state_authorizes_backup_reuse(
        context,
        target_path=target_path,
        backup_path=backup_path,
        state_path=state_path,
    )
    backup_replaced = False
    target_written = False
    target_identity: tuple[int, int] | None = None
    rollback_complete = False
    try:
        if not preserve_existing_backup:
            backup_path.parent.mkdir(parents=True, exist_ok=True)
            backup_payload = {"existed": original_text is not None, "content": original_text}
            write_text_at_authorized_path(backup_path, json.dumps(backup_payload, indent=2) + "\n")
            backup_replaced = True
        write_text_at_authorized_path(target_path, target_payload)
        # The authorized writer replaces the target atomically; only roll back
        # after it reports that the replacement completed.
        target_written = True
        target_identity = _target_identity(target_path)
        write_copilot_state(
            context,
            target_path=target_path,
            backup_path=backup_path,
            state_path=state_path,
            scope=scope,
        )
    except BaseException:
        try:
            if target_written and _target_matches_payload(target_path, target_payload, target_identity):
                try:
                    if original_text is None:
                        target_path.unlink()
                    else:
                        write_text_at_authorized_path(target_path, original_text)
                except OSError:
                    pass
                else:
                    rollback_complete = True
            elif not target_written:
                rollback_complete = True
        finally:
            if backup_replaced and (rollback_complete or not target_written):
                backup_path.unlink(missing_ok=True)
        raise


def _lifecycle_state(context: HarnessContext, request: Mapping[str, object]) -> dict[str, object]:
    """The native verdict; no answer refuses the change, as authentication does.

    Reading no answer as "not Guard's own" would overwrite or skip a real backup.
    """

    from ....native_adapter_state_integrity import AdapterStateIntegrityUnavailableError
    from ....native_runner_authority import NativeRunnerAuthorityError, native_runner_authority

    try:
        return native_runner_authority("copilot_lifecycle_state", request, guard_home=context.guard_home)
    except NativeRunnerAuthorityError as error:
        raise AdapterStateIntegrityUnavailableError from error


def _spelling(path: Path | None) -> str | None:
    """A path as ``pathlib.Path`` equality compares it on this host."""

    return None if path is None else os.path.normcase(str(path))


def copilot_state_authorizes_backup_reuse(
    context: HarnessContext,
    *,
    target_path: Path,
    backup_path: Path,
    state_path: Path,
    state_payload: dict[str, object] | None = None,
) -> bool:
    """Return whether authenticated durable state binds this target to this backup."""

    payload = _json_payload(state_path) if state_payload is None else state_payload
    recorded = [
        authenticated_adapter_path(context.guard_home, harness="copilot", payload=payload, field=field)
        for field in ("managed_config_path", "backup_path")
    ]
    backup: dict[str, object] | None = None
    if not backup_path.is_symlink() and backup_path.is_file():
        try:
            backup = {"text": backup_path.read_text(encoding="utf-8")}
        except (OSError, UnicodeDecodeError):
            backup = {"text": None}
    expected = [_spelling(target_path.resolve()), _spelling(backup_path.resolve())]
    recorded_spellings = [_spelling(path) for path in recorded]
    request = {"action": "backup_reuse", "recorded": recorded_spellings, "expected": expected, "backup": backup}
    decision = _lifecycle_state(context, request).get("decision")
    if decision == "refuse":
        raise RuntimeError("Guard refused to overwrite an unreadable Copilot backup.")
    if decision not in {"reuse", "replace"}:
        raise ValueError("Copilot backup reuse answer is malformed")
    return decision == "reuse"


def _state_targets(context: HarnessContext, payload: dict[str, object]) -> list[tuple[str, list[str], Path, Path]]:
    """Each config a state file may name: its source, spellings, path and root."""

    global_target = context.home_dir / ".copilot" / "mcp-config.json"
    spellings = [str(global_target), str(global_target.resolve())]
    targets = [("global", spellings, global_target, context.home_dir)]
    recorded = authenticated_adapter_path(context.guard_home, harness="copilot", payload=payload, field="workspace_dir")
    current = context.workspace_dir
    bases = [] if recorded is None else [("recorded", recorded, recorded)]
    if current is not None:
        bases += [("current", base, current) for base in dict.fromkeys((current, current.resolve()))]
    for source, base, root in bases:
        for target in (base / ".mcp.json", base / ".vscode" / "mcp.json"):
            targets.append((source, [str(target)], target, root))
    return targets


def validated_copilot_state_entries(
    context: HarnessContext,
    *,
    state_path_for: PathFactory,
    backup_path_for: PathFactory,
) -> list[CopilotStateEntry]:
    state_dir = context.guard_home / "managed" / "copilot"
    _ensure_path_within_root(context.guard_home, state_dir, label="Copilot state")
    found: list[tuple[Path, dict[str, object], list[tuple[Path, Path]]]] = []
    requests: list[dict[str, object]] = []
    errors: dict[tuple[int, int], Exception] = {}
    for state_path in sorted(state_dir.glob("*.state.json")):
        payload = _json_payload(state_path)
        if not adapter_state_is_authenticated(context.guard_home, harness="copilot", payload=payload):
            continue
        candidates: list[dict[str, object]] = []
        named: list[tuple[Path, Path]] = []
        for slot, (source, spellings, target, root) in enumerate(_state_targets(context, payload)):
            paths: dict[str, object] | None = None
            backup = target
            try:
                state, backup = state_path_for(target, context), backup_path_for(target, context)
                paths = {
                    "owned": all(resolves_within_root(context.guard_home, path) for path in (state, backup)),
                    "state": _spelling(state.resolve()),
                    "backup": [str(backup), str(backup.resolve())],
                }
            except (OSError, RuntimeError) as error:
                errors[len(found), slot] = error
            contained = resolves_within_root(root, target)
            candidates.append({"source": source, "keys": spellings, "contained": contained, "paths": paths})
            named.append((target, backup))
        fields = [payload.get(key) for key in ("managed_config_path", "backup_path")]
        requests.append({"state": _spelling(state_path.resolve()), "fields": fields, "candidates": candidates})
        found.append((state_path, payload, named))
    if not found:
        return []
    verdicts = _lifecycle_state(context, {"action": "state_entries", "entries": requests}).get("entries")
    if not isinstance(verdicts, list) or len(verdicts) != len(found):
        raise ValueError("Copilot state entries answer is malformed")
    entries: list[CopilotStateEntry] = []
    for index, ((state_path, payload, named), verdict) in enumerate(zip(found, verdicts, strict=True)):
        if isinstance(verdict, dict) and (index, verdict.get("raise")) in errors:
            raise errors[index, verdict["raise"]]
        if verdict is None:
            continue
        if type(verdict) is not int or not 0 <= verdict < len(named):
            raise ValueError("Copilot state entries answer is malformed")
        entries.append((state_path, *named[verdict], payload))
    return entries
