"""Installed Pi probe cleanup helpers; dependencies remain bound to its public entry point."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .probe_installed_pi_api import probe_api


def _native_state_files(guard_home: Path) -> tuple[Path, ...]:
    _api = probe_api()
    try:
        return tuple((guard_home / "native-runtime").glob("resident-v3-*/generation-*.json"))
    except (OSError, RuntimeError):
        return ()


def _native_cleanup_environment() -> dict[str, str]:
    _api = probe_api()
    allowed = {
        "COMSPEC",
        "HOME",
        "LANG",
        "PATHEXT",
        "SYSTEMROOT",
        "TEMP",
        "TMPDIR",
        "USERPROFILE",
        "WINDIR",
    }
    return {key: value for key, value in _api.os.environ.items() if key in allowed or key.upper().startswith("LC_")}


def _cleanup_native(identity: Any, guard_home: Path) -> None:
    _api = probe_api()
    from codex_plugin_scanner.guard.native_resident_client import (
        close_native_residents,
        stop_native_resident,
    )

    cleanup_error: OSError | RuntimeError | None = None
    try:
        contained = close_native_residents(guard_home)
    except (OSError, RuntimeError) as exc:
        contained = False
        cleanup_error = exc
    if _api._native_state_files(guard_home):
        try:
            if not stop_native_resident(
                executable=identity.path,
                state_dir=guard_home / "native-runtime",
                environment=_api._native_cleanup_environment(),
                timeout_seconds=2.0,
            ):
                cleanup_error = cleanup_error or RuntimeError("native resident stop did not complete")
        except (OSError, RuntimeError) as exc:
            cleanup_error = cleanup_error or exc
    if cleanup_error is None and not contained:
        try:
            contained = close_native_residents(guard_home)
        except (OSError, RuntimeError) as exc:
            cleanup_error = exc
    if cleanup_error is None and not contained:
        cleanup_error = RuntimeError("native resident containment did not complete")
    if cleanup_error is None and _api._native_state_files(guard_home):
        cleanup_error = RuntimeError("native resident state remained after cleanup")
    if cleanup_error is not None:
        raise _api.ProbeError(f"authenticated native cleanup failed: {type(cleanup_error).__name__}") from cleanup_error


def _remove_probe_path(path: Path) -> bool:
    _api = probe_api()
    try:
        if not path.exists() and not path.is_symlink():
            return True
        if path.is_dir() and not path.is_symlink():
            _api.shutil.rmtree(path)
        else:
            path.unlink()
    except OSError:
        return False
    return True


def _scrub_probe_root(root: Path, *, preserve_native_state: bool = False) -> int:
    """Remove probe captures while preserving only scoped native retry state."""
    _api = probe_api()
    if not root.exists():
        return 0
    if root.is_symlink():
        return 1
    try:
        children = tuple(root.iterdir())
    except OSError:
        return 1
    failures = 0
    for child in children:
        if preserve_native_state and child == root / "guard-home" and child.is_dir() and not child.is_symlink():
            native_state = child / "native-runtime"
            preserve_state = native_state.is_dir() and not native_state.is_symlink()
            if not preserve_state:
                if not _api._remove_probe_path(child):
                    failures += 1
                continue
            try:
                nested = tuple(child.iterdir())
            except OSError:
                failures += 1
                continue
            for nested_child in nested:
                if preserve_state and nested_child == native_state:
                    continue
                if not _api._remove_probe_path(nested_child):
                    failures += 1
            continue
        if not _api._remove_probe_path(child):
            failures += 1
    return failures


def _remaining_probe_paths(root: Path, *, preserve_native_state: bool = False) -> int:
    _api = probe_api()
    if not root.exists():
        return 0
    if root.is_symlink():
        return 1
    try:
        children = tuple(root.iterdir())
    except OSError:
        return 1
    remaining = 0
    for child in children:
        if preserve_native_state and child == root / "guard-home" and child.is_dir() and not child.is_symlink():
            native_state = child / "native-runtime"
            preserve_state = native_state.is_dir() and not native_state.is_symlink()
            if not preserve_state:
                remaining += 1
                continue
            try:
                nested = tuple(child.iterdir())
            except OSError:
                remaining += 1
                continue
            remaining += sum(not (preserve_state and nested_child == native_state) for nested_child in nested)
            continue
        remaining += 1
    return remaining


def _retain_private_native_retry_state(root: Path) -> bool:
    """Keep authenticated retry state private when cleanup must be deferred."""
    _api = probe_api()
    guard_home = root / "guard-home"
    native_state = guard_home / "native-runtime"
    try:
        guard_info = _api.os.lstat(guard_home)
        native_info = _api.os.lstat(native_state)
    except OSError:
        return False
    if any(
        _api.stat.S_ISLNK(info.st_mode) or not _api.stat.S_ISDIR(info.st_mode) for info in (guard_info, native_info)
    ):
        return False
    expected_owner = getattr(guard_info, "st_uid", None)
    try:
        for path in (guard_home, native_state):
            path.chmod(0o700)
        guard_info = _api.os.lstat(guard_home)
        native_info = _api.os.lstat(native_state)
    except OSError:
        return False
    pending = [(guard_home, guard_info), (native_state, native_info)]
    while pending:
        current, info = pending.pop()
        mode = _api.stat.S_IMODE(info.st_mode)
        if _api.stat.S_ISLNK(info.st_mode) or not _api.stat.S_ISDIR(info.st_mode) or mode != 0o700:
            return False
        if expected_owner is not None and getattr(info, "st_uid", None) != expected_owner:
            return False
        try:
            with _api.os.scandir(current) as entries:
                children = tuple(entries)
        except OSError:
            return False
        for entry in children:
            try:
                child_info = _api.os.lstat(entry.path)
            except OSError:
                return False
            if expected_owner is not None and getattr(child_info, "st_uid", None) != expected_owner:
                return False
            if _api.stat.S_ISLNK(child_info.st_mode):
                return False
            if _api.stat.S_ISDIR(child_info.st_mode):
                pending.append((_api.Path(entry.path), child_info))
            elif not _api.stat.S_ISREG(child_info.st_mode) or _api.stat.S_IMODE(child_info.st_mode) != 0o600:
                return False
    return True


def _retain_cleanup_receipt(root: Path, failure: BaseException) -> None:
    """Retain only redacted retry state when authenticated cleanup cannot finish."""
    _api = probe_api()
    scrub_failures = _api._scrub_probe_root(root, preserve_native_state=True)
    native_state = root / "guard-home" / "native-runtime"
    native_state_present = native_state.is_dir() and not native_state.is_symlink()
    private_native_retry_state = _api._retain_private_native_retry_state(root)
    if native_state_present and not private_native_retry_state:
        scrub_failures += 1
    remaining_paths = _api._remaining_probe_paths(root, preserve_native_state=True)
    try:
        root.mkdir(mode=0o700, parents=True, exist_ok=True)
        (root / "cleanup-failure.json").write_text(
            _api.json.dumps(
                {
                    "schema": "hol-guard.installed-pi-cleanup-failure.v1",
                    "probe_root": str(root),
                    "error_type": type(failure).__name__,
                    "remaining_nonretry_paths": remaining_paths,
                    "retry_required": True,
                    "scrub_complete": scrub_failures == 0 and remaining_paths == 0,
                    "scrub_failures": scrub_failures,
                    "private_native_retry_state_retained": private_native_retry_state,
                },
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
    except OSError as exc:
        raise _api.ProbeError("redacted cleanup receipt could not be written") from exc
    if scrub_failures or remaining_paths:
        raise _api.ProbeError("probe capture scrub could not be confirmed")


def _retain_unsafe_cleanup_marker(root: Path, failure: BaseException) -> None:
    """Record a redacted timeout marker without touching a possibly live root."""
    _api = probe_api()
    try:
        root_info = _api.os.lstat(root)
        if _api.stat.S_ISLNK(root_info.st_mode) or not _api.stat.S_ISDIR(root_info.st_mode):
            raise OSError("probe root is not a private directory")
        root.chmod(0o700)
        root_info = _api.os.lstat(root)
        if _api.stat.S_IMODE(root_info.st_mode) != 0o700:
            raise OSError("probe root could not be made private")
        marker = root / "cleanup-failure.json"
        marker.write_text(
            _api.json.dumps(
                {
                    "schema": "hol-guard.installed-pi-cleanup-failure.v1",
                    "probe_root": str(root),
                    "error_type": type(failure).__name__,
                    "retry_required": True,
                    "cleanup_deferred": True,
                    "private_native_retry_state_retained": False,
                },
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
        marker.chmod(0o600)
    except OSError as exc:
        raise _api.ProbeError("redacted timeout cleanup marker could not be written safely") from exc


def _remove_probe_root(root: Path) -> None:
    _api = probe_api()
    try:
        _api.shutil.rmtree(root)
    except OSError as exc:
        try:
            _api._retain_cleanup_receipt(root, exc)
        except _api.ProbeError as scrub_failure:
            raise scrub_failure from exc
        raise _api.ProbeError("probe scratch cleanup failed") from exc
