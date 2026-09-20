"""Frozen original atomic writer for real Windows before/after controls.

Original full module Git blob: feb0a1907a024b5fbfd0b7c5ec890d8dc250a0ef.
The original function AST is preserved except for its name; one guarded POSIX
attribute has a checker annotation for Windows stubs.
"""

from __future__ import annotations

from codex_plugin_scanner.guard.daemon import manager as _manager


def original_write_private_atomic_text(path: _manager.Path, text: str) -> None:
    descriptor, temporary_name = _manager.tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary_path = _manager.Path(temporary_name)
    try:
        if _manager.os.name != "nt" and hasattr(_manager.os, "fchmod"):
            _manager.os.fchmod(  # pyright: ignore[reportAttributeAccessIssue]
                descriptor, _manager._GUARD_DAEMON_PRIVATE_FILE_MODE
            )
        with _manager.os.fdopen(descriptor, "w", encoding="utf-8", closefd=False) as handle:
            handle.write(text)
            handle.flush()
            _manager.os.fsync(handle.fileno())
        _manager.os.close(descriptor)
        descriptor = -1
        _manager.os.replace(temporary_path, path)
        _manager._set_private_mode(path, _manager._GUARD_DAEMON_PRIVATE_FILE_MODE)
    finally:
        if descriptor >= 0:
            _manager.os.close(descriptor)
        with _manager.suppress(OSError):
            temporary_path.unlink()
