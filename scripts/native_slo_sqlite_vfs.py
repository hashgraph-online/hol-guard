"""Opt-in observation of the actual Python SQLite engine on an owned Linux store.

The named VFS reports logical VFS calls. It does not report kernel fsync counts,
physical bytes, mmap traffic, or complete process-tree I/O. No default VFS changes.
"""

from __future__ import annotations

import contextlib
import contextvars
import copy
import hashlib
import json
import os
import sqlite3
import stat
import sys
import threading
from pathlib import Path
from typing import Any
from uuid import uuid4

from scripts.native_slo_sqlite_vfs_identity import already_mapped, code_mapping, image_identity, pinned_extension
from scripts.native_slo_sqlite_vfs_loader import load_verified_extension, loader_descriptor_report

_ACTIVE = threading.Lock()
_LOADED_IMAGES: dict[tuple[int, int], dict[str, Any]] = {}
_SCOPE: contextvars.ContextVar[str] = contextvars.ContextVar("guard_vfs_read_scope", default="other")
_RETAINED: list[SQLiteVFSObservation] = []


def _require_supported_runtime() -> None:
    if sys.version_info < (3, 12):
        raise RuntimeError("SQLite VFS observation requires Python 3.12 extension entrypoint support")
    if sys.platform != "linux" or not Path("/proc/self/fd").is_dir():
        raise RuntimeError("SQLite VFS observation requires the admitted Linux descriptor loader")


class _SQLiteProxy:
    def __init__(self, original: Any, observer: SQLiteVFSObservation) -> None:
        self.original, self.observer = original, observer

    def __getattr__(self, name: str) -> Any:
        return getattr(self.original, name)

    def connect(self, database: Any, *args: Any, **kwargs: Any) -> sqlite3.Connection:
        # The selected production factory passes the exact Path and timeout keyword.
        # All other signatures/paths remain untouched and outside this observation.
        with self.observer._lock:
            if (
                self.observer._closing
                or not isinstance(database, Path)
                or database != self.observer.database
                or args
                or set(kwargs) != {"timeout"}
            ):
                self.observer._bypassed_connects += 1
                return self.original.connect(database, *args, **kwargs)
            return self.observer._connect_factory(timeout=kwargs["timeout"])


class SQLiteVFSObservation:
    """One explicitly loaded extension and one nondefault VFS for one owned store."""

    def __init__(self, *, database: Path, extension: Path, extension_sha256: str) -> None:
        _require_supported_runtime()
        if not _ACTIVE.acquire(blocking=False):
            raise RuntimeError("another SQLite VFS observation is active")
        self._lock = threading.RLock()
        self._closing = False
        self._closed = False
        self._module: Any = None
        self._proxy: _SQLiteProxy | None = None
        self._writer_thread: threading.Thread | None = None
        self._stack = contextlib.ExitStack()
        self._control: sqlite3.Connection | None = None
        self._connects = {"other": 0, "writer": 0, "readback": 0}
        self._connect_failures = 0
        self._attestation_failures = 0
        self._identity_unchanged = True
        self._bypassed_connects = 0
        self._final: dict[str, Any] | None = None
        try:
            if _RETAINED:
                raise RuntimeError("an earlier SQLite VFS observation has unretired connections")
            self.database = database.absolute()
            if self.database != self.database.resolve(strict=True):
                raise ValueError("owned database path must not contain symlinks")
            metadata = self.database.stat()
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.getuid() or metadata.st_nlink != 1:
                raise ValueError("database must be an owned regular file")
            if metadata.st_mode & 0o022:
                raise ValueError("database must not be writable by another principal")
            descriptor, extension_identity = self._stack.enter_context(
                pinned_extension(extension, expected_sha256=extension_sha256)
            )
            image_key = (extension_identity["device"], extension_identity["inode"])
            previous = _LOADED_IMAGES.get(image_key)
            if previous is not None and previous != extension_identity:
                raise ValueError("a resident extension image changed after its prior admission")
            if previous is None and already_mapped(extension_identity):
                raise ValueError("extension is already mapped without admission")
            self._control = sqlite3.connect(":memory:", check_same_thread=False)
            self._control.enable_load_extension(True)
            try:
                load_verified_extension(self._control, descriptor, extension_identity)
            finally:
                self._control.enable_load_extension(False)
            self.name = f"guard_rsp131_{uuid4().hex}"
            first = self._command("register", self.name, str(self.database))
            observer_mapping = code_mapping(first["observer_code_address"])
            if any(observer_mapping[key] != extension_identity[key] for key in ("device", "inode")):
                raise RuntimeError("loaded observer callback does not belong to the verified extension inode")
            if not first["registered"] or not first["default_vfs_unchanged"]:
                raise RuntimeError("named VFS registration did not preserve the default VFS")
            source_id = self._control.execute("select sqlite_source_id()").fetchone()[0]
            if source_id != first["sqlite_source_id"] or sqlite3.sqlite_version_info < (3, 31, 0):
                raise RuntimeError("SQLite extension engine identity mismatch")
            import _sqlite3

            api_image = Path(first["sqlite_api_image"])
            if not api_image.is_absolute():
                raise RuntimeError("actual SQLite API image could not be identified")
            api_identity = image_identity(api_image)
            api_mapping = code_mapping(first["sqlite_api_code_address"])
            if any(api_mapping[key] != api_identity[key] for key in ("device", "inode")):
                raise RuntimeError("SQLite API callback does not belong to its hashed runtime image")
            self.identity: dict[str, Any] = {
                "extension": extension_identity,
                "python": image_identity(Path(sys.executable)),
                "python_sqlite_extension": image_identity(Path(_sqlite3.__file__)),
                "actual_sqlite_api_image": api_identity,
                "actual_sqlite_api_mapping": api_mapping,
                "actual_observer_mapping": observer_mapping,
                "sqlite_version": sqlite3.sqlite_version,
                "sqlite_source_id": source_id,
                "extension_loaded_by_actual_python_connection": True,
                "database_path_sha256": hashlib.sha256(os.fsencode(self.database)).hexdigest(),
                "database_admission_identity": [metadata.st_dev, metadata.st_ino],
                "platform": sys.platform,
            }
            _LOADED_IMAGES[image_key] = extension_identity
        except BaseException:
            try:
                try:
                    if self._control is not None:
                        self._control.close()
                finally:
                    self._stack.close()
            finally:
                _ACTIVE.release()
            raise

    def _command(self, command: str, name: str = "", database: str = "") -> dict[str, Any]:
        assert self._control is not None
        raw = self._control.execute("select guard_sqlite_vfs(?, ?, ?)", (command, name, database)).fetchone()[0]
        if not isinstance(raw, str) or len(raw.encode("utf-8")) > 65_536:
            raise RuntimeError("SQLite VFS aggregate exceeded its fixed report bound")
        result = json.loads(raw)
        if result.get("schema") != 1 or len(result.get("cells", [])) != 12:
            raise RuntimeError("SQLite VFS aggregate shape mismatch")
        return result

    @staticmethod
    def _main_opens(snapshot: dict[str, Any], scope: str) -> int:
        return sum(
            cell["vfs_x_open_calls"]
            for cell in snapshot["cells"]
            if cell["scope"] == scope and cell["file_role"] == "main_database"
        )

    def connect(self, *, scope: str = "other", **kwargs: Any) -> sqlite3.Connection:
        """Open an explicit local control before any store factory is installed."""
        with self._lock:
            if self._writer_thread is not None:
                raise RuntimeError("explicit local control is unavailable after factory installation")
            return self._connect_observed(scope=scope, **kwargs)

    def _connect_factory(self, *, timeout: Any) -> sqlite3.Connection:
        """Derive factory attribution from the actual calling thread and context."""
        with self._lock:
            if self._module is None or self._module.sqlite3 is not self._proxy:
                raise RuntimeError("SQLite VFS selected factory is not installed")
            scope = "writer" if threading.current_thread() is self._writer_thread else _SCOPE.get()
            return self._connect_observed(scope=scope, timeout=timeout)

    def _connect_observed(self, *, scope: str, **kwargs: Any) -> sqlite3.Connection:
        if scope not in self._connects or "uri" in kwargs:
            raise ValueError("invalid SQLite VFS connection scope or URI override")
        with self._lock:
            if self._closing:
                raise RuntimeError("SQLite VFS observation is closing")
            before = self._command("snapshot")
            uri = f"{self.database.as_uri()}?vfs={self.name}&guard_scope={scope}"
            try:
                connection = sqlite3.connect(uri, uri=True, **kwargs)
            except BaseException:
                self._connect_failures += 1
                raise
            try:
                after = self._command("snapshot")
                rows = connection.execute("pragma database_list").fetchall()
                actual = next(row[2] for row in rows if row[1] == "main")
                source_id = connection.execute("select sqlite_source_id()").fetchone()[0]
                if (
                    Path(actual) != self.database
                    or source_id != self.identity["sqlite_source_id"]
                    or self._main_opens(after, scope) != self._main_opens(before, scope) + 1
                    or not after["default_vfs_unchanged"]
                    or after["unsupported_method_versions"]
                ):
                    raise RuntimeError("Python SQLite connection did not attest to the named VFS")
                self._connects[scope] += 1
                return connection
            except BaseException:
                self._attestation_failures += 1
                connection.close()
                raise

    def install(self, store: Any, writer: Any) -> None:
        """Patch only this module's reference, never sqlite3.connect globally."""
        from codex_plugin_scanner.guard import store_connection_schema

        with self._lock:
            if (
                self._closing
                or self._module is not None
                or store.path != self.database
                or sum(self._connects.values()) != 0
            ):
                raise RuntimeError("SQLite VFS store scope admission failed")
            if store_connection_schema.sqlite3 is not sqlite3 or store is not writer._store:
                raise RuntimeError("SQLite VFS connection factory or writer ownership changed")
            self._writer_thread = writer._thread
            self._module = store_connection_schema
            self._proxy = _SQLiteProxy(sqlite3, self)
            self._module.sqlite3 = self._proxy

    @contextlib.contextmanager
    def readback(self) -> Any:
        token = _SCOPE.set("readback")
        try:
            yield
        finally:
            _SCOPE.reset(token)

    def report(self) -> dict[str, Any]:
        with self._lock:
            observed = copy.deepcopy(self._final) if self._closed else self._command("snapshot")
            assert observed is not None
            cells = observed["cells"]
            scope_complete = (
                observed["default_vfs_unchanged"]
                and not observed["saturated"]
                and observed["unsupported_method_versions"] == 0
                and observed["outside_owned_file_opens"] == 0
                and self._attestation_failures == 0
                and self._identity_unchanged
                and all(cell["calls_on_different_thread"] == 0 and cell["vfs_x_close_errors"] == 0 for cell in cells)
            )
            return {
                "identity": copy.deepcopy(self.identity),
                "loader": loader_descriptor_report(self.identity["extension"], admitted_images=len(_LOADED_IMAGES)),
                "vfs": observed,
                "attested_connections": dict(self._connects),
                "connection_failures": self._connect_failures,
                "connection_attestation_failures": self._attestation_failures,
                "extension_identity_unchanged": self._identity_unchanged,
                "connections_outside_exact_factory_signature": self._bypassed_connects,
                "connection_scope_at_open_complete": scope_complete,
                "closed": self._closed,
                "all_vfs_files_closed": observed["active_files"] == 0 and observed["opening_files"] == 0,
                "scope": (
                    "named_vfs_connections_from_selected_store_factory"
                    if self._writer_thread is not None
                    else "explicit_named_vfs_local_control_connections"
                ),
                "scope_assignment": (
                    "actual_writer_thread_else_explicit_readback_else_other"
                    if self._writer_thread is not None
                    else "explicit_local_control_scope_at_open"
                ),
                "connection_identity_attestation_is_included_in_observed_calls": True,
                "unavailable": {
                    "kernel_fsync_calls": "VFS_xSync_is_not_a_kernel_syscall_count",
                    "kernel_written_bytes": "VFS_xWrite_status_is_not_a_kernel_byte_count",
                    "physical_device_written_bytes": "not_observed",
                    "mmap_read_bytes": "xFetch_returns_a_mapping_not_consumed_byte_counts",
                    "shm_physical_bytes": "original_shared_memory_callbacks_forwarded_without_byte_accounting",
                    "directory_sync_effects": "original_VFS_xDelete_and_other_nonfile_callbacks_are_forwarded",
                    "failed_xWrite_actual_bytes": "a_failing_write_may_have_written_an_unknown_prefix",
                    "complete_database_io": "other_factories_and_processes_are_outside_this_scope",
                },
                "qualified": False,
            }

    def close(self) -> bool:
        with self._lock:
            if self._closed:
                return True
            self._closing = True
            if self._module is not None:
                if self._module.sqlite3 is not self._proxy:
                    self._attestation_failures += 1
                else:
                    self._module.sqlite3 = sqlite3
                self._module = None
            observed = self._command("snapshot")
            if observed["active_files"] or observed["opening_files"]:
                if self not in _RETAINED:
                    _RETAINED.append(self)
                return False
            self._final = self._command("unregister")
            assert self._control is not None
            self._control.close()
            self._control = None
            try:
                self._stack.close()
            except BaseException:
                self._identity_unchanged = False
                raise
            finally:
                self._closed = True
                if self in _RETAINED:
                    _RETAINED.remove(self)
                _ACTIVE.release()
            return True

    def __enter__(self) -> SQLiteVFSObservation:
        return self

    def __exit__(self, *args: Any) -> None:
        if not self.close():
            raise RuntimeError("SQLite VFS observation ended with unretired connections")
