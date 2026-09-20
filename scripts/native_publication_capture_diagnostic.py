"""Observe reservation metadata comparisons without reading their sources."""

from __future__ import annotations

import threading
from collections.abc import Callable, Generator
from contextlib import contextmanager, suppress
from typing import cast, final

from codex_plugin_scanner.guard import native_policy_snapshot_publisher_scoped as scoped

_Metadata = tuple[int, int, int, int] | None
_Fingerprint = tuple[tuple[str, _Metadata], ...]
_Compare = Callable[[_Fingerprint, _Fingerprint, str], bool]
_KINDS = ("database", "wal", "shm", "journal", "configuration", "verifier", "command_authority", "other_policy")
_DATABASE_SUFFIXES = {"": "database", "-wal": "wal", "-shm": "shm", "-journal": "journal"}
_LOCK = threading.RLock()
_installation: _Installation | None = None


def _kind(path: str, database_path: str) -> str:
    for suffix, kind in _DATABASE_SUFFIXES.items():
        if path == database_path + suffix:
            return kind
    name = path.replace("\\", "/").rsplit("/", 1)[-1]
    if name in {"config.toml", ".ai-plugin-scanner-guard.toml", ".hol-guard.toml"}:
        return "configuration"
    if name == "policy-verifier.key":
        return "verifier"
    if name == "command-control-authority.v1.json":
        return "command_authority"
    return "other_policy"


@final
class _Installation:
    """A detached wrapper remains a pass-through for already captured calls."""

    def __init__(self, original: _Compare) -> None:
        self.original = original
        self.observers: dict[CaptureMetadataObservation, int] = {}
        self.active = True

        def compare(before: _Fingerprint, after: _Fingerprint, database_path: str) -> bool:
            result = original(before, after, database_path)
            with suppress(BaseException):
                with _LOCK:
                    observers = tuple(
                        observer
                        for observer, owner in self.observers.items()
                        if self.active and owner == threading.get_ident()
                    )
                for observer in observers:
                    observer.record(before, after, database_path, result)
            return result

        self.compare = compare


@final
class CaptureMetadataObservation:
    """Retain only finite categories and capped counters from existing results."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._attached = False
        self._checks = 0
        self._changed = 0
        self._kinds = {kind: 0 for kind in _KINDS}

    def record(self, before: _Fingerprint, after: _Fingerprint, database_path: str, equal: bool) -> None:
        changed_kinds: set[str] = set()
        if not equal:
            previous, current = dict(before), dict(after)
            for path in previous.keys() | current.keys():
                left, right = previous.get(path), current.get(path)
                kind = _kind(path, database_path)
                # Match the existing comparator: only database-family ctime
                # normalization is permitted. No source fence is evaluated here.
                normalized_left = left[:3] if left and kind in _DATABASE_SUFFIXES.values() else left
                normalized_right = right[:3] if right and kind in _DATABASE_SUFFIXES.values() else right
                if normalized_left != normalized_right:
                    changed_kinds.add(kind)
        with self._lock:
            self._checks = min(999, self._checks + 1)
            self._changed = min(999, self._changed + (not equal))
            for kind in changed_kinds:
                self._kinds[kind] = min(999, self._kinds[kind] + 1)

    @contextmanager
    def attach(self, publisher: object) -> Generator[None, None, None]:
        global _installation
        try:
            thread = cast(dict[str, object], vars(publisher)).get("_thread")
        except TypeError:
            thread = None
        owner = thread.ident if isinstance(thread, threading.Thread) else None
        if type(owner) is not int:
            yield
            return
        with _LOCK:
            if _installation is None:
                _installation = _Installation(scoped._capture_metadata_equal)
                scoped._capture_metadata_equal = _installation.compare
            installation = _installation
            installation.observers[self] = owner
            self._attached = True
        try:
            yield
        finally:
            with _LOCK:
                _ = installation.observers.pop(self, None)
                if not installation.observers:
                    installation.active = False
                    if scoped._capture_metadata_equal is installation.compare:
                        scoped._capture_metadata_equal = installation.original
                    if _installation is installation:
                        _installation = None

    def describe(self) -> str:
        with self._lock:
            kinds = ",".join(f"{kind}:{self._kinds[kind]}" for kind in _KINDS if self._kinds[kind]) or "none"
            return (
                f"; reservation_metadata_attached={self._attached}"
                f"; reservation_metadata_checks={self._checks}"
                f"; reservation_metadata_changed={self._changed}"
                f"; reservation_metadata_kinds={kinds}"
            )
