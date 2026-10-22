"""Verified factory boundary and thin IO for Rust metadata preparation.

Rust requests bounded fetches and owns every traversal, proof, index, CAS write
and handle check. This module never interprets catalog or transport metadata.
"""

from __future__ import annotations

import base64
import json
import threading
import time
from contextlib import suppress
from contextvars import Context, ContextVar
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..daemon.background_diagnostics import failure_detail, record_background_event
from ..file_identity import full_stat_identity
from ..native_resident_client import native_resident_client_request
from ..native_runtime import _isolated_environment, native_runtime_status
from ..strict_json_pairs import unique_json_object
from . import lifecycle
from .authority import VerifiedDistribution

CAPABILITY = "catalog-prepare-v1"
BATCH_CAPABILITY = "catalog-prepare-batch-v1"
_lock = threading.Lock()
_cached: tuple[Path, str, DiscoveryHandle] | None = None
# One bounded background preparation slot, outside HTTP/hook/lease execution.
# Only a handle is cached. Errors are retried automatically after a short
# backoff; no contributor or user preparation command is needed.
_ready_lock = threading.Lock()
_home: Path | None = None
_worker: threading.Thread | None = None
_handle = None
_retry_after = 0.0
_refresh_worker: threading.Thread | None = None
_refresh_after = 0.0
_transport: ContextVar[list[Any] | None] = ContextVar("catalog_preparation_transport", default=None)
# Preparation reverifies the installed release from scratch on every attempt, so
# a deterministic fault (a resealed runtime whose manifests disagree, a corrupt
# asset) fails every attempt identically. One failure can still be a cold start
# racing a restarting resident, so a read only reports a failing preparation
# after this many consecutive attempts have failed.
PERSISTENT_PREPARATION_FAILURES = 2
# `installed_discovery` reports a failing preparation with this exact message.
# The read path matches it by value, the way this module already classifies the
# handle codes above, so a test that stubs this module keeps its behaviour.
PREPARATION_FAILING = "native discovery preparation failing"
PREPARING = "native discovery preparing"
# A resident that is restarting or was replaced mid-attempt fails preparation
# without saying anything about the installed release, so these never count
# toward a failing preparation.
_RETRYABLE_FAILURES = frozenset({"native discovery transport unavailable", "native discovery runtime changed"})
_failures = 0


@dataclass(frozen=True, slots=True, init=False)
class DiscoveryHandle:
    guard_home: Path
    native: dict[str, Any]

    def __new__(cls):
        raise TypeError("discovery handles must be prepared from authenticated metadata")

    @property
    def root(self):
        return self.native["root"]

    @property
    def authority(self):
        return self.native["authority"]

    @property
    def expires_at(self):
        return self.native["expires_at"]


def _installed_type():
    from .installed_bundle import VerifiedInstalledBundle

    return VerifiedInstalledBundle


def _native(guard_home, action):
    captured = _transport.get()
    status = captured[0] if captured else native_runtime_status()
    if (
        not status.available
        or not status.compatible
        or status.identity is None
        or status.capabilities is None
        or CAPABILITY not in status.capabilities.features
    ):
        raise ValueError("native discovery preparation unavailable")
    metadata = status.identity.path.lstat()
    stamp = full_stat_identity(metadata)
    if metadata.st_size != status.identity.size or metadata.st_mtime_ns != status.identity.mtime_ns:
        raise ValueError("native discovery runtime changed")
    if captured is not None:
        if not captured:
            captured.extend((status, stamp))
        elif stamp != captured[1]:
            raise ValueError("native discovery runtime changed")
    if action["kind"] == "begin":
        if BATCH_CAPABILITY not in status.capabilities.features:
            raise ValueError("native discovery batched preparation unavailable")
        action = {**action, "kind": "begin_batched"}
    payload = json.dumps(
        {
            "operation": "catalog_prepare_v1",
            "request": {"guard_home": str(guard_home), "action": action},
            "deadline_budget_ms": 60_000,
        },
        separators=(",", ":"),
    ).encode()
    response = native_resident_client_request(
        executable=status.identity.path,
        guard_home=guard_home,
        environment=_isolated_environment(),
        payload=payload,
        timeout_seconds=60,
    )
    if response is None:
        raise ValueError("native discovery transport unavailable")
    value = json.loads(response, object_pairs_hook=unique_json_object)
    if not isinstance(value, dict) or value.get("schema") != "guard.catalog-prepare-result.v1":
        raise ValueError("native discovery result invalid")
    if value.get("outcome") == "error":
        raise ValueError(value.get("error_code", "native discovery failed"))
    return value


def prepare_discovery(guard_home: Path, authority, *, fetch=None) -> DiscoveryHandle:
    """Forward verified factory bytes; preparation runs outside hook decisions."""
    token = _transport.set([])
    try:
        # A preparation asks for up to 64 members per batch. One session verifies
        # and copies the runtime once for all of them.
        with lifecycle.session():
            return _prepare_discovery(guard_home, authority, fetch=fetch)
    finally:
        _transport.reset(token)


def _recheck_runtime():
    captured = _transport.get()
    if captured:
        current = native_runtime_status()
        if not current.available or not current.compatible or current.identity != captured[0].identity:
            raise ValueError("native discovery runtime changed")


def _prepare_discovery(guard_home: Path, authority, *, fetch=None) -> DiscoveryHandle:
    global _cached
    if type(authority) is VerifiedDistribution:
        profile = "remote"
        expiry = authority.expires_at
        if fetch is None:
            raise ValueError("discovery remote transport absent")
    elif type(authority) is _installed_type():
        profile, expiry, fetch = "installed", None, authority.preparation_fetch()
    else:
        raise ValueError("discovery requires factory-authenticated authority")
    guard_home = guard_home.absolute()
    with _lock:
        if _cached is not None and _cached[:2] == (guard_home, authority.digest):
            try:
                handle = require_handle(_cached[2], guard_home)
                _recheck_runtime()
                return handle
            except ValueError as error:
                if str(error) not in {
                    "catalog_prepare_handle_invalid",
                    "catalog_prepare_object_corrupt",
                    "catalog_prepare_object_unavailable",
                }:
                    raise
                # A restarted resident has no registered handle. Re-prepare
                # from the same verified factory; Rust rechecks every proof.
                _cached = None
        result = _native(
            guard_home,
            {
                "kind": "begin",
                "authority": {
                    "data": base64.b64encode(authority.data).decode("ascii"),
                    "digest": authority.digest,
                    "source_sha": authority.source_sha,
                    "profile": profile,
                    "expires_at": expiry,
                },
            },
        )
        session = None
        try:
            while result.get("outcome") in {"fetch", "fetch_batch", "continue"}:
                session = result["session"]
                if result["outcome"] == "continue":
                    result = _native(guard_home, {"kind": "resume", "session": session})
                    continue
                if result["outcome"] == "fetch_batch":
                    requests = result["fetches"]
                    if not isinstance(requests, list) or not 0 < len(requests) <= 64:
                        raise ValueError("native discovery batch invalid")
                    data = [base64.b64encode(fetch(r["location"], r["length"])).decode("ascii") for r in requests]
                    result = _native(guard_home, {"kind": "advance_batch", "session": session, "data": data})
                    continue
                request = result["fetch"]
                data = fetch(request["location"], request["length"])
                result = _native(
                    guard_home,
                    {"kind": "advance", "session": session, "data": base64.b64encode(data).decode("ascii")},
                )
            if result.get("outcome") != "complete":
                raise ValueError("native discovery preparation incomplete")
        except BaseException:
            if session is not None:
                with suppress(ValueError, OSError):
                    _native(guard_home, {"kind": "abort", "session": session})
            raise
        _recheck_runtime()
        handle = object.__new__(DiscoveryHandle)
        object.__setattr__(handle, "guard_home", guard_home)
        object.__setattr__(handle, "native", result["handle"])
        _cached = (guard_home, authority.digest, handle)
        return handle


def _prepare_ready(home):
    global _handle, _worker, _retry_after, _failures
    handle = None
    retryable = False
    try:
        from .installed_bundle import load_installed_bundle

        handle = prepare_discovery(home, load_installed_bundle())
    except (ImportError, OSError, ValueError, KeyError, TypeError) as error:
        retryable = type(error) is ValueError and str(error) in _RETRYABLE_FAILURES
        # A permanent fault here used to leave no line anywhere while every
        # catalog read answered 503, so a broken installed runtime could only
        # be found by probing the bundle. The thread stays non-fatal and the
        # backoff below is unchanged; this only records what failed.
        record_background_event("catalog_preparation_failed", failure_detail(error))
    finally:
        with _ready_lock:
            if _home == home:
                if _handle is None:
                    _handle = handle
                if handle is not None:
                    _failures = 0
                elif not retryable:
                    _failures += 1
            _worker = None
            _retry_after = time.monotonic() + (1.0 if handle is None else 0.0)
        request_refresh(home)


def _refresh(home, store):
    global _handle, _refresh_worker, _failures
    try:
        from .current_refresh import refresh, restore

        if store is None:
            from ..store import GuardStore

            store = GuardStore(home)
        try:
            handle = refresh(store)
        except Exception:
            # Vetted verifier errors are not all ValueError/OSError. Restore
            # still requires its own factory and native completed-view proof.
            handle = restore(store)
        with _ready_lock:
            if _home == home:
                _handle = handle
                if handle is not None:
                    # A published view proves preparation works again, so an
                    # older streak must not survive a later invalidation.
                    _failures = 0
    except Exception as error:
        # Complete previous view and active protection remain independent, so
        # this stays non-fatal; it is recorded because a publication that never
        # refreshes is otherwise indistinguishable from one that never ran.
        record_background_event("catalog_publication_refresh_failed", failure_detail(error))
    finally:
        with _ready_lock:
            _refresh_worker = None


def request_refresh(home: Path, *, store=None):
    """Daemon timer and initial control-plane preparation share one IO worker."""
    global _home, _refresh_worker, _refresh_after
    home = home.absolute()
    with _ready_lock:
        if _home is None:
            _home = home
        if _home != home or _refresh_worker is not None or time.monotonic() < _refresh_after:
            return
        _refresh_after = time.monotonic() + 300.0
        # A fresh context keeps the caller's lifecycle session out of this
        # worker, which can outlive it (free-threaded builds inherit context).
        _refresh_worker = threading.Thread(
            target=Context().run,
            args=(_refresh, home, store),
            name="catalog-current-publication",
            daemon=True,
        )
        _refresh_worker.start()


def installed_discovery(guard_home: Path) -> DiscoveryHandle:
    """Nonblocking control-plane readiness; the worker verifies and prepares.

    Raises ``ValueError(PREPARING)`` while preparation may still succeed, and
    ``ValueError(PREPARATION_FAILING)`` once consecutive attempts have failed.
    Both keep the caller off a trusted snapshot; only the second tells it that
    waiting cannot help.
    """
    global _home, _worker, _handle, _failures
    home = guard_home.absolute()
    with _ready_lock:
        if _home == home and _handle is not None:
            return _handle
        if _worker is None and time.monotonic() >= _retry_after:
            if _home != home:
                _failures = 0
            _home, _handle = home, None
            _worker = threading.Thread(target=_prepare_ready, args=(home,), name="catalog-preparation", daemon=True)
            _worker.start()
        failing = _home == home and _failures >= PERSISTENT_PREPARATION_FAILURES
    raise ValueError(PREPARATION_FAILING if failing else PREPARING)


def invalidate(home, handle):
    global _handle, _cached
    with _ready_lock:
        if _home == home.absolute() and _handle is handle:
            _handle = None
            # A child CAS object may have failed although the root is intact.
            # Force full Rust proof reconstruction, not just root validation.
            if _cached is not None and _cached[2] is handle:
                _cached = None


def require_handle(handle, guard_home: Path) -> DiscoveryHandle:
    if type(handle) is not DiscoveryHandle:
        raise ValueError("discovery handle is unverified")
    result = _native(guard_home.absolute(), {"kind": "validate", "handle": handle.native})
    if result.get("outcome") != "valid":
        raise ValueError("native discovery handle invalid")
    return handle
