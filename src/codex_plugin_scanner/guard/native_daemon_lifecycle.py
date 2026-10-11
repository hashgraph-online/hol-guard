"""Transport for the native daemon lifecycle decision owner.

The resident decides the pure questions of the Guard daemon lifecycle: how a
process command line classifies, which processes prove or contradict a daemon
for a home, which port is configured or adoptable, whether a health payload or
state record is current, whether a reservation may be claimed and whether a
recorded start is still live. Python gathers only what the operating system can
supply (a resolved path, a pid probe, a Windows argv, a decoded launcher
payload) and acts on the verdict. It never recomputes or overrides one.

Facts are requested lazily: the resident replies ``{"need": "facts", "keys":
[...]}``, the caller resolves exactly those keys (``None`` means the probe
failed) and repeats the identical request with them added. Anything but a
bound, well-formed answer raises ``NativeDaemonLifecycleError`` so callers fail
closed.
"""

from __future__ import annotations

import contextvars
import copy
import hashlib
import json
import math
import os
import threading
import time
from collections import OrderedDict
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any
from uuid import uuid4

from .native_context import _canonical_request_sha256, _resolve_existing_digest_home, ensure_resident_prerequisite
from .native_execution import _resident_request
from .native_resident_client import native_resident_client_failure_code, native_resident_client_ready
from .native_runtime import native_runtime_probe_missed, native_runtime_status
from .native_runtime_resilience import native_record_resident_failure, native_record_resident_success

DAEMON_LIFECYCLE_FEATURE = "daemon-lifecycle-decision-v1"
_REQUEST_SCHEMA = "guard-daemon-lifecycle-decision-request.v1"
_RESULT_SCHEMA = "guard-daemon-lifecycle-decision-result.v1"
_OPERATION = "daemon_lifecycle_decide"
_MAX_REQUEST_BYTES = 2 * 1024 * 1024
_MAX_NEED_ROUNDS = 8
_TIMEOUT_SECONDS = 10.0
# The pooled resident is spawned lazily by the first request of a process, and
# every packaged CLI step is a new process. A cold Windows runner can spend
# longer than the steady-state budget just starting the resident executable
# (process creation plus first-run scanning of a 20 MB binary) before it
# answers. Grant that one spawn an allowance so a slow start does not become a
# lifecycle outage that fails daemon startup; the caller's deadline still wins.
_COLD_START_ALLOWANCE_SECONDS = 20.0
_RUNTIME_PROBE_WAIT_SECONDS = 15.0
_RUNTIME_PROBE_RETRY_SECONDS = 0.3

FactResolver = Callable[[str], object]

# A verdict is a pure function of (platform, query, facts), so an identical
# request needs no second round trip. ``_NEED_KEYS`` remembers which facts a
# query asked for so a repeat sends them in the first request instead of
# discovering them one round at a time; ``_VERDICTS`` replays a verdict only for
# byte-identical inputs. Both are keyed by the resident binary identity, bounded,
# and never hold failures. Time-bearing checks carry ``now`` in the query and
# therefore never repeat; they are not cached at all.
_UNCACHED_CHECKS = frozenset({"wake_claim", "recovery_claim", "start_progress_live", "ephemeral_inactive"})
_FLOAT_QUERY_FIELDS = frozenset({"now", "worker_ready_floor", "fallback_age_seconds"})
_CACHE_ENTRIES = 512
_CACHE_QUERY_BYTES = 64 * 1024
_cache_lock = threading.Lock()
_NEED_KEYS: OrderedDict[str, tuple[str, ...]] = OrderedDict()
_VERDICTS: OrderedDict[str, dict[str, Any]] = OrderedDict()
_DAEMON_LIFECYCLE_DEADLINE: contextvars.ContextVar[float | None] = contextvars.ContextVar(
    "hol_guard_daemon_lifecycle_deadline",
    default=None,
)


def _digest(material: object) -> str | None:
    try:
        encoded = json.dumps(material, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)
    except (TypeError, ValueError):
        return None
    if len(encoded) > _CACHE_QUERY_BYTES:
        return None
    return hashlib.sha256(encoded.encode("ascii")).hexdigest()


def _remember(cache: OrderedDict[str, Any], key: str, value: object) -> None:
    with _cache_lock:
        cache[key] = value
        cache.move_to_end(key)
        while len(cache) > _CACHE_ENTRIES:
            cache.popitem(last=False)


def _recall(cache: OrderedDict[str, Any], key: str) -> Any:
    with _cache_lock:
        value = cache.get(key)
        if value is not None:
            cache.move_to_end(key)
        return value


class NativeDaemonLifecycleError(RuntimeError):
    """No authoritative native answer; callers must fail closed.

    This is not a ``ValueError``. Health probes catch ``ValueError`` to mean
    the payload is stale or unreadable, and a resident outage must not take
    that path.
    """


def _fail(code: str) -> NativeDaemonLifecycleError:
    return NativeDaemonLifecycleError(code)


def _record_failure(home: Path, reason: str) -> None:
    status = native_runtime_status()
    if status.identity is not None:
        native_record_resident_failure(status.identity.sha256, home, reason=reason)


def _record_success(home: Path) -> None:
    status = native_runtime_status()
    if status.identity is not None:
        native_record_resident_success(status.identity.sha256, home)


def bind_daemon_lifecycle_deadline(deadline: float | None) -> contextvars.Token[float | None]:
    """Narrow the active lifecycle deadline to ``deadline`` when it is sooner."""

    current = _DAEMON_LIFECYCLE_DEADLINE.get()
    if deadline is None:
        chosen = current
    elif isinstance(deadline, bool) or not isinstance(deadline, (int, float)) or not math.isfinite(deadline):
        raise _fail("native_daemon_lifecycle_deadline")
    elif current is None:
        chosen = float(deadline)
    else:
        chosen = min(current, float(deadline))
    return _DAEMON_LIFECYCLE_DEADLINE.set(chosen)


def reset_daemon_lifecycle_deadline(token: contextvars.Token[float | None]) -> None:
    _DAEMON_LIFECYCLE_DEADLINE.reset(token)


def daemon_lifecycle_deadline() -> float | None:
    return _DAEMON_LIFECYCLE_DEADLINE.get()


def _active_deadline(explicit: float | None) -> float | None:
    bound = _DAEMON_LIFECYCLE_DEADLINE.get()
    if explicit is None:
        return bound
    if isinstance(explicit, bool) or not isinstance(explicit, (int, float)) or not math.isfinite(explicit):
        raise _fail("native_daemon_lifecycle_deadline")
    if bound is None:
        return float(explicit)
    return min(bound, float(explicit))


def _timeout_seconds(deadline: float | None, *, cold_start: bool = False) -> float:
    budget = _TIMEOUT_SECONDS + (_COLD_START_ALLOWANCE_SECONDS if cold_start else 0.0)
    if deadline is None:
        return budget
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError("Guard daemon operation deadline exceeded.")
    return min(budget, remaining)


def _await_native_runtime(timeout_seconds: float) -> float:
    """Wait out a transient capability-probe miss before asking the resident.

    A freshly installed runtime can fail its first ``capabilities`` probe on a cold host; that miss is
    never cached and clears on the next attempt. Without a wait the one lifecycle request reads the miss
    as "no resident" and the daemon operation fails. The verdict stays the resident's: this only waits
    for the runtime to become usable and never decides anything. Only an installed runtime whose probe
    missed is waited on; no runtime at all, or a real incompatibility, returns at once. Returns the
    seconds spent so the caller can charge them against the request budget.
    """

    started = time.monotonic()
    deadline = started + min(timeout_seconds, _RUNTIME_PROBE_WAIT_SECONDS)
    waited = False
    while True:
        status = native_runtime_status(deadline_monotonic=deadline)
        if status.available and status.capabilities is not None:
            break
        if status.identity is not None or not native_runtime_probe_missed():
            break  # A manifest error or no runtime at all is not transient; report it as is.
        if time.monotonic() + _RUNTIME_PROBE_RETRY_SECONDS >= deadline:
            break
        waited = True
        time.sleep(_RUNTIME_PROBE_RETRY_SECONDS)
    # A runtime that was usable at once costs the request nothing; only a real wait is charged to it.
    return time.monotonic() - started if waited else 0.0


def _runtime_unavailable_detail() -> str:
    """Name why no client ran: an unusable runtime leaves no transport failure code."""

    status = native_runtime_status()
    if status.available and status.compatible and status.capabilities is not None:
        return "no_client_code"
    return f"runtime_unavailable:{status.reason}"


def _resident_is_cold(home: Path) -> bool:
    """True when this process holds no warm resident client, so a spawn is due."""

    status = native_runtime_status()
    if status.identity is None:
        return False
    return not native_resident_client_ready(status.identity.path, home)


def _normalize_query_numbers(query: Mapping[str, object]) -> dict[str, object]:
    """Match the resident's ``f64`` JSON spelling before the request is hashed."""

    normalized: dict[str, object] = {}
    for key, value in query.items():
        if key not in _FLOAT_QUERY_FIELDS or value is None:
            normalized[key] = value
            continue
        if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
            raise _fail("native_daemon_lifecycle_request_invalid")
        normalized[key] = float(value)
    return normalized


def _round_trip(
    query: Mapping[str, object],
    facts: Mapping[str, object],
    home: Path,
    platform: str,
    timeout_seconds: float,
) -> dict[str, Any]:
    request: dict[str, object] = {
        "schema": _REQUEST_SCHEMA,
        "request_id": f"daemon-lifecycle-{uuid4().hex}",
        "platform": platform,
        "facts": dict(facts),
        "query": dict(query),
    }
    try:
        digest = "sha256:" + _canonical_request_sha256(request)
    except (TypeError, ValueError) as error:
        raise _fail("native_daemon_lifecycle_request_invalid") from error
    if not ensure_resident_prerequisite(home):
        raise _fail("native_daemon_lifecycle_prerequisite_unavailable")
    timeout_seconds -= _await_native_runtime(timeout_seconds)
    if timeout_seconds <= 0:
        raise _fail("native_daemon_lifecycle_deadline")
    response = _resident_request(
        operation=_OPERATION,
        request=request,
        guard_home=home,
        timeout_seconds=timeout_seconds,
        required_feature=DAEMON_LIFECYCLE_FEATURE,
        response_schema=_RESULT_SCHEMA,
        max_request_bytes=_MAX_REQUEST_BYTES,
        record_success=False,
    )
    if response is None:
        # ``_resident_request`` already recorded the failure; do not count it twice.
        detail = native_resident_client_failure_code() or _runtime_unavailable_detail()
        raise _fail(f"native_daemon_lifecycle_unavailable:{detail}")
    if (
        response.get("schema") != _RESULT_SCHEMA
        or response.get("request_id") != request["request_id"]
        or response.get("request_sha256") != digest
    ):
        _record_failure(home, "native_daemon_lifecycle_binding_mismatch")
        raise _fail("native_daemon_lifecycle_unavailable")
    if response.get("status") != "ok" or response.get("code") != "ok":
        # A bound refusal answers this exact request; it is not an outage.
        _record_success(home)
        raise _fail("native_daemon_lifecycle_refused")
    payload = response.get("payload")
    if not isinstance(payload, dict):
        _record_failure(home, "native_daemon_lifecycle_payload_invalid")
        raise _fail("native_daemon_lifecycle_payload_invalid")
    return payload


def native_daemon_lifecycle(
    check: str,
    query: Mapping[str, object],
    *,
    resolve_fact: FactResolver | None = None,
    guard_home: Path | None = None,
    platform: str | None = None,
    deadline_monotonic: float | None = None,
) -> dict[str, Any]:
    """Return the resident's verdict for one ``check``, resolving fact requests."""

    return _decide(check, query, resolve_fact, guard_home, platform, deadline_monotonic)


def _decide(
    check: str,
    query: Mapping[str, object],
    resolve_fact: FactResolver | None,
    guard_home: Path | None,
    platform: str | None,
    deadline_monotonic: float | None,
) -> dict[str, Any]:
    # Verdicts are pure, so a home that does not exist yet must not be created
    # (or get its own resident) just to be asked a question; use the context home.
    home = _resolve_existing_digest_home(guard_home)
    platform = platform or ("nt" if os.name == "nt" else "posix")
    deadline = _active_deadline(deadline_monotonic)
    # The resident digests its typed decoding of the request, which omits unset
    # optional fields and renders f64 fields with a fractional part. Match that
    # spelling before hashing so an integer ``10`` is not a different request
    # from the resident's ``10.0``.
    numbers = _normalize_query_numbers(query)
    full_query = {"check": check, **{key: value for key, value in numbers.items() if value is not None}}
    status = native_runtime_status(deadline_monotonic=deadline)
    identity = status.identity.sha256 if status.identity is not None else ""
    query_key = None
    if check not in _UNCACHED_CHECKS and identity:
        query_digest = _digest({"platform": platform, "query": full_query})
        query_key = None if query_digest is None else f"{identity}:{home}:{query_digest}"
    facts: dict[str, object] = {}
    if query_key is not None and resolve_fact is not None:
        for key in _recall(_NEED_KEYS, query_key) or ():
            facts[key] = resolve_fact(key)
        facts_digest = _digest(facts)
        if facts_digest is not None:
            cached = _recall(_VERDICTS, f"{query_key}:{facts_digest}")
            if cached is not None:
                if not ensure_resident_prerequisite(home):
                    raise _fail("native_daemon_lifecycle_prerequisite_unavailable")
                return copy.deepcopy(cached)
    for _ in range(_MAX_NEED_ROUNDS):
        payload = _round_trip(
            full_query,
            facts,
            home,
            platform,
            _timeout_seconds(deadline, cold_start=_resident_is_cold(home)),
        )
        if payload.get("need") != "facts":
            _record_success(home)
            if query_key is not None:
                _remember(_NEED_KEYS, query_key, tuple(sorted(facts)))
                facts_digest = _digest(facts)
                if facts_digest is not None:
                    _remember(_VERDICTS, f"{query_key}:{facts_digest}", copy.deepcopy(payload))
            return payload
        keys = payload.get("keys")
        if resolve_fact is None or not isinstance(keys, list) or not keys:
            raise _fail("native_daemon_lifecycle_need_unsupplied")
        for key in keys:
            if not isinstance(key, str) or key in facts:
                raise _fail("native_daemon_lifecycle_need_invalid")
            facts[key] = resolve_fact(key)
    raise _fail("native_daemon_lifecycle_need_loop")
