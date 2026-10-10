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

import copy
import hashlib
import json
import os
import threading
from collections import OrderedDict
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any
from uuid import uuid4

from .native_context import _canonical_request_sha256, _resolve_existing_digest_home, ensure_resident_prerequisite
from .native_execution import _resident_request
from .native_resident_client import native_resident_client_failure_code
from .native_runtime import native_runtime_status
from .native_runtime_resilience import native_record_resident_failure, native_record_resident_success

DAEMON_LIFECYCLE_FEATURE = "daemon-lifecycle-decision-v1"
_REQUEST_SCHEMA = "guard-daemon-lifecycle-decision-request.v1"
_RESULT_SCHEMA = "guard-daemon-lifecycle-decision-result.v1"
_OPERATION = "daemon_lifecycle_decide"
_MAX_REQUEST_BYTES = 2 * 1024 * 1024
_MAX_NEED_ROUNDS = 8
_TIMEOUT_SECONDS = 10.0

FactResolver = Callable[[str], object]

# A verdict is a pure function of (platform, query, facts), so an identical
# request needs no second round trip. ``_NEED_KEYS`` remembers which facts a
# query asked for so a repeat sends them in the first request instead of
# discovering them one round at a time; ``_VERDICTS`` replays a verdict only for
# byte-identical inputs. Both are keyed by the resident binary identity, bounded,
# and never hold failures. Time-bearing checks carry ``now`` in the query and
# therefore never repeat; they are not cached at all.
_UNCACHED_CHECKS = frozenset({"wake_claim", "recovery_claim", "start_progress_live", "ephemeral_inactive"})
_CACHE_ENTRIES = 512
_CACHE_QUERY_BYTES = 64 * 1024
_cache_lock = threading.Lock()
_NEED_KEYS: OrderedDict[str, tuple[str, ...]] = OrderedDict()
_VERDICTS: OrderedDict[str, dict[str, Any]] = OrderedDict()


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


class NativeDaemonLifecycleError(ValueError):
    """No authoritative native answer; callers must fail closed."""


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


def _round_trip(query: Mapping[str, object], facts: Mapping[str, object], home: Path, platform: str) -> dict[str, Any]:
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
    response = _resident_request(
        operation=_OPERATION,
        request=request,
        guard_home=home,
        timeout_seconds=_TIMEOUT_SECONDS,
        required_feature=DAEMON_LIFECYCLE_FEATURE,
        response_schema=_RESULT_SCHEMA,
        max_request_bytes=_MAX_REQUEST_BYTES,
        record_success=False,
    )
    if response is None:
        # ``_resident_request`` already recorded the failure; do not count it twice.
        detail = native_resident_client_failure_code() or "no_client_code"
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
) -> dict[str, Any]:
    """Return the resident's verdict for one ``check``, resolving fact requests."""

    return _decide(check, query, resolve_fact, guard_home, platform)


def _decide(
    check: str,
    query: Mapping[str, object],
    resolve_fact: FactResolver | None,
    guard_home: Path | None,
    platform: str | None,
) -> dict[str, Any]:
    # Verdicts are pure, so a home that does not exist yet must not be created
    # (or get its own resident) just to be asked a question; use the context home.
    home = _resolve_existing_digest_home(guard_home)
    platform = platform or ("nt" if os.name == "nt" else "posix")
    # The resident digests its typed decoding of the request, which omits unset
    # optional fields; omit them here too so both sides hash identical bytes.
    full_query = {"check": check, **{key: value for key, value in query.items() if value is not None}}
    status = native_runtime_status()
    identity = status.identity.sha256 if status.identity is not None else ""
    query_key = None
    if check not in _UNCACHED_CHECKS and identity:
        query_digest = _digest({"platform": platform, "query": full_query})
        query_key = None if query_digest is None else f"{identity}:{query_digest}"
    facts: dict[str, object] = {}
    if query_key is not None and resolve_fact is not None:
        for key in _recall(_NEED_KEYS, query_key) or ():
            facts[key] = resolve_fact(key)
        facts_digest = _digest(facts)
        if facts_digest is not None:
            cached = _recall(_VERDICTS, f"{query_key}:{facts_digest}")
            if cached is not None:
                return copy.deepcopy(cached)
    for _ in range(_MAX_NEED_ROUNDS):
        payload = _round_trip(full_query, facts, home, platform)
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
