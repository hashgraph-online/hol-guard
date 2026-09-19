"""Bounded forwarding observation of real installed publisher work.

No result, deadline, key, snapshot or cache entry is replaced. Raw config,
paths, commands, signing material and IPC bytes are never retained. Timings
include observer overhead and cannot supply an uninstrumented SLO sample.
"""

from __future__ import annotations

import hashlib
import json
import re
import threading
import time
from collections import Counter
from collections.abc import Callable, Mapping
from contextlib import ExitStack
from pathlib import Path
from typing import Any, TypedDict
from unittest.mock import patch

MAX_EVENTS = 256
PAGE_SIZE = 32
_DIGEST = re.compile(r"[0-9a-f]{64}")


class PolicyBinding(TypedDict):
    generation: int
    policy_digest: str
    runtime_identity: str


def public_binding(value: object) -> PolicyBinding | None:
    if not isinstance(value, Mapping):
        return None
    generation, policy_digest, runtime_identity = (value.get(key) for key in PolicyBinding.__annotations__)
    if type(generation) is not int or not 0 < generation < 2**64:
        return None
    if not isinstance(policy_digest, str) or _DIGEST.fullmatch(policy_digest) is None:
        return None
    if not isinstance(runtime_identity, str) or _DIGEST.fullmatch(runtime_identity) is None:
        return None
    return {"generation": generation, "policy_digest": policy_digest, "runtime_identity": runtime_identity}


class PublicationObserver:
    def __init__(self, publisher: Any, workspaces: tuple[Path, ...]) -> None:
        if len(workspaces) not in {1, 10, 100} or len(set(workspaces)) != len(workspaces):
            raise ValueError("workspace observer scope bound invalid")
        self.publisher = publisher
        self.workspaces = {workspace: index for index, workspace in enumerate(workspaces)}
        self.started = time.monotonic()
        self._lock = threading.Lock()
        self._local = threading.local()
        self._stack = ExitStack()
        self._rows: list[dict[str, object]] = []
        self._counts: Counter[str] = Counter()
        self._phase = 0
        self._closed = False
        self._installed = False
        self._frozen = False
        self._active = 0
        self._active_at_freeze: int | None = None
        self._attempt = 0

    def phase(self, index: int) -> None:
        if type(index) is not int or not 0 <= index <= 8:
            raise ValueError("workspace observer phase outside bound")
        with self._lock:
            self._phase = index

    def _mark(self, phase: int | None = None) -> tuple[int, float, float]:
        with self._lock:
            phase = self._phase if phase is None else phase
            self._active += 1
        return phase, time.monotonic(), time.thread_time()

    def _record(self, kind: str, mark: tuple[int, float, float], **fields: object) -> None:
        row = {
            "kind": kind,
            "phase": mark[0],
            "publication": getattr(self._local, "attempt", None),
            "started_ms": (mark[1] - self.started) * 1000,
            "finished_ms": (time.monotonic() - self.started) * 1000,
            "thread_cpu_ms": (time.thread_time() - mark[2]) * 1000,
            **fields,
        }
        with self._lock:
            self._active -= 1
            if self._frozen:
                return
            self._counts[kind] += 1
            if fields.get("scope_counts_overflow") is True:
                self._counts["scope_overflow"] += 1
            if len(self._rows) < MAX_EVENTS:
                self._rows.append(row)
            else:
                self._counts["overflow"] += 1

    def _compilation(self, original: Callable[..., Any]) -> Callable[..., Any]:
        def observed(*args: Any, **kwargs: Any) -> Any:
            mark = self._mark(getattr(self._local, "publication_phase", None))
            previous = getattr(self._local, "compilation", None)
            context: dict[str, Any] = {
                "mark": mark,
                "loads": 0,
                "scopes": [0] * (len(self.workspaces) + 1),
                "unregistered": 0,
                "failures": 0,
                "overflow": False,
                "wall_ms": 0.0,
                "cpu_ms": 0.0,
            }
            self._local.compilation = context
            succeeded = False
            try:
                result = original(*args, **kwargs)
                succeeded = True
                return result
            finally:
                self._local.compilation = previous
                cache = getattr(self.publisher, "_compiled_workspace_policies", None)
                self._record(
                    "compile",
                    mark,
                    succeeded=succeeded,
                    config_loads=context["loads"],
                    scope_loads=context["scopes"],
                    unregistered_loads=context["unregistered"],
                    config_load_failures=context["failures"],
                    scope_counts_overflow=context["overflow"],
                    config_load_wall_ms=context["wall_ms"],
                    config_load_thread_cpu_ms=context["cpu_ms"],
                    cache_entries=len(cache) if isinstance(cache, Mapping) else None,
                    registered_workspaces=len(self.publisher._workspace_paths),
                )

        return observed

    def _load_config(self, original: Callable[..., Any]) -> Callable[..., Any]:
        def observed(*args: Any, **kwargs: Any) -> Any:
            context = getattr(self._local, "compilation", None)
            if context is None:
                return original(*args, **kwargs)
            started, cpu = time.monotonic(), time.thread_time()
            context["loads"] += 1
            workspace = kwargs.get("workspace")
            scope = -1 if workspace is None else self.workspaces.get(workspace)
            if scope is None:
                context["unregistered"] += 1
            elif context["scopes"][scope + 1] < 255:
                context["scopes"][scope + 1] += 1
            else:
                context["overflow"] = True
            succeeded = False
            try:
                result = original(*args, **kwargs)
                succeeded = True
                return result
            finally:
                context["failures"] += not succeeded
                context["wall_ms"] += (time.monotonic() - started) * 1000
                context["cpu_ms"] += (time.thread_time() - cpu) * 1000

        return observed

    def _encode(self, original: Callable[..., Any]) -> Callable[..., Any]:
        def observed(snapshot: Any, *args: Any, **kwargs: Any) -> Any:
            encoded = original(snapshot, *args, **kwargs)
            context = getattr(self._local, "publication", None)
            if context is not None:
                context["binding"] = public_binding(snapshot)
            return encoded

        return observed

    def _transport(self, original: Callable[..., Any]) -> Callable[..., Any]:
        def observed(*args: Any, **kwargs: Any) -> Any:
            if kwargs.get("publisher") is not self.publisher:
                return original(*args, **kwargs)
            mark = self._mark(getattr(self._local, "publication_phase", None))
            previous = getattr(self._local, "publication", None)
            context: dict[str, object] = {"binding": None}
            self._local.publication = context
            client = kwargs["client"]

            def forwarded_client(*client_args: Any, **client_kwargs: Any) -> Any:
                push_mark = self._mark(mark[0])
                succeeded = False
                try:
                    output = client(*client_args, **client_kwargs)
                    succeeded = True
                    return output
                finally:
                    self._record("push", push_mark, binding=context["binding"], returned=succeeded)

            try:
                result = original(*args, **{**kwargs, "client": forwarded_client})
                binding = public_binding(result[0]) if isinstance(result, tuple) and len(result) == 2 else None
                self._record("transport_ack", mark, binding=binding, validated=binding is not None)
                return result
            except BaseException:
                self._record("transport_ack", mark, binding=context["binding"], validated=False)
                raise
            finally:
                self._local.publication = previous

        return observed

    def _publication(self, original: Callable[..., Any]) -> Callable[..., Any]:
        def observed(*args: Any, **kwargs: Any) -> Any:
            mark = self._mark()
            previous = getattr(self._local, "attempt", None), getattr(self._local, "publication_phase", None)
            with self._lock:
                self._attempt += 1
                self._local.attempt = self._attempt
            self._local.publication_phase = mark[0]
            try:
                return original(*args, **kwargs)
            finally:
                # The production method has already checked the epoch, current
                # controls and resident fingerprint before opening its barrier.
                # Inspect the already committed state under its existing lock.
                # Calling a readiness getter here could itself expire authority
                # or request a new publication and would change the experiment.
                with self.publisher._condition:
                    binding = (
                        public_binding(self.publisher._snapshot)
                        if (self.publisher._acked and not self.publisher._closed)
                        else None
                    )
                self._record("barrier", mark, binding=binding, ready=binding is not None)
                self._local.attempt, self._local.publication_phase = previous

        return observed

    def __enter__(self) -> PublicationObserver:
        from codex_plugin_scanner.guard import config
        from codex_plugin_scanner.guard import native_policy_snapshot_publisher as publisher_module
        from codex_plugin_scanner.guard import native_policy_snapshot_publisher_transport as transport_module

        if self._installed or self._closed:
            raise RuntimeError("workspace observer lifecycle invalid")
        try:
            for owner, name, wrapper in (
                (self.publisher, "_compiled_effective_policy", self._compilation),
                (config, "load_guard_config", self._load_config),
                (publisher_module, "_publish_snapshot_v3", self._transport),
                (transport_module, "_policy_snapshot_push_bytes_v3", self._encode),
                (self.publisher, "_publish_once", self._publication),
            ):
                self._stack.enter_context(patch.object(owner, name, wrapper(getattr(owner, name))))
            self._installed = True
        except BaseException:
            self.close()
            raise
        return self

    def close(self) -> None:
        self._stack.close()
        self._closed = True

    def freeze(self) -> None:
        with self._lock:
            if not self._frozen:
                self._frozen = True
                self._active_at_freeze = self._active

    def __exit__(self, *_args: object) -> None:
        self.close()

    def rows(self, phase: int | None = None) -> list[dict[str, object]]:
        with self._lock:
            result = []
            for row in self._rows:
                if phase is None or row["phase"] == phase:
                    copied = dict(row)
                    binding = copied.get("binding")
                    if isinstance(binding, dict):
                        copied["binding"] = dict(binding)
                    scopes = copied.get("scope_loads")
                    if isinstance(scopes, list):
                        copied["scope_loads"] = list(scopes)
                    result.append(copied)
            return result

    def page(self, offset: int) -> dict[str, object]:
        rows = self.rows()
        if type(offset) is not int or not 0 <= offset <= len(rows):
            raise ValueError("workspace observer page outside bound")
        return {"rows": rows[offset : offset + PAGE_SIZE], "total": len(rows)}

    def report(self) -> dict[str, object]:
        rows = self.rows()
        with self._lock:
            counts = dict(self._counts)
        return {
            "events": len(rows),
            "event_bound": MAX_EVENTS,
            "counts": counts,
            "event_digest": hashlib.sha256(
                json.dumps(rows, sort_keys=True, separators=(",", ":")).encode()
            ).hexdigest(),
            "complete": counts.get("overflow", 0) == 0
            and counts.get("scope_overflow", 0) == 0
            and self._active_at_freeze in {None, 0},
            "calls_in_flight_at_freeze": self._active_at_freeze,
            "timing_scope": "instrumented_publisher_thread_including_forwarding_observer",
            "thread_cpu_scope": "calling_thread_only_excludes_native_resident_cpu",
            "headline_timing_eligible": False,
        }
