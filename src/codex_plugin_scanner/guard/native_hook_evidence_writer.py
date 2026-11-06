"""The hook evidence writer owned by the native resident.

``daemon.runtime_hook_evidence_writer.RuntimeHookEvidenceWriter`` keeps a
queue, a journal and a draining thread per Guard home. All of that now lives in
the resident, which builds one writer per Guard home from its own store,
correlation, receipt, Composio and journal seams. This module is the client:
it shapes the same calls Python made on the writer object, sends them to the
resident, and keeps the two concerns the resident has no handle on.

The first is waking the in-process snapshot publishers after a write that moved
provider policy. The resident counts those mutations and reports them; the
caller wakes its own publishers.

The second is fatal-store recovery. ``GuardStore._recover_fatal_sqlite_store``
quarantines a store a probe has proven unusable, writes the forensics beside it
and rebuilds the database. That belongs to the ``GuardStore`` object this
process owns, so the resident reports the failure instead and the recovery runs
here.

The resident reports that failure on every reply, not only on a counter read,
because the writer drains on its own thread and a daemon that never reads
counters would otherwise keep writing to a store it has already lost. It holds
the failure until this client acknowledges the identifier it recovered from, so
a reply lost in transport, or a recovery that itself fails, is retried rather
than forgotten.

A resident that is unavailable, replies unbound, or violates the contract never
yields a silent default: the call raises ``NativeHookEvidenceWriterUnavailableError``
rather than reporting evidence as queued when nothing was.
"""

from __future__ import annotations

import logging
import re
import sqlite3
from collections.abc import Mapping
from pathlib import Path
from typing import TYPE_CHECKING, Any, Final
from uuid import uuid4

from .native_context import _canonical_request_sha256, ensure_resident_prerequisite
from .native_execution import _resident_request
from .native_guard_store import _raise_for_code
from .native_resident_prerequisite_reason import prerequisite_unavailable_code
from .native_runtime import native_runtime_status
from .native_runtime_resilience import native_record_resident_failure, native_record_resident_success

if TYPE_CHECKING:
    from .store_connection_schema import GuardStore

HOOK_EVIDENCE_WRITER_FEATURE: Final = "hook-evidence-writer-v1"
_REQUEST_SCHEMA: Final = "guard-hook-evidence-writer-request.v1"
_RESULT_SCHEMA: Final = "guard-hook-evidence-writer-result.v1"
# The writer queues bounded records; the resident's own submission bound plus
# envelope slack is the only transport limit that matters here.
_MAX_REQUEST_BYTES: Final = 4 * 1024 * 1024 + 4096
# One round trip queues a record onto an in-process queue. A wait longer than
# this means the resident is not answering, not that the writer is busy.
_TIMEOUT_SECONDS: Final = 5.0
# `RuntimeHookEvidenceWriter.stop` waited for its own thread; the resident
# waits for the writer it owns and this bounds the transport around that wait.
_STOP_TRANSPORT_SLACK_SECONDS: Final = 5.0

_FATAL_STORE_CODES: Final = frozenset({"native_guard_store_sqlite_corrupt", "native_guard_store_sqlite_io"})
# The store client owns every `native_guard_store_*` code and maps it to the
# exception the caller expects; the writer op's own codes are not store codes.
_STORE_CODE_PREFIX: Final = "native_guard_store_"
_CODE: Final = re.compile(r"[a-z0-9_]{1,64}")

_LOGGER: Final = logging.getLogger(__name__)


class NativeHookEvidenceWriterUnavailableError(RuntimeError):
    """The resident gave no authoritative answer; the evidence was not queued."""

    reason: str = "native_hook_evidence_writer_unavailable"


def _unavailable(reason: str) -> NativeHookEvidenceWriterUnavailableError:
    error = NativeHookEvidenceWriterUnavailableError(f"Guard hook evidence writer unavailable ({reason}).")
    error.reason = reason
    return error


def unreachable_writer_stats() -> dict[str, Any]:
    """The counters a reader gets when the resident cannot answer.

    The writer lives in the resident now, so a reader that only wants to
    report health can be refused where the in-process writer always answered.
    Health is what someone consults once something is already wrong, so the
    unreachable resident is reported as the fault it is — started and not
    running — rather than as a refused health request.
    """

    return {
        "queued": 0,
        "queued_bytes": 0,
        "accepted": 0,
        "processed": 0,
        "dropped": 0,
        "failures": 0,
        "recovered": 0,
        "durable_pending": 0,
        "degraded": True,
        "running": False,
        "started": True,
        "receipt_accepted": 0,
        "receipt_processed": 0,
        "receipt_deduped": 0,
        "receipt_dropped": 0,
        "receipt_failures": 0,
        "receipt_durable_pending": 0,
    }


class NativeHookEvidenceWriter:
    """The resident's writer for one Guard home, shaped like the Python one.

    Holds the ``GuardStore`` only to recover it: no evidence is written through
    it, and no verdict is recalculated here.
    """

    def __init__(self, *, store: GuardStore) -> None:
        self._store = store
        self._guard_home = Path(store.guard_home)
        self._source = store.guard_source
        # The failure this client still owes a recovery for, and the identifier
        # of the one it has finished with. Both outlive a single call: recovery
        # that fails is retried on the next reply, and the resident keeps the
        # failure until a request carries the acknowledgement.
        self._pending_fatal: tuple[str, str] | None = None
        self._fatal_ack: str | None = None

    @property
    def guard_home(self) -> Path:
        return self._guard_home

    def _call(self, action: Mapping[str, object], *, timeout_seconds: float) -> dict[str, object]:
        if not ensure_resident_prerequisite(self._guard_home):
            raise _unavailable(
                prerequisite_unavailable_code("native_hook_evidence_writer_prerequisite_unavailable", self._guard_home)
            )
        request: dict[str, object] = {
            "schema": _REQUEST_SCHEMA,
            "request_id": f"hook-evidence-writer-{uuid4().hex}",
            "guard_home": str(self._guard_home),
            "source": self._source,
            # Always on the wire, including as ``None``: the resident digests
            # the request it decoded, so a key sent only sometimes would make
            # the two digests disagree and every call read as unbound.
            "store_fatal_ack": self._fatal_ack,
            **dict(action),
        }
        try:
            digest = "sha256:" + _canonical_request_sha256(request)
        except (TypeError, ValueError):
            raise _unavailable("native_hook_evidence_writer_request_invalid") from None
        response = _resident_request(
            operation="hook_evidence_writer",
            request=request,
            guard_home=self._guard_home,
            timeout_seconds=timeout_seconds,
            required_feature=HOOK_EVIDENCE_WRITER_FEATURE,
            response_schema=_RESULT_SCHEMA,
            max_request_bytes=_MAX_REQUEST_BYTES,
            record_success=False,
        )
        identity = native_runtime_status().identity
        if (
            response is None
            or response.get("request_id") != request["request_id"]
            or response.get("request_sha256") != digest
        ):
            if response is not None and identity is not None:
                native_record_resident_failure(
                    identity.sha256, self._guard_home, reason="native_hook_evidence_writer_binding"
                )
            raise _unavailable("native_hook_evidence_writer_unavailable")
        if identity is not None:
            native_record_resident_success(identity.sha256, self._guard_home)
        # The resident answered, so the acknowledgement this request carried
        # has been applied and must not be repeated.
        self._fatal_ack = None
        status, code, payload = response.get("status"), response.get("code"), response.get("payload")
        if status == "error":
            self._raise_for_resident_error(code, payload)
        if status != "ok" or code != "ok" or not isinstance(payload, dict):
            raise _unavailable("native_hook_evidence_writer_response_invalid")
        return payload

    @staticmethod
    def _raise_for_resident_error(code: object, payload: object) -> None:
        """Raise the exception the resident's code names.

        Only the store's own codes are the store client's to map. The writer
        op refuses a request with codes of its own, and routing those through
        the store mapper turned every refusal into a SQLite failure that the
        callers catching this module's error never saw.
        """

        if isinstance(code, str) and code.startswith(_STORE_CODE_PREFIX):
            _raise_for_code(code, payload)
        named = code if isinstance(code, str) and _CODE.fullmatch(code) else "unavailable"
        raise _unavailable(f"native_hook_evidence_writer_{named}")

    def start(self) -> bool:
        """Build the resident's writer for this home before a hook needs it.

        Constructing the writer replays its journal. A caller that knows it
        is about to record evidence, and that can afford the replay now
        rather than on the submission that follows, warms the writer here.

        Warming is not the caller's to fail on. A resident that refuses here
        refuses the submission too, and that is where the caller learns it.
        """

        try:
            payload = self._call({"action": "start"}, timeout_seconds=_TIMEOUT_SECONDS)
        except Exception:
            return False
        self._consume_signals(payload)
        return payload.get("running") is True

    def _queued(self, action: Mapping[str, object]) -> bool:
        payload = self._call(action, timeout_seconds=_TIMEOUT_SECONDS)
        # A submission is the one call a daemon always makes, so it is the path
        # that has to carry the signals a running writer raised.
        self._consume_signals(payload)
        queued = payload.get("queued")
        if not isinstance(queued, bool):
            raise _unavailable("native_hook_evidence_writer_response_invalid")
        return queued

    def submit_command_activity(
        self,
        *,
        harness: str,
        event: str,
        payload: Mapping[str, object],
        succeeded: bool,
        policy_action: str | None = None,
        receipt_id: str | None = None,
        prompted: bool = False,
        approval_reuse_status: str = "not-applicable",
    ) -> bool:
        return self._queued(
            {
                "action": "submit_command_activity",
                "harness": harness,
                "event": event,
                "payload": dict(payload),
                "succeeded": succeeded,
                "policy_action": policy_action,
                "receipt_id": receipt_id,
                "prompted": prompted,
                "approval_reuse_status": approval_reuse_status,
            }
        )

    def submit_composio_discovery(
        self,
        *,
        harness: str,
        payload: Mapping[str, object],
        succeeded: bool,
    ) -> bool:
        return self._queued(
            {
                "action": "submit_composio_discovery",
                "harness": harness,
                "payload": dict(payload),
                "succeeded": succeeded,
            }
        )

    def submit_native_decision_receipt(self, receipt: Mapping[str, object]) -> bool:
        return self._queued({"action": "submit_native_decision_receipt", "receipt": dict(receipt)})

    def stats(self) -> dict[str, Any]:
        """The writer's counters, with the two signals the resident hands back.

        ``policy_mutations`` is read and cleared in the resident and dropped
        here. ``store_fatal`` stays there until this client acknowledges it.
        Neither is reported as a counter.
        """

        payload = self._call({"action": "stats"}, timeout_seconds=_TIMEOUT_SECONDS)
        self._consume_signals(payload)
        return payload

    def stop(self, *, timeout_seconds: float = 1.0) -> bool:
        """Drain the resident's writer for this home and drop it.

        The Python writer defaulted to one second of draining and the resident
        to two, so the value is always sent rather than left to either default.
        """

        # The resident re-serializes the request to check the digest it binds
        # its reply to, and it holds the budget as a float. An int sent here
        # would canonicalise as `2` on this side and `2.0` on that one, so the
        # reply would arrive unbound after the writer has already been drained.
        budget = float(max(0.0, timeout_seconds))
        payload = self._call(
            {"action": "stop", "timeout_seconds": budget},
            timeout_seconds=budget + _STOP_TRANSPORT_SLACK_SECONDS,
        )
        # Read the drain result before recovery runs: this writer has already
        # left the resident's registry, so a recovery that raises here would
        # otherwise lose the one answer the caller asked for.
        drained = payload.get("drained")
        self._consume_signals(payload)
        if not isinstance(drained, bool):
            raise _unavailable("native_hook_evidence_writer_response_invalid")
        return drained

    def _consume_signals(self, payload: Mapping[str, object]) -> None:
        if isinstance(payload, dict):
            # The resident still reports a mutation count; nothing reads it.
            payload.pop("policy_mutations", None)
        fatal = payload.pop("store_fatal", None) if isinstance(payload, dict) else None
        if isinstance(fatal, Mapping):
            identifier, code = fatal.get("id"), fatal.get("code")
            if isinstance(identifier, str) and isinstance(code, str):
                self._pending_fatal = (identifier, code)
        self._recover_store()

    def _recover_store(self) -> None:
        """Run the store's own recovery for the failure the resident reported.

        The resident names the failure in the ``native_guard_store_*`` codes the
        store client already maps, so the exception the recovery inspects is
        built by that same mapping rather than a second classifier here.

        A recovery that raises leaves the failure pending, so the next reply
        tries it again. Only a recovery that returns acknowledges the failure,
        and only the acknowledgement lets the resident drop it.
        """

        pending = self._pending_fatal
        if pending is None:
            return
        identifier, code = pending
        if code in _FATAL_STORE_CODES:
            try:
                _raise_for_code(code, None)
            except sqlite3.DatabaseError as error:
                try:
                    self._store._recover_fatal_sqlite_store(error)
                except Exception:
                    # The store is still broken. Keep the failure pending; the
                    # next reply from the resident asks for it again.
                    _LOGGER.exception("Guard store recovery failed for %s.", code)
                    return
        self._pending_fatal, self._fatal_ack = None, identifier


__all__ = [
    "HOOK_EVIDENCE_WRITER_FEATURE",
    "NativeHookEvidenceWriter",
    "NativeHookEvidenceWriterUnavailableError",
]
