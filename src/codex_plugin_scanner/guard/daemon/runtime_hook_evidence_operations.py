"""Admission and command-activity operations for the evidence writer."""

from __future__ import annotations


def submit_command_activity(
    self: _writer.RuntimeHookEvidenceWriter,
    *,
    harness: str,
    event: str,
    payload: _writer.Mapping[str, object],
    succeeded: bool,
    policy_action: str | None = None,
    receipt_id: str | None = None,
    prompted: bool = False,
    approval_reuse_status: str = "not-applicable",
) -> bool:
    if event == "PreToolUse" and not _writer.is_guard_action(policy_action):
        return False
    # Reject saturated work before touching the caller's payload. Only
    # compact immutable facts survive this call; output/metadata trees are
    # neither copied nor serialized on the response path.
    with self._condition:
        if self._stopping or len(self._records) >= self._max_records or self._queued_bytes >= self._max_bytes:
            self._dropped += 1
            self._degraded = True
            return False
    try:
        correlation = self._derive_correlation(harness=harness, event=event, payload=payload)
        invocation_preview = _writer.build_invocation_preview_from_payload(payload)
        has_command = _writer._payload_has_command(payload)
    except Exception:
        with self._condition:
            self._dropped += 1
        return False
    record = _writer._CommandActivityRecord(
        record_id=_writer.uuid4().hex,
        harness=harness,
        event=event,
        correlation=correlation,
        has_command=has_command,
        succeeded=succeeded,
        payload_bytes=0,
        policy_action=policy_action,
        occurred_at=_writer.datetime.now(_writer.timezone.utc).isoformat(),
        receipt_id=receipt_id,
        prompted=prompted,
        approval_reuse_status=approval_reuse_status,
        invocation_preview=invocation_preview,
    )
    serialized = record.serialized()
    if _writer._CommandActivityRecord.from_json(_writer.json.loads(serialized)) is None:
        return False
    # Account for the retained preview as well as the aggregate journal
    # record, including multibyte Unicode. The original payload is absent.
    record = _writer.replace(
        record,
        payload_bytes=len(serialized) + len((invocation_preview or "").encode("utf-8")),
    )
    with self._condition:
        if (
            self._stopping
            or len(self._records) >= self._max_records
            or self._queued_bytes + record.payload_bytes > self._max_bytes
        ):
            self._dropped += 1
            self._degraded = True
            return False
        self._records.append(record)
        if self._queue_observation is not None:
            self._observe_queue(record, "admission")
        self._queued_bytes += record.payload_bytes
        self._accepted += 1
        self._condition.notify()
    return True


def submit_native_decision_receipt(
    self: _writer.RuntimeHookEvidenceWriter, receipt: _writer.Mapping[str, object]
) -> bool:
    """Queue one Rust receipt without touching SQLite or waiting on I/O."""

    validated = _writer.validate_native_decision_receipt(receipt)
    if validated is None:
        with self._condition:
            self._receipt_dropped += 1
            self._dropped += 1
            self._degraded = True
        return False
    record = _writer._NativeDecisionReceiptRecord(receipt=validated, payload_bytes=0)
    record = _writer._NativeDecisionReceiptRecord(receipt=validated, payload_bytes=len(record.serialized()))
    receipt_id = record.record_id
    with self._condition:
        if receipt_id in self._receipt_seen:
            self._receipt_deduped += 1
            return True
        if (
            self._stopping
            or len(self._records) >= self._max_records
            or self._queued_bytes + record.payload_bytes > self._max_bytes
        ):
            self._receipt_dropped += 1
            self._dropped += 1
            self._degraded = True
            return False
        self._records.append(record)
        if self._queue_observation is not None:
            self._observe_queue(record, "admission")
        self._queued_bytes += record.payload_bytes
        self._receipt_seen[receipt_id] = None
        while len(self._receipt_seen) > self._max_records * 4:
            self._receipt_seen.popitem(last=False)
        self._accepted += 1
        self._receipt_accepted += 1
        self._condition.notify()
    return True


def _derive_correlation(
    self: _writer.RuntimeHookEvidenceWriter,
    *,
    harness: str,
    event: str,
    payload: _writer.Mapping[str, object],
) -> _writer.CorrelationHandle | None:
    key = self._correlation_key
    if key is None:
        key = _writer.load_or_create_installation_correlation_key(self._guard_home)
        self._correlation_key = key
    try:
        return _writer.derive_proven_request_correlation(harness=harness, event=event, payload=payload, key=key)
    except (OSError, ValueError):
        key = _writer.load_or_create_installation_correlation_key(self._guard_home)
        self._correlation_key = key
        return _writer.derive_proven_request_correlation(harness=harness, event=event, payload=payload, key=key)


def _persist_command_activity(self: _writer.RuntimeHookEvidenceWriter, record: _writer._CommandActivityRecord) -> None:
    if record.event != "PreToolUse":
        _writer.persist_deferred_post_hook_command_activity(
            store=self._store,
            harness=record.harness,
            correlation=record.correlation,
            has_command=record.has_command,
            succeeded=record.succeeded,
            invocation_preview=record.invocation_preview,
            activity_id=record.record_id if record.occurred_at is not None else None,
            occurred_at=_writer.datetime.fromisoformat(record.occurred_at) if record.occurred_at is not None else None,
        )
        return
    if not record.has_command or record.policy_action is None or record.occurred_at is None:
        return
    correlation = record.correlation
    # A prevented attempt cannot produce a post event. Keep its evidence
    # separate from a later approved retry of the same call.
    if correlation is not None and record.policy_action not in ("allow", "warn"):
        digest = _writer.hashlib.sha256(
            _writer.json.dumps(
                [
                    "native-prevented-attempt-v1",
                    correlation.digest,
                    record.policy_action,
                    record.receipt_id,
                    record.prompted,
                    record.approval_reuse_status,
                ]
            ).encode("utf-8")
        ).hexdigest()
        correlation = _writer.replace(correlation, digest=digest)
    evidence = _writer.build_native_pre_hook_evidence(
        activity_id=record.record_id,
        occurred_at=_writer.datetime.fromisoformat(record.occurred_at),
        harness=record.harness,
        policy_action=_writer.cast(_writer.GuardAction, record.policy_action),
        request_correlation=correlation,
        receipt_id=record.receipt_id,
        prompted=record.prompted,
        approval_reuse_status=_writer.ActivityApprovalReuseStatus(record.approval_reuse_status),
    )
    if not self._store.is_exact_command_activity_pre_replay(evidence):
        self._store.record_command_activity(evidence, invocation_preview=record.invocation_preview)


# Bind only after all declarations so a direct helper import cannot form a cycle.
from . import runtime_hook_evidence_writer as _writer  # noqa: E402
