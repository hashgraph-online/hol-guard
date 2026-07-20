"""External monotonic control for the workflow-capability authority ledger."""

# pyright: reportAny=false, reportPrivateUsage=false, reportUnknownArgumentType=false
# pyright: reportUnknownVariableType=false, reportUnusedCallResult=false

from __future__ import annotations

import json
import sqlite3
from dataclasses import asdict, dataclass, replace
from typing import Protocol, cast

from .store_workflow_capability_time import validate_monotonic_workflow_capability_time
from .store_workflow_capability_transitions import validate_global_authority_ledger
from .workflow_capabilities import WorkflowCapabilityError, parse_utc_timestamp
from .workflow_capability_transitions import (
    ZERO_TRANSITION_SHA256,
    SignedAuthorityTransition,
    authority_transition_sha256,
)

_CONTROL_VERSION = 1


class _ControlStore(Protocol):
    def _load_workflow_capability_control(self) -> str | None: ...

    def _store_workflow_capability_control(self, encoded: str) -> bool: ...


@dataclass(frozen=True, slots=True)
class WorkflowCapabilityControl:
    version: int
    committed_sequence: int
    committed_head_sha256: str
    pending_sequence: int | None
    pending_head_sha256: str | None
    observed_at: str

    def __post_init__(self) -> None:
        if self.version != _CONTROL_VERSION:
            raise WorkflowCapabilityError("unsupported_capability_control_version")
        if type(self.committed_sequence) is not int or self.committed_sequence < 0:
            raise WorkflowCapabilityError("invalid_capability_control_sequence")
        _digest("committed_head_sha256", self.committed_head_sha256)
        if (self.pending_sequence is None) != (self.pending_head_sha256 is None):
            raise WorkflowCapabilityError("invalid_capability_control_pending")
        if self.pending_sequence is not None:
            if type(self.pending_sequence) is not int or self.pending_sequence != self.committed_sequence + 1:
                raise WorkflowCapabilityError("invalid_capability_control_pending")
            _digest("pending_head_sha256", cast(str, self.pending_head_sha256))
        parse_utc_timestamp(self.observed_at)


def load_validate_and_observe_control(
    store: _ControlStore,
    connection: sqlite3.Connection,
    *,
    key: bytes,
    key_id: str,
    now: str,
    create: bool,
) -> WorkflowCapabilityControl:
    sequence, head = validate_global_authority_ledger(connection, key=key, key_id=key_id)
    encoded = store._load_workflow_capability_control()
    if encoded is None:
        if _has_authority_data(connection):
            raise WorkflowCapabilityError("capability_control_bootstrap_refused")
        if not create:
            raise WorkflowCapabilityError("capability_control_unavailable")
        control = WorkflowCapabilityControl(
            version=_CONTROL_VERSION,
            committed_sequence=0,
            committed_head_sha256=ZERO_TRANSITION_SHA256,
            pending_sequence=None,
            pending_head_sha256=None,
            observed_at=now,
        )
        _store_control(store, control)
    else:
        control = _decode_control(encoded)
    if control.pending_sequence is not None:
        if sequence != control.pending_sequence or head != control.pending_head_sha256:
            raise WorkflowCapabilityError("capability_control_pending_unresolved")
        control = WorkflowCapabilityControl(
            version=_CONTROL_VERSION,
            committed_sequence=sequence,
            committed_head_sha256=head,
            pending_sequence=None,
            pending_head_sha256=None,
            observed_at=control.observed_at,
        )
        _store_control(store, control)
    if sequence != control.committed_sequence or head != control.committed_head_sha256:
        raise WorkflowCapabilityError("capability_control_rollback_detected")
    if validate_monotonic_workflow_capability_time(now=now, observed_at=control.observed_at):
        control = replace(control, observed_at=now)
        _store_control(store, control)
    return control


def prepare_control_transition(
    store: _ControlStore,
    control: WorkflowCapabilityControl,
    signed_transition: SignedAuthorityTransition,
) -> WorkflowCapabilityControl:
    transition = signed_transition.transition
    head = authority_transition_sha256(signed_transition)
    if (
        control.pending_sequence is not None
        or transition.sequence != control.committed_sequence + 1
        or transition.previous_transition_sha256 != control.committed_head_sha256
    ):
        raise WorkflowCapabilityError("capability_control_transition_invalid")
    pending = replace(
        control,
        pending_sequence=transition.sequence,
        pending_head_sha256=head,
        observed_at=transition.occurred_at,
    )
    _store_control(store, pending)
    return pending


def finalize_control_transition(store: _ControlStore, pending: WorkflowCapabilityControl) -> None:
    if pending.pending_sequence is None or pending.pending_head_sha256 is None:
        raise WorkflowCapabilityError("capability_control_pending_missing")
    finalized = WorkflowCapabilityControl(
        version=_CONTROL_VERSION,
        committed_sequence=pending.pending_sequence,
        committed_head_sha256=pending.pending_head_sha256,
        pending_sequence=None,
        pending_head_sha256=None,
        observed_at=pending.observed_at,
    )
    _store_control(store, finalized)


def _has_authority_data(connection: sqlite3.Connection) -> bool:
    counts = connection.execute(
        """
        select
          (select count(*) from guard_workflow_capabilities) +
          (select count(*) from guard_workflow_capability_authority_transitions) +
          (select count(*) from guard_events where event_name in (
            'workflow_capability.issued', 'workflow_capability.claimed', 'workflow_capability.revoked'
          ))
        """
    ).fetchone()
    return counts is not None and int(counts[0]) != 0


def _decode_control(encoded: str) -> WorkflowCapabilityControl:
    try:
        payload = json.loads(encoded)
    except json.JSONDecodeError as error:
        raise WorkflowCapabilityError("capability_control_invalid") from error
    if type(payload) is not dict or set(payload) != set(WorkflowCapabilityControl.__dataclass_fields__):
        raise WorkflowCapabilityError("capability_control_invalid")
    typed = cast(dict[str, object], payload)
    try:
        control = WorkflowCapabilityControl(
            version=_integer(typed["version"]),
            committed_sequence=_integer(typed["committed_sequence"]),
            committed_head_sha256=_string(typed["committed_head_sha256"]),
            pending_sequence=_optional_integer(typed["pending_sequence"]),
            pending_head_sha256=_optional_string(typed["pending_head_sha256"]),
            observed_at=_string(typed["observed_at"]),
        )
    except (KeyError, TypeError) as error:
        raise WorkflowCapabilityError("capability_control_invalid") from error
    if _encode_control(control) != encoded:
        raise WorkflowCapabilityError("capability_control_invalid")
    return control


def _store_control(store: _ControlStore, control: WorkflowCapabilityControl) -> None:
    if not store._store_workflow_capability_control(_encode_control(control)):
        raise WorkflowCapabilityError("capability_control_unavailable")


def _encode_control(control: WorkflowCapabilityControl) -> str:
    return json.dumps(asdict(control), sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _digest(name: str, value: str) -> None:
    if type(value) is not str or len(value) != 64 or any(character not in "0123456789abcdef" for character in value):
        raise WorkflowCapabilityError(f"invalid_{name}")


def _string(value: object) -> str:
    if type(value) is not str:
        raise WorkflowCapabilityError("capability_control_invalid")
    return value


def _optional_string(value: object) -> str | None:
    return None if value is None else _string(value)


def _integer(value: object) -> int:
    if type(value) is not int:
        raise WorkflowCapabilityError("capability_control_invalid")
    return value


def _optional_integer(value: object) -> int | None:
    return None if value is None else _integer(value)
