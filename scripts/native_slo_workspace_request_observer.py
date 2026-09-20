"""Bounded forwarding request observation for separate workspace lifecycle cells.

The original HTTP request and native-review callable keep their arguments,
results, exceptions and deadlines. Authority/receipt readbacks happen on the
controlling caller outside the native hook, and are never writer I/O samples.
"""

from __future__ import annotations

import json
import threading
import time
from collections.abc import Callable, Mapping, Sequence
from contextlib import ExitStack, nullcontext
from pathlib import Path
from typing import Any
from unittest.mock import patch

from scripts.native_slo_expiry import _authenticated_readback, _readback_matches
from scripts.native_slo_mixed_request import fixture_request, request_attempt
from scripts.native_slo_mixed_response import delivered_decision
from scripts.native_slo_workspace_decision import (
    MAX_REQUESTS,
    authority_projection,
    finite_time,
    join_decisions,
    receipt_projection,
)
from scripts.native_slo_workspace_observer import public_binding


class WorkspaceRequestObserver:
    def __init__(
        self,
        session: Any,
        witness: Any,
        workspaces: tuple[Path, ...],
        *,
        maximum: int,
        clock: Callable[[], float] | None = None,
        wall_clock: Callable[[], float] | None = None,
    ) -> None:
        if (
            type(maximum) is not int
            or not 1 <= maximum <= MAX_REQUESTS
            or not 1 <= len(workspaces) <= 100
            or len(set(workspaces)) != len(workspaces)
            or witness.session is not session
            or type(witness.maximum) is not int
            or witness.maximum < maximum
            or witness.reader.legacy
            or witness.reader.profile != "candidate"
        ):
            raise ValueError("workspace request observer scope invalid")
        root = session.root
        if (
            not isinstance(root, Path)
            or not root.is_absolute()
            or root.resolve(strict=True) != root
            or not isinstance(session.guard_home, Path)
            or not session.guard_home.is_relative_to(root)
            or session.guard_home.resolve(strict=True) != session.guard_home
            or any(
                not isinstance(path, Path)
                or not path.is_relative_to(root)
                or path.resolve(strict=True) != path
                or not path.is_dir()
                for path in workspaces
            )
        ):
            raise ValueError("workspace request paths outside owned canonical root")
        self.session, self.witness, self.workspaces = session, witness, workspaces
        self.maximum = maximum
        self.started = witness.started
        if not finite_time(self.started):
            raise ValueError("workspace request clock origin invalid")
        self.clock = time.monotonic if clock is None else clock
        self.wall_clock = time.time if wall_clock is None else wall_clock
        self._clock_kind = "time.monotonic" if clock is None else "injected_control_clock"
        self._wall_clock_kind = "time.time" if wall_clock is None else "injected_control_clock"
        self.worker = session.daemon._server.hook_worker
        self._lock = threading.RLock()
        self._stack = ExitStack()
        self._rows: dict[str, dict[str, Any]] = {}
        self._faults = 0
        self._unowned_calls = 0
        self._active = 0
        self._native_active = 0
        self._active_at_freeze: int | None = None
        self._native_at_freeze: int | None = None
        self._late_native_calls = 0
        self._refused_offers = 0
        self._restored = False
        self._original: Any = None
        self._frozen = False
        self._installed = False
        self._closed = False
        self._wrapper: Any = None

    def _stamp(self) -> float:
        value = self.clock()
        if not finite_time(value):
            raise ValueError("workspace request clock invalid")
        return (value - self.started) * 1000

    def _wall_stamp(self) -> float:
        value = self.wall_clock()
        if not finite_time(value):
            raise ValueError("workspace request wall clock invalid")
        return value * 1000

    def _guard(self, attempt: str, callback: Callable[[], None]) -> None:
        try:
            callback()
        except BaseException:
            with self._lock:
                self._faults += 1
                self._rows[attempt]["capture_faults"] += 1

    def _readback_scope(self) -> Any:
        observer = getattr(self.witness, "sqlite_observer", None)
        return observer.readback() if observer is not None else nullcontext()

    def _authority(self) -> dict[str, Any] | None:
        with self._readback_scope():
            binding, accepted = _authenticated_readback(self.session.store)
        if accepted is None or not _readback_matches(binding, accepted, accepted):
            return None
        return authority_projection(accepted)

    def _entered(self, attempt: str, kwargs: Mapping[str, Any]) -> None:
        with self._lock:
            row = self._rows[attempt]
            row["review_calls"] += 1
            if row["review_calls"] != 1:
                raise RuntimeError("duplicate owned native review")
            row["review_entered_ms"] = self._stamp()
            row["review_entered_wall_ms"] = self._wall_stamp()
            supplied = kwargs.get("policy_snapshot")
            row["request_binding"] = public_binding(supplied)
            row["request_mode"] = supplied.get("mode") if isinstance(supplied, Mapping) else None
            row["request_command_bound"] = (
                supplied.get("command_extensions_bound") is True if isinstance(supplied, Mapping) else False
            )
            row["request_scope_matches"] = (
                kwargs.get("cwd") == self.workspaces[row["workspace_index"]]
                and kwargs.get("guard_home") == self.session.guard_home
                and kwargs.get("harness") == "claude-code"
                and kwargs.get("event") == "PreToolUse"
                and kwargs.get("observe_mode") is False
            )

    def _returned(self, attempt: str, result: object) -> None:
        stamp, wall_stamp = self._stamp(), self._wall_stamp()
        receipt = result.get("receipt") if isinstance(result, Mapping) else None
        projected = receipt_projection(receipt)
        with self._lock:
            row = self._rows[attempt]
            row["review_returned_ms"] = stamp
            row["review_returned_wall_ms"] = wall_stamp
            row["review_returned"] = True
            row["native_receipt"] = projected
            row["native_receipt_validated"] = projected is not None

    def __enter__(self) -> WorkspaceRequestObserver:
        if self._installed or self._closed or getattr(self.witness, "_instrumentation_active", False) is not True:
            raise RuntimeError("enter the paired receipt witness before the request observer")
        if self.session.daemon._server.hook_worker is not self.worker:
            raise RuntimeError("workspace request worker changed before observation")
        original = self.worker._review_raw_hook_native
        self._original = original

        def observed(*args: Any, **kwargs: Any) -> Any:
            attempt = None
            try:
                request = kwargs.get("payload")
                attempt = request_attempt(request)
            except BaseException:
                with self._lock:
                    self._faults += 1
            with self._lock:
                tracked = isinstance(attempt, str) and attempt in self._rows
                if not tracked:
                    self._unowned_calls += 1
                elif self._frozen:
                    self._late_native_calls += 1
                    tracked = False
                else:
                    self._native_active += 1
            if not tracked:
                return original(*args, **kwargs)
            assert isinstance(attempt, str)
            try:
                self._guard(attempt, lambda: self._entered(attempt, kwargs))
                result = original(*args, **kwargs)
                self._guard(attempt, lambda: self._returned(attempt, result))
                return result
            finally:
                with self._lock:
                    self._native_active -= 1

        try:
            self._wrapper = observed
            self._stack.enter_context(patch.object(self.worker, "_review_raw_hook_native", observed))
            self._installed = True
        except BaseException:
            self.close()
            raise
        return self

    def probe(self, index: int, workspace_index: int) -> Mapping[str, object]:
        """Offer one original PreToolUse request; preserve its actual return/error."""
        from scripts.native_slo_session import _request

        if (
            type(index) is not int
            or not 0 <= index < self.maximum
            or type(workspace_index) is not int
            or not 0 <= workspace_index < len(self.workspaces)
        ):
            with self._lock:
                self._refused_offers += 1
            raise ValueError("workspace request index outside declared bound")
        attempt = f"mixed-policy-{index}"
        with self._lock:
            if (
                not self._installed
                or self._closed
                or self._frozen
                or attempt in self._rows
                or self.session.daemon._server.hook_worker is not self.worker
                or getattr(self.worker, "_review_raw_hook_native", None) is not self._wrapper
            ):
                self._refused_offers += 1
                raise RuntimeError("workspace request offer lifecycle invalid")
            self._rows[attempt] = {
                "attempt": attempt,
                "workspace_index": workspace_index,
                "review_calls": 0,
                "review_returned": False,
                "request_returned": False,
                "capture_faults": 0,
            }
            self._active += 1
        row = self._rows[attempt]
        try:
            self._guard(attempt, lambda: row.update(authority_before=self._authority()))
            self._guard(attempt, lambda: row.update(offered_ms=self._stamp()))
            response = _request(
                self.session.daemon,
                guard_home=self.session.guard_home,
                workspace=self.workspaces[workspace_index],
                harness="claude-code",
                request_payload=fixture_request("claude-code", "PreToolUse", attempt=attempt),
            )
            self._guard(
                attempt,
                lambda: row.update(
                    delivered_ms=self._stamp(),
                    request_returned=True,
                    delivered_decision=delivered_decision("PreToolUse", response),
                ),
            )
            self._guard(attempt, lambda: row.update(authority_after=self._authority()))
            return response
        finally:
            with self._lock:
                self._active -= 1

    def freeze(self) -> None:
        with self._lock:
            if not self._frozen:
                self._frozen = True
                self._active_at_freeze = self._active
                self._native_at_freeze = self._native_active

    def close(self) -> None:
        if self._closed:
            return
        self.freeze()
        if self._installed and getattr(self.worker, "_review_raw_hook_native", None) is not self._wrapper:
            with self._lock:
                self._faults += 1
            # A later owner must not be overwritten by our restoration.
            _ = self._stack.pop_all()
        else:
            self._stack.close()
            self._restored = getattr(self.worker, "_review_raw_hook_native", None) is self._original
        self._closed = True

    def __exit__(self, *_args: object) -> None:
        self.close()

    def _committed(self, row: dict[str, Any]) -> None:
        witness_row = self.witness.row(row["attempt"])
        if not isinstance(witness_row, Mapping):
            return
        row.update(
            witness_decision_id=witness_row.get("decision_id"),
            native_finished_ms=witness_row.get("native_finished_ms"),
            writer_admitted=witness_row.get("writer_admitted"),
            witness_committed=witness_row.get("committed"),
            witness_commit_binding_valid=witness_row.get("commit_binding_valid"),
        )
        receipt = row.get("native_receipt")
        identity = receipt.get("decision_id") if isinstance(receipt, Mapping) else None
        if not isinstance(identity, str):
            return
        with self._readback_scope():
            with self.session.store._connect() as connection:
                before = connection.execute(
                    "select count(*) from native_hook_decision_receipts where decision_id = ?", (identity,)
                ).fetchone()[0]
            stored = self.witness.reader.read(identity)
            with self.session.store._connect() as connection:
                after = connection.execute(
                    "select count(*) from native_hook_decision_receipts where decision_id = ?", (identity,)
                ).fetchone()[0]
        projected = receipt_projection(stored)
        row.update(
            committed_receipt=projected,
            committed_receipt_validated=projected is not None,
            committed_row_count=before if type(before) is int and type(after) is int and before == after else None,
            committed_row_count_before=before,
            committed_row_count_after=after,
            commit_observed_ms=self._stamp(),
        )

    def join(
        self,
        *,
        accepted: float,
        snapshot: Mapping[str, Any],
        action: str,
        declared_indexes: Sequence[int],
    ) -> dict[str, object]:
        """Read committed identity only after the caller's original bounded drain."""
        authority = authority_projection(snapshot)
        if (
            not finite_time(accepted)
            or not 1 <= len(declared_indexes) <= self.maximum
            or any(type(index) is not int or not 0 <= index < self.maximum for index in declared_indexes)
            or len(set(declared_indexes)) != len(declared_indexes)
        ):
            raise ValueError("workspace request join declaration invalid")
        with self._lock:
            if not self._frozen or not self._closed:
                raise RuntimeError("close request observation before committed readback")
            selected = [f"mixed-policy-{index}" for index in declared_indexes]
            offered = list(self._rows)
            declaration_complete = set(selected) == set(offered)
            # Preserve every owned offer, including an undeclared failing one.
            rows = [json.loads(json.dumps(row)) for row in self._rows.values()]
            complete = (
                declaration_complete
                and self._active_at_freeze == self._native_at_freeze == self._active == self._native_active == 0
                and self._faults == self._late_native_calls == self._refused_offers == 0
                and self._restored
            )
        for row in rows:
            try:
                self._committed(row)
                row["request_binding_matches"] = (
                    row.get("request_binding") == public_binding(authority)
                    and row.get("request_mode") == "enforce"
                    and row.get("request_command_bound") is True
                )
                row["authority_readback_before"] = row.get("authority_before") == authority
                row["authority_readback_after"] = row.get("authority_after") == authority
            except BaseException:
                row["capture_faults"] += 1
                complete = False
        report = self.witness.report()
        complete = complete and (
            report.get("native_receipts") == len(self._rows) == report.get("committed")
            and not any(
                report.get(key)
                for key in (
                    "missing",
                    "binding_mismatches",
                    "writer_rejected",
                    "writer_admission_unobserved",
                    "pre_receipts_without_program_binding",
                )
            )
            and not any(
                report.get("observations", {}).get(key)
                for key in (
                    "duplicate_observations",
                    "witness_overflow",
                    "invalid_receipt_identity",
                    "native_without_receipt",
                )
            )
        )
        result = join_decisions(
            rows,
            authority=authority,
            action=action,
            accepted_ms=(accepted - self.started) * 1000,
            declared_attempts=selected,
            observation_complete=complete,
        )
        result["actual_request_rows"] = rows
        result["declared_attempts"] = selected
        result["owned_offered_attempts"] = offered
        result["undeclared_owned_attempts"] = [attempt for attempt in offered if attempt not in selected]
        result["receipt_witness"] = {
            key: report.get(key)
            for key in (
                "native_receipts",
                "committed",
                "missing",
                "binding_mismatches",
                "writer_rejected",
                "writer_admission_unobserved",
                "pre_receipts_without_program_binding",
                "observations",
            )
        }
        # A retained wrapper can start during the caller-side SQL readbacks.
        # Export one final lifecycle snapshot and refuse completion if it
        # changed, even if that call has not returned to the receipt witness.
        with self._lock:
            complete = complete and (
                self._active_at_freeze == self._native_at_freeze == self._active == self._native_active == 0
                and self._faults == self._late_native_calls == self._refused_offers == 0
                and self._restored
            )
            result["passed"] = result["passed"] is True and complete
            result["observation_complete"] = complete
            result["unowned_native_calls_excluded"] = self._unowned_calls
            result["observation_lifecycle"] = {
                "http_requests_in_flight_at_freeze": self._active_at_freeze,
                "native_calls_in_flight_at_freeze": self._native_at_freeze,
                "http_requests_currently_in_flight": self._active,
                "native_calls_currently_in_flight": self._native_active,
                "late_native_calls": self._late_native_calls,
                "refused_offers": self._refused_offers,
                "capture_faults": self._faults,
                "owned_wrapper_restored": self._restored,
            }
        result["clock_sources"] = {"monotonic": self._clock_kind, "wall": self._wall_clock_kind}
        result["receipt_bound"] = {"requests": self.maximum, "bytes_per_validated_receipt": 16 * 1024}
        result["readback_scope"] = "caller-side sequential SQL counts and validated getter, not atomic commit time"
        return result
