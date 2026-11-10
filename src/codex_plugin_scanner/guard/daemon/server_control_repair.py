"""Protection repair route handler for the daemon."""

# pyright: reportAttributeAccessIssue=false, reportUnknownMemberType=false

from __future__ import annotations

import sqlite3
from collections.abc import Mapping
from datetime import datetime, timezone

from ..config import (
    load_guard_config,
)
from ..models import (
    GuardRuntimeRegistration,
)
from ..runtime_artifact_reconciliation import (
    repair_failing_managed_harness_hooks,
)
from .protection_repair_retry import containment_repair_outcome, incomplete_protection_repair_payload
from .protection_repair_stages import (
    harness_hooks_repair_reason,
    integrity_repair_reasons,
    record_incomplete_protection_repair,
    repair_daemon_registration,
)
from .server_common import (
    _now,
)
from .server_control_connect_flow import (
    _repair_command_activity_persistence_health,
)


class _RepairSettingsRoutes:
    """Handler methods for control-plane routes."""

    def _record_incomplete_protection_repair(self, check_reasons: Mapping[str, str]) -> None:
        record_incomplete_protection_repair(self._daemon_server().diagnostics, check_reasons)

    def _handle_protection_repair(self, payload: dict[str, object]) -> None:
        check_id = self._optional_string(payload.get("check_id"))
        store = self.server.store  # type: ignore[attr-defined]
        if check_id in {"all", "policy_engine", "rule_packs", "tamper_checks"}:
            repaired_check_ids: list[str] = []
            pending_check_ids: list[str] = []
            failed_check_ids: list[str] = []
            check_reasons: dict[str, str] = {}
            if check_id == "all":
                daemon_server = self._daemon_server()
                registration_reason = repair_daemon_registration(
                    store,
                    session_id=daemon_server.runtime_session_id,
                    registration=GuardRuntimeRegistration(
                        daemon_host=daemon_server.runtime_host,
                        daemon_port=daemon_server.daemon_port(),
                        started_at=daemon_server.runtime_started_at,
                    ),
                    last_heartbeat_at=_now(),
                )
                if registration_reason is None:
                    repaired_check_ids.append("daemon")
                else:
                    failed_check_ids.append("daemon")
                    check_reasons["daemon"] = registration_reason
            try:
                status = store.setup_policy_integrity(now=_now(), include_items=False)
                if status.get("mode") != "protected":
                    status = store.repair_policy_integrity(
                        clear_invalid=False,
                        now=_now(),
                        include_items=False,
                    )
            except (OSError, RuntimeError, TypeError, ValueError):
                check_reasons.update(integrity_repair_reasons(restored=False))
                self._record_incomplete_protection_repair(check_reasons)
                self._write_json(
                    {
                        "error": "protection_repair_failed",
                        "message": "Guard could not restore integrity protection automatically.",
                        "check_reasons": check_reasons,
                    },
                    status=409,
                )
                return
            repaired = status.get("mode") == "protected"
            degraded_reasons = status.get("degraded_reasons")
            reason_count = len(degraded_reasons) if isinstance(degraded_reasons, list) else 0
            if repaired:
                repaired_check_ids.extend(["policy_engine", "rule_packs", "tamper_checks"])
            else:
                failed_check_ids.extend(["policy_engine", "rule_packs", "tamper_checks"])
                check_reasons.update(integrity_repair_reasons(restored=False))
            hook_failures: list[str] | tuple[str, ...] = []
            if check_id == "all":
                hook_repair_unknown = False
                try:
                    _, hook_failures = repair_failing_managed_harness_hooks(store)
                except (OSError, RuntimeError, TypeError, ValueError, sqlite3.Error):
                    hook_failures = []
                    hook_repair_unknown = True
                has_active_hooks = any(
                    isinstance(install.get("harness"), str) and install.get("active") is True
                    for install in store.list_managed_installs()
                )
                if hook_failures or hook_repair_unknown or not has_active_hooks:
                    failed_check_ids.append("harness_hooks")
                    check_reasons["harness_hooks"] = harness_hooks_repair_reason(
                        has_active_hooks=has_active_hooks,
                        hook_failures=hook_failures,
                        hook_repair_unknown=hook_repair_unknown,
                    )
                else:
                    repaired_check_ids.append("harness_hooks")
                if repaired:
                    (
                        containment_repaired,
                        containment_failed,
                        containment_reasons,
                    ) = containment_repair_outcome(
                        lambda: self._containment_health_payload(force_refresh=True),
                        guard_home=store.guard_home,
                    )
                    repaired_check_ids.extend(containment_repaired)
                    failed_check_ids.extend(containment_failed)
                    for failed_check_id in containment_failed:
                        check_reasons[failed_check_id] = containment_reasons[failed_check_id]
                    try:
                        config = load_guard_config(store.guard_home)
                        _repair_command_activity_persistence_health(store)
                        store.maintain_command_activity(
                            now=datetime.now(timezone.utc),
                            detail_retain_days=config.evidence_retain_days,
                        )
                        evidence_health = store.get_command_activity_persistence_health()
                        if evidence_health.active_error_count > 0:
                            failed_check_ids.append("decision_stream")
                            check_reasons["decision_stream"] = "decision_stream_degraded"
                        else:
                            repaired_check_ids.append("decision_stream")
                    except (OSError, RuntimeError, TypeError, ValueError, sqlite3.Error):
                        failed_check_ids.append("decision_stream")
                        check_reasons["decision_stream"] = "decision_stream_health_unavailable"
                if repaired and (failed_check_ids or pending_check_ids):
                    self._record_incomplete_protection_repair(check_reasons)
                    self._write_json(
                        incomplete_protection_repair_payload(
                            repaired_check_ids=repaired_check_ids,
                            failed_check_ids=failed_check_ids,
                            failed_harnesses=hook_failures,
                            pending_check_ids=pending_check_ids,
                            has_active_hooks=has_active_hooks,
                            hook_failures=hook_failures,
                            hook_repair_unknown=hook_repair_unknown,
                            check_reasons=check_reasons,
                        ),
                        status=409,
                    )
                    return
            if not repaired or failed_check_ids or pending_check_ids:
                self._record_incomplete_protection_repair(check_reasons)
            self._write_json(
                {
                    **({"error": "local_integrity_repair_incomplete"} if not repaired else {}),
                    "repaired": repaired,
                    "repair_scope": "local_integrity",
                    "check_ids": repaired_check_ids,
                    **({"failed_check_ids": failed_check_ids} if failed_check_ids else {}),
                    "pending_check_ids": pending_check_ids,
                    "check_reasons": check_reasons,
                    "message": (
                        "Integrity protection restored."
                        if repaired
                        else (
                            "Guard could not establish a local integrity proof. "
                            "Unverified local rules remain disabled. Local repair did not change Guard Cloud policy "
                            "availability. Retry local repair from Protect; "
                            f"Guard will keep the remaining {reason_count or 1} issue isolated."
                        )
                    ),
                },
                status=200 if repaired else 409,
            )
            return
        if check_id == "decision_stream":
            check_reasons: dict[str, str] = {}
            try:
                config = load_guard_config(store.guard_home)
                _repair_command_activity_persistence_health(store)
            except (OSError, RuntimeError, TypeError, ValueError, sqlite3.Error):
                check_reasons["decision_stream"] = "decision_stream_health_unavailable"
                self._record_incomplete_protection_repair(check_reasons)
                self._write_json(
                    {
                        "error": "protection_repair_failed",
                        "message": "Guard could not verify the command evidence store.",
                        "check_reasons": check_reasons,
                    },
                    status=409,
                )
                return
            try:
                store.maintain_command_activity(
                    now=datetime.now(timezone.utc),
                    detail_retain_days=config.evidence_retain_days,
                )
                health = store.get_command_activity_persistence_health()
            except (OSError, RuntimeError, TypeError, ValueError, sqlite3.Error):
                check_reasons["decision_stream"] = "decision_stream_health_unavailable"
                self._record_incomplete_protection_repair(check_reasons)
                self._write_json(
                    {
                        "error": "protection_repair_failed",
                        "message": "Guard could not verify the command evidence store.",
                        "check_reasons": check_reasons,
                    },
                    status=409,
                )
                return
            repaired = health.active_error_count == 0
            if not repaired:
                check_reasons["decision_stream"] = "decision_stream_degraded"
                self._record_incomplete_protection_repair(check_reasons)
            self._write_json(
                {
                    "repaired": repaired,
                    "repair_scope": "local_integrity",
                    "check_ids": ["decision_stream"] if repaired else [],
                    **({"failed_check_ids": ["decision_stream"]} if not repaired else {}),
                    "check_reasons": check_reasons,
                    "message": (
                        "Command evidence is healthy."
                        if repaired
                        else "Guard could not restore command evidence persistence."
                    ),
                },
                status=200 if repaired else 409,
            )
            return
        self._write_json({"error": "unsupported_protection_check"}, status=400)
