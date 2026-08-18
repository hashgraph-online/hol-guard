from __future__ import annotations

import os

from lab_common import atomic, decode_json_object, json_bytes

from codex_plugin_scanner.guard.mdm.cloud_control import ContractError, iso, validate_remediation
from codex_plugin_scanner.guard.mdm.policy import parse_managed_policy


class DeviceRemediationMixin:
    """Fixed remediation execution, fleet projection, and deterministic faults."""

    def _execute_remediation(self, job: dict[str, object]) -> dict[str, object]:
        action = job["action"]
        parameters = job["parameters"]
        if action == "repair":
            last_good = self.state / "last-good-policy.json"
            if last_good.is_symlink() or not last_good.exists():
                raise RuntimeError("last_good_policy_unavailable")
            policy = decode_json_object(last_good.read_bytes())
            parse_managed_policy(policy)
            if self.policy_path.is_symlink():
                self.policy_path.unlink()
            atomic(self.policy_path, json_bytes(policy))
            return {"action": action, "scope": parameters.get("scope"), "restored": True}
        if action == "policy-refresh":
            return {"action": action, "refreshRequested": True}
        if action == "service-register":
            service = parameters.get("service")
            atomic(self.state / f"service-{service}.state", b"registered\n")
            return {"action": action, "service": service, "registered": True}
        if action in {"version-converge", "install"}:
            target = parameters.get("targetVersion")
            atomic(self.state / "target-version.state", f"{target}\n".encode())
            return {"action": action, "targetVersion": target, "converged": True}
        if action == "integrity-scan":
            return {"action": action, "integrity": self.policy_integrity()}
        raise RuntimeError("remediation_action_unsupported")

    def remediate(self) -> None:
        status, _, data = self.request("GET", "/runtime/v1/remediations")
        if status != 200 or not isinstance(data, dict):
            return
        jobs = data.get("jobs", [])
        if not isinstance(jobs, list):
            return
        completed_jobs = self.meta["completedJobs"]
        assert isinstance(completed_jobs, dict)
        for raw_job in jobs:
            if not isinstance(raw_job, dict):
                continue
            job_id = raw_job.get("jobId")
            if not isinstance(job_id, str):
                continue
            previous = completed_jobs.get(job_id)
            if isinstance(previous, dict):
                self._queue("results", previous)
                continue
            try:
                job = validate_remediation(raw_job, self.workspace, self.device, self.generation)
                detail = self._execute_remediation(job)
                outcome = "succeeded"
            except (ContractError, RuntimeError, OSError, ValueError) as error:
                detail = {"reason": getattr(error, "code", str(error))[:160]}
                outcome = "failed"
            result = {
                "jobId": job_id,
                "status": outcome,
                "observedAt": iso(self._now()),
                "detail": detail,
            }
            completed_jobs[job_id] = result
            self._save("meta", self.meta)
            self._queue("results", result)
        self.flush()

    @property
    def outbox_depth(self) -> int:
        return sum(
            len(self.outbox[key]) for key in ("acks", "health", "results") if isinstance(self.outbox.get(key), list)
        )

    @property
    def dead_letter_depth(self) -> int:
        value = self.outbox.get("deadLetters")
        return len(value) if isinstance(value, list) else 0

    def view(self) -> dict[str, object]:
        integrity = self.policy_integrity()
        return {
            "schemaVersion": "hol-guard-mdm-device-state.v2",
            "workspaceId": self.workspace,
            "deviceId": self.device,
            "installationGeneration": self.generation,
            "revision": self.meta["revision"],
            "policyHash": self.meta["policyHash"],
            "requestSequence": self.meta["requestSequence"],
            "healthSequence": self.meta["healthSequence"],
            "outboxDepth": self.outbox_depth,
            "deadLetterDepth": self.dead_letter_depth,
            "policyExists": self.policy_path.exists() and not self.policy_path.is_symlink(),
            "policyIntegrity": integrity["state"],
            "policyIntegrityReason": integrity["reason"],
            "lastSyncError": self.meta.get("lastSyncError"),
        }

    def apply_fault(self, payload: dict[str, object]) -> None:
        allowed = {
            "crashAfterWrite",
            "replayNext",
            "workspaceOverride",
            "holdOutbox",
            "clockOffsetSeconds",
            "tamperPolicy",
            "symlinkPolicy",
            "removePolicy",
        }
        if set(payload) - allowed:
            raise ContractError("fault_invalid")
        for boolean_name in (
            "crashAfterWrite",
            "replayNext",
            "holdOutbox",
            "tamperPolicy",
            "symlinkPolicy",
            "removePolicy",
        ):
            if boolean_name in payload and not isinstance(payload[boolean_name], bool):
                raise ContractError("fault_invalid")
        workspace_override = payload.get("workspaceOverride")
        if (
            "workspaceOverride" in payload
            and workspace_override is not None
            and not isinstance(workspace_override, str)
        ):
            raise ContractError("fault_invalid")
        if "clockOffsetSeconds" in payload:
            offset = payload["clockOffsetSeconds"]
            if not isinstance(offset, int) or isinstance(offset, bool) or not -86_400 <= offset <= 86_400:
                raise ContractError("fault_invalid")
        if payload.get("removePolicy") is True and (self.policy_path.is_symlink() or self.policy_path.exists()):
            self.policy_path.unlink()
        if payload.get("tamperPolicy") is True:
            if self.policy_path.is_symlink():
                self.policy_path.unlink()
            atomic(self.policy_path, b'{"schemaVersion":"hol-guard-mdm-policy.v1","settings":{"mode":"observe"}}')
            os.chmod(self.policy_path, 0o666)
        if payload.get("symlinkPolicy") is True:
            if self.policy_path.is_symlink() or self.policy_path.exists():
                self.policy_path.unlink()
            target = self.state / "attacker-policy.json"
            atomic(target, b'{"schemaVersion":"hol-guard-mdm-policy.v1","settings":{"mode":"observe"}}')
            self.policy_path.parent.mkdir(parents=True, exist_ok=True)
            self.policy_path.symlink_to(target)
        for key in ("crashAfterWrite", "replayNext", "workspaceOverride", "holdOutbox", "clockOffsetSeconds"):
            if key in payload:
                self.faults[key] = payload[key]
