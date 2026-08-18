#!/usr/bin/env python3
"""Drive the multi-device MDM Cloud integration and emit bounded evidence."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from lab_common import NATIVE_CERTIFICATION_GATES, http_request
from orchestrator_initial_remediation import run_remediation_and_evidence
from orchestrator_initial_resilience import run_resilience_and_repair_setup
from orchestrator_initial_rollout import run_enrollment_and_rollout
from orchestrator_support import ALPHA, Recorder, _device_fault, _publish, _state, _sync

from codex_plugin_scanner.guard.mdm.cloud_control import iso, utcnow


def _run_initial(
    cloud: str,
    proxy: str,
    devices: dict[str, str],
    admin: str,
    recorder: Recorder,
) -> None:
    canary_revision = run_enrollment_and_rollout(cloud, proxy, devices, admin, recorder)
    repair = run_resilience_and_repair_setup(cloud, proxy, devices, admin, recorder, canary_revision)
    run_remediation_and_evidence(cloud, devices, admin, recorder, repair)


def _run_restart(
    cloud: str,
    devices: dict[str, str],
    admin: str,
    recorder: Recorder,
) -> None:
    before = {name: http_request("GET", url + "/state")[2] for name, url in devices.items()}
    cloud_before = _state(cloud, admin)
    recorder.add(
        "Cloud database, signing authority, and device identities survive process restart",
        cloud_before.get("auditChainValid") is True
        and len(cloud_before.get("devices", [])) >= 4
        and all(isinstance(value, dict) and value.get("revision") is not None for value in before.values()),
        {
            "deviceCount": len(cloud_before.get("devices", [])),
            "revisions": {
                name: value.get("revision") if isinstance(value, dict) else None for name, value in before.items()
            },
        },
    )
    recorder.add(
        "durable outbox remains present before post-restart sync",
        isinstance(before.get("device-c"), dict) and before["device-c"].get("outboxDepth", 0) > 0,
        before.get("device-c"),
    )

    _device_fault(devices["device-c"], {"holdOutbox": False})
    after = {name: _sync(url) for name, url in devices.items()}
    recorder.add(
        "all devices resume with monotonic request identity after restart",
        all(value.get("error") is None for value in after.values())
        and all(
            isinstance(before[name], dict) and value.get("requestSequence", 0) > before[name].get("requestSequence", 0)
            for name, value in after.items()
        ),
        {
            name: {
                "revision": value.get("revision"),
                "requestSequence": value.get("requestSequence"),
            }
            for name, value in after.items()
        },
    )
    recorder.add(
        "queued evidence drains after restart without dead letters",
        after["device-c"].get("outboxDepth") == 0 and after["device-c"].get("deadLetterDepth") == 0,
        after["device-c"],
    )

    signing_probe = _publish(cloud, admin, ALPHA, ["device-a"], "enforce")
    signing_sync = _sync(devices["device-a"])
    recorder.add(
        "persisted Cloud signing key remains trusted after restart",
        signing_probe.get("httpStatus") == 201
        and signing_sync.get("revision") == signing_probe.get("revision")
        and signing_sync.get("error") is None,
        {"publish": signing_probe, "sync": signing_sync},
    )
    final_state = _state(cloud, admin)
    recorder.add(
        "audit chain remains valid after Cloud restart and new writes",
        final_state.get("auditChainValid") is True,
        {"auditChainValid": final_state.get("auditChainValid"), "auditCount": len(final_state.get("audit", []))},
    )


def _report(recorder: Recorder) -> dict[str, object]:
    return {
        "schemaVersion": "hol-guard-mdm-cloud-integration-lab.v1",
        "generatedAt": iso(utcnow()),
        "workspaceId": ALPHA,
        "healthy": all(step.get("passed") is True for step in recorder.steps),
        "stepCount": len(recorder.steps),
        "steps": recorder.steps,
        "nativeCertification": {
            "outcome": "not-evaluated",
            "requiredGates": NATIVE_CERTIFICATION_GATES,
            "reason": "native_platform_or_vendor_required",
        },
    }


def orchestrate(
    cloud: str,
    proxy: str,
    devices: dict[str, str],
    admin: str,
    output: str | Path | None,
    *,
    phase: str = "full",
    input_report: str | Path | None = None,
) -> dict[str, object]:
    existing: list[dict[str, object]] = []
    if input_report is not None:
        try:
            loaded = json.loads(Path(input_report).read_text(encoding="utf-8"))
            if isinstance(loaded, dict) and isinstance(loaded.get("steps"), list):
                existing = [step for step in loaded["steps"] if isinstance(step, dict)]
        except (OSError, json.JSONDecodeError):
            existing = []
    recorder = Recorder(existing)
    try:
        if phase in {"initial", "full"}:
            _run_initial(cloud, proxy, devices, admin, recorder)
        if phase in {"restart", "full"}:
            _run_restart(cloud, devices, admin, recorder)
    except Exception as error:  # keep bounded evidence even on an unexpected lab defect
        recorder.add(
            "orchestrator completed without an unexpected exception",
            False,
            {"type": type(error).__name__, "message": str(error)[:512]},
        )
    report = _report(recorder)
    if output is not None:
        path = Path(output)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(report, sort_keys=True) + "\n", encoding="utf-8")
    return report


def _required_admin_token() -> str:
    token = os.environ.get("HOL_MDM_LAB_ADMIN_TOKEN", "").strip()
    if not token:
        raise RuntimeError("HOL_MDM_LAB_ADMIN_TOKEN is required")
    return token


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output")
    parser.add_argument("--input-report")
    parser.add_argument("--phase", choices=("initial", "restart", "full"), default="full")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    devices = {
        "device-a": os.environ["HOL_MDM_DEVICE_A_URL"],
        "device-b": os.environ["HOL_MDM_DEVICE_B_URL"],
        "device-c": os.environ["HOL_MDM_DEVICE_C_URL"],
        "device-d": os.environ["HOL_MDM_DEVICE_D_URL"],
    }
    report = orchestrate(
        os.environ["HOL_MDM_CLOUD_ADMIN_URL"],
        os.environ["HOL_MDM_PROXY_URL"],
        devices,
        _required_admin_token(),
        args.output,
        phase=args.phase,
        input_report=args.input_report,
    )
    print(json.dumps(report, sort_keys=True) if args.json else json.dumps(report, indent=2))
    return 0 if report["healthy"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
