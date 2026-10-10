"""Conservative readiness copy for doctor's passive harness diagnostics."""

from __future__ import annotations

from collections.abc import Mapping
from typing import cast


def _command_probe_results(probe: object) -> tuple[Mapping[str, object], ...]:
    if not isinstance(probe, Mapping):
        return ()
    # Hermes/OpenClaw use command; OpenCode uses paths/config. Do not crawl
    # arbitrary configuration or turn other adapter metadata into probe results.
    typed_probe = cast(Mapping[str, object], probe)
    nested = tuple(
        cast(Mapping[str, object], typed_probe[key])
        for key in ("command", "paths", "config")
        if isinstance(typed_probe.get(key), Mapping)
    )
    return (typed_probe, *nested)


def doctor_runtime_readiness(diagnostics: Mapping[str, object]) -> dict[str, str]:
    """Do not promote registration, manifest trust or a CLI probe to evaluation proof.

    The current doctor probes do not verify an authenticated Guard decision in
    the loaded harness session. Until that proof has its own contract, this
    projection deliberately cannot return a passing readiness result.
    """

    state = "unknown"
    reason = "hook_evaluation_unverified"
    detail = (
        "Doctor has not verified an authenticated Guard decision from this harness. "
        "Registration and CLI checks do not prove runtime readiness."
    )
    if diagnostics.get("setup_status") == "broken":
        state = "fail"
        reason = "guard_setup_broken"
        detail = (
            "Guard registration is marked broken. Preserve this report and inspect the warnings "
            "before changing the installation. The loaded session's evaluation remains unverified."
        )
    elif diagnostics.get("setup_status") in ("partial", "not_found"):
        reason = "hook_registration_unconfirmed"
        detail = (
            "Guard registration is incomplete or missing. Doctor has not verified an authenticated "
            "Guard decision from this harness."
        )
    else:
        probes = _command_probe_results(diagnostics.get("runtime_probe"))
        if any(probe.get("timed_out") is True for probe in probes):
            reason = "harness_probe_timed_out"
            detail = (
                "The harness diagnostic check timed out. Inspect the probe and daemon diagnostics; "
                "no authenticated Guard decision was verified."
            )
        elif any(probe.get("ok") is False for probe in probes):
            reason = "harness_probe_failed"
            detail = (
                "The harness diagnostic check failed. Inspect the probe and daemon diagnostics; "
                "no authenticated Guard decision was verified."
            )
        elif any(probe.get("skipped") is True for probe in probes):
            reason = "harness_probe_not_run"
            detail = (
                "Global doctor checked registration without running the harness CLI probe. "
                "No authenticated Guard decision was verified."
            )
    return {"state": state, "reason_code": reason, "detail": detail}
