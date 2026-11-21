"""Conservative readiness copy for doctor's passive harness diagnostics, decided natively."""

from __future__ import annotations

import json
from collections.abc import Mapping
from typing import cast

from ..native_runner_authority import NativeRunnerAuthorityError, native_runner_authority


def doctor_runtime_readiness(diagnostics: Mapping[str, object]) -> dict[str, str]:
    """The native ``harness_diagnostics`` readiness for one harness's diagnostics.

    It never passes: doctor's probes do not verify an authenticated Guard
    decision in the loaded harness session.
    """

    probe = json.loads(json.dumps(diagnostics.get("runtime_probe"), default=str))
    try:
        answer = native_runner_authority(
            "harness_diagnostics",
            {"op": "readiness", "setup_status": diagnostics.get("setup_status"), "runtime_probe": probe},
        ).get("readiness")
    except NativeRunnerAuthorityError:
        answer = None
    if not isinstance(answer, dict):
        # Doctor still reports when the runtime cannot answer; readiness stays unproven.
        return {
            "state": "unknown",
            "reason_code": "native_runtime_unavailable",
            "detail": "The native runtime did not answer, so no authenticated Guard decision was verified.",
        }
    return {str(key): str(value) for key, value in cast("dict[str, object]", answer).items()}
