"""Content-free native-stop outcomes and bounded optional diagnostic output."""

from __future__ import annotations

import json
import os
import re
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

_STOP_DIAGNOSTIC_SCHEMA = "hol-guard.native-resident-stop-diagnostic.v1"
_STOP_DIAGNOSTIC_PATH_ENV = "NATIVE_STOP_DIAGNOSTIC_PATH"
_STOP_DIAGNOSTIC_FIELDS = (
    "acknowledged",
    "authenticated",
    "generation_present",
    "owner_lock",
    "marker_lock",
    "endpoint",
    "serving_shutdown",
)
_STOP_FAILURE_STATUSES = frozenset({"failed", "contained_client_cleanup_failed"})
_TRANSIENT_STOP_ERRORS = frozenset(
    {
        "native_resident_stop_unavailable",
        "native_resident_stop_in_progress",
    }
)
_STOP_RETRY_DELAY_SECONDS = 0.1
_STOP_DIAGNOSTIC_RE = re.compile(
    rb"\b(?P<code>native_resident_stop_[a-z0-9_]+)"
    rb"(?P<fields>(?::[a-z_]+=(?:true|false|free|busy|unverified|absent|present))*)"
)


@dataclass(frozen=True)
class NativeStopResult:
    """Bounded resident-stop outcome and privacy-safe containment evidence."""

    contained: bool
    diagnostic: dict[str, object]

    def __bool__(self) -> bool:
        return self.contained


def _build_stop_diagnostic(
    status: str,
    *,
    error: str | None = None,
    fields: Mapping[str, str] | None = None,
) -> dict[str, object]:
    diagnostic: dict[str, object] = {
        "schema": _STOP_DIAGNOSTIC_SCHEMA,
        "operation": "resident-stop",
        "status": status,
    }
    if error is not None:
        diagnostic["error"] = error
    for field in _STOP_DIAGNOSTIC_FIELDS:
        diagnostic[field] = (fields or {}).get(field, "unknown")
    return diagnostic


def _write_stop_diagnostic(diagnostic: Mapping[str, object]) -> None:
    path_value = os.environ.get(_STOP_DIAGNOSTIC_PATH_ENV)
    if not path_value:
        return
    try:
        Path(path_value).write_text(json.dumps(diagnostic, separators=(",", ":")), encoding="utf-8")
    except OSError:
        return


def _stop_diagnostic_from_stderr(stderr: bytes) -> dict[str, object]:
    match = _STOP_DIAGNOSTIC_RE.search(stderr[:8192])
    if match is None:
        return _build_stop_diagnostic("failed", error="native_resident_stop_process_failed")
    code = match.group("code").decode("ascii")
    if not code.startswith("native_resident_stop_"):
        code = "native_resident_stop_process_failed"
    fields = {
        key.decode("ascii"): value.decode("ascii")
        for key, value in re.findall(rb":([a-z_]+)=([a-z]+)", match.group("fields"))
        if key.decode("ascii") in _STOP_DIAGNOSTIC_FIELDS
    }
    return _build_stop_diagnostic("failed", error=code, fields=fields)
