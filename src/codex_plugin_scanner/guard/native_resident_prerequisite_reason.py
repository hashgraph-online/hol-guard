"""Bounded, non-secret reasons for a resident prerequisite that could not be provisioned."""

from __future__ import annotations

import re
import threading
from collections import OrderedDict
from pathlib import Path

_MAX_HOMES = 64
_MAX_PART = 48
# A fixed machine code: lowercase words joined by underscores. Only errors raised
# by the snapshot layer itself (whose argument is always a code literal) may
# carry one; any other exception message is untrusted and never forwarded.
_SAFE_CODE = re.compile(r"[a-z]{2,}(?:_[a-z0-9]{1,12}){1,6}")
_HEX_RUN = re.compile(r"[0-9a-f]{16,}")
_LOCK = threading.Lock()
_FAILURES: OrderedDict[str, str] = OrderedDict()


def _is_trusted_code(error: BaseException) -> bool:
    from .native_policy_snapshot_constants import NativePolicySnapshotError

    return (
        isinstance(error, NativePolicySnapshotError)
        and bool(error.args)
        and isinstance(error.args[0], str)
        and _SAFE_CODE.fullmatch(error.args[0]) is not None
    )


def _class_part(error: BaseException) -> str:
    name = re.sub(r"[^A-Za-z0-9_]", "", type(error).__name__)[:_MAX_PART] or "Error"
    detail = ""
    # Only trusted machine codes are carried; free-form messages can hold paths or secrets.
    if _is_trusted_code(error):
        detail = f":{error.args[0]}"
    elif isinstance(error, OSError) and isinstance(error.errno, int):
        winerror = getattr(error, "winerror", None)
        detail = f":e{error.errno}" + (f"w{winerror}" if isinstance(winerror, int) else "")
    return f"{name}{detail}"


def prerequisite_failure_reason(phase: str, error: BaseException) -> str:
    """``<phase>:<exception class>[:<machine code>]`` with no paths or secrets."""

    return f"{phase}:{_class_part(error)}"


def record_prerequisite_failure(home_key: str, reason: str) -> None:
    with _LOCK:
        _FAILURES[home_key] = reason
        _FAILURES.move_to_end(home_key)
        while len(_FAILURES) > _MAX_HOMES:
            _FAILURES.popitem(last=False)


def clear_prerequisite_failure(home_key: str) -> None:
    with _LOCK:
        _FAILURES.pop(home_key, None)


def prerequisite_failure_for_home(guard_home: Path) -> str | None:
    from .directory_path_authority import canonical_guard_home_path

    try:
        key = str(canonical_guard_home_path(guard_home))
    except OSError:
        key = str(guard_home)
    with _LOCK:
        return _FAILURES.get(key)


def prerequisite_unavailable_code(base: str, guard_home: Path) -> str:
    """``base`` alone, or ``base:<reason>`` when provisioning recorded why it failed."""

    reason = prerequisite_failure_for_home(guard_home)
    return f"{base}:{reason}" if reason else base
