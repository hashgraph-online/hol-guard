"""Finite failure facts for the existing fresh-process corpus gate."""

from __future__ import annotations

import json
import subprocess
from collections.abc import Iterator
from contextlib import contextmanager
from typing import cast

_PREFIX = "corpus_diagnostic="
_STAGES = frozenset(
    {
        "worker_evaluation",
        "worker_process",
        "worker_report",
        "coordinator_process",
        "coordinator_report",
        "coordinator_evaluation",
    }
)
_REASONS = frozenset({"exception", "timeout", "nonzero_exit", "os_error", "invalid_report"})
_EXCEPTIONS = (
    (subprocess.CalledProcessError, "CalledProcessError"),
    (subprocess.TimeoutExpired, "TimeoutExpired"),
    (OSError, "OSError"),
    (PermissionError, "PermissionError"),
    (FileNotFoundError, "FileNotFoundError"),
    (MemoryError, "MemoryError"),
    (ValueError, "ValueError"),
    (json.JSONDecodeError, "JSONDecodeError"),
    (KeyError, "KeyError"),
    (TypeError, "TypeError"),
    (RuntimeError, "RuntimeError"),
    (AssertionError, "AssertionError"),
    (ImportError, "ImportError"),
    (ModuleNotFoundError, "ModuleNotFoundError"),
)
_EXCEPTION_NAMES = frozenset((*(name for _, name in _EXCEPTIONS), "other"))
_KEYS = frozenset(
    {
        "stage",
        "reason",
        "exception",
        "returncode",
        "errno",
        "worker_index",
        "worker_reason",
        "worker_exception",
        "coordinator_returncode",
    }
)


class CorpusDiagnosticError(RuntimeError):
    """Carries only an already serialized, finite diagnostic."""


def _integer(value: object, minimum: int, maximum: int) -> int | None:
    return value if type(value) is int and minimum <= value <= maximum else None


def _choice(value: object, choices: frozenset[str]) -> bool:
    return type(value) is str and value in choices


def _decode_facts(value: object) -> dict[str, object] | None:
    if type(value) is not str or len(value) > 2048 or not value.startswith(_PREFIX):
        return None
    try:
        facts = json.loads(value[len(_PREFIX) :])
    except (ValueError, RecursionError):
        return None
    if type(facts) is not dict or facts.keys() != _KEYS:
        return None
    if not _choice(facts["stage"], _STAGES) or not _choice(facts["reason"], _REASONS):
        return None
    if not _choice(facts["exception"], _EXCEPTION_NAMES):
        return None
    for key, minimum, maximum in (
        ("returncode", -(2**31), 2**32 - 1),
        ("coordinator_returncode", -(2**31), 2**32 - 1),
        ("errno", 0, 4095),
        ("worker_index", 0, 3),
    ):
        if facts[key] is not None and _integer(facts[key], minimum, maximum) is None:
            return None
    for key, choices in (("worker_reason", _REASONS), ("worker_exception", _EXCEPTION_NAMES)):
        if facts[key] is not None and not _choice(facts[key], choices):
            return None
    return facts


def _failure_text(error: Exception, stage: str, worker_index: int | None) -> str:
    # Do not stringify exceptions or inspect attributes of unknown subclasses.
    if type(error) is CorpusDiagnosticError and len(error.args) == 1:
        previous = _decode_facts(error.args[0])
        if previous is not None:
            return _PREFIX + json.dumps(previous, sort_keys=True)
    facts: dict[str, object] = {
        "stage": stage if _choice(stage, _STAGES) else "coordinator_process",
        "reason": "invalid_report" if stage in {"worker_report", "coordinator_report"} else "exception",
        "exception": next((name for cls, name in _EXCEPTIONS if type(error) is cls), "other"),
        "returncode": None,
        "coordinator_returncode": None,
        "errno": None,
        "worker_index": _integer(worker_index, 0, 3),
        "worker_reason": None,
        "worker_exception": None,
    }
    if type(error) is subprocess.TimeoutExpired:
        facts["reason"] = "timeout"
    elif type(error) is subprocess.CalledProcessError:
        facts["reason"] = "nonzero_exit"
        facts["returncode"] = _integer(error.returncode, -(2**31), 2**32 - 1)
        nested = _decode_facts(error.stderr)
        if nested is not None:
            if stage == "worker_process" and nested["stage"] == "worker_evaluation":
                facts["worker_reason"] = nested["reason"]
                facts["worker_exception"] = nested["exception"]
            elif stage == "coordinator_process" and nested["stage"] in _STAGES - {"coordinator_process"}:
                # Keep both physical exit codes; never infer timeout from an exit code.
                nested["coordinator_returncode"] = facts["returncode"]
                return _PREFIX + json.dumps(nested, sort_keys=True)
    elif any(type(error) is cls for cls in (OSError, PermissionError, FileNotFoundError)):
        facts["reason"] = "os_error"
        facts["errno"] = _integer(cast(OSError, error).errno, 0, 4095)
    return _PREFIX + json.dumps(facts, sort_keys=True)


@contextmanager
def corpus_failure_boundary(stage: str, worker_index: int | None = None) -> Iterator[None]:
    __tracebackhide__ = True
    try:
        yield
    except Exception as error:
        raise CorpusDiagnosticError(_failure_text(error, stage, worker_index)) from None
