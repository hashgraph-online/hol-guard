"""Bounded reason label for a failed installed SLO proof.

The benchmark's own checks raise ``RuntimeError("native_installed_slo_failed:
<reason>")``. The aggregate category (``benchmark_contract``) does not say
which check failed, so a failed nightly could not be diagnosed from its
report. Only that exact built-in shape is read, never ``str()`` of an
arbitrary exception, and the reason is reduced to an identifier-like label
that still passes the report's privacy screen.
"""

from __future__ import annotations

import re
from collections.abc import MutableMapping

from scripts.native_slo_contract import assert_privacy_safe, sanitize_aggregate

_CONTRACT_PREFIX = "native_installed_slo_failed:"
_MAX_MESSAGE_CHARS = 256
_MAX_LABEL_CHARS = 96
_MAX_CHAIN = 8
# A canonical reason is a fixed sentence.  Anything shaped like a filesystem
# path is refused outright rather than slugged into a label.
_PATH_LIKE = re.compile(r"[\\~]|/[^/\s]*/|[A-Za-z]:[\\/]")
_IDENTIFIER = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,63}")


def contract_failure_reason(error: BaseException) -> str | None:
    """Return the label of the first benchmark check failure in the chain."""

    current: BaseException | None = error
    seen: set[int] = set()
    while current is not None and id(current) not in seen and len(seen) < _MAX_CHAIN:
        seen.add(id(current))
        if type(current) is RuntimeError and len(current.args) == 1:
            message = current.args[0]
            if type(message) is str and len(message) <= _MAX_MESSAGE_CHARS and message.startswith(_CONTRACT_PREFIX):
                label = _label(message[len(_CONTRACT_PREFIX) :])
                if label is not None:
                    return label
        current = current.__cause__ or current.__context__
    return None


def _label(reason: str) -> str | None:
    if _PATH_LIKE.search(reason):
        return None
    slug = re.sub(r"[^a-z0-9]+", "_", reason.lower()).strip("_")[:_MAX_LABEL_CHARS].rstrip("_")
    if not slug:
        return None
    sanitized = sanitize_aggregate(slug)
    return sanitized if isinstance(sanitized, str) else None


def annotate_failure_reason(result: MutableMapping[str, object], error: BaseException) -> str | None:
    """Add the check label to ``result['failure']`` and return it, if any."""

    label = contract_failure_reason(error)
    failure = result.get("failure")
    if label is None or not isinstance(failure, MutableMapping):
        return None
    failure["reason"] = label
    try:
        assert_privacy_safe(result)
    except ValueError:
        del failure["reason"]
        return None
    return label


def exception_chain_summary(error: BaseException) -> str:
    """Name each exception in the chain by type and errno, never by message."""

    parts: list[str] = []
    current: BaseException | None = error
    seen: set[int] = set()
    while current is not None and id(current) not in seen and len(seen) < _MAX_CHAIN:
        seen.add(id(current))
        name = type(current).__name__
        part = name if _IDENTIFIER.fullmatch(name) else "Exception"
        errno = getattr(current, "errno", None)
        if type(errno) is int:
            part += f"[errno={errno}]"
        parts.append(part)
        current = current.__cause__ or current.__context__
    return "<-".join(parts)


__all__ = ["annotate_failure_reason", "contract_failure_reason", "exception_chain_summary"]
