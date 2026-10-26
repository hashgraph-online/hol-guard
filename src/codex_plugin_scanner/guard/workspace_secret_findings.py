"""Project the native secret scan into workspace findings and coverage.

The native snapshot decides everything about a secret finding: it redacts the
matched text, normalizes the severity, groups repeats of one secret in a file,
derives the stable ``finding_id`` and decides whether the scan was complete.
This module only checks that the reply has that shape and copies it into the
stored finding. A reply that does not match is dropped rather than copied, so a
malformed reply cannot smuggle free text into stored findings, and a dropped
finding leaves the detector incomplete instead of silently complete.
"""

from __future__ import annotations

import re
import secrets
from collections.abc import Mapping
from typing import Any, Final

SECRET_DETECTOR: Final = "secrets"
SECRETS_RESULT_SCHEMA: Final = "guard.workspace-secrets.v1"
MAX_SECRET_FINDINGS: Final = 500
FINGERPRINT_KEY_STATE_KEY: Final = "workspace_secret_fingerprint_key"

_FINDING_ID = re.compile(r"[0-9a-f]{32}")
_RULE_ID = re.compile(r"[A-Za-z0-9_.:-]{1,128}")
_FINGERPRINT = re.compile(r"[0-9a-f]{32}")
_REASON = re.compile(r"[a-z0-9_]{1,40}")
_SEVERITIES: Final = frozenset({"critical", "high", "medium", "low", "info", "unknown"})
# The native scan leaves a longer path unread and reports it as a truncation,
# so every path it reports fits here.
_MAX_PATH_CHARS: Final = 4096
_MAX_LINES: Final = 16
_SKIP_KINDS: Final = ("credential_store", "not_text", "oversize")


def load_fingerprint_key(store: Any, now: str) -> str:
    """Read (or create) the per-install secret that keys secret fingerprints.

    The native scan keys each fingerprint with it, so a stored fingerprint
    cannot be used to test guessed values without this key. It stays in the
    local store and is handed to the native process on stdin only.
    """

    existing = _stored_fingerprint_key(store)
    if existing is not None:
        return existing
    # Two first runs can race here; inserting only when absent and reading back
    # gives both the same key instead of letting the last writer replace it.
    store.insert_sync_payload_if_absent(FINGERPRINT_KEY_STATE_KEY, {"key": secrets.token_hex(32)}, now)
    stored = _stored_fingerprint_key(store)
    if stored is not None:
        return stored
    # A row that holds no usable key is replaced.
    created = secrets.token_hex(32)
    store.set_sync_payload(FINGERPRINT_KEY_STATE_KEY, {"key": created}, now)
    return created


def _stored_fingerprint_key(store: Any) -> str | None:
    raw = store.get_sync_payload(FINGERPRINT_KEY_STATE_KEY)
    existing = raw.get("key") if isinstance(raw, dict) else None
    return existing if isinstance(existing, str) and len(existing) >= 32 else None


def project_secret_findings(result: object) -> list[dict[str, object]]:
    """Return the well-formed findings of a native secret result."""

    return _projection(result)[0]


def secret_coverage(result: object) -> tuple[str, dict[str, object], list[str]]:
    """Return the detector status, a coverage summary and any truncation reasons.

    The status is the native one for a well-formed result; a missing or
    malformed result is an ``error``, and a finding that fails validation makes
    an otherwise complete scan ``incomplete``.
    """

    if not isinstance(result, Mapping) or result.get("schema") != SECRETS_RESULT_SCHEMA:
        return "error", {}, ["unreadable_result"]
    status = result.get("status")
    if status not in {"complete", "incomplete"}:
        return "error", {}, ["unreadable_result"]
    reasons = _reasons(result.get("truncation_reasons"))
    if _projection(result)[1]:
        reasons = sorted({*reasons, "invalid_finding"})
    if status == "incomplete" and not reasons:
        reasons = ["incomplete"]
    skipped = result.get("skipped")
    summary: dict[str, object] = {
        "files_scanned": _count(result.get("files_scanned")),
        "bytes_scanned": _count(result.get("bytes_scanned")),
        "skipped": {kind: _count(skipped.get(kind)) if isinstance(skipped, Mapping) else 0 for kind in _SKIP_KINDS},
        "truncation_reasons": reasons,
    }
    return ("incomplete" if reasons else "complete"), summary, reasons


def _projection(result: object) -> tuple[list[dict[str, object]], int]:
    raw = result.get("findings") if isinstance(result, Mapping) else None
    if not isinstance(raw, list):
        return [], 0
    findings = [finding for item in raw[:MAX_SECRET_FINDINGS] if (finding := _finding(item)) is not None]
    return findings, len(raw[:MAX_SECRET_FINDINGS]) - len(findings) + max(0, len(raw) - MAX_SECRET_FINDINGS)


def _finding(item: object) -> dict[str, object] | None:
    if not isinstance(item, Mapping):
        return None
    finding_id = item.get("finding_id")
    rule_id = item.get("rule_id")
    path = item.get("path")
    line = item.get("line")
    lines = item.get("lines")
    occurrences = item.get("occurrences")
    fingerprint = item.get("fingerprint")
    severity = item.get("severity")
    if (
        not isinstance(finding_id, str)
        or not _FINDING_ID.fullmatch(finding_id)
        or not isinstance(rule_id, str)
        or not _RULE_ID.fullmatch(rule_id)
        or not isinstance(path, str)
        or not path
        or len(path) > _MAX_PATH_CHARS
        or "\0" in path
        or not _is_line(line)
        or not isinstance(lines, list)
        or not 1 <= len(lines) <= _MAX_LINES
        or not all(_is_line(value) for value in lines)
        or not _is_count(occurrences)
        or not isinstance(fingerprint, str)
        or not _FINGERPRINT.fullmatch(fingerprint)
        or severity not in _SEVERITIES
    ):
        return None
    return {
        "finding_id": finding_id,
        "source_kind": "secret",
        "detector": SECRET_DETECTOR,
        "severity": severity,
        "decision": "warn",
        "ecosystem": None,
        "package_name": None,
        "package_version": None,
        "fix_version": None,
        "rule_ids": [rule_id],
        "advisory_ids": [],
        "path": path,
        "line": line,
        "lines": list(lines),
        "occurrences": occurrences,
        "fingerprint": fingerprint,
        "validation_state": "unvalidated",
        "lifecycle_state": "open",
    }


def _is_line(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 1


def _is_count(value: object) -> bool:
    return _is_line(value)


def _reasons(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    return sorted({item for item in value if isinstance(item, str) and _REASON.fullmatch(item)})


def _count(value: object) -> int:
    return value if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else 0


__all__ = [
    "MAX_SECRET_FINDINGS",
    "SECRET_DETECTOR",
    "load_fingerprint_key",
    "project_secret_findings",
    "secret_coverage",
]
