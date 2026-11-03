"""Bind actual tool inputs to observed Guard requests, with shared public redactions."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any


def fixture_path_aliases(replacements: dict[str, str]) -> dict[str, str]:
    """Redact macOS display aliases only when they resolve to the same fixture path."""
    result = dict(replacements)
    for original, placeholder in replacements.items():
        if re.fullmatch(r"[A-Za-z]:\\.+", original):
            # Git for Windows prints the same drive path with forward slashes.
            result[original.replace("\\", "/")] = placeholder
            continue
        path = Path(original)
        if path.parts[:2] != ("/", "private") or len(path.parts) < 3 or path.parts[2] not in {"tmp", "var"}:
            continue
        alias = original.removeprefix("/private")
        try:
            if Path(alias).resolve(strict=True) == path.resolve(strict=True):
                result[alias] = placeholder
        except OSError:
            continue
    return result


Redaction = str | re.Pattern[str]


def _redaction_order(item: tuple[Redaction, str]) -> tuple[int, int]:
    """Hide credentials before paths, and the longest spelling of each before its prefixes."""
    matcher = item[0]
    if isinstance(matcher, re.Pattern):
        return (0, -len(matcher.pattern))
    return (1, -len(matcher))


def redact_value(value: Any, replacements: dict[Redaction, str]) -> Any:
    """Apply the same redactions to host and Guard evidence.

    A plain key is replaced literally. A compiled one stands for a secret the
    transcript may have folded or re-encoded, and is substituted through a
    function so its placeholder is never read as a backreference.

    A mapping is rewritten on both sides. A tool that reports per-path or
    per-token results names them in its property names, so a secret reaches the
    export as readably from a key as from a value, and a path alias belongs on
    a key for the same reason.
    """
    if isinstance(value, str):
        for old, new in sorted(replacements.items(), key=_redaction_order):
            if isinstance(old, re.Pattern):
                value = old.sub(lambda _match, text=new: text, value)
            else:
                value = value.replace(old, new)
        return value
    if isinstance(value, list):
        return [redact_value(item, replacements) for item in value]
    if isinstance(value, dict):
        return {redact_value(key, replacements): redact_value(item, replacements) for key, item in value.items()}
    return value


def input_digest(value: dict) -> str:
    """Hash canonical public input bytes independently of insertion order."""
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _unverified_row(row: dict, code: str) -> dict:
    """Keep an unverifiable observation as a failed attempt with its cause."""
    kept = {key: row[key] for key in ("event", "tool", "tool_call_id", "elapsed_ms", "http_status") if key in row}
    return {**kept, "observer_error": True, "observer_error_code": code}


def public_observations(rows: list[dict], replacements: dict[Redaction, str]) -> list[dict]:
    """Check original observer bytes before exporting comparable public inputs.

    A row whose input cannot be verified becomes an observer error naming the
    check it failed. The judge counts it as a failed attempt, and the other
    rows of the case stay available.
    """
    result = []
    for row in rows:
        # A discarded bridge reply is retried by the extension. It is not a
        # Guard answer, and leaving it in the case fails the retry that recovered.
        if row.get("observer_error_code") == "bridge_no_reply":
            continue
        if row.get("observer_error") or row.get("transport_error"):
            result.append(row)
            continue
        raw = row.get("input_json")
        if not isinstance(raw, str) or len(raw.encode("utf-8")) > 256_000:
            result.append(_unverified_row(row, "input_missing_or_oversized"))
            continue
        observed_digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()
        if observed_digest != row.get("input_sha256"):
            result.append(_unverified_row(row, "input_digest_mismatch"))
            continue
        try:
            value = json.loads(raw)
        except ValueError:
            value = None
        if not isinstance(value, dict):
            result.append(_unverified_row(row, "input_not_object"))
            continue
        public_input = redact_value(value, replacements)
        public_row = {key: item for key, item in row.items() if key not in {"input_json", "input_sha256"}}
        public_row.update(
            input=public_input,
            input_sha256=input_digest(public_input),
            observed_input_sha256=observed_digest,
        )
        result.append(public_row)
    return result


def input_matches(tool: str, executed: dict, reviewed: dict) -> bool:
    """Accept identity or the pinned OMP adapter's derived edit-path metadata."""
    expected = {key: value for key, value in executed.items() if key not in {"i", "intent"}}
    actual = {key: value for key, value in reviewed.items() if key not in {"i", "intent"}}
    if expected == actual:
        return True
    if tool != "edit":
        return False
    target = expected.get("path", expected.get("file_path"))
    patch = expected.get("input")
    if isinstance(patch, str):
        headers = [header.strip(" \t") for header in re.findall(r"^\[([^\n]+)#[0-9A-Fa-f]{4}\]$", patch, re.MULTILINE)]
        if len(headers) != 1 or (target is not None and target != headers[0]):
            return False
        target = headers[0]
    if not isinstance(target, str) or not target:
        return False
    enriched = {**expected, "path": target, "paths": [target]}
    if any(key in expected and expected[key] != enriched[key] for key in ("path", "paths")):
        return False
    return actual == enriched


def post_input_matches(tool: str, reviewed: dict[str, Any], completed: dict[str, Any], result: Any = None) -> bool:
    """Bind resolved read paths without accepting a different target or read options."""
    if reviewed == completed:
        return True
    if tool != "read" or set(reviewed) != set(completed):
        return False
    path_keys = set(reviewed) & {"path", "file_path"}
    if len(path_keys) != 1:
        return False
    key = path_keys.pop()
    original, resolved = reviewed[key], completed[key]
    if not isinstance(original, str) or not isinstance(resolved, str):
        return False
    # A bare `:raw` returns the whole file without line formatting, so its
    # result must still prove the same resolved source from the first line.
    selector = re.fullmatch(r"(.+):(?:([1-9][0-9]*)(?:-([1-9][0-9]*))?|raw)", original)
    if selector:
        base, first, last = selector.groups()
        first = first or "1"
        if last is not None and int(last) < int(first):
            return False
        details = result.get("details") if isinstance(result, dict) else None
        if not isinstance(details, dict):
            return False
        meta, display = details.get("meta"), details.get("displayContent")
        source = meta.get("source") if isinstance(meta, dict) else None
        if (
            not isinstance(source, dict)
            or source != {"type": "path", "value": resolved}
            or not isinstance(display, dict)
            or display.get("startLine") != int(first)
        ):
            return False
        # The actual SDK result proves it resolved a selector rather than read
        # a literal colon-named file. Guard alone cannot supply that proof.
        original = base
    # Windows agents resolve with backslash separators. Accept them only when
    # the whole resolved path is in that form and the reviewed path has no
    # backslash, so a POSIX name containing one never matches a different file.
    if resolved.startswith(("{{workspace}}\\", "{{home}}\\")) and "/" not in resolved:
        if "\\" in original:
            return False
        resolved = resolved.replace("\\", "/")
    if original.startswith("~/"):
        expected = "{{home}}/" + original[2:]
    elif original.startswith(("/", "{{")):
        expected = original
    else:
        expected = "{{workspace}}/" + original.removeprefix("./")
    if any(part in {".", "..", ""} for part in expected.split("/")[1:]):
        return False
    return resolved == expected and all(completed[other] == reviewed[other] for other in reviewed if other != key)


def public_native_receipt(receipt: object, replacements: dict[Redaction, str]) -> dict[str, Any] | None:
    """Keep only safe native denial metadata and structured extension binding."""
    if not isinstance(receipt, dict):
        return None
    selected = {
        key: receipt[key]
        for key in (
            "schema",
            "version",
            "authority",
            "decision_id",
            "request_id",
            "harness",
            "event_name",
            "payload_kind",
            "decision",
            "policy_action",
            "observed_policy_action",
            "reason_code",
            "command_extensions",
        )
        if key in receipt
    }
    return redact_value(selected, replacements)


def public_native_extension_evidence(edge: object, replacements: dict[Redaction, str]) -> dict[str, Any] | None:
    """Export bounded full observations from an independent native expectation probe."""
    if not isinstance(edge, dict):
        return None
    result = edge.get("result")
    if not isinstance(result, dict) or not isinstance(result.get("command_extensions"), dict):
        return None
    return redact_value(result["command_extensions"], replacements)
