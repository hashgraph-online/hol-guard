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


def redact_value(value: Any, replacements: dict[str, str]) -> Any:
    """Apply the same redactions to host and Guard evidence."""
    if isinstance(value, str):
        for old, new in sorted(replacements.items(), key=lambda item: -len(item[0])):
            value = value.replace(old, new)
        return value
    if isinstance(value, list):
        return [redact_value(item, replacements) for item in value]
    if isinstance(value, dict):
        return {key: redact_value(item, replacements) for key, item in value.items()}
    return value


def input_digest(value: dict) -> str:
    """Hash canonical public input bytes independently of insertion order."""
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def public_observations(rows: list[dict], replacements: dict[str, str]) -> list[dict]:
    """Check original observer bytes before exporting comparable public inputs."""
    result = []
    for row in rows:
        if row.get("observer_error") or row.get("transport_error"):
            result.append(row)
            continue
        raw = row.get("input_json")
        if not isinstance(raw, str) or len(raw.encode("utf-8")) > 256_000:
            raise ValueError("missing or oversized original Guard input")
        observed_digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()
        if observed_digest != row.get("input_sha256"):
            raise ValueError("original Guard input does not match its observed digest")
        value = json.loads(raw)
        if not isinstance(value, dict):
            raise ValueError("Guard input must be a complete object")
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


def post_input_matches(tool: str, reviewed: dict[str, Any], completed: dict[str, Any]) -> bool:
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


def public_native_receipt(receipt: object, replacements: dict[str, str]) -> dict[str, Any] | None:
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


def public_native_extension_evidence(edge: object, replacements: dict[str, str]) -> dict[str, Any] | None:
    """Export bounded full observations from an independent native expectation probe."""
    if not isinstance(edge, dict):
        return None
    result = edge.get("result")
    if not isinstance(result, dict) or not isinstance(result.get("command_extensions"), dict):
        return None
    return redact_value(result["command_extensions"], replacements)
