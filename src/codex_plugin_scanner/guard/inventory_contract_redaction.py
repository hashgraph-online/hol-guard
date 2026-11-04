"""Inventory redaction and safe serialization of untrusted strings."""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path
from typing import cast

from . import native_inventory_url_redaction as _native_url
from .inventory_contract_constants import (
    _SENSITIVE_VALUE_RE,
    _is_sensitive_key,
)

# One native request redacts a value whose JSON text fits this budget. A larger
# dict or list is split by member, so neither the request nor the answer nears
# the resident's frame limits even when every string is escaped or redacted.
_NATIVE_VALUE_BUDGET = 128 * 1024
# Redaction can lengthen a value several times over; the answer must still fit.
_METADATA_BUDGET = 256 * 1024


def redact_local_path(path: str | Path, *, home_dir: Path | None = None) -> str:
    """Replace private absolute path prefixes while preserving useful relative identity."""
    candidate = Path(path)
    if home_dir is None:
        return candidate.name
    try:
        relative = candidate.resolve().relative_to(home_dir.resolve())
    except (OSError, RuntimeError, ValueError):
        return candidate.name
    return f"{{home}}/{relative.as_posix()}"


def redact_headers(headers: dict[str, str]) -> dict[str, str]:
    """Preserve header names while redacting credential-bearing header values."""
    return _native_url.redact_headers(list(headers))


def redact_url(value: str) -> str:
    """Remove sensitive URL credentials and query values before exporting an endpoint."""
    return _native_url.redact_url(value)


def _prefetch_export_redactions(
    artifacts: tuple[object, ...],
    cisco_runs: tuple[object, ...] = (),
    *,
    home_dir: Path,
    workspace_dir: Path | None,
) -> None:
    """Answer every redaction a snapshot export makes, in batched requests.

    The per-value redaction below then reads the pass's answers instead of
    asking the resident once per string, and each artifact's metadata is
    redacted in batches of whole artifacts rather than once per artifact.

    A value this walk misses is still redacted; it only costs its own request.
    """
    urls: list[str] = []
    paths: list[str] = []
    commands: list[str] = []
    # An MCP server's tools carry its URL and command outside the metadata.
    for artifact in artifacts:
        url = getattr(artifact, "url", None)
        if isinstance(url, str) and url:
            urls.append(url)
        command = getattr(artifact, "command", None)
        if isinstance(command, str) and command:
            commands.append(command)
    for run in cisco_runs:
        if not _is_supported_scanner_run(run):
            continue
        commands.append(_finding_command_text(str(getattr(run, "message", ""))))
        for finding in tuple(getattr(run, "findings", ()) or ()):
            commands.append(_finding_command_text(_scanner_finding_title(finding)))
            commands.append(_finding_command_text(str(getattr(finding, "description", "") or "")))
            file_path = getattr(finding, "file_path", None)
            if isinstance(file_path, str) and file_path:
                paths.append(file_path)
    _native_url.prefetch(
        urls,
        paths=paths,
        commands=commands,
        home_dir=home_dir,
        workspace_dir=workspace_dir,
    )
    _prefetch_artifact_metadata(artifacts, _native_url.roots(home_dir, workspace_dir))


def _safe_source_detail(run: object) -> str:
    """Redact source descriptions and record the resulting redaction counts."""
    status = str(getattr(run, "status", "unknown"))
    metadata = getattr(run, "metadata", {})
    finding_count = None
    if isinstance(metadata, dict):
        candidate = metadata.get("totalFindings")
        if isinstance(candidate, int):
            finding_count = candidate
    suffix = f", findings={finding_count}" if finding_count is not None else ""
    return f"status={status}{suffix}"


def _safe_finding_text(value: str, *, home_dir: Path, workspace_dir: Path | None) -> str:
    """Sanitize finding text without exposing private paths or credential values."""
    redacted = _redact_command_value(_finding_command_text(value), home_dir, workspace_dir)
    return redacted[:500]


SUPPORTED_SCANNER_SOURCES = ("cisco-mcp-scanner", "cisco-skill-scanner")
"""The scanners whose runs become inventory findings.

A run from anything else is dropped before it is redacted, so asking about its
text would be a request made for a finding that is never exported.
"""


def _is_supported_scanner_run(run: object) -> bool:
    """Whether this run's findings reach the export at all."""
    return str(getattr(run, "source", "")) in SUPPORTED_SCANNER_SOURCES


def _scanner_finding_title(finding: object) -> str:
    """The title a finding is redacted under, named once for both sides.

    A finding that carries no title is exported under a stand-in rather than an
    empty string, and the prefetch has to ask about the string the export will
    actually redact or that finding costs its own round trip.
    """
    return str(getattr(finding, "title", "") or "Cisco scanner finding")


def _finding_command_text(value: str) -> str:
    """The command string a finding's text is redacted as.

    The prefetch has to ask about the same string this does, so the one
    substitution both sides apply first lives here rather than in either.
    """
    return _SENSITIVE_VALUE_RE.sub("redacted", value)


def _safe_artifact_metadata(
    artifact: object,
    *,
    home_dir: Path,
    workspace_dir: Path | None,
) -> dict[str, object]:
    """Restrict exported artifact metadata to supported fields and sanitized values.

    The native runtime redacts every value, moves adapter-authored trust claims
    aside and adds the artifact's own fields; a pass usually has the answer.
    """
    entry, roots = _metadata_entry(artifact), _native_url.roots(home_dir, workspace_dir)
    cache = _native_url.pass_answers()
    text = cache.get(_metadata_key(entry, roots)) if cache is not None else None
    metadata = json.loads(text if isinstance(text, str) else _native_artifact_metadata([entry], roots)[0])
    if not isinstance(metadata, dict):
        raise _native_url.NativeInventoryUrlRedactionError("native_inventory_url_redaction_unavailable")
    return metadata


def _prefetch_artifact_metadata(artifacts: tuple[object, ...], roots: dict[str, str | None]) -> None:
    """Answer every artifact's metadata in requests of at most 4096 artifacts and 256 KiB."""
    cache = _native_url.pass_answers()
    if cache is None:
        return
    batches: list[list[str]] = [[]]
    size = 0
    for entry in dict.fromkeys(map(_metadata_entry, artifacts)):
        if batches[-1] and (len(batches[-1]) == 4096 or size + len(entry) > _METADATA_BUDGET):
            batches.append([])
            size = 0
        batches[-1].append(entry)
        size += len(entry)
    for batch in filter(None, batches):
        for entry, text in zip(batch, _native_artifact_metadata(batch, roots), strict=True):
            cache[_metadata_key(entry, roots)] = text


def _metadata_key(entry: str, roots: dict[str, str | None]) -> tuple[str, object]:
    return "artifact_metadata", (entry, *roots.values())


def _metadata_entry(artifact: object) -> str:
    """The artifact fields its exported metadata is built from, as JSON text that keeps key order."""
    raw = getattr(artifact, "metadata", {})
    fields = {key: getattr(artifact, key, None) for key in ("config_path", "command", "url", "transport")}
    return json.dumps(
        {
            "metadata": _wire(raw if isinstance(raw, dict) else {}),
            "artifact_type": str(getattr(artifact, "artifact_type", "unknown")),
            **{key: value if isinstance(value, str) else None for key, value in fields.items()},
        }
    )


def _wire(value: object) -> object:
    """The value as the export saw it: string keys, tuples as lists, a path as its text."""
    if isinstance(value, dict):
        return {str(key): _wire(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_wire(item) for item in value]
    return str(value) if isinstance(value, Path) else value


def _native_artifact_metadata(entries: list[str], roots: dict[str, str | None]) -> list[str]:
    texts = _native_export_redaction({"op": "artifact_metadata", **roots, "artifacts": entries}).get("metadata")
    if not isinstance(texts, list) or len(texts) != len(entries) or not all(isinstance(text, str) for text in texts):
        raise _native_url.NativeInventoryUrlRedactionError("native_inventory_url_redaction_unavailable")
    return cast("list[str]", texts)


def _redact_known_path(value: str, home_dir: Path, workspace_dir: Path | None) -> str:
    """Redact one known local path using the operator home boundary."""
    return _native_url.redact_known_path(value, home_dir, workspace_dir)


def _redact_command_value(value: str, home_dir: Path, workspace_dir: Path | None) -> str:
    """Redact path and credential values from an exported command string."""
    return _native_url.redact_command_value(value, home_dir, workspace_dir)


def _assert_serialized_inventory_payload_safe(payload: object) -> None:
    """Reject serialized inventory that still violates the export safety contract."""
    for part in _payload_parts(payload):
        answer = _native_export_redaction({"op": "assert_payload_safe", "payload": part})
        safe = answer.get("safe")
        if not isinstance(safe, bool):
            raise _native_url.NativeInventoryUrlRedactionError("native_inventory_url_redaction_unavailable")
        if not safe:
            raise ValueError("Inventory snapshot serialization produced unsafe payload.")


def _payload_parts(value: object) -> Iterator[str]:
    """JSON texts within the request budget that, checked together, check the value.

    Every match the safety patterns can make starts inside one encoded string
    and needs nothing past its closing quote: the text between strings holds
    only brackets, separators, numbers and literals, none of which a pattern
    can start in or run through. An oversized container is therefore checked
    as runs of its members, each key alone as the string JSON writes for it,
    and each part finds exactly the matches the whole text holds. A string
    over the budget goes alone, so the split always makes progress.
    """
    text = _json_text(value)
    if len(text) <= _NATIVE_VALUE_BUDGET or not isinstance(value, (dict, list, tuple)):
        yield text
        return
    members: list[object] = []
    if isinstance(value, dict):
        for key, item in value.items():
            (key_text,) = json.loads(_json_text({key: None}))
            members.extend((key_text, item))
    else:
        members.extend(value)
    batch: list[object] = []
    size = 0
    for member in members:
        member_size = len(_json_text(member)) + 2
        if member_size > _NATIVE_VALUE_BUDGET:
            yield from _payload_parts(member)
            continue
        if batch and size + member_size > _NATIVE_VALUE_BUDGET:
            yield _json_text(batch)
            batch, size = [], 0
        batch.append(member)
        size += member_size
    if batch:
        yield _json_text(batch)


def _safe_json(
    value: object,
    *,
    parent_key: str = "",
    parent_sensitive: bool = False,
) -> object:
    """Normalize metadata into bounded JSON-compatible evidence."""
    text = _json_text(value)
    if len(text) > _NATIVE_VALUE_BUDGET and isinstance(value, dict):
        key_sensitive = parent_sensitive or bool(parent_key and _is_sensitive_key(parent_key))
        projected: dict[object, object] = {}
        for key, item in value.items():
            projected[_safe_json(str(key))] = _safe_json(item, parent_key=str(key), parent_sensitive=key_sensitive)
        return projected
    if len(text) > _NATIVE_VALUE_BUDGET and isinstance(value, (list, tuple)):
        return [_safe_json(item, parent_key=parent_key, parent_sensitive=parent_sensitive) for item in value]
    answer = _native_export_redaction(
        {"op": "safe_json", "value": text, "parent_key": parent_key, "parent_sensitive": parent_sensitive}
    )
    projected_text = answer.get("value")
    if not isinstance(projected_text, str):
        raise _native_url.NativeInventoryUrlRedactionError("native_inventory_url_redaction_unavailable")
    return json.loads(projected_text)


def _json_text(value: object) -> str:
    """The value as the JSON text the native redaction reads; a path exports its name."""

    def _path_name(item: object) -> object:
        if isinstance(item, Path):
            return item.name
        raise TypeError(f"Object of type {type(item).__name__} is not JSON serializable")

    return json.dumps(value, default=_path_name)


def _native_export_redaction(args: dict[str, object]) -> dict[str, object]:
    """Ask the native runtime for one export redaction answer."""
    from .native_runner_authority import NativeRunnerAuthorityError, native_runner_authority

    try:
        return native_runner_authority("inventory_export_redaction", args)
    except (NativeRunnerAuthorityError, KeyError, TypeError) as error:
        raise _native_url.NativeInventoryUrlRedactionError("native_inventory_url_redaction_unavailable") from error
