"""Inventory redaction and safe serialization of untrusted strings."""

from __future__ import annotations

import json
from pathlib import Path

from . import native_inventory_url_redaction as _native_url
from .inventory_contract_constants import (
    _SAFE_SERIALIZED_MARKERS,
    _SENSITIVE_VALUE_RE,
    _SERIALIZER_REDACTED_VALUE,
    _SERIALIZER_SECRET_ASSIGNMENT_RE,
    _SERIALIZER_UNSAFE_PATH_RE,
    _is_sensitive_key,
)


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


def classify_endpoint_host(value: str | None) -> str:
    """Classify an endpoint host without making a network request."""
    return _native_url.classify_endpoint_host(value)


def _prefetch_export_redactions(
    artifacts: tuple[object, ...],
    cisco_runs: tuple[object, ...] = (),
    *,
    home_dir: Path,
    workspace_dir: Path | None,
) -> None:
    """Answer every redaction a snapshot export makes, in batched requests.

    The per-value redaction below then reads the pass's answers instead of
    asking the resident once per string. Paths dominate that count: every
    metadata string that is not a URL is offered to the resident as a path, so
    batching only the URLs left the walk one round trip per string.

    A value this walk misses is still redacted; it only costs its own request.
    """
    urls: list[str] = []
    hosts: list[str] = []
    paths: list[str] = []
    commands: list[str] = []
    for artifact in artifacts:
        url = getattr(artifact, "url", None)
        if isinstance(url, str) and url:
            urls.append(url)
            hosts.append(url)
        config_path = getattr(artifact, "config_path", None)
        if isinstance(config_path, str) and config_path:
            paths.append(config_path)
        command = getattr(artifact, "command", None)
        if isinstance(command, str) and command:
            commands.append(command)
        _collect_metadata_values(getattr(artifact, "metadata", None), urls, paths)
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
        hosts,
        paths=paths,
        commands=commands,
        home_dir=home_dir,
        workspace_dir=workspace_dir,
    )


def _collect_metadata_values(value: object, urls: list[str], paths: list[str]) -> None:
    """Gather the strings ``_sanitize_paths`` will redact, by how it redacts them.

    This mirrors that walk exactly, including the sensitive keys it replaces
    without asking: a value gathered here that the walk never reaches would be
    a request made for nothing, and one it reaches but this misses is the
    unbatched round trip this exists to avoid.
    """
    if isinstance(value, Path):
        paths.append(str(value))
    elif isinstance(value, dict):
        for key, item in value.items():
            if not _is_sensitive_key(str(key)):
                _collect_metadata_values(item, urls, paths)
    elif isinstance(value, (list, tuple)):
        for item in value:
            _collect_metadata_values(item, urls, paths)
    elif isinstance(value, str):
        if "://" in value:
            urls.append(value)
        else:
            paths.append(value)


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
    """Restrict exported artifact metadata to supported fields and sanitized values."""
    artifact_type = str(getattr(artifact, "artifact_type", "unknown"))
    raw_metadata = getattr(artifact, "metadata", {})
    metadata = _sanitize_paths(raw_metadata if isinstance(raw_metadata, dict) else {}, home_dir, workspace_dir)
    if not isinstance(metadata, dict):
        metadata = {}
    from .trust_metadata_boundary import separate_untrusted_adapter_trust_metadata

    metadata = separate_untrusted_adapter_trust_metadata(metadata)
    config_path = getattr(artifact, "config_path", None)
    command = getattr(artifact, "command", None)
    url = getattr(artifact, "url", None)
    transport = getattr(artifact, "transport", None)
    if isinstance(config_path, str) and config_path:
        metadata["configPath"] = _redact_known_path(config_path, home_dir, workspace_dir)
    if isinstance(command, str) and command:
        metadata["command"] = _redact_command_value(command, home_dir, workspace_dir)
    if isinstance(url, str) and url:
        metadata["url"] = redact_url(url)
        metadata["endpointHostClass"] = classify_endpoint_host(url)
    if isinstance(transport, str) and transport:
        metadata["transport"] = transport
    metadata["artifactType"] = artifact_type
    return metadata


def _sanitize_paths(value: object, home_dir: Path, workspace_dir: Path | None) -> object:
    """Recursively sanitize private path values in supported metadata structures."""
    if isinstance(value, Path):
        return _redact_known_path(str(value), home_dir, workspace_dir)
    if isinstance(value, dict):
        redacted: dict[str, object] = {}
        for key, item in value.items():
            string_key = str(key)
            if _is_sensitive_key(string_key):
                redacted[string_key] = item if isinstance(item, bool) else "present_redacted"
                continue
            redacted[string_key] = _sanitize_paths(item, home_dir, workspace_dir)
        return redacted
    if isinstance(value, (list, tuple)):
        return [_sanitize_paths(item, home_dir, workspace_dir) for item in value]
    if isinstance(value, str):
        if "://" in value:
            return redact_url(value)
        return _redact_known_path(value, home_dir, workspace_dir)
    return value


def _redact_known_path(value: str, home_dir: Path, workspace_dir: Path | None) -> str:
    """Redact one known local path using the operator home boundary."""
    return _native_url.redact_known_path(value, home_dir, workspace_dir)


def _redact_command_value(value: str, home_dir: Path, workspace_dir: Path | None) -> str:
    """Redact path and credential values from an exported command string."""
    return _native_url.redact_command_value(value, home_dir, workspace_dir)


def _sanitize_serializer_string(
    value: str,
    *,
    parent_key: str = "",
    parent_sensitive: bool = False,
) -> str:
    """Apply final string redaction before inventory serialization."""
    if value in _SAFE_SERIALIZED_MARKERS:
        return value
    if parent_sensitive or (parent_key and _is_sensitive_key(parent_key)):
        return _SERIALIZER_REDACTED_VALUE
    if _SERIALIZER_UNSAFE_PATH_RE.search(value):
        return _SERIALIZER_REDACTED_VALUE
    if _SENSITIVE_VALUE_RE.search(value):
        return _SERIALIZER_REDACTED_VALUE
    if _SERIALIZER_SECRET_ASSIGNMENT_RE.search(value):
        return _SERIALIZER_REDACTED_VALUE
    return value


def _assert_serialized_inventory_payload_safe(payload: object) -> None:
    """Reject serialized inventory that still violates the export safety contract."""
    encoded = json.dumps(payload, sort_keys=True)
    if (
        _SERIALIZER_UNSAFE_PATH_RE.search(encoded)
        or _SENSITIVE_VALUE_RE.search(encoded)
        or _SERIALIZER_SECRET_ASSIGNMENT_RE.search(encoded)
    ):
        raise ValueError("Inventory snapshot serialization produced unsafe payload.")


def _safe_json(
    value: object,
    *,
    parent_key: str = "",
    parent_sensitive: bool = False,
) -> object:
    """Normalize metadata into bounded JSON-compatible evidence."""
    key_sensitive = parent_sensitive or bool(parent_key and _is_sensitive_key(parent_key))
    if isinstance(value, dict):
        return {
            _sanitize_serializer_string(str(key)): _safe_json(
                item,
                parent_key=str(key),
                parent_sensitive=key_sensitive,
            )
            for key, item in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [_safe_json(item, parent_key=parent_key, parent_sensitive=parent_sensitive) for item in value]
    if isinstance(value, Path):
        return value.name
    if isinstance(value, str):
        return _sanitize_serializer_string(
            value,
            parent_key=parent_key,
            parent_sensitive=parent_sensitive,
        )
    return value
