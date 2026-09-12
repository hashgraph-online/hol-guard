"""Inventory redaction and safe serialization of untrusted strings."""

from __future__ import annotations

import ipaddress
import json
import re
from pathlib import Path
from typing import Literal
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from .inventory_contract_constants import (
    _SAFE_SERIALIZED_MARKERS,
    _SENSITIVE_KEY_RE,
    _SENSITIVE_VALUE_RE,
    _SERIALIZER_REDACTED_VALUE,
    _SERIALIZER_SECRET_ASSIGNMENT_RE,
    _SERIALIZER_UNSAFE_PATH_RE,
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
    return {key.lower(): "present_redacted" if _SENSITIVE_KEY_RE.search(key) else "present" for key in headers}


def redact_url(value: str) -> str:
    """Remove sensitive URL credentials and query values before exporting an endpoint."""
    try:
        parsed = urlsplit(value)
    except ValueError:
        return "malformed_url_redacted"
    hostname = parsed.hostname or ""
    if ":" in hostname and not hostname.startswith("["):
        hostname = f"[{hostname}]"
    netloc = hostname
    try:
        port = parsed.port
    except ValueError:
        port = None
    if port is not None:
        netloc = f"{netloc}:{port}"
    redacted_pairs = [
        (key, "redacted" if _SENSITIVE_KEY_RE.search(key) else item)
        for key, item in parse_qsl(parsed.query.replace(";", "&"), keep_blank_values=True)
    ]
    return urlunsplit((parsed.scheme, netloc, parsed.path, urlencode(redacted_pairs), parsed.fragment))


def classify_endpoint_host(value: str | None) -> Literal["none", "local_loopback", "local_private", "remote_public"]:
    """Classify an endpoint host without making a network request."""
    if not value:
        return "none"
    try:
        parsed = urlsplit(value)
    except ValueError:
        return "remote_public"
    host = (parsed.hostname or "").lower()
    if host in {"localhost", "127.0.0.1", "::1"}:
        return "local_loopback"
    try:
        if ipaddress.ip_address(host).is_private:
            return "local_private"
    except ValueError:
        pass
    return "remote_public"


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
    redacted = _SENSITIVE_VALUE_RE.sub("redacted", value)
    redacted = _redact_command_value(redacted, home_dir, workspace_dir)
    return redacted[:500]


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
            if _SENSITIVE_KEY_RE.search(string_key):
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
    path = Path(value)
    if path.is_absolute():
        home_redacted = redact_local_path(path, home_dir=home_dir)
        if home_redacted.startswith("{home}/"):
            return home_redacted
        if workspace_dir is not None:
            try:
                relative = path.resolve().relative_to(workspace_dir.resolve())
                return f"{{workspace}}/{relative.as_posix()}"
            except (OSError, RuntimeError, ValueError):
                return path.name
        return path.name
    return value


def _redact_command_value(value: str, home_dir: Path, workspace_dir: Path | None) -> str:
    """Redact path and credential values from an exported command string."""
    redacted = re.sub(
        r"(?i)\b[a-z][a-z0-9+.-]*://[^\s]+",
        lambda match: redact_url(match.group(0)),
        value,
    )
    redacted = re.sub(
        r"(^|\s)(/[^\s]+)",
        lambda match: f"{match.group(1)}{_redact_known_path(match.group(2), home_dir, workspace_dir)}",
        redacted,
    )
    redacted = re.sub(
        r"(?i)(authorization:\s*bearer\s+)\S+",
        r"\1redacted",
        redacted,
    )
    redacted = re.sub(
        r"(?i)((?:api[_-]?key|auth|password|secret|token)=)\S+",
        r"\1redacted",
        redacted,
    )
    redacted = re.sub(
        r"(?i)((?:--)?(?:api[_-]?key|auth|password|secret|token)\s+)\S+",
        r"\1redacted",
        redacted,
    )
    return redacted


def _sanitize_serializer_string(
    value: str,
    *,
    parent_key: str = "",
    parent_sensitive: bool = False,
) -> str:
    """Apply final string redaction before inventory serialization."""
    if value in _SAFE_SERIALIZED_MARKERS:
        return value
    if parent_sensitive or (parent_key and _SENSITIVE_KEY_RE.search(parent_key)):
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
    key_sensitive = parent_sensitive or bool(parent_key and _SENSITIVE_KEY_RE.search(parent_key))
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
