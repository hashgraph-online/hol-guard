"""Bounded extension listing metadata. Never imported by runtime enforcement."""

from __future__ import annotations

import ipaddress
import json
from functools import lru_cache
from importlib.resources import files
from pathlib import Path
from typing import cast
from urllib.parse import urlsplit

from jsonschema import Draft202012Validator, FormatChecker
from jsonschema.exceptions import ValidationError

from .errors import BuilderError
from .io import canonical_json, checked_path, parse_json, read_bytes
from .models import Metadata

LISTING_SCHEMA = "guard.extension-listing.v1"
MAX_LISTING_BYTES = 16_384
MAX_TAGLINE_LENGTH = 140
CATEGORY_LABELS = {
    "core-safety": "Core safety",
    "cloud-infrastructure": "Cloud and infrastructure",
    "data-resilience": "Data and resilience",
    "delivery-remote": "Delivery and remote operations",
    "managed-services": "Managed services",
    "package-supply-chain": "Package supply chain",
    "specialized-tools": "Specialized tools",
    "other": "Other extensions",
}
DEFAULT_LIMITATIONS = (
    "Coverage is limited to the reviewed operations and the surrounding Guard policy.",
    "A maintainer profile is not a security certification or an official upstream endorsement.",
)


@lru_cache(maxsize=1)
def listing_schema() -> dict[str, object]:
    payload = files("codex_plugin_scanner.guard.extension_builder").joinpath("listing.v1.schema.json")
    return cast(dict[str, object], json.loads(payload.read_text(encoding="utf-8")))


def _public_https(value: str) -> None:
    try:
        parsed = urlsplit(value)
        host = parsed.hostname
        if (
            parsed.scheme != "https"
            or not host
            or parsed.username is not None
            or parsed.password is not None
            or parsed.port not in (None, 443)
            or host.lower() in {"localhost", "localhost.localdomain"}
            or host.lower().endswith((".localhost", ".local", ".internal"))
            or any(ord(char) <= 32 or ord(char) == 127 for char in value)
            or "\\" in value
        ):
            raise ValueError("non-public reference")
        try:
            _ = ipaddress.ip_address(host)
        except ValueError:
            if "." not in host or host.endswith("."):
                raise ValueError("non-public host") from None
        else:
            raise ValueError("Literal IP references are not supported")
    except ValueError as exc:
        raise BuilderError("listing_url", "Listing links must use public HTTPS without credentials.") from exc


def validate_listing(payload: object, *, expected_id: str | None = None) -> dict[str, object]:
    """Validate bounded listing metadata without resolving links or performing a claim grant."""

    validator = Draft202012Validator(listing_schema(), format_checker=FormatChecker())
    try:
        validator.validate(payload)
    except (ValidationError, RecursionError) as exc:
        raise BuilderError("listing_schema", "Listing does not match the bounded publisher metadata contract.") from exc
    row = cast(dict[str, object], payload)
    if expected_id is not None and row["extensionId"] != expected_id:
        raise BuilderError("listing_identity", "Listing identity must match its native contribution and filename.")
    for value in [row["tagline"], *cast(list[str], row["limitations"])]:
        if (
            not isinstance(value, str)
            or value != value.strip()
            or any(ord(char) < 32 or ord(char) == 127 for char in value)
        ):
            raise BuilderError("listing_text", "Listing text must be trimmed, single-line plain text.")
    reference = row.get("documentationUrl")
    if isinstance(reference, str):
        _public_https(reference)
    if len(canonical_json(row).encode("utf-8")) > MAX_LISTING_BYTES:
        raise BuilderError("listing_limit", "Listing exceeds its byte budget.")
    return row


def load_listing(path: Path, *, expected_id: str) -> dict[str, object]:
    path = checked_path(path)
    if path.name != f"{expected_id}.json":
        raise BuilderError("listing_identity", "Listing filename must match the native contribution ID.")
    return validate_listing(parse_json(read_bytes(path, limit=MAX_LISTING_BYTES)), expected_id=expected_id)


def listing_template(metadata: Metadata) -> str:
    """Produce optional public listing fields without inventing publisher claim authority."""

    row: dict[str, object] = {
        "schemaVersion": LISTING_SCHEMA,
        "extensionId": metadata.contribution_id,
        "tagline": f"Reviewed operation coverage for {metadata.name}."[:MAX_TAGLINE_LENGTH].rstrip(),
        "category": "specialized-tools" if metadata.kind == "mcp" else "other",
        "limitations": list(DEFAULT_LIMITATIONS),
    }
    try:
        _public_https(metadata.homepage)
    except BuilderError:
        pass  # Optional public links cannot invalidate accepted native metadata.
    else:
        row["documentationUrl"] = metadata.homepage
    return canonical_json(validate_listing(row, expected_id=metadata.contribution_id))


def category_for_extension(extension_id: str) -> str:
    if extension_id in {
        "command.container-runtime",
        "command.data-protection",
        "command.encoded-execution",
        "command.filesystem",
        "command.git",
        "command.guard-self-protection",
        "command.kubernetes-secrets",
        "command.shell-mutations",
        "command.system",
        "command.windows",
    }:
        return "core-safety"
    if extension_id in {
        "command.api-gateway",
        "command.cdn",
        "command.dns",
        "command.infrastructure-as-code",
        "command.kubernetes-operations",
        "command.load-balancer",
    } or extension_id.startswith("command.cloud."):
        return "cloud-infrastructure"
    if extension_id.startswith(("command.backup.", "command.database.", "command.storage.")):
        return "data-resilience"
    if extension_id == "command.github" or extension_id.startswith(
        ("command.cicd.", "command.platform.", "command.remote.")
    ):
        return "delivery-remote"
    if extension_id in {
        "command.email",
        "command.feature-flags",
        "command.monitoring",
        "command.payment",
    } or extension_id.startswith(("command.messaging.", "command.search.")):
        return "managed-services"
    if extension_id.startswith("command.package."):
        return "package-supply-chain"
    if extension_id == "command.skill-sunset" or extension_id.startswith(("command.mcp-", "mcp.")):
        return "specialized-tools"
    return "other"
