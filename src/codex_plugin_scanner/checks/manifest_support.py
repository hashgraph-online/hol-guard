"""Manifest helper constants and functions."""

from __future__ import annotations

import re
from pathlib import Path

from ..models import Finding, Severity
from ..path_support import is_safe_relative_path

RECOMMENDED_FIELDS = ("author", "homepage", "repository", "license", "keywords")
INTERFACE_METADATA_FIELDS = ("displayName", "shortDescription", "longDescription", "developerName", "category")
INTERFACE_URL_FIELDS = ("websiteURL", "privacyPolicyURL", "termsOfServiceURL")
INTERFACE_ASSET_FIELDS = ("composerIcon", "logo")
HEX_COLOR_RE = re.compile(r"^#[0-9A-Fa-f]{6}$")


def manifest_finding(
    rule_id: str,
    title: str,
    description: str,
    remediation: str,
    *,
    severity: Severity = Severity.MEDIUM,
) -> Finding:
    return Finding(
        rule_id=rule_id,
        severity=severity,
        category="manifest-validation",
        title=title,
        description=description,
        remediation=remediation,
        file_path=".codex-plugin/plugin.json",
    )


def load_interface(manifest: dict | None) -> dict | None:
    if manifest is None:
        return None
    interface = manifest.get("interface")
    if interface is None:
        return None
    if isinstance(interface, dict):
        return interface
    return {}


def is_https_url(value: object) -> bool:
    return isinstance(value, str) and value.startswith("https://")


def interface_asset_paths(value: object) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [item for item in value if isinstance(item, str)]
    return []


def safe_manifest_path(plugin_dir: Path, value: str, *, require_exists: bool = False) -> bool:
    return is_safe_relative_path(plugin_dir, value, require_prefix=True, require_exists=require_exists)
