"""Guard advisory identity helpers."""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlsplit

_PACKAGE_URL_ECOSYSTEMS = {
    "npm": "npm",
    "pnpm": "npm",
    "yarn": "npm",
    "pip": "pypi",
    "uv": "pypi",
    "go": "golang",
}


@dataclass(frozen=True, slots=True)
class ProtectTargetIdentity:
    """Subset of install target data advisory matching needs."""

    artifact_id: str
    artifact_name: str
    ecosystem: str
    package_name: str | None
    package_url: str | None
    source_url: str | None


def build_package_url(ecosystem: str, package_name: str | None, version: str | None) -> str | None:
    """Build a simple purl-style identifier for registry package installs."""

    if package_name is None:
        return None
    purl_type = _PACKAGE_URL_ECOSYSTEMS.get(ecosystem)
    if purl_type is None:
        return None
    base = f"pkg:{purl_type}/{normalize_identity_value(package_name)}"
    if version is None or not version.strip():
        return base
    return f"{base}@{version.strip()}"


def advisory_matches_target(advisory: dict[str, object], target: ProtectTargetIdentity) -> bool:
    """Match advisories against install targets using stable identities first."""

    advisory_id = advisory.get("artifact_id")
    if isinstance(advisory_id, str) and advisory_id == target.artifact_id:
        return True

    advisory_ecosystem = advisory.get("ecosystem")
    if isinstance(advisory_ecosystem, str) and advisory_ecosystem not in {target.ecosystem, "*"}:
        return False

    package_url = advisory.get("package_url")
    if isinstance(package_url, str) and _package_url_matches(package_url, target.package_url):
        return True

    if _normalized_membership(advisory.get("aliases"), target.package_name, target.artifact_name):
        return True

    advisory_package = advisory.get("package") or advisory.get("name")
    normalized_advisory_package = (
        normalize_identity_value(advisory_package) if isinstance(advisory_package, str) else ""
    )
    if normalized_advisory_package != "" and normalized_advisory_package in {
        normalize_identity_value(target.package_name),
        normalize_identity_value(target.artifact_name),
    }:
        return True

    publisher = advisory.get("publisher")
    normalized_publisher = normalize_identity_value(publisher) if isinstance(publisher, str) else ""
    if normalized_publisher != "" and normalized_publisher == normalize_identity_value(target.package_name):
        return True

    if _normalized_membership(advisory.get("publisher_identities"), target.package_name):
        return True

    if _endpoint_indicator_matches(advisory.get("endpoint_indicators"), target.source_url):
        return True

    advisory_source_url = advisory.get("source_url")
    if not isinstance(advisory_source_url, str):
        return False

    normalized_advisory_source = _normalized_url_indicator(advisory_source_url)
    normalized_target_source = _normalized_url_indicator(target.source_url)
    return (
        normalized_advisory_source != ""
        and normalized_target_source != ""
        and normalized_advisory_source == normalized_target_source
    )


def normalize_identity_value(value: str | None) -> str:
    return value.strip().lower() if isinstance(value, str) and value.strip() else ""


def _normalized_membership(values: object, *candidates: str | None) -> bool:
    if not isinstance(values, list):
        return False
    normalized_values = {normalize_identity_value(item) for item in values if isinstance(item, str)}
    normalized_candidates = {normalize_identity_value(candidate) for candidate in candidates if candidate is not None}
    normalized_candidates.discard("")
    return bool(normalized_values & normalized_candidates)


def _package_url_matches(advisory_url: str, target_url: str | None) -> bool:
    if target_url is None:
        return False
    normalized_advisory = _package_url_base(advisory_url)
    normalized_target = _package_url_base(target_url)
    return normalized_advisory != "" and normalized_advisory == normalized_target


def _package_url_base(package_url: str) -> str:
    normalized = normalize_identity_value(package_url)
    for separator in ("?", "#"):
        normalized = normalized.split(separator, 1)[0]
    last_at = normalized.rfind("@")
    if last_at == -1 or last_at < normalized.rfind("/"):
        return normalized
    return normalized[:last_at]


def _endpoint_indicator_matches(values: object, source_url: str | None) -> bool:
    if source_url is None or not isinstance(values, list):
        return False
    normalized_source = _normalized_url_indicator(source_url)
    return any(
        isinstance(item, str) and _url_indicator_matches(normalized_source, _normalized_url_indicator(item))
        for item in values
    )


def _normalized_url_indicator(value: str | None) -> str:
    if value is None:
        return ""
    parsed = urlsplit(value)
    if not parsed.scheme or not parsed.netloc:
        return normalize_identity_value(value)
    path = parsed.path.rstrip("/")
    return normalize_identity_value(f"{parsed.netloc}{path}")


def _url_indicator_matches(normalized_source: str, normalized_indicator: str) -> bool:
    if normalized_source == "" or normalized_indicator == "":
        return False
    return normalized_source == normalized_indicator or normalized_source.startswith(f"{normalized_indicator}/")
