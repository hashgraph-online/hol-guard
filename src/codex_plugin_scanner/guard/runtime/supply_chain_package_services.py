"""Retained package-request services for the local supply-chain evaluator.

Cloud-adjacent service work extracted from ``supply_chain_package_eval``:
registry metadata lookups, tarball download/inspection, request-payload and
workspace-fingerprint construction, lockfile context, and Guard Cloud
evaluate-URL normalization. Services use explicit library dependencies and an
injected lockfile parser; they never import the evaluator or borrow its namespace.
"""

from __future__ import annotations

import json
import time
import urllib.parse
import urllib.request
from pathlib import Path
from typing import TYPE_CHECKING

from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.version import InvalidVersion, Version

from ..models import GuardArtifact
from ..native_archive_inspection import inspect_archive_native
from ..stable_digest import stable_digest_hex
from .js_semver import highest_js_version_for_selector
from .lockfile_evaluation_support import LockfileTextParser
from .lockfile_parse_result import LOCKFILE_PARSER_VERSION
from .restricted_archive_download import (
    RestrictedArchiveDownload,
    RestrictedArchiveFailure,
    download_restricted_archive,
)
from .runner import _normalized_receipts_sync_url, _urlopen_json_with_timeout_retry
from .supply_chain_package_identity import PackageIdentityError, normalize_qualified_package_name
from .workspace_path_guard import (
    read_bytes_within_workspace,
    read_text_within_workspace,
    resolve_path_within_workspace,
)

if TYPE_CHECKING:
    from .restricted_archive_download import RestrictedArchiveDownloadResult

_NPM_REGISTRY_METADATA_BASE_URL = "https://registry.npmjs.org"
_PYPI_REGISTRY_METADATA_BASE_URL = "https://pypi.org/pypi"
_TARBALL_SCAN_TIMEOUT_SECONDS = 2
_TARBALL_SCAN_MAX_BYTES = 6 * 1024 * 1024
_TARBALL_SCAN_MAX_FILES = 500
_TARBALL_SCAN_MAX_PACKAGE_JSON_BYTES = 256 * 1024
_TIMEOUT_SECONDS = 1
_RETRY_TIMEOUT_SECONDS = 1


def _hash_paths(workspace_dir: Path | None, raw_paths: object) -> list[str]:
    if workspace_dir is None or not isinstance(raw_paths, list):
        return []
    hashes: list[str] = []
    for item in raw_paths:
        payload = read_bytes_within_workspace(workspace_dir, str(item))
        if payload is None:
            continue
        hashes.append(stable_digest_hex(payload))
    return hashes


def _stable_hash(value: object) -> str:
    return stable_digest_hex(json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8"))


def _string_tuple(value: object) -> tuple[str, ...]:
    if not isinstance(value, (list, tuple)):
        return ()
    return tuple(item for item in value if isinstance(item, str))


def _optional_string(value: object) -> str | None:
    if isinstance(value, str) and value.strip():
        return value.strip()
    return None


def _normalize_package_name(ecosystem: str, package_name: str) -> str:
    try:
        return normalize_qualified_package_name(ecosystem, package_name)
    except PackageIdentityError:
        return package_name.strip()


def _workspace_fingerprint(
    workspace_id: str,
    *,
    workspace_dir: Path | None,
    artifact: GuardArtifact,
    bundle_meta: dict[str, str] | None,
) -> str:
    manifest_hashes = _hash_paths(workspace_dir, artifact.metadata.get("manifest_paths"))
    lockfile_hashes = _hash_paths(workspace_dir, artifact.metadata.get("lockfile_paths"))
    return _stable_hash(
        {
            "workspace_id": workspace_id,
            "workspace_name": workspace_dir.name if workspace_dir is not None else None,
            "manifest_hashes": manifest_hashes,
            "lockfile_hashes": lockfile_hashes,
            "lockfile_parser_version": LOCKFILE_PARSER_VERSION,
            "bundle_policy_hash": bundle_meta["policy_hash"] if bundle_meta is not None else None,
        }
    )


def _build_request_payload(
    *,
    artifact: GuardArtifact,
    targets: tuple[dict[str, object], ...],
    workspace_dir: Path | None,
    workspace_fingerprint: str,
    policy_version: str,
    parse_text_result: LockfileTextParser,
) -> dict[str, object]:
    lockfile_context = _lockfile_context(workspace_dir, artifact, parse_text_result=parse_text_result)
    payload: dict[str, object] = {
        "commandShape": {
            "argCount": len(str(artifact.metadata.get("redacted_command") or "").split()),
            "flags": list(_string_tuple(artifact.metadata.get("flags"))),
            "packageManager": str(artifact.metadata.get("package_manager") or "unknown"),
            "redacted": True,
            "verb": str(artifact.metadata.get("intent_kind") or "install"),
        },
        "harness": artifact.harness,
        "packages": [
            {
                "direct": True,
                "ecosystem": str(target["ecosystem"]),
                "name": str(target["name"]),
                "namespace": target["namespace"],
                **(
                    {"sourceUrl": str(target.get("source_redacted") or target["source_url"])}
                    if target.get("source_url")
                    else {}
                ),
                **({"sourceIdentity": str(target["source_identity"])} if target.get("source_identity") else {}),
                **({"version": str(target["version"])} if target.get("version") else {}),
                **({"range": str(target["range"])} if target.get("range") else {}),
            }
            for target in targets
        ],
        "policyVersion": policy_version,
        "workspaceFingerprint": workspace_fingerprint,
    }
    if lockfile_context is not None:
        # Guard Cloud zod schemas use .optional() (undefined), not .nullable().
        # Explicit nulls (common when a lockfile exists without a package.json) make
        # evaluate return HTTP 400 and fail-closed block paid/connected installs.
        payload["lockfileContext"] = {
            key: value
            for key in ("dependencyCount", "fileName", "lockfileHash", "manifestHash", "repository")
            if (value := lockfile_context.get(key)) is not None
        }
    return payload


def _lockfile_context(
    workspace_dir: Path | None,
    artifact: GuardArtifact,
    *,
    parse_text_result: LockfileTextParser,
) -> dict[str, object] | None:
    if workspace_dir is None:
        return None
    lockfile_paths = artifact.metadata.get("lockfile_paths")
    if not isinstance(lockfile_paths, list) or not lockfile_paths:
        return None
    lockfile_path = resolve_path_within_workspace(workspace_dir, str(lockfile_paths[0]))
    if lockfile_path is None or not lockfile_path.exists():
        return None
    if lockfile_path.name.lower() == "bun.lockb":
        return None
    lockfile_text = read_text_within_workspace(workspace_dir, str(lockfile_paths[0]))
    if lockfile_text is None:
        return None
    parse_result = parse_text_result(lockfile_path.name, lockfile_text)
    if not parse_result.complete:
        return {
            "dependencyCount": 0,
            "fileName": lockfile_path.name,
            "lockfileHash": parse_result.source_hash,
            "lockfileParserVersion": parse_result.parser_version,
            "parseComplete": False,
            "parseError": parse_result.error_reason,
        }
    manifest_hashes = _hash_paths(workspace_dir, artifact.metadata.get("manifest_paths"))
    return {
        "dependencyCount": len(parse_result.entries),
        "fileName": lockfile_path.name,
        "lockfileHash": parse_result.source_hash,
        "lockfileParserVersion": parse_result.parser_version,
        "manifestHash": manifest_hashes[0] if manifest_hashes else None,
        "parseComplete": True,
        "repository": workspace_dir.name,
    }


def _scan_external_tarball(
    source_url: str,
    *,
    retain_download: bool = False,
    request_deadline: float | None = None,
    guard_home: Path,
) -> tuple[dict[str, str] | None, RestrictedArchiveDownload | None]:
    download_timeout = _TARBALL_SCAN_TIMEOUT_SECONDS
    if request_deadline is not None:
        remaining = request_deadline - time.monotonic()
        if remaining <= 0:
            return _external_archive_request_timeout_result(), None
        download_timeout = min(download_timeout, remaining)
    downloaded = _download_external_tarball(source_url, timeout_seconds=download_timeout)
    if isinstance(downloaded, RestrictedArchiveFailure):
        return (
            {
                "decision": "block",
                "code": downloaded.code,
                "message": downloaded.message,
                "severity": "high",
            },
            None,
        )
    if not isinstance(downloaded, RestrictedArchiveDownload):
        return None, None
    retain_blob = False
    try:
        inspection_timeout = _TARBALL_SCAN_TIMEOUT_SECONDS
        if request_deadline is not None:
            # The inspector parent reserves a 0.5s termination grace after its
            # child's own deadline; include that grace in the request budget.
            remaining = request_deadline - time.monotonic() - 0.5
            if remaining <= 0:
                return _external_archive_request_timeout_result(), None
            inspection_timeout = min(inspection_timeout, remaining)
        inspection = inspect_archive_native(
            downloaded.path,
            expected_sha256=downloaded.sha256,
            state_dir=guard_home,
            timeout_seconds=inspection_timeout,
            max_archive_bytes=_TARBALL_SCAN_MAX_BYTES,
            max_files=_TARBALL_SCAN_MAX_FILES,
            max_package_json_bytes=_TARBALL_SCAN_MAX_PACKAGE_JSON_BYTES,
        )
        if inspection.status != "clean":
            return (
                {
                    "decision": "block",
                    "code": inspection.code,
                    "message": inspection.message,
                    "severity": inspection.severity,
                },
                None,
            )
        retain_blob = retain_download
        return (
            {
                "decision": "ask",
                "code": "external_tarball_source",
                "message": "External tarball source requires review before any archive download.",
                "severity": "medium",
            },
            downloaded if retain_blob else None,
        )
    finally:
        if not retain_blob:
            downloaded.cleanup()


def _external_archive_request_timeout_result() -> dict[str, str]:
    return {
        "decision": "block",
        "code": "external_archive_request_timeout",
        "message": "External archive request exceeded Guard's aggregate time limit.",
        "severity": "high",
    }


def _download_external_tarball(
    source_url: str,
    *,
    timeout_seconds: float = _TARBALL_SCAN_TIMEOUT_SECONDS,
) -> RestrictedArchiveDownloadResult:
    return download_restricted_archive(
        source_url,
        max_bytes=_TARBALL_SCAN_MAX_BYTES,
        timeout_seconds=timeout_seconds,
    )


def _registry_resolved_target_version(*, target: dict[str, object], requested_range: str) -> str | None:
    ecosystem = _optional_string(target.get("ecosystem")) or "npm"
    if _optional_string(target.get("source_url")) is not None:
        return None
    package_name = _registry_package_name(target)
    if package_name is None:
        return None
    if ecosystem == "npm":
        return _npm_registry_resolved_version(package_name=package_name, requested_range=requested_range)
    if ecosystem == "pypi":
        normalized_name = _normalize_package_name("pypi", package_name)
        return _pypi_registry_resolved_version(package_name=normalized_name, requested_range=requested_range)
    return None


def _registry_package_name(target: dict[str, object]) -> str | None:
    package_name = _optional_string(target.get("name"))
    if package_name is None:
        return None
    namespace = _optional_string(target.get("namespace"))
    return f"{namespace}/{package_name}" if namespace is not None else package_name


def _npm_registry_resolved_version(*, package_name: str, requested_range: str) -> str | None:
    metadata_url = f"{_NPM_REGISTRY_METADATA_BASE_URL.rstrip('/')}/{urllib.parse.quote(package_name, safe='')}"
    request = urllib.request.Request(
        metadata_url,
        headers={
            "Accept": "application/vnd.npm.install-v1+json",
            "User-Agent": "hol-guard-local",
        },
    )
    try:
        payload = _urlopen_json_with_timeout_retry(
            request=request,
            timeout_seconds=_TIMEOUT_SECONDS,
            retry_timeout_seconds=_RETRY_TIMEOUT_SECONDS,
        )
    except (OSError, RuntimeError, ValueError):
        return None
    versions_payload = payload.get("versions")
    if not isinstance(versions_payload, dict):
        return None
    versions = [version for version in versions_payload if isinstance(version, str)]
    if not versions:
        return None
    return highest_js_version_for_selector(versions, requested_range)


def _pypi_registry_resolved_version(*, package_name: str, requested_range: str) -> str | None:
    metadata_url = f"{_PYPI_REGISTRY_METADATA_BASE_URL.rstrip('/')}/{urllib.parse.quote(package_name, safe='')}/json"
    request = urllib.request.Request(
        metadata_url,
        headers={
            "Accept": "application/json",
            "User-Agent": "hol-guard-local",
        },
    )
    try:
        payload = _urlopen_json_with_timeout_retry(
            request=request,
            timeout_seconds=_TIMEOUT_SECONDS,
            retry_timeout_seconds=_RETRY_TIMEOUT_SECONDS,
        )
    except (OSError, RuntimeError, ValueError):
        return None
    releases_payload = payload.get("releases")
    if not isinstance(releases_payload, dict):
        return None
    normalized_range = _normalized_pypi_requested_range(requested_range)
    if normalized_range is None:
        return None
    try:
        specifier = SpecifierSet(normalized_range)
    except InvalidSpecifier:
        return None
    matching_versions: list[Version] = []
    for release in releases_payload:
        if not isinstance(release, str):
            continue
        try:
            parsed_version = Version(release)
        except InvalidVersion:
            continue
        if parsed_version in specifier:
            matching_versions.append(parsed_version)
    if not matching_versions:
        return None
    matching_versions.sort()
    return str(matching_versions[-1])


def _normalized_pypi_requested_range(requested_range: str) -> str | None:
    normalized = requested_range.strip()
    if not normalized:
        return None
    if normalized.startswith("~="):
        return normalized
    if normalized.startswith("^"):
        return _pypi_caret_specifier(normalized[1:])
    if normalized.startswith("~"):
        return _pypi_tilde_specifier(normalized[1:])
    return normalized


def _pypi_caret_specifier(value: str) -> str | None:
    base = _optional_string(value)
    if base is None:
        return None
    try:
        parsed_version = Version(base)
    except InvalidVersion:
        return None
    release = parsed_version.release
    major = release[0] if len(release) >= 1 else 0
    minor = release[1] if len(release) >= 2 else 0
    patch = release[2] if len(release) >= 3 else 0
    if major > 0:
        upper_bound = f"{major + 1}"
    elif minor > 0:
        upper_bound = f"0.{minor + 1}"
    else:
        upper_bound = f"0.0.{patch + 1}"
    return f">={base},<{upper_bound}"


def _pypi_tilde_specifier(value: str) -> str | None:
    base = _optional_string(value)
    if base is None:
        return None
    try:
        parsed_version = Version(base)
    except InvalidVersion:
        return None
    release = parsed_version.release
    major = release[0] if len(release) >= 1 else 0
    upper_bound = f"{major}.{release[1] + 1}" if len(release) >= 2 else f"{major + 1}"
    return f">={base},<{upper_bound}"


def _normalized_supply_chain_evaluate_url(sync_url: str, workspace_id: str) -> str:
    parsed = urllib.parse.urlsplit(_normalized_receipts_sync_url(sync_url))
    if parsed.path.rstrip("/") == "/api/guard/receipts/sync":
        next_path = "/api/guard/supply-chain/evaluate"
    elif parsed.path.rstrip("/") == "/guard/receipts/sync":
        next_path = "/guard/supply-chain/evaluate"
    else:
        next_path = parsed.path.rstrip("/") + "/supply-chain/evaluate"
    query_pairs = [
        (key, value)
        for key, value in urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
        if key != "workspaceId"
    ]
    query_pairs.append(("workspaceId", workspace_id))
    return urllib.parse.urlunsplit(
        (
            parsed.scheme,
            parsed.netloc,
            next_path,
            urllib.parse.urlencode(query_pairs),
            "",
        )
    )
