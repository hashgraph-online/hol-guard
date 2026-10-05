"""Retained package-request services for the local supply-chain evaluator.

Cloud-adjacent service work extracted from ``supply_chain_package_eval``:
registry metadata lookups, tarball download/inspection, request-payload and
workspace-fingerprint construction, lockfile context, and Guard Cloud
evaluate-URL normalization. Evaluation authority (evidence, risk, override,
reuse, and launch decisions) stays in ``supply_chain_package_eval``.
"""

from __future__ import annotations

import importlib
import sys
from pathlib import Path
from typing import TYPE_CHECKING

from ..models import GuardArtifact

if TYPE_CHECKING:
    from packaging.version import Version

    from .restricted_archive_download import RestrictedArchiveDownload, RestrictedArchiveDownloadResult

_NPM_REGISTRY_METADATA_BASE_URL = "https://registry.npmjs.org"
_PYPI_REGISTRY_METADATA_BASE_URL = "https://pypi.org/pypi"
_TARBALL_SCAN_TIMEOUT_SECONDS = 2
_TARBALL_SCAN_MAX_BYTES = 6 * 1024 * 1024
_TARBALL_SCAN_MAX_FILES = 500
_TARBALL_SCAN_MAX_PACKAGE_JSON_BYTES = 256 * 1024


def _pe():
    """Lazy accessor for the evaluator module's namespace.

    Service functions keep resolving evaluator-owned names (helpers, seams,
    constants) through this accessor so module-level monkeypatching of
    ``supply_chain_package_eval`` remains byte-identical for callers.
    """
    module = sys.modules.get("codex_plugin_scanner.guard.runtime.supply_chain_package_eval")
    if module is None:
        module = importlib.import_module("codex_plugin_scanner.guard.runtime.supply_chain_package_eval")
    return module


def _workspace_fingerprint(
    workspace_id: str,
    *,
    workspace_dir: Path | None,
    artifact: GuardArtifact,
    bundle_meta: dict[str, str] | None,
) -> str:
    manifest_hashes = _pe()._hash_paths(workspace_dir, artifact.metadata.get("manifest_paths"))
    lockfile_hashes = _pe()._hash_paths(workspace_dir, artifact.metadata.get("lockfile_paths"))
    return _pe()._stable_hash(
        {
            "workspace_id": workspace_id,
            "workspace_name": workspace_dir.name if workspace_dir is not None else None,
            "manifest_hashes": manifest_hashes,
            "lockfile_hashes": lockfile_hashes,
            "lockfile_parser_version": _pe().LOCKFILE_PARSER_VERSION,
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
) -> dict[str, object]:
    lockfile_context = _pe()._lockfile_context(workspace_dir, artifact)
    payload: dict[str, object] = {
        "commandShape": {
            "argCount": len(str(artifact.metadata.get("redacted_command") or "").split()),
            "flags": list(_pe()._string_tuple(artifact.metadata.get("flags"))),
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


def _lockfile_context(workspace_dir: Path | None, artifact: GuardArtifact) -> dict[str, object] | None:
    if workspace_dir is None:
        return None
    lockfile_paths = artifact.metadata.get("lockfile_paths")
    if not isinstance(lockfile_paths, list) or not lockfile_paths:
        return None
    lockfile_path = _pe().resolve_path_within_workspace(workspace_dir, str(lockfile_paths[0]))
    if lockfile_path is None or not lockfile_path.exists():
        return None
    if lockfile_path.name.lower() == "bun.lockb":
        return None
    lockfile_text = _pe().read_text_within_workspace(workspace_dir, str(lockfile_paths[0]))
    if lockfile_text is None:
        return None
    parse_result = _pe()._parse_lockfile_text_result(lockfile_path.name, lockfile_text)
    if not parse_result.complete:
        return {
            "dependencyCount": 0,
            "fileName": lockfile_path.name,
            "lockfileHash": parse_result.source_hash,
            "lockfileParserVersion": parse_result.parser_version,
            "parseComplete": False,
            "parseError": parse_result.error_reason,
        }
    manifest_hashes = _pe()._hash_paths(workspace_dir, artifact.metadata.get("manifest_paths"))
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
        remaining = request_deadline - _pe().time.monotonic()
        if remaining <= 0:
            return _pe()._external_archive_request_timeout_result(), None
        download_timeout = min(download_timeout, remaining)
    downloaded = _pe()._download_external_tarball(source_url, timeout_seconds=download_timeout)
    if isinstance(downloaded, _pe().RestrictedArchiveFailure):
        return (
            {
                "decision": "block",
                "code": downloaded.code,
                "message": downloaded.message,
                "severity": "high",
            },
            None,
        )
    if not isinstance(downloaded, _pe().RestrictedArchiveDownload):
        return None, None
    retain_blob = False
    try:
        inspection_timeout = _TARBALL_SCAN_TIMEOUT_SECONDS
        if request_deadline is not None:
            # The inspector parent reserves a 0.5s termination grace after its
            # child's own deadline; include that grace in the request budget.
            remaining = request_deadline - _pe().time.monotonic() - 0.5
            if remaining <= 0:
                return _pe()._external_archive_request_timeout_result(), None
            inspection_timeout = min(inspection_timeout, remaining)
        inspection = _pe().inspect_archive_native(
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
    return _pe().download_restricted_archive(
        source_url,
        max_bytes=_TARBALL_SCAN_MAX_BYTES,
        timeout_seconds=timeout_seconds,
    )


def _registry_resolved_target_version(*, target: dict[str, object], requested_range: str) -> str | None:
    ecosystem = _pe()._optional_string(target.get("ecosystem")) or "npm"
    if _pe()._optional_string(target.get("source_url")) is not None:
        return None
    package_name = _pe()._registry_package_name(target)
    if package_name is None:
        return None
    if ecosystem == "npm":
        return _pe()._npm_registry_resolved_version(package_name=package_name, requested_range=requested_range)
    if ecosystem == "pypi":
        normalized_name = _pe()._normalize_package_name("pypi", package_name)
        return _pe()._pypi_registry_resolved_version(package_name=normalized_name, requested_range=requested_range)
    return None


def _registry_package_name(target: dict[str, object]) -> str | None:
    package_name = _pe()._optional_string(target.get("name"))
    if package_name is None:
        return None
    namespace = _pe()._optional_string(target.get("namespace"))
    return f"{namespace}/{package_name}" if namespace is not None else package_name


def _npm_registry_resolved_version(*, package_name: str, requested_range: str) -> str | None:
    metadata_url = f"{_NPM_REGISTRY_METADATA_BASE_URL.rstrip('/')}/{_pe().urllib.parse.quote(package_name, safe='')}"
    request = _pe().urllib.request.Request(
        metadata_url,
        headers={
            "Accept": "application/vnd.npm.install-v1+json",
            "User-Agent": "hol-guard-local",
        },
    )
    try:
        payload = _pe()._urlopen_json_with_timeout_retry(
            request=request,
            timeout_seconds=_pe()._TIMEOUT_SECONDS,
            retry_timeout_seconds=_pe()._RETRY_TIMEOUT_SECONDS,
        )
    except (OSError, RuntimeError, ValueError):
        return None
    versions_payload = payload.get("versions")
    if not isinstance(versions_payload, dict):
        return None
    versions = [version for version in versions_payload if isinstance(version, str)]
    if not versions:
        return None
    return _pe().highest_js_version_for_selector(versions, requested_range)


def _pypi_registry_resolved_version(*, package_name: str, requested_range: str) -> str | None:
    metadata_url = (
        f"{_PYPI_REGISTRY_METADATA_BASE_URL.rstrip('/')}/{_pe().urllib.parse.quote(package_name, safe='')}/json"
    )
    request = _pe().urllib.request.Request(
        metadata_url,
        headers={
            "Accept": "application/json",
            "User-Agent": "hol-guard-local",
        },
    )
    try:
        payload = _pe()._urlopen_json_with_timeout_retry(
            request=request,
            timeout_seconds=_pe()._TIMEOUT_SECONDS,
            retry_timeout_seconds=_pe()._RETRY_TIMEOUT_SECONDS,
        )
    except (OSError, RuntimeError, ValueError):
        return None
    releases_payload = payload.get("releases")
    if not isinstance(releases_payload, dict):
        return None
    normalized_range = _pe()._normalized_pypi_requested_range(requested_range)
    if normalized_range is None:
        return None
    try:
        specifier = _pe().SpecifierSet(normalized_range)
    except _pe().InvalidSpecifier:
        return None
    matching_versions: list[Version] = []
    for release in releases_payload:
        if not isinstance(release, str):
            continue
        try:
            parsed_version = _pe().Version(release)
        except _pe().InvalidVersion:
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
        return _pe()._pypi_caret_specifier(normalized[1:])
    if normalized.startswith("~"):
        return _pe()._pypi_tilde_specifier(normalized[1:])
    return normalized


def _pypi_caret_specifier(value: str) -> str | None:
    base = _pe()._optional_string(value)
    if base is None:
        return None
    try:
        parsed_version = _pe().Version(base)
    except _pe().InvalidVersion:
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
    base = _pe()._optional_string(value)
    if base is None:
        return None
    try:
        parsed_version = _pe().Version(base)
    except _pe().InvalidVersion:
        return None
    release = parsed_version.release
    major = release[0] if len(release) >= 1 else 0
    upper_bound = f"{major}.{release[1] + 1}" if len(release) >= 2 else f"{major + 1}"
    return f">={base},<{upper_bound}"


def _normalized_supply_chain_evaluate_url(sync_url: str, workspace_id: str) -> str:
    parsed = _pe().urllib.parse.urlsplit(_pe()._normalized_receipts_sync_url(sync_url))
    if parsed.path.rstrip("/") == "/api/guard/receipts/sync":
        next_path = "/api/guard/supply-chain/evaluate"
    elif parsed.path.rstrip("/") == "/guard/receipts/sync":
        next_path = "/guard/supply-chain/evaluate"
    else:
        next_path = parsed.path.rstrip("/") + "/supply-chain/evaluate"
    query_pairs = [
        (key, value)
        for key, value in _pe().urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
        if key != "workspaceId"
    ]
    query_pairs.append(("workspaceId", workspace_id))
    return _pe().urllib.parse.urlunsplit(
        (
            parsed.scheme,
            parsed.netloc,
            next_path,
            _pe().urllib.parse.urlencode(query_pairs),
            "",
        )
    )
