"""External archive review and bounded inspection."""

from __future__ import annotations


def _is_external_https_tarball_source(source_url: str) -> bool:
    return _eval.is_external_https_archive_source(source_url)


def _target_is_external_https_archive(target: dict[str, object]) -> bool:
    ecosystem = (_eval._optional_string(target.get("ecosystem")) or "").lower()
    source_url = _eval._optional_string(target.get("source_url"))
    source_spec = _eval._npm_source_spec(source_url, ecosystem=ecosystem)
    return bool(
        ecosystem in {"npm", "pypi"}
        and source_url is not None
        and (source_spec is None or not source_spec.is_git)
        and _eval._is_external_https_tarball_source(source_url)
    )


def _target_requires_npm_source_review(target: dict[str, object]) -> bool:
    return (_eval._optional_string(target.get("ecosystem")) or "").lower() == "npm" and _eval._optional_string(
        target.get("source_kind")
    ) in {"git", "invalid", "local", "url"}


def _external_tarball_dependency_result(
    target: dict[str, object],
    *,
    network_authorized: bool,
    retain_download: bool,
    request_deadline: float | None = None,
) -> tuple[dict[str, object], _eval.RestrictedArchiveDownload | None]:
    source_url = _eval._optional_string(target.get("source_url"))
    if source_url is None:
        return (
            _eval._heuristic_package_result(
                target=target,
                decision="ask",
                code="external_tarball_source",
                message="External tarball source requires review before install.",
                severity="medium",
            ),
            None,
        )
    if target.get("external_archive_source_integrity_invalid") is True:
        return (
            _eval._heuristic_package_result(
                target=target,
                decision="block",
                code="external_archive_source_integrity_invalid",
                message="External archive private source no longer matches its approved public identity.",
                severity="high",
            ),
            None,
        )
    if _eval.canonical_external_https_archive_source(source_url) is None:
        return (
            _eval._heuristic_package_result(
                target=target,
                decision="block",
                code="external_archive_destination_rejected",
                message="External archive source is not a canonical public HTTPS URL.",
                severity="high",
            ),
            None,
        )
    if not network_authorized:
        return (
            _eval._heuristic_package_result(
                target=target,
                decision="ask",
                code="external_tarball_source",
                message="External tarball source requires review before any archive download.",
                severity="medium",
            ),
            None,
        )
    scan, retained_download = _eval._scan_external_tarball(
        source_url,
        retain_download=retain_download,
        request_deadline=request_deadline,
    )
    if scan is None:
        return (
            _eval._heuristic_package_result(
                target=target,
                decision="block",
                code="external_archive_inspection_incomplete",
                message="Guard could not complete restricted download and offline archive inspection.",
                severity="high",
            ),
            None,
        )
    return (
        _eval._heuristic_package_result(
            target=target,
            decision=scan["decision"],
            code=scan["code"],
            message=scan["message"],
            severity=scan["severity"],
        ),
        retained_download,
    )


def _scan_external_tarball(
    source_url: str,
    *,
    retain_download: bool = False,
    request_deadline: float | None = None,
) -> tuple[dict[str, str] | None, _eval.RestrictedArchiveDownload | None]:
    download_timeout = _eval._TARBALL_SCAN_TIMEOUT_SECONDS
    if request_deadline is not None:
        remaining = request_deadline - _eval.time.monotonic()
        if remaining <= 0:
            return _eval._external_archive_request_timeout_result(), None
        download_timeout = min(download_timeout, remaining)
    downloaded = _eval._download_external_tarball(source_url, timeout_seconds=download_timeout)
    if isinstance(downloaded, _eval.RestrictedArchiveFailure):
        return (
            {
                "decision": "block",
                "code": downloaded.code,
                "message": downloaded.message,
                "severity": "high",
            },
            None,
        )
    if not isinstance(downloaded, _eval.RestrictedArchiveDownload):
        return None, None
    retain_blob = False
    try:
        inspection_timeout = _eval._TARBALL_SCAN_TIMEOUT_SECONDS
        if request_deadline is not None:
            # The inspector parent reserves a 0.5s termination grace after its
            # child's own deadline; include that grace in the request budget.
            remaining = request_deadline - _eval.time.monotonic() - 0.5
            if remaining <= 0:
                return _eval._external_archive_request_timeout_result(), None
            inspection_timeout = min(inspection_timeout, remaining)
        inspection = _eval.inspect_archive_offline(
            downloaded.path,
            expected_sha256=downloaded.sha256,
            timeout_seconds=inspection_timeout,
            max_archive_bytes=_eval._TARBALL_SCAN_MAX_BYTES,
            max_files=_eval._TARBALL_SCAN_MAX_FILES,
            max_package_json_bytes=_eval._TARBALL_SCAN_MAX_PACKAGE_JSON_BYTES,
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


def _source_url_from_specifier(specifier: str | None) -> str | None:
    if specifier is None:
        return None
    if _eval.parse_npm_source_spec(specifier) is not None:
        return specifier
    if _eval.re.match(r"^[A-Za-z][A-Za-z0-9+.-]*://", specifier) is not None or specifier.lower().startswith(
        ("http:", "https:", "git+", "github:", "gitlab:", "bitbucket:", "file:")
    ):
        return specifier
    return None


def _source_url_from_raw_spec(raw_spec: str) -> str | None:
    separator = _eval._NAMED_SOURCE_SEPARATOR_RE.search(raw_spec)
    candidate = raw_spec[separator.end() :] if separator is not None else raw_spec
    if "://" in candidate or candidate.lower().startswith(
        ("http:", "https:", "git+", "github:", "gitlab:", "bitbucket:", "file:")
    ):
        return candidate
    if _eval._source_url_from_specifier(raw_spec) is not None:
        return raw_spec
    for index, character in enumerate(raw_spec):
        if character == "@" and index > 0 and _eval.parse_npm_source_spec(raw_spec[index + 1 :]) is not None:
            return raw_spec[index + 1 :]
    return None


# Resolve the facade after declarations so direct helper imports retain the cycle.
from . import supply_chain_package_eval as _eval  # noqa: E402
