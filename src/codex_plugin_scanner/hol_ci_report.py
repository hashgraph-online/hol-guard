"""Opt-in scan summary sent to HOL Plugins from a public repository's own run.

The report carries the repository, commit, run, scanner version, plugin folder,
score, grade and finding counts. It never carries code, file contents, paths
other than the scanned folder, or finding text. GitHub's OIDC token proves
which repository, commit and run sent it; its audience is the sha256 of the
exact body. Any failure is reported as a warning and never fails the job.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Callable, Mapping
from contextlib import AbstractContextManager
from http.client import HTTPException
from typing import Protocol
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlsplit
from urllib.request import Request, urlopen

HOL_CI_REPORT_URL = "https://hol.org/api/plugins/ci-reports"
HOL_CI_REPORT_SCHEMA = "hol.plugin-ci-report.v1"
HOL_CI_REPORT_AUDIENCE_PREFIX = "hol-plugin-ci-report:"
_SEVERITIES = ("critical", "high", "medium", "low", "info")
_FOLDER_PATTERN = re.compile(r"^[A-Za-z0-9._-]+(?:/[A-Za-z0-9._-]+)*$")
_DRIVE_PATTERN = re.compile(r"^[A-Za-z]:")
_TIMEOUT_SECONDS = 10


class _Readable(Protocol):
    def read(self) -> bytes: ...


Opener = Callable[..., AbstractContextManager[_Readable]]


def report_folder(plugin_dir: str) -> str:
    """Return the scanned folder relative to the repository root, or "" for the root or anything unusual."""
    raw = plugin_dir.strip()
    # Absolute paths (POSIX, UNC, root-relative or drive-letter Windows) are host paths, not repository folders.
    if raw.startswith(("/", "\\")) or _DRIVE_PATTERN.match(raw):
        return ""
    candidate = raw.replace("\\", "/").strip("/")
    while candidate.startswith("./"):
        candidate = candidate[2:]
    if candidate in {"", "."} or len(candidate) > 200:
        return ""
    if not _FOLDER_PATTERN.match(candidate) or any(part in {".", ".."} for part in candidate.split("/")):
        return ""
    return candidate


def build_ci_report_body(
    *,
    repository: str,
    commit_sha: str,
    workflow_run_id: str,
    scanner_version: str,
    plugin_dir: str,
    score: int | None,
    grade: str | None,
    max_severity: str | None,
    severity_counts: Mapping[str, int],
) -> str:
    findings = {severity: int(severity_counts.get(severity, 0)) for severity in _SEVERITIES}
    payload = {
        "schema": HOL_CI_REPORT_SCHEMA,
        "repository": repository,
        "commit_sha": commit_sha,
        "workflow_run_id": workflow_run_id,
        "scanner_version": scanner_version,
        "plugin_path": report_folder(plugin_dir),
        "score": score,
        "grade": grade,
        "max_severity": max_severity,
        "findings": findings,
    }
    return json.dumps(payload, separators=(",", ":"), sort_keys=True)


def ci_report_audience(body: str) -> str:
    return HOL_CI_REPORT_AUDIENCE_PREFIX + hashlib.sha256(body.encode("utf-8")).hexdigest()


def _request_oidc_token(*, request_url: str, request_token: str, audience: str, opener: Opener) -> str:
    separator = "&" if urlsplit(request_url).query else "?"
    request = Request(
        f"{request_url}{separator}audience={quote(audience, safe='')}",
        headers={"Authorization": f"Bearer {request_token}", "Accept": "application/json"},
    )
    with opener(request, timeout=_TIMEOUT_SECONDS) as response:
        payload = json.loads(response.read().decode("utf-8"))
    token = payload.get("value") if isinstance(payload, dict) else None
    if not isinstance(token, str) or not token:
        raise RuntimeError("GitHub did not return an OIDC token")
    return token


def send_ci_report(
    body: str,
    *,
    request_url: str,
    request_token: str,
    endpoint: str = HOL_CI_REPORT_URL,
    opener: Opener = urlopen,
) -> str:
    """Send the report; return a one-line status for the log. Never raises."""
    if not request_url or not request_token:
        return "skipped: the job needs `permissions: id-token: write` to report to HOL"
    try:
        token = _request_oidc_token(
            request_url=request_url,
            request_token=request_token,
            audience=ci_report_audience(body),
            opener=opener,
        )
        request = Request(
            endpoint,
            data=body.encode("utf-8"),
            method="POST",
            headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
        )
        with opener(request, timeout=_TIMEOUT_SECONDS) as response:
            receipt = json.loads(response.read().decode("utf-8") or "{}")
        listings = receipt.get("listings") if isinstance(receipt, dict) else None
        return f"sent ({listings} HOL listing(s) updated)" if isinstance(listings, int) else "sent"
    except HTTPError as error:
        return f"not sent: HOL answered {error.code}"
    except (URLError, OSError, HTTPException, RuntimeError, ValueError) as error:
        return f"not sent: {type(error).__name__}"
