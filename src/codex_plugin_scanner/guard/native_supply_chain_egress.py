"""Network egress for the resident's supply-chain evaluation.

The resident never opens a socket for package evaluation. When it needs Guard
Cloud, the OAuth endpoint, a public registry or an external archive it answers
``supply_chain_egress_required`` with the exchanges it wants. This module
performs them under the managed network policy (destination allow-list,
policy proxy, CA bundle, proxy credentials, system proxies) through the same
transports Python used before: ``managed_urlopen`` for HTTP and
``download_restricted_archive`` for archives. It only moves bytes; the resident
parses every response and owns every decision.
"""

from __future__ import annotations

import os
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from .mdm.network_transport import ManagedNetworkError, managed_urlopen, resolved_network_policy, validate_destination
from .runtime.restricted_archive_download import RestrictedArchiveFailure, download_restricted_archive

EGRESS_REQUIRED_CODE = "supply_chain_egress_required"
# Resident-side limits (``EGRESS_MAX_*`` in guard-contracts supply_chain_egress.rs).
INLINE_BODY_MAX_BYTES = 32 * 1024
# The whole request is capped at 256 KiB by ``_resident_request``; inline bodies
# stop well short of that so headers and the artifact always fit.
INLINE_BUDGET_BYTES = 128 * 1024
MAX_NEEDS = 16
MAX_SUPPLIED = 64
# A retry pause the resident asked for. Bounded so a hostile value cannot stall.
MAX_DELAY_SECONDS = 30.0
_MAX_HEADERS = 64
_MAX_URL_BYTES = 8192
_NEED_KEYS = frozenset(
    {
        "class",
        "method",
        "url",
        "headers",
        "body",
        "body_sha256",
        "occurrence",
        "timeout_seconds",
        "max_redirects",
        "max_response_bytes",
        "delay_seconds",
    }
)
_CLASSES = frozenset({"oauth", "cloud", "registry", "archive"})
_MAX_RESPONSE_BYTES_CEILING = 64 * 1024 * 1024
_MAX_TIMEOUT_SECONDS = 60.0
_MAX_REDIRECTS_CEILING = 10


class EgressProtocolError(ValueError):
    """The resident's egress request is malformed; the evaluation cannot proceed."""


class EgressExchanger:
    """Performs needs and keeps what the next request must carry."""

    def __init__(self, spool_dir: Path) -> None:
        self.spool_dir = spool_dir
        self.supplied: list[dict[str, object]] = []
        self._inline_used = 0
        self._spool_count = 0

    def fulfil(self, payload: object) -> None:
        for need in parse_needs(payload):
            if len(self.supplied) >= MAX_SUPPLIED:
                raise EgressProtocolError("too many exchanges")
            self.supplied.append(self._answer(need))

    def _answer(self, need: Mapping[str, Any]) -> dict[str, object]:
        delay = min(max(float(need["delay_seconds"]), 0.0), MAX_DELAY_SECONDS)
        if delay > 0:
            time.sleep(delay)
        outcome = self._archive(need) if need["class"] == "archive" else self._http(need)
        return {
            "class": need["class"],
            "method": need["method"],
            "url": need["url"],
            "body_sha256": need["body_sha256"],
            "occurrence": need["occurrence"],
            "outcome": outcome,
        }

    def _http(self, need: Mapping[str, Any]) -> dict[str, object]:
        url = str(need["url"])
        if urllib.parse.urlsplit(url).scheme not in {"http", "https"}:
            return {"kind": "blocked", "code": "egress_scheme_not_allowed"}
        body = need.get("body")
        data = body.encode("utf-8") if isinstance(body, str) else None
        request = urllib.request.Request(
            url,
            data=data,
            headers={str(k): str(v) for k, v in dict(need["headers"]).items()},
            method=str(need["method"]),
        )
        limit = int(need["max_response_bytes"])
        try:
            with managed_urlopen(
                request,
                timeout=float(need["timeout_seconds"]),
                allow_redirects=int(need["max_redirects"]) > 0,
            ) as response:
                return self._response_outcome(
                    int(response.status),
                    response.headers.items(),
                    response.read(limit + 1),
                    limit,
                )
        except urllib.error.HTTPError as error:
            try:
                return self._response_outcome(int(error.code), error.headers.items(), error.read(limit + 1), limit)
            finally:
                error.close()
        except ManagedNetworkError as error:
            return {"kind": "blocked", "code": str(error)[:128]}
        except TimeoutError:
            return {"kind": "timeout"}
        except urllib.error.URLError as error:
            if isinstance(error.reason, TimeoutError):
                return {"kind": "timeout"}
            return {"kind": "error", "message": type(error.reason).__name__}
        except (OSError, ValueError) as error:
            return {"kind": "error", "message": type(error).__name__}

    def _response_outcome(
        self,
        status: int,
        header_items: Any,
        body: bytes,
        limit: int,
    ) -> dict[str, object]:
        if len(body) > limit:
            return {"kind": "error", "message": "response too large"}
        headers = {str(k): str(v) for k, v in list(header_items)[:_MAX_HEADERS]}
        outcome: dict[str, object] = {"kind": "response", "status": status, "headers": headers}
        if not body:
            return outcome
        text = _inline_text(body) if self._inline_used + len(body) <= INLINE_BUDGET_BYTES else None
        if text is not None:
            self._inline_used += len(body)
            outcome["body"] = text
            return outcome
        self._spool_count += 1
        name = f"body-{self._spool_count}"
        path = self.spool_dir / name
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        with os.fdopen(fd, "wb") as handle:
            handle.write(body)
        outcome["body_file"] = name
        return outcome

    def _archive(self, need: Mapping[str, Any]) -> dict[str, object]:
        url = str(need["url"])
        try:
            policy, _managed = resolved_network_policy(None)
            validate_destination(url, policy)
        except ManagedNetworkError as error:
            return {"kind": "archive_failure", "code": str(error)[:128], "message": "Managed network policy refused"}
        with tempfile.TemporaryDirectory(prefix="archive-", dir=self.spool_dir) as scratch:
            result = download_restricted_archive(
                url,
                max_bytes=int(need["max_response_bytes"]),
                max_redirects=int(need["max_redirects"]),
                timeout_seconds=float(need["timeout_seconds"]),
                temp_dir=Path(scratch),
            )
            if isinstance(result, RestrictedArchiveFailure):
                return {"kind": "archive_failure", "code": result.code, "message": result.message}
            try:
                return {"kind": "archive", "sha256": result.sha256, "size": result.size, "final_url": result.final_url}
            finally:
                result.cleanup()


def _inline_text(body: bytes) -> str | None:
    if len(body) > INLINE_BODY_MAX_BYTES:
        return None
    try:
        return body.decode("utf-8")
    except UnicodeDecodeError:
        return None


def parse_needs(payload: object) -> list[Mapping[str, Any]]:
    """Validate the resident's needs; anything off-contract aborts the evaluation."""
    if not isinstance(payload, dict) or set(payload) != {"needs"}:
        raise EgressProtocolError("egress payload invalid")
    needs = payload["needs"]
    if not isinstance(needs, list) or not 0 < len(needs) <= MAX_NEEDS:
        raise EgressProtocolError("egress needs invalid")
    return [_checked_need(need) for need in needs]


def _checked_need(need: object) -> Mapping[str, Any]:
    if not isinstance(need, dict) or not set(need) <= _NEED_KEYS:
        raise EgressProtocolError("egress need invalid")
    required = _NEED_KEYS - {"body"}
    if not required <= set(need):
        raise EgressProtocolError("egress need incomplete")
    headers = need["headers"]
    valid = (
        need["class"] in _CLASSES
        and isinstance(need["method"], str)
        and need["method"] in {"GET", "POST"}
        and isinstance(need["url"], str)
        and 0 < len(need["url"]) <= _MAX_URL_BYTES
        and isinstance(headers, dict)
        and len(headers) <= _MAX_HEADERS
        and all(isinstance(k, str) and isinstance(v, str) for k, v in headers.items())
        and isinstance(need["body_sha256"], str)
        and _is_count(need["occurrence"], 1, 1 << 16)
        and _is_number(need["timeout_seconds"], 0.0, _MAX_TIMEOUT_SECONDS, exclusive_low=True)
        and _is_count(need["max_redirects"], 0, _MAX_REDIRECTS_CEILING)
        and _is_count(need["max_response_bytes"], 1, _MAX_RESPONSE_BYTES_CEILING)
        and _is_number(need["delay_seconds"], 0.0, 3600.0)
        and (need.get("body") is None or isinstance(need["body"], str))
    )
    if not valid:
        raise EgressProtocolError("egress need invalid")
    return need


def _is_count(value: object, low: int, high: int) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and low <= value <= high


def _is_number(value: object, low: float, high: float, *, exclusive_low: bool = False) -> bool:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return False
    return (value > low if exclusive_low else value >= low) and value <= high


@contextmanager
def private_spool_dir() -> Iterator[Path]:
    """A 0700 directory for response bodies too big to inline, removed afterwards."""
    with tempfile.TemporaryDirectory(prefix="hol-guard-egress-") as name:
        path = Path(name).resolve()
        path.chmod(0o700)
        yield path


__all__ = [
    "EGRESS_REQUIRED_CODE",
    "EgressExchanger",
    "EgressProtocolError",
    "parse_needs",
    "private_spool_dir",
]
