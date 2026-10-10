"""External-archive downloads for the resident's supply-chain evaluation.

The resident never opens a socket and never reads an archive. When it needs
one it asks the caller to download it under the managed network policy and to
inspect the blob offline with the sandboxed native worker. This module does
exactly that and reports the digest, the size and the inspector's verdict. The
resident decides what they mean.

With ``retain`` the verified blobs are kept (mode 0400, system temp) so a
reviewed launch can run against the bytes that were inspected. Blobs the
resident's final answer does not ask for are removed.
"""

from __future__ import annotations

import tempfile
import time
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from .mdm.network_transport import ManagedNetworkError, resolved_network_policy, validate_destination
from .native_archive_inspection import inspect_archive_native
from .runtime.restricted_archive_contract import RestrictedArchiveDownload, RestrictedArchiveFailure
from .runtime.restricted_archive_download import download_restricted_archive
from .stable_digest import stable_digest_hex

# Time kept back for the inspector parent's termination grace.
_INSPECTION_GRACE_SECONDS = 0.5
_TIMEOUT_CODE = "external_archive_request_timeout"
_TIMEOUT_MESSAGE = "External archive request exceeded Guard's aggregate time limit."
_VERDICT_KEYS = ("status", "code", "message", "severity")


class ArchiveFulfilment:
    """Downloads and inspects the archives one evaluation asks for."""

    def __init__(self, *, guard_home: Path, scratch_dir: Path, retain: bool) -> None:
        self._guard_home = guard_home
        self._scratch_dir = scratch_dir
        self._retain = retain
        self._elapsed = 0.0
        self._retained: list[RestrictedArchiveDownload] = []

    def fulfil(self, need: Mapping[str, Any]) -> dict[str, object]:
        started = time.monotonic()
        try:
            return self._fulfil(need)
        finally:
            self._elapsed += time.monotonic() - started

    def _fulfil(self, need: Mapping[str, Any]) -> dict[str, object]:
        url = str(need["url"])
        try:
            policy, _managed = resolved_network_policy(None)
            validate_destination(url, policy)
        except ManagedNetworkError as error:
            return {"kind": "archive_failure", "code": str(error)[:128], "message": "Managed network policy refused"}
        spec = need.get("inspect")
        aggregate = _required_timeout(spec.get("aggregate_timeout_seconds")) if isinstance(spec, Mapping) else None
        download_timeout = float(need["timeout_seconds"])
        if aggregate is not None:
            remaining = aggregate - self._elapsed
            if remaining <= 0:
                return {"kind": "archive_failure", "code": _TIMEOUT_CODE, "message": _TIMEOUT_MESSAGE}
            download_timeout = min(download_timeout, remaining)
        # A retained blob lives where the caller's launch can reach it; the rest stay
        # in the private spool and are removed as soon as they have been inspected.
        with tempfile.TemporaryDirectory(prefix="archive-", dir=self._scratch_dir) as scratch:
            result = download_restricted_archive(
                url,
                max_bytes=int(need["max_response_bytes"]),
                max_redirects=int(need["max_redirects"]),
                timeout_seconds=download_timeout,
                temp_dir=None if self._retain else Path(scratch),
            )
            if isinstance(result, RestrictedArchiveFailure):
                return {"kind": "archive_failure", "code": result.code, "message": result.message}
            keep = False
            try:
                outcome: dict[str, object] = {
                    "kind": "archive",
                    "sha256": result.sha256,
                    "size": result.size,
                    "final_url": result.final_url,
                }
                if isinstance(spec, Mapping):
                    verdict = self._inspect(result, need, spec, aggregate)
                    if verdict is None:
                        return {"kind": "archive_failure", "code": _TIMEOUT_CODE, "message": _TIMEOUT_MESSAGE}
                    outcome["inspection"] = verdict
                    keep = self._retain and verdict["status"] == "clean"
                else:
                    keep = self._retain
                if keep:
                    self._retained.append(result)
                return outcome
            finally:
                if not keep:
                    result.cleanup()

    def _inspect(
        self,
        download: RestrictedArchiveDownload,
        need: Mapping[str, Any],
        spec: Mapping[str, Any],
        aggregate: float | None,
    ) -> dict[str, str] | None:
        timeout = float(spec["timeout_seconds"])
        if aggregate is not None:
            remaining = aggregate - self._elapsed - _INSPECTION_GRACE_SECONDS
            if remaining <= 0:
                return None
            timeout = min(timeout, remaining)
        inspection = inspect_archive_native(
            download.path,
            expected_sha256=download.sha256,
            state_dir=self._guard_home,
            timeout_seconds=timeout,
            max_archive_bytes=int(need["max_response_bytes"]),
            max_files=int(spec["max_files"]),
            max_package_json_bytes=int(spec["max_package_json_bytes"]),
        )
        return {key: str(getattr(inspection, key)) for key in _VERDICT_KEYS}

    def claim(self, descriptors: object) -> list[RestrictedArchiveDownload]:
        """Hand over the retained blobs the resident's answer names; remove the rest.

        An answer that names a blob this caller does not hold is a protocol
        failure: the caller must not launch against bytes nobody inspected.
        """
        wanted = descriptors if isinstance(descriptors, list) else []
        claimed: list[RestrictedArchiveDownload] = []
        pool = list(self._retained)
        self._retained = []
        try:
            for item in wanted:
                match = _take_match(pool, item)
                if match is None:
                    raise LookupError("resident named an archive this caller does not hold")
                claimed.append(match)
        except BaseException:
            for download in claimed:
                download.cleanup()
            raise
        finally:
            for download in pool:
                download.cleanup()
        return claimed

    def discard(self) -> None:
        for download in self._retained:
            download.cleanup()
        self._retained = []


def _required_timeout(value: object) -> float:
    """Accept only a real number. Booleans and other objects are not timeouts."""

    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise TypeError("archive timeout must be a number")
    return float(value)


def _take_match(pool: list[RestrictedArchiveDownload], descriptor: object) -> RestrictedArchiveDownload | None:
    if not isinstance(descriptor, Mapping):
        return None
    for index, download in enumerate(pool):
        if (
            descriptor.get("sha256") == download.sha256
            and descriptor.get("size") == download.size
            and descriptor.get("source_url_hash") == stable_digest_hex(download.source_url.encode("utf-8"))
            and descriptor.get("final_url_hash") == stable_digest_hex(download.final_url.encode("utf-8"))
        ):
            return pool.pop(index)
    return None


__all__ = ["ArchiveFulfilment"]
