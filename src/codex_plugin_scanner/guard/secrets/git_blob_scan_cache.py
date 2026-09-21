"""Bounded, scan-local finding reuse without retaining entire Git blobs."""

from __future__ import annotations

from collections import OrderedDict
from collections.abc import Callable
from dataclasses import dataclass, replace
from pathlib import Path
from typing import final

from .git_object_reader import GitObjectReader
from .secret_detection import SecretFinding, SecretScanSource, _path_policy_key, detector_version

_MAX_CACHE_ENTRIES = 1_024
_MAX_CACHED_FINDINGS = 10_000


@dataclass(frozen=True, slots=True)
class _CachedScan:
    findings: tuple[SecretFinding, ...]
    bytes_scanned: int
    finding_budget: int


@final
class GitBlobScanCache:
    """Reuse complete results only when the new finding budget can contain them.

    Truncated detector results depend on provider iteration order before the
    final sort. Slicing a larger result would change that contract, so a smaller
    budget triggers a rescan unless the cached result is known to be complete.
    """

    def __init__(self) -> None:
        self._version = detector_version()
        self._entries: OrderedDict[tuple[object, ...], _CachedScan] = OrderedDict()
        self._findings_count = 0

    def scan(
        self,
        reader: GitObjectReader,
        *,
        oid: str,
        size: int,
        path: str,
        source: SecretScanSource,
        commit: str | None,
        finding_budget: int,
        max_file_bytes: int,
        scan_blob: Callable[..., tuple[tuple[SecretFinding, ...], int]],
    ) -> tuple[tuple[SecretFinding, ...], int]:
        # Suffix also controls the repository scanner's binary exclusion before
        # the rich detector is invoked. Keeping it exact is conservative.
        key = (oid, self._version, _path_policy_key(path), Path(path).suffix.lower())
        cached = self._entries.get(key)
        if cached is not None and (
            cached.finding_budget == finding_budget
            or (len(cached.findings) < cached.finding_budget and len(cached.findings) <= finding_budget)
        ):
            self._entries.move_to_end(key)
            return (
                tuple(replace(finding, path=path, source=source, commit=commit) for finding in cached.findings),
                cached.bytes_scanned,
            )
        data = reader.read(oid, size=size, max_bytes=max_file_bytes)
        findings, bytes_scanned = scan_blob(
            data, path=path, source=source, commit=commit, finding_budget=finding_budget
        )
        if cached is not None:
            self._findings_count -= len(cached.findings)
        self._entries[key] = _CachedScan(findings, bytes_scanned, finding_budget)
        self._entries.move_to_end(key)
        self._findings_count += len(findings)
        while len(self._entries) > _MAX_CACHE_ENTRIES or self._findings_count > _MAX_CACHED_FINDINGS:
            _, evicted = self._entries.popitem(last=False)
            self._findings_count -= len(evicted.findings)
        return findings, bytes_scanned
