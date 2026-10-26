"""Injected archive I/O for resident-backed external-archive tests.

The resident asks its caller for downloads and for the sandboxed inspector's
verdict; these fakes replace only those two caller-side steps so the resident
still makes every decision.
"""

from __future__ import annotations

import hashlib
import tempfile
from collections.abc import Callable
from pathlib import Path
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard import native_supply_chain_archive
from codex_plugin_scanner.guard.runtime.restricted_archive_contract import (
    RestrictedArchiveDownload,
    RestrictedArchiveFailure,
)

CLEAN_VERDICT = {
    "status": "clean",
    "code": "archive_clean",
    "message": "Archive inspection found no blocking behavior.",
    "severity": "info",
}


def install_download(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    *,
    payload: Callable[[str], bytes] | bytes = b"inspected bytes",
    failure: RestrictedArchiveFailure | None = None,
    calls: list[str] | None = None,
) -> list[Path]:
    """Replace the restricted download; returns every blob path it created."""

    created: list[Path] = []

    def download(
        url: str,
        *,
        max_bytes: int,
        max_redirects: int,
        timeout_seconds: float,
        temp_dir: Path | None = None,
    ) -> RestrictedArchiveDownload | RestrictedArchiveFailure:
        del max_bytes, max_redirects, timeout_seconds
        if calls is not None:
            calls.append(url)
        if failure is not None:
            return failure
        body = payload(url) if callable(payload) else payload
        directory = temp_dir if temp_dir is not None else Path(tempfile.mkdtemp(dir=tmp_path))
        path = directory / f"blob-{len(created)}.tgz"
        path.write_bytes(body)
        path.chmod(0o400)
        created.append(path)
        return RestrictedArchiveDownload(
            path=path,
            sha256=hashlib.sha256(body).hexdigest(),
            size=len(body),
            source_url=url,
            final_url=url,
        )

    monkeypatch.setattr(native_supply_chain_archive, "download_restricted_archive", download)
    return created


def install_inspection(
    monkeypatch: pytest.MonkeyPatch,
    verdict: dict[str, str] | None = None,
    calls: list[str] | None = None,
) -> None:
    """Replace the sandboxed inspector with a fixed verdict."""

    answer = SimpleNamespace(**(verdict or CLEAN_VERDICT))

    def inspect(path: Path, **kwargs: object) -> SimpleNamespace:
        del kwargs
        if calls is not None:
            calls.append(path.name)
        return answer

    monkeypatch.setattr(native_supply_chain_archive, "inspect_archive_native", inspect)


def forbid_download(monkeypatch: pytest.MonkeyPatch, reason: str) -> None:
    def unexpected(*_args: object, **_kwargs: object) -> object:
        pytest.fail(reason)

    monkeypatch.setattr(native_supply_chain_archive, "download_restricted_archive", unexpected)
