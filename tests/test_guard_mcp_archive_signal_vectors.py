"""Shared-vector end-to-end check of the resident archive binder and reason projection.

``tests/fixtures/mcp_proxy_decision/archive_signal_vectors.json`` was recorded from
the Python proxy helpers before they moved into the resident (see its provenance
block). The reason vectors replay through the real Python transport and the real
resident; the archive binding is exercised end to end against real files. There
is no Python oracle: the vectors are the contract.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.native_mcp_proxy_decision import (
    native_external_archive_bind,
    native_package_reason_signals,
)
from codex_plugin_scanner.guard.runtime.restricted_archive_contract import RestrictedArchiveDownload

VECTORS = json.loads(
    (Path(__file__).parent / "fixtures" / "mcp_proxy_decision" / "archive_signal_vectors.json").read_text(
        encoding="utf-8"
    )
)["vectors"]
ARCHIVE_URL = "https://example.com/pkg-1.0.0.tgz"

pytestmark = pytest.mark.skipif(
    os.environ.get("HOL_GUARD_NATIVE_REGRESSION") != "1",
    reason="needs the resident runtime (HOL_GUARD_NATIVE_REGRESSION=1)",
)


@pytest.fixture(scope="module")
def guard_home(tmp_path_factory: pytest.TempPathFactory) -> Path:
    return tmp_path_factory.mktemp("mcp-archive-signal-home")


def _download(tmp_path: Path, payload: bytes) -> RestrictedArchiveDownload:
    path = tmp_path / "pkg.tgz"
    path.write_bytes(payload)
    path.chmod(0o400)
    return RestrictedArchiveDownload(
        path=path,
        sha256=hashlib.sha256(payload).hexdigest(),
        size=len(payload),
        source_url=ARCHIVE_URL,
        final_url=ARCHIVE_URL,
    )


def test_archive_binding_reverifies_downloads_in_the_resident(guard_home: Path, tmp_path: Path) -> None:
    # The recorded binding vectors replay in the resident's own tests; this
    # checks the transport and the resident-side file verification end to end.
    download = _download(tmp_path, b"inspected archive")
    local = str(download.path)
    params = {"name": "install", "arguments": {"spec": f"demo@{ARCHIVE_URL}", "n": 1.0}}
    bound = native_external_archive_bind(params, (download,), requires_binding=True, guard_home=guard_home)
    assert bound == {"name": "install", "arguments": {"spec": f"demo@{local}", "n": 1.0}}
    argv = native_external_archive_bind(
        ["pip", "install", ARCHIVE_URL], (download,), requires_binding=True, guard_home=guard_home
    )
    assert argv == ["pip", "install", local]
    assert native_external_archive_bind(params, (), requires_binding=False, guard_home=guard_home) == params
    assert native_external_archive_bind(params, (), requires_binding=True, guard_home=guard_home) is None

    download.path.chmod(0o600)
    download.path.write_bytes(b"substituted archive")
    download.path.chmod(0o400)
    assert native_external_archive_bind(params, (download,), requires_binding=True, guard_home=guard_home) is None


def test_reason_signals_match_every_recorded_vector(guard_home: Path) -> None:
    checked = 0
    for vector in VECTORS:
        request = vector["request"]
        if request["check"] != "package_reason_signals":
            continue
        signals = native_package_reason_signals(request["reasons"], guard_home=guard_home)
        assert list(signals) == vector["expected"]["signals"], vector["id"]
        checked += 1
    assert checked >= 15
