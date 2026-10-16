from __future__ import annotations

import hashlib
import json
import zipfile
from pathlib import Path

import pytest

from scripts.build_native_hol_guard_wheel import _record_content
from scripts.embed_native_wheel_manifest import MANIFEST_MEMBER, MANIFEST_SCHEMA, main

VERSION = "3.44.0"
DIST_INFO = f"hol_guard-{VERSION}.dist-info"


def _pure_wheel(dist: Path) -> Path:
    entries = {
        "codex_plugin_scanner/__init__.py": b"",
        f"{DIST_INFO}/METADATA": f"Metadata-Version: 2.4\nName: hol-guard\nVersion: {VERSION}\n".encode(),
        f"{DIST_INFO}/WHEEL": b"Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: py3-none-any\n",
    }
    record = f"{DIST_INFO}/RECORD"
    entries[record] = _record_content({**entries, record: b""}, record_path=record)
    wheel = dist / f"hol_guard-{VERSION}-py3-none-any.whl"
    with zipfile.ZipFile(wheel, "w") as archive:
        for name, content in entries.items():
            archive.writestr(name, content)
    return wheel


def test_embed_lists_every_native_wheel_and_updates_record(tmp_path: Path) -> None:
    dist = tmp_path / "dist"
    dist.mkdir()
    pure = _pure_wheel(dist)
    natives = {}
    for platform in ("win_amd64", "win_arm64"):
        wheel = dist / f"hol_guard-{VERSION}-py3-none-{platform}.whl"
        wheel.write_bytes(platform.encode())
        natives[wheel.name] = hashlib.sha256(platform.encode()).hexdigest()

    assert main(["--dist-dir", str(dist), "--version", VERSION]) == 0

    with zipfile.ZipFile(pure) as archive:
        document = json.loads(archive.read(MANIFEST_MEMBER))
        record = archive.read(f"{DIST_INFO}/RECORD").decode()
        assert all(info.date_time == (1980, 1, 1, 0, 0, 0) for info in archive.infolist())
    assert document == {"schema": MANIFEST_SCHEMA, "version": VERSION, "wheels": natives}
    assert f"{MANIFEST_MEMBER},sha256=" in record
    assert sorted(path.name for path in dist.iterdir()) == sorted([pure.name, *natives])


@pytest.mark.parametrize("natives", [False, True])
def test_embed_refuses_without_native_wheels_or_twice(tmp_path: Path, natives: bool) -> None:
    dist = tmp_path / "dist"
    dist.mkdir()
    pure = _pure_wheel(dist)
    if natives:
        (dist / f"hol_guard-{VERSION}-py3-none-win_arm64.whl").write_bytes(b"native")
        assert main(["--dist-dir", str(dist), "--version", VERSION]) == 0
    before = pure.read_bytes()

    assert main(["--dist-dir", str(dist), "--version", VERSION]) == 1
    assert pure.read_bytes() == before
