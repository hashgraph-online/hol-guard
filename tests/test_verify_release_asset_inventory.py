from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from scripts.ci.verify_release_asset_inventory import verify_release_assets

VERSION = "3.0.0a269"


def _directories(tmp_path: Path) -> tuple[Path, Path]:
    release_dir = tmp_path / "release"
    dist_dir = tmp_path / "dist"
    release_dir.mkdir()
    dist_dir.mkdir()
    owned_asset = b"owned wheel"
    (release_dir / "hol_guard.whl").write_bytes(owned_asset)
    (dist_dir / "hol_guard.whl").write_bytes(owned_asset)
    return release_dir, dist_dir


def test_accepts_owned_assets_and_matching_mcpb_pair(tmp_path: Path) -> None:
    release_dir, dist_dir = _directories(tmp_path)
    mcpb = release_dir / f"hol-guard-{VERSION}.mcpb"
    mcpb.write_bytes(b"signed bundle")
    digest = hashlib.sha256(mcpb.read_bytes()).hexdigest()
    (release_dir / f"{mcpb.name}.sha256").write_text(
        f"{digest}  /temporary/build/{mcpb.name}\n",
        encoding="utf-8",
    )

    verify_release_assets(release_dir, dist_dir, VERSION)


def test_rejects_unowned_release_asset(tmp_path: Path) -> None:
    release_dir, dist_dir = _directories(tmp_path)
    (release_dir / "unowned.bin").write_bytes(b"untrusted")

    with pytest.raises(ValueError, match=r"Unexpected release asset: unowned\.bin"):
        verify_release_assets(release_dir, dist_dir, VERSION)


@pytest.mark.parametrize("missing_suffix", ["", ".sha256"])
def test_rejects_incomplete_mcpb_pair(tmp_path: Path, missing_suffix: str) -> None:
    release_dir, dist_dir = _directories(tmp_path)
    other_suffix = ".sha256" if missing_suffix == "" else ""
    (release_dir / f"hol-guard-{VERSION}.mcpb{other_suffix}").write_bytes(b"incomplete")

    with pytest.raises(ValueError, match="must both be present"):
        verify_release_assets(release_dir, dist_dir, VERSION)


def test_rejects_mcpb_checksum_mismatch(tmp_path: Path) -> None:
    release_dir, dist_dir = _directories(tmp_path)
    (release_dir / f"hol-guard-{VERSION}.mcpb").write_bytes(b"bundle")
    (release_dir / f"hol-guard-{VERSION}.mcpb.sha256").write_text(
        f"{'0' * 64}  bundle.mcpb\n",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="does not match its checksum"):
        verify_release_assets(release_dir, dist_dir, VERSION)
