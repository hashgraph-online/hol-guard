"""Post-sign attestation accepts the slash-bearing alpha tag only for the alpha channel."""

from __future__ import annotations

from pathlib import Path

import pytest

from scripts.release.verify_desktop_core_attestation import DesktopAttestationError, verify, verify_archive

ALPHA = "3.4.0a2"
ALPHA_TAG = f"alpha/v{ALPHA}"
SOURCE = "a" * 40
TARGET = "aarch64-apple-darwin"


def _call(function, tmp_path: Path, *, version: str, tag: str, channel: str):
    artifact = tmp_path / "artifact"
    artifact.write_bytes(b"\xcf\xfa\xed\xfe" + b"core")
    for name in ("manifest.json", "marker.json"):
        (tmp_path / name).write_text("{}", encoding="utf-8")
    return function(
        artifact,
        tmp_path / "manifest.json",
        tmp_path / "marker.json",
        version=version,
        source_commit=SOURCE,
        source_tag=tag,
        target=TARGET,
        expected_team_id="ABCDEF1234",
        channel=channel,
    )


@pytest.mark.parametrize("function", [verify, verify_archive])
def test_alpha_tag_passes_token_validation_and_reaches_manifest_comparison(function, tmp_path: Path) -> None:
    with pytest.raises(DesktopAttestationError, match="mismatch for"):
        _call(function, tmp_path, version=ALPHA, tag=ALPHA_TAG, channel="alpha")


@pytest.mark.parametrize("function", [verify, verify_archive])
@pytest.mark.parametrize(
    "tag",
    [
        "v3.4.0a2",
        "alpha/v3.4.0a1",
        "alpha/v3.4.0a2/extra",
        "alpha/v3.4.0a2\n",
        "alpha/v3.4.0a02",
        "beta/v3.4.0a2",
        "alpha/../v3.4.0a2",
    ],
)
def test_alpha_channel_requires_the_exact_alpha_tag(function, tmp_path: Path, tag: str) -> None:
    with pytest.raises(DesktopAttestationError, match="alpha"):
        _call(function, tmp_path, version=ALPHA, tag=tag, channel="alpha")


@pytest.mark.parametrize("function", [verify, verify_archive])
def test_stable_channel_still_rejects_a_slash_in_the_source_tag(function, tmp_path: Path) -> None:
    with pytest.raises(DesktopAttestationError, match="bounded release token"):
        _call(function, tmp_path, version=ALPHA, tag=ALPHA_TAG, channel="stable")


@pytest.mark.parametrize("function", [verify, verify_archive])
def test_unknown_channel_is_rejected(function, tmp_path: Path) -> None:
    with pytest.raises(DesktopAttestationError, match="channel"):
        _call(function, tmp_path, version=ALPHA, tag=ALPHA_TAG, channel="beta")
