"""Keep shipped urllib3 requirements consistent with the reviewed dependency lock."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib

ROOT = Path(__file__).resolve().parents[1]
SNAPSHOTS = (
    "docker-requirements.txt",
    "action/scanner-runtime-requirements.txt",
    "action/scanner-cisco-runtime-requirements.txt",
    "action/pypi-attestations-requirements.txt",
)


@pytest.mark.parametrize("snapshot_path", SNAPSHOTS)
def test_shipped_urllib3_matches_project_override_and_lock(snapshot_path: str) -> None:
    """Reject missing, duplicate, stale, or differently hashed release requirements."""
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    lock = tomllib.loads((ROOT / "uv.lock").read_text(encoding="utf-8"))
    packages = [package for package in lock["package"] if package["name"] == "urllib3"]
    assert len(packages) == 1, "urllib3 must have one reviewed lock entry"
    package = packages[0]
    version = package["version"]
    requirement = f"urllib3=={version}"
    assert requirement in project["tool"]["uv"]["override-dependencies"]

    expected_hashes = {package["sdist"]["hash"], *(wheel["hash"] for wheel in package["wheels"])}
    text = (ROOT / snapshot_path).read_text(encoding="utf-8")
    logical_lines = text.replace("\\\n", "").splitlines()
    entries = [line.strip() for line in logical_lines if line.strip().startswith("urllib3==")]
    assert len(entries) == 1, f"{snapshot_path}: require exactly one urllib3 pin"
    tokens = entries[0].split()
    assert tokens[0] == requirement, f"{snapshot_path}: urllib3 differs from uv.lock"
    expected_options = {f"--hash={digest}" for digest in expected_hashes}
    assert set(tokens[1:]) == expected_options, f"{snapshot_path}: urllib3 hashes differ from uv.lock"
    assert len(tokens[1:]) == len(expected_options), f"{snapshot_path}: duplicate urllib3 hashes"
