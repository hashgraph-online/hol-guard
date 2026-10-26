"""Behavior of the publish repair step that reuses attested release wheels."""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
PUBLISH_WORKFLOW = ROOT / ".github" / "workflows" / "publish.yml"
STEP_NAME = "Reuse wheels already attested on the GitHub release"
WHEEL = "hol_guard-9.9.9-py3-none-any.whl"

FAKE_GH = """#!/usr/bin/env bash
set -euo pipefail
mode="${FAKE_GH_MODE:-ok}"
case "$1 $2" in
  "release view")
    if [[ "$mode" == notfound ]]; then echo "release not found" >&2; exit 1; fi
    if [[ "$mode" == outage ]]; then echo "HTTP 502: Bad Gateway" >&2; exit 1; fi
    if [[ "$mode" == nowheels ]]; then printf '{"isDraft":true,"isPrerelease":false,"assets":[]}'; exit 0; fi
    printf '{"isDraft":false,"isPrerelease":false,"assets":[{"name":"%s"}]}' "$FAKE_RELEASE_WHEEL"
    ;;
  "release download")
    shift 2
    dir=""
    while [[ $# -gt 0 ]]; do
      if [[ "$1" == --dir ]]; then dir="$2"; shift; fi
      shift
    done
    printf 'release-bytes' > "$dir/$FAKE_RELEASE_WHEEL"
    if [[ "$mode" != noprovenance ]]; then printf 'bundle' > "$dir/hol-guard-v9.9.9.intoto.jsonl"; fi
    ;;
  "attestation verify")
    [[ "$mode" != badattestation ]]
    ;;
  *)
    echo "unexpected gh call: $*" >&2
    exit 2
    ;;
esac
"""


def _step_script() -> str:
    workflow = yaml.safe_load(PUBLISH_WORKFLOW.read_text(encoding="utf-8"))
    steps = workflow["jobs"]["assemble-native-guard-distributions"]["steps"]
    return next(step["run"] for step in steps if step.get("name") == STEP_NAME)


def _run(tmp_path: Path, mode: str, release_wheel: str = WHEEL) -> tuple[subprocess.CompletedProcess[str], Path]:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    gh = bin_dir / "gh"
    gh.write_text(FAKE_GH, encoding="utf-8")
    gh.chmod(0o755)
    dist = tmp_path / "dist"
    dist.mkdir()
    (dist / WHEEL).write_text("rebuilt-bytes", encoding="utf-8")
    runner_temp = tmp_path / "runner-temp"
    runner_temp.mkdir()
    env = {
        **os.environ,
        "PATH": f"{bin_dir}{os.pathsep}{os.environ['PATH']}",
        "FAKE_GH_MODE": mode,
        "FAKE_RELEASE_WHEEL": release_wheel,
        "GITHUB_REPOSITORY": "example/repo",
        "GITHUB_STEP_SUMMARY": str(tmp_path / "summary.md"),
        "RUNNER_TEMP": str(runner_temp),
        "TMPDIR": str(runner_temp),
        "DIST_DIR": str(dist),
        "SOURCE_SHA": "0" * 40,
        "VERSION": "9.9.9",
    }
    result = subprocess.run(
        ["bash", "-c", _step_script()],
        cwd=runner_temp,
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    return result, dist


pytestmark = pytest.mark.skipif(
    os.name == "nt" or shutil.which("bash") is None or shutil.which("jq") is None,
    reason="the workflow step runs under bash with jq on Linux runners",
)


def test_verified_release_wheels_replace_the_rebuilt_bytes(tmp_path: Path) -> None:
    result, dist = _run(tmp_path, "ok")

    assert result.returncode == 0, result.stderr
    assert (dist / WHEEL).read_text(encoding="utf-8") == "release-bytes"


@pytest.mark.parametrize("mode", ["notfound", "nowheels"])
def test_a_release_without_wheels_keeps_the_rebuilt_wheels(tmp_path: Path, mode: str) -> None:
    result, dist = _run(tmp_path, mode)

    assert result.returncode == 0, result.stderr
    assert (dist / WHEEL).read_text(encoding="utf-8") == "rebuilt-bytes"


@pytest.mark.parametrize(
    ("mode", "release_wheel"),
    [
        ("outage", WHEEL),
        ("noprovenance", WHEEL),
        ("badattestation", WHEEL),
        ("ok", "hol_guard-9.9.9-py3-none-win_amd64.whl"),
    ],
)
def test_unverifiable_release_state_fails_without_touching_dist(
    tmp_path: Path, mode: str, release_wheel: str
) -> None:
    result, dist = _run(tmp_path, mode, release_wheel)

    assert result.returncode != 0
    assert (dist / WHEEL).read_text(encoding="utf-8") == "rebuilt-bytes"
