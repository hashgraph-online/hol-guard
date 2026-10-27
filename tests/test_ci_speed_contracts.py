"""Keep CI optimizations bound to trusted inputs and complete release proofs."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import time
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest
import yaml

from scripts.ci.pytest_duration_manifest import load_latest_duration_manifest, node_id_digest, write_duration_manifest
from tests.release_workflow_helpers import native_target_matrix, native_wheel_job
from tests.support.ci_workflow import expand_ci_job_actions

ROOT = Path(__file__).resolve().parents[1]


def _workflow(name: str) -> dict[str | bool, Any]:
    """Load expanded workflow definitions for CI contract assertions."""
    return expand_ci_job_actions(yaml.safe_load((ROOT / ".github/workflows" / name).read_text()))


def test_ci_checkouts_do_not_expose_credentials_to_project_code() -> None:
    workflow = _workflow("ci.yml")
    checkouts = [
        step
        for job in workflow["jobs"].values()
        for step in job.get("steps", [])
        if step.get("uses", "").startswith("actions/checkout@")
    ]

    assert checkouts
    assert all(step.get("with", {}).get("persist-credentials") is False for step in checkouts)


@pytest.mark.parametrize("filename", ["publish-mcpb.yml", "publish-mcp-registry.yml"])
def test_downstream_publication_requires_successful_same_repository_release(filename: str) -> None:
    """Privileged checkout depends on independently verified canonical run provenance."""
    workflow = _workflow(filename)
    # PyYAML's YAML 1.1 loader parses the unquoted Actions key as True.
    trigger = workflow[True]
    assert set(trigger) == {"workflow_run", "workflow_dispatch"}
    assert trigger["workflow_run"] == {
        "workflows": ["Publish to PyPI"],
        "types": ["completed"],
        "branches": ["main", "release/3.0", "v[0-9]+.[0-9]+.[0-9]+"],
    }
    assert trigger["workflow_dispatch"]["inputs"]["publication_run_id"]["required"] is True
    verifier = workflow["jobs"]["verify"]
    assert verifier["uses"] == "./.github/workflows/verify-mcp-release-source.yml"
    assert verifier["permissions"] == {"actions": "read", "contents": "read"}
    assert "secrets" not in verifier
    job = workflow["jobs"]["publish"]
    for gated_job in (verifier, job):
        assert "always()" not in gated_job["if"]
        for condition in (
            "github.event.workflow_run.conclusion == 'success'",
            'contains(fromJSON(\'["push", "workflow_dispatch"]\'), github.event.workflow_run.event)',
            "github.event.workflow_run.run_attempt == 1",
            "github.event.workflow_run.head_repository.full_name == github.repository",
            "github.event.workflow_run.head_branch)",
            "[skip release publish]",
        ):
            assert condition in gated_job["if"]
    assert "needs.verify.outputs.sha != ''" in job["if"]
    assert "needs.verify.outputs.branch != ''" in job["if"]
    assert "verify" in ([job["needs"]] if isinstance(job["needs"], str) else job["needs"])
    checkout = next(step for step in job["steps"] if step.get("uses", "").startswith("actions/checkout@"))
    assert checkout["with"]["ref"] == "${{ needs.verify.outputs.sha }}"
    assert checkout["with"]["persist-credentials"] is False
    release = next(step for step in job["steps"] if step.get("id") == "release")
    assert release["env"]["SOURCE_SHA"] == "${{ needs.verify.outputs.sha }}"
    assert release["env"]["SOURCE_REF"] == "refs/heads/${{ needs.verify.outputs.branch }}"
    assert 'git tag --points-at "$SOURCE_SHA"' in release["run"]
    if filename == "publish-mcpb.yml":
        validation = workflow["jobs"]["validate"]
        assert validation["needs"] == "verify"
        assert "always()" not in validation["if"]
        assert "pull_request" not in validation["if"]
        assert "needs.verify.outputs.sha != ''" in validation["if"]
        assert "needs.verify.outputs.branch != ''" in validation["if"]
        checkout = validation["steps"][0]
        assert checkout["with"]["ref"] == "${{ needs.verify.outputs.sha }}"
        assert checkout["with"]["persist-credentials"] is False
        assert "validate" in job["needs"]


@pytest.mark.parametrize(
    "script", ["scripts/build_native_hol_guard_wheel.py", "scripts/ci/native_approval_contract_gate.py"]
)
def test_native_wheel_helpers_run_without_site_packages(script: str) -> None:
    result = subprocess.run(
        [sys.executable, "-I", "-S", str(ROOT / script), "--help"],
        capture_output=True,
        text=True,
        timeout=15,
    )
    assert result.returncode == 0, result.stderr


def test_native_wheel_build_keeps_all_platforms_and_integrity_checks() -> None:
    job = native_wheel_job()
    assert len(native_target_matrix(job)) == 6
    selector = next(
        step for step in _workflow("publish.yml")["jobs"]["build"]["steps"] if step.get("id") == "native_wheel_matrix"
    )
    platforms = [leg["platform_tag"] for leg in json.loads(selector["env"]["NATIVE_WHEEL_MATRIX"])]
    assert platforms == [
        "manylinux_2_17_x86_64",
        "macosx_13_0_x86_64",
        "macosx_11_0_arm64",
        "win_amd64",
        "win_arm64",
        "manylinux_2_17_aarch64",
    ]
    assert 'select(.platform_tag != "win_arm64" and .platform_tag != "manylinux_2_17_aarch64")' in selector["run"]
    commands = "\n".join(step.get("run", "") for step in job["steps"])
    assert "uv sync" not in commands
    assert "pip install" not in commands
    assert "native_approval_contract_gate.py --root . --require-release-root" in commands
    assert '"$RUNTIME" self-test --json' in commands
    assert "python scripts/build_native_hol_guard_wheel.py" in commands


def test_duration_telemetry_uses_complete_push_manifest_on_target_branch() -> None:
    """Restore the newest complete push manifest, even when other main jobs failed."""
    workflow = _workflow("ci.yml")
    assert set(workflow[True]["pull_request"]["branches"]) <= set(workflow[True]["push"]["branches"])
    job = workflow["jobs"]["native-command-evaluators"]
    plan = next(step for step in job["steps"] if step.get("uses") == "./.github/actions/plan-pytest")
    assert plan["with"]["telemetry-branch"] == "${{ github.event.pull_request.base.ref || github.ref_name }}"
    action = expand_ci_job_actions(yaml.safe_load((ROOT / ".github/actions/plan-pytest/action.yml").read_text()))
    restore = next(step for step in action["runs"]["steps"] if step.get("id") == "latest-duration-telemetry")
    assert restore["env"]["TELEMETRY_BRANCH"] == "${{ inputs.telemetry-branch }}"
    command = restore["run"]
    assert restore["continue-on-error"] is True
    assert command.splitlines()[0] == (
        "timeout --signal=KILL 5s bash --noprofile --norc -e -o pipefail -s <<'DURATION_TELEMETRY'"
    )
    assert command.splitlines()[-1] == "DURATION_TELEMETRY"
    # Only a run whose every coverage shard passed and reported publishes this
    # artifact, so requiring a fully green run would only make timings stale.
    assert "/actions/workflows/ci.yml/runs" in command
    assert '-f branch="$TELEMETRY_BRANCH" -f event=push' in command
    assert '.event == "push" and .head_branch == env.TELEMETRY_BRANCH' in command
    assert '.path == ".github/workflows/ci.yml"' in command
    assert "/actions/runs/${run_id}/artifacts" in command
    assert "-f name=pytest-duration-manifest-candidate" in command
    assert "status=success" not in command
    assert "conclusion" not in command
    assert 'test -n "$artifact_id"' in command
    assert "release/3.0" not in command


@pytest.mark.skipif(os.name == "nt" or not shutil.which("timeout"), reason="Linux telemetry uses GNU timeout and Bash")
@pytest.mark.parametrize("mode", ["valid", "missing", "corrupt", "hung-parent", "hung-grandchild"])
def test_optional_duration_restore_is_bounded_and_publishes_only_valid_complete_bytes(
    tmp_path: Path, mode: str
) -> None:
    action = yaml.safe_load((ROOT / ".github/actions/plan-pytest/action.yml").read_text())
    restore = next(step for step in action["runs"]["steps"] if step.get("id") == "latest-duration-telemetry")
    # Isolate the action's fixed temporary paths without changing its commands.
    temporary = tmp_path / "temporary"
    temporary.mkdir()
    command = restore["run"].replace("/tmp/", f"{temporary}/")
    now = datetime(2026, 10, 23, 12, tzinfo=timezone.utc)
    fallback = tmp_path / "committed.json.gz"
    write_duration_manifest(fallback, {"tests/test_example.py::test_one": 3.0}, now - timedelta(days=1))
    downloaded = tmp_path / "downloaded.json.gz"
    write_duration_manifest(downloaded, {"tests/test_example.py::test_one": 7.0}, now - timedelta(hours=1))
    archive = tmp_path / "artifact.zip"
    with zipfile.ZipFile(archive, "w") as zipped:
        zipped.writestr(
            "pytest-duration-manifest-candidate.json.gz", downloaded.read_bytes() if mode != "corrupt" else b"bad gzip"
        )
    bindir = tmp_path / "bin"
    bindir.mkdir()
    descendant = bindir / "descendant.py"
    descendant.write_text(
        "import os, signal, subprocess, sys, time\n"
        "from pathlib import Path\n"
        "signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
        "with Path(os.environ['PROCESS_RECORDS']).open('a') as record:\n"
        "    record.write(f'{sys.argv[1]} {os.getpid()} {os.getpgrp()}\\n')\n"
        "if sys.argv[1] == 'child':\n"
        "    subprocess.run([sys.executable, __file__, 'grandchild'], check=True,\n"
        "                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)\n"
        "else:\n"
        "    Path(os.environ['CHILD_READY']).touch()\n"
        "    time.sleep(7)\n"
        "    Path(os.environ['LATE_PUBLICATION']).write_text('late')\n"
    )
    gh = bindir / "gh"
    gh.write_text(
        f"#!{sys.executable}\n"
        "import os, signal, subprocess, sys, time\n"
        "from pathlib import Path\n"
        "args = ' '.join(sys.argv[1:])\n"
        "if '/workflows/ci.yml/runs' in args:\n"
        "    if os.environ['MODE'].startswith('hung'):\n"
        "        if os.environ['MODE'] == 'hung-parent': signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
        "        with Path(os.environ['PROCESS_RECORDS']).open('a') as record:\n"
        "            record.write(f'parent {os.getpid()} {os.getpgrp()}\\n')\n"
        "        subprocess.run([sys.executable, os.environ['DESCENDANT'], 'child'], check=True,\n"
        "                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)\n"
        "    else: print('101\\n100')\n"
        "elif '/runs/100/artifacts' in args and os.environ['MODE'] != 'missing': print('123')\n"
        "elif '/artifacts/123/zip' in args: sys.stdout.buffer.write(Path(os.environ['ARCHIVE']).read_bytes())\n",
        encoding="utf-8",
    )
    gh.chmod(0o755)
    published = tmp_path / "pytest-duration-manifest.latest.json.gz"
    child_ready = tmp_path / "child-ready"
    process_records = tmp_path / "process-records"
    sentinel = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(20)"], start_new_session=True)
    started = time.monotonic()
    try:
        result = subprocess.run(
            ["bash", "--noprofile", "--norc", "-e", "-o", "pipefail", "-c", command],
            cwd=tmp_path,
            env={
                **os.environ,
                "PATH": f"{bindir}{os.pathsep}{os.environ['PATH']}",
                "GITHUB_REPOSITORY": "owner/repo",
                "TELEMETRY_BRANCH": "main",
                "MODE": mode,
                "ARCHIVE": str(archive),
                "CHILD_READY": str(child_ready),
                "LATE_PUBLICATION": str(published),
                "DESCENDANT": str(descendant),
                "PROCESS_RECORDS": str(process_records),
            },
            capture_output=True,
            timeout=10,
        )
        assert sentinel.poll() is None
        if mode.startswith("hung"):
            records = [line.split() for line in process_records.read_text().splitlines()]
            assert {record[0] for record in records} == {"parent", "child", "grandchild"}
            assert len({record[2] for record in records}) == 1
            assert int(records[0][2]) not in {os.getpgrp(), os.getpgid(sentinel.pid)}
            for _role, pid, _group in records:
                state = subprocess.run(["ps", "-o", "stat=", "-p", pid], capture_output=True, text=True).stdout.strip()
                assert not state or state.startswith("Z"), (pid, state)
    finally:
        sentinel.terminate()
        sentinel.wait(timeout=5)
    elapsed = time.monotonic() - started
    if mode == "valid":
        assert result.returncode == 0, result.stderr
        assert published.read_bytes() == downloaded.read_bytes()
        expected = 7.0
    else:
        assert result.returncode != 0
        if mode.startswith("hung"):
            assert result.returncode == 137
            assert child_ready.exists()
            assert 5 <= elapsed < 8
            # A surviving TERM-resistant descendant would publish at seven seconds.
            time.sleep(max(0, 7.5 - elapsed))
        assert not published.exists()
        expected = 3.0
    durations, selected = load_latest_duration_manifest([fallback, published], now=now, max_age=timedelta(days=28))
    assert selected == (published if mode == "valid" else fallback)
    assert durations == {node_id_digest("tests/test_example.py::test_one"): expected}
