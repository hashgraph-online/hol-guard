"""Serialize writers to each immutable platform asset set while platforms run in parallel."""

import json
import os
import subprocess
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize(
    ("name", "publisher", "platform"),
    [
        ("desktop-core-alpha-feed.yml", "publish-macos-arm64", "macos-arm64"),
        ("desktop-core-linux-feed.yml", "publish-linux-x64", "linux-x64"),
    ],
)
def test_platform_feed_writer_queue_retains_pending_versions(name: str, publisher: str, platform: str) -> None:
    workflow = Path(__file__).resolve().parents[1] / ".github" / "workflows" / name
    config = yaml.safe_load(workflow.read_text(encoding="utf-8"))
    assert "concurrency" not in config
    assert "concurrency" not in config["jobs"]["validate"]
    assert config["jobs"][publisher]["concurrency"] == {
        "group": f"desktop-core-stable-feed-{platform}",
        "cancel-in-progress": False,
        "queue": "max",
    }
    writers = [name for name, job in config["jobs"].items() if job["permissions"]["contents"] == "write"]
    assert writers == [publisher]
    assert "github.event_name != 'pull_request'" in config["jobs"][publisher]["if"]
    assert "tests/test_desktop_core_feed_queue.py" in config[True]["pull_request"]["paths"]
    commands = "\n".join(step.get("run", "") for step in config["jobs"][publisher]["steps"])
    assert "gh release upload" in commands
    assert "gh release edit" not in commands
    assert "gh release create" not in commands


@pytest.mark.parametrize(
    ("name", "publisher"),
    [
        ("desktop-core-alpha-feed.yml", "publish-macos-arm64"),
        ("desktop-core-linux-feed.yml", "publish-linux-x64"),
    ],
)
def test_trusted_dispatch_skips_relint_but_other_events_require_it(name: str, publisher: str) -> None:
    workflow = Path(__file__).resolve().parents[1] / ".github" / "workflows" / name
    config = yaml.safe_load(workflow.read_text(encoding="utf-8"))
    assert config["jobs"]["validate"]["if"] == "github.event_name != 'workflow_dispatch'"
    job = config["jobs"][publisher]
    assert job["needs"] == "validate"
    condition = job["if"]
    assert condition.startswith("${{ !cancelled() && github.event_name != 'pull_request' &&")
    assert "needs.validate.result == 'success' ||" in condition
    assert "(github.event_name == 'workflow_dispatch' && needs.validate.result == 'skipped')" in condition


def _release(tag: str, *, prerelease: bool = False) -> dict[str, object]:
    version = tag[1:]
    names = [f"hol_guard-{version}-py3-none-macosx_11_0_arm64.whl", f"hol-guard-v{version}.intoto.jsonl"]
    return {
        "tag_name": tag,
        "draft": False,
        "prerelease": prerelease,
        "assets": [{"name": name, "state": "uploaded"} for name in names],
    }


RELEASES = [_release("v1.3.0", prerelease=True), _release("v1.2.4"), _release("v1.2.3")]


def _discover(tmp_path: Path, requested: str) -> subprocess.CompletedProcess[str]:
    stubs = tmp_path / "bin"
    stubs.mkdir()
    fixtures = tmp_path / "fixtures"
    fixtures.mkdir()
    (fixtures / "list.json").write_text(json.dumps(RELEASES), encoding="utf-8")
    for release in RELEASES:
        (fixtures / f"{release['tag_name']}.json").write_text(json.dumps(release), encoding="utf-8")
    gh = stubs / "gh"
    # Emulates `gh api [--paginate] <path> --jq <filter>` against the fixtures and logs each request path.
    gh.write_text(
        "#!/bin/bash\n"
        "set -euo pipefail\n"
        "args=(\"$@\")\n"
        "path=''; filter=''\n"
        "for ((i = 0; i < ${#args[@]}; i++)); do\n"
        "  case \"${args[i]}\" in\n"
        "    --jq) filter=\"${args[i + 1]}\"; i=$((i + 1)) ;;\n"
        "    repos/*) path=\"${args[i]}\" ;;\n"
        "  esac\n"
        "done\n"
        "echo \"$path\" >> \"$RUNNER_TEMP/gh-requests.txt\"\n"
        "case \"$path\" in\n"
        "  */releases/tags/*) fixture=\"$FIXTURES/${path##*/}.json\" ;;\n"
        "  */releases\\?per_page=100) fixture=\"$FIXTURES/list.json\" ;;\n"
        "  *) exit 2 ;;\n"
        "esac\n"
        "test -f \"$fixture\" || { echo 'HTTP 404: Not Found' >&2; exit 1; }\n"
        "jq -c \"$filter\" \"$fixture\"\n",
        encoding="utf-8",
    )
    gh.chmod(0o755)
    env = {
        **os.environ,
        "PATH": f"{stubs}{os.pathsep}{os.environ['PATH']}",
        "RUNNER_TEMP": str(tmp_path),
        "FIXTURES": str(fixtures),
        "GITHUB_REPOSITORY": "example/core",
        "REQUESTED_CORE_VERSION": requested,
    }
    return subprocess.run(
        ["bash", str(ROOT / "scripts" / "release" / "discover_core_release.sh"), "macosx_.*_arm64"],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )


def test_named_core_version_reads_only_that_release(tmp_path: Path) -> None:
    result = _discover(tmp_path, "1.2.3")
    assert result.returncode == 0, result.stderr
    assert "version=1.2.3\ntag=v1.2.3\n" in result.stdout
    assert (tmp_path / "gh-requests.txt").read_text(encoding="utf-8").split() == ["repos/example/core/releases/tags/v1.2.3"]


def test_unnamed_discovery_scans_all_releases_for_the_newest_stable(tmp_path: Path) -> None:
    result = _discover(tmp_path, "")
    assert result.returncode == 0, result.stderr
    assert "version=1.2.4\ntag=v1.2.4\n" in result.stdout
    assert (tmp_path / "gh-requests.txt").read_text(encoding="utf-8").split() == [
        "repos/example/core/releases?per_page=100"
    ]


@pytest.mark.parametrize("requested", ["1.3.0", "1.2.9", "1.2", "v1.2.3", "1.2.3/../x"])
def test_named_discovery_rejects_unpublished_prerelease_or_malformed_versions(tmp_path: Path, requested: str) -> None:
    result = _discover(tmp_path, requested)
    assert result.returncode != 0
    assert "available=true" not in result.stdout


@pytest.mark.parametrize(
    ("name", "platform"),
    [("desktop-core-alpha-feed.yml", "macosx_.*_arm64"), ("desktop-core-linux-feed.yml", "manylinux_.*_x86_64")],
)
def test_feeds_discover_through_the_shared_script(name: str, platform: str) -> None:
    config = yaml.safe_load((ROOT / ".github" / "workflows" / name).read_text(encoding="utf-8"))
    publisher = next(job for job_name, job in config["jobs"].items() if job_name != "validate")
    step = next(step for step in publisher["steps"] if step.get("id") == "release")
    assert step["run"] == f"bash scripts/release/discover_core_release.sh '{platform}' >> \"$GITHUB_OUTPUT\""
    assert step["env"]["REQUESTED_CORE_VERSION"] == "${{ inputs.core_version || '' }}"
    for trigger in ("pull_request", "push"):
        assert "scripts/release/discover_core_release.sh" in config[True][trigger]["paths"]
