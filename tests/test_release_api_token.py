"""Contracts for the release GitHub App token and the rate-limit-only gh retry."""

from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path

import pytest

from tests.release_workflow_helpers import PUBLISH_WORKFLOW, ROOT, load_workflow

ACTION_DIR = ROOT / ".github" / "actions" / "release-api-token"
RETRY_SCRIPT = ACTION_DIR / "gh-retry.sh"
WORKFLOWS = ROOT / ".github" / "workflows"
RELEASE_PLEASE_WORKFLOW = WORKFLOWS / "release-please.yml"
DELETE_ALPHA_WORKFLOW = WORKFLOWS / "delete-alpha-release.yml"
CORE_FEED_WORKFLOW = WORKFLOWS / "desktop-core-alpha-feed.yml"
APP_TOKEN_ACTION = "actions/create-github-app-token@bcd2ba49218906704ab6c1aa796996da409d3eb1"
TOOLING_ACTION = "./.release-api-token/.github/actions/release-api-token"
LOCAL_ACTION = "./.github/actions/release-api-token"
WORKFLOW_TOKEN = "${{ github.token }}"
PRIMARY_LIMIT = "gh: API rate limit exceeded for installation ID 1. (HTTP 403)"

FAKE_GH = """#!/usr/bin/env bash
if [[ "$1 $2" == "api rate_limit" ]]; then
  if [[ -n "${FAKE_RESET_IN:-}" ]]; then
    echo $(( $(date +%s) + FAKE_RESET_IN ))
    exit 0
  fi
  exit 1
fi
count=$(( $(cat "$FAKE_STATE/count" 2>/dev/null || echo 0) + 1 ))
echo "$count" > "$FAKE_STATE/count"
if [[ "$count" -le "${FAKE_FAILURES:-0}" ]]; then
  echo "$FAKE_ERROR" >&2
  exit "${FAKE_EXIT:-1}"
fi
echo "ok $*"
"""

FAKE_SLEEP = """#!/usr/bin/env bash
echo "$1" >> "$FAKE_STATE/sleeps"
"""


def _write_executable(path: Path, content: str) -> None:
    path.write_text(content, encoding="utf-8")
    path.chmod(0o755)


@pytest.fixture
def fake_bin(tmp_path: Path) -> Path:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    _write_executable(bin_dir / "gh", FAKE_GH)
    _write_executable(bin_dir / "sleep", FAKE_SLEEP)
    return bin_dir


def _run_retry(fake_bin: Path, *, failures: int = 0, error: str = PRIMARY_LIMIT, **env: str):
    state = fake_bin.parent
    run_env = {
        **os.environ,
        "PATH": f"{fake_bin}{os.pathsep}{os.environ['PATH']}",
        "FAKE_STATE": str(state),
        "FAKE_FAILURES": str(failures),
        "FAKE_ERROR": error,
        "GH_RETRY_REAL_GH": str(fake_bin / "gh"),
        **env,
    }
    result = subprocess.run(
        ["bash", str(RETRY_SCRIPT), "api", "repos/o/r/git/refs"],
        capture_output=True,
        text=True,
        env=run_env,
        check=False,
    )
    count_file = state / "count"
    sleeps_file = state / "sleeps"
    calls = int(count_file.read_text()) if count_file.exists() else 0
    sleeps = [int(line) for line in sleeps_file.read_text().split()] if sleeps_file.exists() else []
    return result, calls, sleeps


def test_retry_passes_success_through_untouched(fake_bin: Path) -> None:
    result, calls, sleeps = _run_retry(fake_bin)

    assert result.returncode == 0
    assert result.stdout == "ok api repos/o/r/git/refs\n"
    assert calls == 1
    assert sleeps == []


@pytest.mark.parametrize(
    "error",
    [
        "HTTP 404: Not Found (https://api.github.com/repos/o/r/git/ref/tags/x)",
        "HTTP 403: Resource not accessible by integration",
        "HTTP 422: Reference already exists",
    ],
)
def test_retry_never_repeats_failures_that_are_not_rate_limits(fake_bin: Path, error: str) -> None:
    result, calls, sleeps = _run_retry(fake_bin, failures=1, error=error, FAKE_EXIT="4")

    assert result.returncode == 4
    assert error in result.stderr
    assert "gh-retry" not in result.stderr
    assert calls == 1
    assert sleeps == []


def test_primary_rate_limit_waits_for_the_reported_reset(fake_bin: Path) -> None:
    result, calls, sleeps = _run_retry(fake_bin, failures=2, FAKE_RESET_IN="30")

    assert result.returncode == 0
    assert result.stdout == "ok api repos/o/r/git/refs\n"
    assert PRIMARY_LIMIT not in result.stderr
    assert result.stderr.count("gh-retry: primary rate limit") == 2
    assert calls == 3
    assert len(sleeps) == 2
    assert all(30 <= delay <= 32 for delay in sleeps)


@pytest.mark.parametrize(
    "error",
    [
        "HTTP 403: You have exceeded a secondary rate limit. Please wait a few minutes before you try again.",
        "HTTP 429: Too Many Requests",
    ],
)
def test_secondary_rate_limit_backs_off_exponentially(fake_bin: Path, error: str) -> None:
    result, calls, sleeps = _run_retry(fake_bin, failures=3, error=error)

    assert result.returncode == 0
    assert result.stderr.count("gh-retry: secondary rate limit") == 3
    assert calls == 4
    assert sleeps == [60, 120, 240]


def test_retry_gives_up_after_the_attempt_limit_with_gh_status(fake_bin: Path) -> None:
    result, calls, sleeps = _run_retry(fake_bin, failures=99, FAKE_EXIT="1", GH_RETRY_MAX_ATTEMPTS="3")

    assert result.returncode == 1
    assert PRIMARY_LIMIT in result.stderr
    assert "still rate limited after 3 attempts" in result.stderr
    assert calls == 3
    assert len(sleeps) == 2


def test_retry_fails_closed_when_the_reset_exceeds_the_budget(fake_bin: Path) -> None:
    result, calls, sleeps = _run_retry(fake_bin, failures=1, FAKE_RESET_IN="5000")

    assert result.returncode == 1
    assert PRIMARY_LIMIT in result.stderr
    assert "beyond the 3900s retry budget" in result.stderr
    assert calls == 1
    assert sleeps == []


def test_retry_caps_secondary_backoff_and_total_wait(fake_bin: Path) -> None:
    error = "You have exceeded a secondary rate limit"
    result, calls, sleeps = _run_retry(fake_bin, failures=99, error=error, GH_RETRY_MAX_WAIT_SECONDS="2000")

    assert result.returncode == 1
    assert sleeps == [60, 120, 240, 480, 900]
    assert "beyond the 2000s retry budget" not in result.stderr
    assert "still rate limited after 6 attempts" in result.stderr
    assert calls == 6


def _composite() -> dict[object, object]:
    return load_workflow(ACTION_DIR / "action.yml")


def _composite_step(name: str) -> dict[str, object]:
    return next(step for step in _composite()["runs"]["steps"] if step.get("name") == name)


def test_composite_mints_a_pinned_scoped_app_token_or_uses_the_workflow_token() -> None:
    action = _composite()
    mint = _composite_step("Mint release App installation token")

    assert action["runs"]["using"] == "composite"
    assert mint["uses"].split(" ")[0] == APP_TOKEN_ACTION
    assert mint["if"] == "steps.config.outputs.app == 'true'"
    assert mint["continue-on-error"] == "${{ inputs.fallback-on-error == 'true' }}"
    assert mint["with"] == {
        "client-id": "${{ inputs.client-id }}",
        "private-key": "${{ inputs.private-key }}",
        "permission-contents": "${{ inputs.permission-contents }}",
        "permission-pull-requests": "${{ inputs.permission-pull-requests }}",
    }
    assert action["inputs"]["permission-contents"]["default"] == "read"
    assert action["inputs"]["fallback-on-error"]["default"] == "false"
    assert action["outputs"]["token"]["value"] == "${{ steps.mint.outputs.token || github.token }}"
    config = _composite_step("Read release App configuration")["run"]
    assert '"$HAS_CLIENT_ID" == "true" && "$HAS_PRIVATE_KEY" == "true"' in config
    report = _composite_step("Report release API token source")
    assert "token }}" not in report["run"]
    assert set(report["env"]) == {"APP_CONFIGURED", "MINT_OUTCOME", "PERMISSION_CONTENTS", "PERMISSION_PULL_REQUESTS"}


def test_composite_installs_the_retry_wrapper_once(tmp_path: Path, fake_bin: Path) -> None:
    step = _composite_step("Route gh through the rate-limit retry wrapper")
    runner_temp = tmp_path / "runner"
    runner_temp.mkdir()
    github_path = tmp_path / "github_path"
    env = {
        **os.environ,
        "PATH": f"{fake_bin}{os.pathsep}{os.environ['PATH']}",
        "RUNNER_TEMP": str(runner_temp),
        "GITHUB_PATH": str(github_path),
        "RETRY_SCRIPT": str(RETRY_SCRIPT),
        "FAKE_STATE": str(tmp_path),
    }

    for _ in range(2):
        subprocess.run(["bash", "-e", "-c", step["run"]], env=env, check=True)

    wrapper_dir = runner_temp / "release-gh-bin"
    assert github_path.read_text().splitlines() == [str(wrapper_dir)]
    wrapped = subprocess.run(
        [str(wrapper_dir / "gh"), "release", "view", "v1"],
        capture_output=True,
        text=True,
        env={**env, "PATH": f"{wrapper_dir}{os.pathsep}{env['PATH']}"},
        check=True,
    )
    assert wrapped.stdout == "ok release view v1\n"


def _steps(path: Path, job: str) -> list[dict[str, object]]:
    return load_workflow(path)["jobs"][job]["steps"]


def _step(steps: list[dict[str, object]], name: str) -> dict[str, object]:
    return next(step for step in steps if step.get("name") == name)


APP_TOKEN_STEPS = [
    (PUBLISH_WORKFLOW, "reserve-alpha-tag", "release-token", "write", None, ["Reserve exact alpha tag"]),
    (
        PUBLISH_WORKFLOW,
        "publish-alpha-testpypi",
        "release-token",
        "read",
        None,
        ["Revalidate alpha source before TestPyPI"],
    ),
    (
        PUBLISH_WORKFLOW,
        "publish-alpha-pypi",
        "release-token",
        "read",
        None,
        ["Revalidate alpha publication authorization"],
    ),
    (
        PUBLISH_WORKFLOW,
        "release-unpublished-alpha-reservation",
        "release-token",
        "write",
        None,
        ["Delete unpublished reservation tag"],
    ),
    (
        PUBLISH_WORKFLOW,
        "reserve-main-tag",
        "release-token",
        "write",
        None,
        ["Bind stable tag to the exact main source"],
    ),
    (
        PUBLISH_WORKFLOW,
        "release-main",
        "release-token",
        "write",
        "read",
        ["Generate release notes", "Create discoverable main release"],
    ),
    (
        PUBLISH_WORKFLOW,
        "release-alpha",
        "release-token",
        "write",
        "read",
        ["Generate release notes"],
    ),
    (
        PUBLISH_WORKFLOW,
        "release-alpha",
        "release-token-after-pypi",
        "write",
        "read",
        ["Create discoverable alpha prerelease"],
    ),
    (
        DELETE_ALPHA_WORKFLOW,
        "delete",
        "release-token",
        "write",
        None,
        ["Confirm the tag is a prerelease cut from main", "Delete the GitHub prerelease and tag"],
    ),
    (
        CORE_FEED_WORKFLOW,
        "publish-macos-arm64",
        "release-token-read",
        "read",
        None,
        [
            "Discover newest published stable Core release, or the exact requested alpha prerelease",
            "Inspect immutable Core asset state",
            "Download existing Core assets",
        ],
    ),
    (
        CORE_FEED_WORKFLOW,
        "publish-macos-arm64",
        "release-token-write",
        "write",
        None,
        ["Require alpha prerelease and tag to still be published", "Publish immutable Core assets"],
    ),
]


@pytest.mark.parametrize(("path", "job", "token_id", "contents", "pull_requests", "users"), APP_TOKEN_STEPS)
def test_release_api_calls_use_a_scoped_app_token_minted_before_use(
    path: Path, job: str, token_id: str, contents: str, pull_requests: str | None, users: list[str]
) -> None:
    steps = _steps(path, job)
    index = next(i for i, step in enumerate(steps) if step.get("id") == token_id)
    select = steps[index]
    expected = {
        "client-id": "${{ vars.HOL_RELEASE_APP_CLIENT_ID }}",
        "private-key": "${{ secrets.HOL_RELEASE_APP_PRIVATE_KEY }}",
        "permission-contents": contents,
    }
    if pull_requests:
        expected["permission-pull-requests"] = pull_requests
    if job in {"release-unpublished-alpha-reservation", "release-main", "release-alpha"}:
        expected["fallback-on-error"] = "true"

    assert select["uses"] in {TOOLING_ACTION, LOCAL_ACTION}
    assert select["with"] == expected
    for name in users:
        assert steps.index(_step(steps, name)) > index
        assert _step(steps, name)["env"]["GH_TOKEN"] == f"${{{{ steps.{token_id}.outputs.token }}}}"


@pytest.mark.parametrize(
    ("path", "job"),
    [(path, job) for path, job, *_ in APP_TOKEN_STEPS if path != CORE_FEED_WORKFLOW]
    + [(RELEASE_PLEASE_WORKFLOW, "dispatch-alpha-publish"), (PUBLISH_WORKFLOW, "wake-alpha-core-feed")],
)
def test_tooling_comes_from_the_workflow_commit_after_the_source_checkout(path: Path, job: str) -> None:
    steps = _steps(path, job)
    action_index = next(i for i, step in enumerate(steps) if step.get("uses") in {TOOLING_ACTION, LOCAL_ACTION})
    checkouts = [i for i, step in enumerate(steps) if str(step.get("uses", "")).startswith("actions/checkout@")]

    if steps[action_index]["uses"] == LOCAL_ACTION:
        root = steps[checkouts[0]]
        assert checkouts[0] < action_index
        assert "ref" not in root.get("with", {})
        return
    tooling = _step(steps, "Check out release API token tooling")
    tooling_index = steps.index(tooling)
    assert tooling["with"] == {
        "ref": "${{ github.sha }}",
        "fetch-depth": 1,
        "persist-credentials": False,
        "path": ".release-api-token",
        "sparse-checkout": ".github/actions/release-api-token",
        "sparse-checkout-cone-mode": False,
    }
    assert tooling_index < action_index
    assert all(i < tooling_index for i in checkouts if i != tooling_index)


def test_dispatches_keep_the_workflow_token_for_actor_gates() -> None:
    dispatches = 0
    for path in WORKFLOWS.glob("*.yml"):
        for job in load_workflow(path)["jobs"].values():
            for step in job.get("steps", []):
                if "gh workflow run" in str(step.get("run", "")):
                    dispatches += 1
                    assert step["env"]["GH_TOKEN"] in {WORKFLOW_TOKEN, "${{ secrets.GITHUB_TOKEN }}"}, path.name

    assert dispatches >= 4
    for path, job in ((RELEASE_PLEASE_WORKFLOW, "dispatch-alpha-publish"), (PUBLISH_WORKFLOW, "wake-alpha-core-feed")):
        wrapper = _step(_steps(path, job), "Route gh through the rate-limit retry wrapper")
        assert wrapper["uses"] == TOOLING_ACTION
        assert "with" not in wrapper


def test_attestation_verification_keeps_the_workflow_token() -> None:
    for path in (PUBLISH_WORKFLOW, DELETE_ALPHA_WORKFLOW, CORE_FEED_WORKFLOW, RELEASE_PLEASE_WORKFLOW):
        for job in load_workflow(path)["jobs"].values():
            for step in job.get("steps", []):
                run = str(step.get("run", ""))
                token = step.get("env", {}).get("GH_TOKEN")
                if "gh attestation verify" not in run or token in {None, WORKFLOW_TOKEN}:
                    continue
                assert step["env"]["WORKFLOW_GH_TOKEN"] == WORKFLOW_TOKEN
                for line in run.splitlines():
                    if "gh attestation verify" in line:
                        assert 'GH_TOKEN="$WORKFLOW_GH_TOKEN" gh attestation verify' in line, step["name"]


def test_package_and_publication_records_stay_on_the_workflow_token() -> None:
    delete_steps = _steps(DELETE_ALPHA_WORKFLOW, "delete")
    release_main = _steps(PUBLISH_WORKFLOW, "release-main")
    record = "Record completed stable publication for future repairs and backfills"
    core_inputs = _step(
        _steps(PUBLISH_WORKFLOW, "publish-main-assets"), "Publish and remotely verify immutable package inputs"
    )

    assert _step(delete_steps, "Delete the alpha container image tag")["env"]["GH_TOKEN"] == WORKFLOW_TOKEN
    assert _step(release_main, record)["env"]["GH_TOKEN"] == WORKFLOW_TOKEN
    assert core_inputs["env"]["GH_TOKEN"] == WORKFLOW_TOKEN


def test_jobs_that_retry_rate_limits_leave_room_for_one_reset() -> None:
    for path, job in (
        (DELETE_ALPHA_WORKFLOW, "delete"),
        (PUBLISH_WORKFLOW, "wake-alpha-core-feed"),
    ):
        assert load_workflow(path)["jobs"][job]["timeout-minutes"] >= 70
    wait = re.search(r"GH_RETRY_MAX_WAIT_SECONDS:-(\d+)", RETRY_SCRIPT.read_text(encoding="utf-8"))
    assert wait is not None
    assert int(wait.group(1)) <= 70 * 60


def test_core_feed_runs_when_the_token_action_changes() -> None:
    triggers = load_workflow(CORE_FEED_WORKFLOW)[True]

    assert ".github/actions/release-api-token/**" in triggers["pull_request"]["paths"]
    assert ".github/actions/release-api-token/**" in triggers["push"]["paths"]
