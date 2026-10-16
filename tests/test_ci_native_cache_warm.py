"""Warm trusted native caches without serializing unrelated CI work."""

from pathlib import Path

import yaml

from tests.support.ci_workflow import load_ci_workflow

ROOT = Path(__file__).resolve().parents[1]


def test_warmer_runs_only_on_relevant_main_pushes_and_has_its_own_queue() -> None:
    warm = yaml.safe_load((ROOT / ".github/workflows/native-ci-cache-warm.yml").read_text())
    ci = load_ci_workflow()
    assert set(warm[True]) == {"push"}
    assert warm[True]["push"]["branches"] == ["main"]
    paths = warm[True]["push"]["paths"]
    for source in ("rust/**", "contributions/**", "contracts/**", "spec/**"):
        assert source in paths
    for action in (
        "setup-rust",
        "ci-job-native-command-build",
        "ci-job-macos-native-runtime",
        "ci-job-windows-native-runtime",
    ):
        assert f".github/actions/{action}/**" in paths
    assert ".github/workflows/ci.yml" in paths
    assert warm["permissions"] == {"contents": "read"}
    assert warm["concurrency"]["group"] != ci["concurrency"]["group"]
    assert warm["concurrency"]["cancel-in-progress"] is False
    assert set(warm["jobs"]) == {"linux", "macos", "windows"}
    assert all("needs" not in job and "secrets" not in job for job in warm["jobs"].values())


def test_warmer_and_ci_share_builds_profiles_and_per_commit_deduplication() -> None:
    raw_ci = yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text())
    warm = yaml.safe_load((ROOT / ".github/workflows/native-ci-cache-warm.yml").read_text())
    for flag in ("CARGO_PROFILE_RELEASE_LTO", "CARGO_PROFILE_RELEASE_CODEGEN_UNITS"):
        assert warm["env"][flag] == raw_ci["env"][flag]
    assert "CARGO_PROFILE_RELEASE_OPT_LEVEL" not in warm["env"]
    for platform, producer, action in (
        ("linux", "native-command-evaluators", "ci-job-native-command-build"),
        ("macos", "macos-native-runtime", "ci-job-macos-native-runtime"),
        ("windows", "windows-native-runtime", "ci-job-windows-native-runtime"),
    ):
        job, required = warm["jobs"][platform], raw_ci["jobs"][producer]
        assert job["runs-on"] == required["runs-on"]
        if platform == "linux":
            planning = next(step for step in required["steps"] if step.get("uses") == "./.github/actions/plan-pytest")
            assert planning["timeout-minutes"] == 5
            assert required["timeout-minutes"] == job["timeout-minutes"] + planning["timeout-minutes"]
        else:
            assert job["timeout-minutes"] == required["timeout-minutes"]
        assert job["concurrency"] == {
            "group": f"native-ci-build-${{{{ github.sha }}}}-{platform}",
            "cancel-in-progress": False,
        }
        # Other workflows can build the same SHA; they must not displace a
        # required producer from the single pending slot in the shared group.
        assert required["concurrency"] == {
            "group": "${{ (github.event_name == 'push' && github.ref == 'refs/heads/main') "
            f"&& format('native-ci-build-{{0}}-{platform}', github.sha) "
            f"|| format('native-ci-build-run-{{0}}-{platform}', github.run_id) }}}}",
            "cancel-in-progress": False,
        }
        assert f"./.github/actions/{action}" in [step.get("uses") for step in job["steps"]]
        assert f"./.github/actions/{action}" in [step.get("uses") for step in required["steps"]]
        checkout = job["steps"][0]
        assert checkout["uses"].startswith("actions/checkout@")
        assert checkout["with"] == {"persist-credentials": False}
        assert producer in raw_ci["jobs"]["required"]["needs"]
    # Capacity changes must not silently collapse the behavioral matrix.
    assert raw_ci["env"]["CI_PYTEST_COVERAGE_SHARDS"] == "64"
    assert len(raw_ci["jobs"]["macos-gates"]["strategy"]["matrix"]["shard-index"]) == 12
