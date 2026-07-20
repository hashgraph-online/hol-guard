"""Contracts for installed same-repository pull-request canaries."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import cast

import yaml

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW_PATH = ROOT / ".github/workflows/publish.yml"
MANIFEST_PATH = ROOT / "release-metadata/release-22-installed-evidence.json"


def _mapping(value: object) -> dict[str, object]:
    mapping = _raw_mapping(value)
    assert all(isinstance(key, str) for key in mapping)
    return cast(dict[str, object], mapping)


def _raw_mapping(value: object) -> dict[object, object]:
    assert isinstance(value, dict)
    return cast(dict[object, object], value)


def _sequence(value: object) -> list[object]:
    assert isinstance(value, list)
    return cast(list[object], value)


def _text(value: object) -> str:
    assert isinstance(value, str)
    return value


def _workflow() -> dict[object, object]:
    decoded = cast(object, yaml.safe_load(WORKFLOW_PATH.read_text(encoding="utf-8")))
    return _raw_mapping(decoded)


def _job(name: str) -> dict[str, object]:
    return _mapping(_mapping(_workflow()["jobs"])[name])


def _steps(container: dict[str, object]) -> list[dict[str, object]]:
    return [_mapping(step) for step in _sequence(container["steps"])]


def _named_step(steps: list[dict[str, object]], name: str) -> dict[str, object]:
    return next(step for step in steps if step.get("name") == name)


def _action_step(steps: list[dict[str, object]], prefix: str) -> dict[str, object]:
    return next(step for step in steps if str(step.get("uses", "")).startswith(prefix))


def test_build_binds_subject_to_exact_pull_request_head_and_artifact() -> None:
    build = _job("build")
    steps = _steps(build)
    checkout = _action_step(steps, "actions/checkout")
    bind = _named_step(steps, "Bind installed canary subject")

    assert "github.event.pull_request.head.sha" in _text(_mapping(checkout["with"])["ref"])
    assert bind["if"] == "github.event_name == 'pull_request'"
    assert '--version "$VERSION"' in _text(bind["run"])
    assert '--source-sha "$SOURCE_SHA"' in _text(bind["run"])
    assert any(_mapping(step["with"]).get("name") == "installed-canary-subject" for step in steps if "with" in step)


def test_same_repo_post_publish_matrix_covers_all_supported_operating_systems() -> None:
    job = _job("pr-installed-canary")

    assert job["needs"] == ["build", "publish-testpypi"]
    assert "github.event.pull_request.head.repo.full_name == github.repository" in _text(job["if"])
    strategy = _mapping(job["strategy"])
    assert strategy["fail-fast"] is False
    assert _mapping(strategy["matrix"])["os"] == ["ubuntu-latest", "macos-latest", "windows-latest"]
    steps = _steps(job)
    checkout = _action_step(steps, "actions/checkout")
    assert _mapping(checkout["with"])["ref"] == "${{ needs.build.outputs.source_sha }}"
    bun = _action_step(steps, "oven-sh/setup-bun")
    assert bun["uses"] == "oven-sh/setup-bun@0c5077e51419868618aeaa5fe8019c62421857d6"
    assert _mapping(bun["with"])["bun-version"] == "1.3.14"


def test_matrix_proves_remote_bytes_install_origin_record_corpus_and_dashboard() -> None:
    steps = _steps(_job("pr-installed-canary"))
    names = [step.get("name") for step in steps]

    assert "Download exact TestPyPI wheel bytes" in names
    assert "Verify PR head, version, and TestPyPI bytes" in names
    assert "Install only the verified wheel" in names
    assert "Prove the harness rejects missing evidence" in names
    assert "Run installed 51k corpus and dashboard smoke" in names
    assert "Run canonical command extension analytics Dockerlab" in names
    assert "Upload installed canary evidence" in names
    workflow_text = WORKFLOW_PATH.read_text(encoding="utf-8")
    assert "verify-release --registry testpypi" in workflow_text
    assert "--download-dir verified-testpypi" in workflow_text
    assert "git rev-parse 'HEAD^{commit}'" in workflow_text
    assert "installed-canary/missing-subject.json" in workflow_text
    assert "-m scripts.run_installed_canary" in workflow_text
    assert "PYTHONPATH=" in workflow_text
    assert '-X "pycache_prefix=$RUNNER_TEMP/hol-guard-evidence-cache"' in workflow_text
    assert "pnpm" not in workflow_text
    assert "runner.os == 'Linux'" in workflow_text
    assert 'cmp "$VERIFIED_WHEEL" "dist/$WHEEL_NAME"' in workflow_text
    assert "bunx playwright install --with-deps chromium" in workflow_text
    assert "cd ../tests/dockerlabs/command-extension-analytics" in workflow_text
    assert "bun run guard:test:command-extension-analytics" in workflow_text
    assert "installed-canary/command-extension-analytics.json" in workflow_text
    assert ".artifacts/command-extension-analytics/*.png" in workflow_text
    canonical_runner_text = (ROOT / "tests/dockerlabs/command-extension-analytics/runner.ts").read_text(
        encoding="utf-8"
    )
    assert "Bun.env.HOL_GUARD_LAB_EXPECTED_VERSION" in canonical_runner_text
    verifier_text = (ROOT / "scripts/installed_canary_proof.py").read_text(encoding="utf-8")
    assert 'f"{PROJECT} @ {wheel.resolve().as_uri()}#sha256={digest}"' in verifier_text
    assert 'read_text("direct_url.json")' in verifier_text
    assert 'direct_url_mapping["archive_info"]' in verifier_text
    assert ".dist-info/RECORD" in verifier_text
    runner_text = (ROOT / "scripts/run_installed_canary.py").read_text(encoding="utf-8")
    assert 'shutil.which("bun")' in runner_text
    assert '"build",' in runner_text
    assert 'manifest["canonical_digests"]' in runner_text
    assert '"no_post_execution_proof": _no_post_execution_proof_smoke()' in runner_text
    assert '"$CANARY_PYTHON" -m pip install --no-compile' in workflow_text
    assert "uv pip install" not in workflow_text


def test_slice_manifest_binds_the_release_correction_chain_and_repo_relative_ownership() -> None:
    manifest = _mapping(cast(object, json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))))

    assert manifest["schema_version"] == "hol-guard.release-slice-manifest.v2"
    assert manifest["target_branch"] == "release/2.2"
    pull_requests = [_mapping(item) for item in _sequence(manifest["pull_requests"])]
    assert [item["number"] for item in pull_requests] == [1746, 1761, 1764, 1767, 1763]
    by_number = {cast(int, item["number"]): item for item in pull_requests}
    assert by_number[1746]["depends_on"] == []
    assert by_number[1761]["depends_on"] == [1746]
    assert by_number[1761]["corrected_by"] == [1764, 1767]
    assert by_number[1764]["depends_on"] == [1761]
    assert by_number[1767]["depends_on"] == [1761, 1764]
    assert by_number[1763]["depends_on"] == [1746, 1761, 1764, 1767]
    assert by_number[1763]["final_base_sha"] == "3c895a4104698a63ce0b3d8c5a25710ae5ffaa6a"
    assert by_number[1763]["final_base_requirement"] == "the release/2.2 commit produced by pull request 1767"

    slices = [_mapping(item) for item in _sequence(manifest["slices"])]
    assert [item["id"] for item in slices] == [f"CDX-{number:03d}" for number in range(63, 75)]
    assert "at most 10 exact repeated uses" in _text(slices[0]["acceptance"])
    overlap_exceptions = {
        Path(_text(item["path"])): (_text(item["original_slice"]), _text(item["final_slice"]))
        for item in (_mapping(value) for value in _sequence(manifest["ownership_overlap_exceptions"]))
    }
    observed_overlaps: set[Path] = set()
    ownership: dict[Path, str] = {}
    ownership_counts = {1761: 0, 1763: 0}
    tracked_paths = set(
        subprocess.run(
            ["git", "ls-files", "-z"],
            cwd=ROOT,
            check=True,
            capture_output=True,
            text=True,
        ).stdout.split("\0")
    )
    for item in slices:
        assert item["pull_request"] in {1761, 1763}
        for path_value in (*_sequence(item["deliverables"]), *_sequence(item["evidence_paths"])):
            path = Path(_text(path_value))
            assert not path.is_absolute()
            assert ".." not in path.parts
            assert (ROOT / path).is_file(), f"manifest path does not exist: {path}"
            assert path.as_posix() in tracked_paths, f"manifest path is not tracked: {path}"
        for path_value in _sequence(item["deliverables"]):
            path = Path(_text(path_value))
            if path in ownership:
                assert overlap_exceptions[path] == (ownership[path], _text(item["id"]))
                observed_overlaps.add(path)
            else:
                ownership[path] = _text(item["id"])
            ownership_counts[cast(int, item["pull_request"])] += 1
    assert observed_overlaps == overlap_exceptions.keys()
    assert ownership_counts == {1761: 38, 1763: 26}

    gates = _mapping(manifest["gates"])
    review = _mapping(gates["review"])
    assert review == {
        "required_independent_exact_diff_verdict": "SHIP",
        "required_unresolved_non_outdated_thread_count": 0,
        "required_quiet_window_seconds": 310,
        "recorded_exception": (
            "pull request 1761 was corrected by pull requests 1764 and 1767 after its premature merge"
        ),
    }
    verification = [_text(value) for value in _sequence(manifest["verification"])]
    assert all("pnpm" not in command for command in verification)
    canonical_lab_verification = (
        "cd tests/dockerlabs/command-extension-analytics && bun run guard:test:command-extension-analytics"
    )
    assert canonical_lab_verification in verification
    assert all("tests/dockerlabs/command-extension-analytics.test.mjs" not in command for command in verification)
    assert all(
        "tests/dockerlabs/command-extension-analytics.test.mjs" not in _text(path)
        for item in slices
        for path in (*_sequence(item["deliverables"]), *_sequence(item["evidence_paths"]))
    )
    assert "git diff --check" in verification
