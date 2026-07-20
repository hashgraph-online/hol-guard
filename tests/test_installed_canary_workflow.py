"""Contracts for installed same-repository pull-request canaries."""

from __future__ import annotations

import json
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
    verifier_text = (ROOT / "scripts/installed_canary_proof.py").read_text(encoding="utf-8")
    assert 'f"{PROJECT} @ {wheel.resolve().as_uri()}#sha256={digest}"' in verifier_text
    assert 'read_text("direct_url.json")' in verifier_text
    assert ".dist-info/RECORD" in verifier_text
    runner_text = (ROOT / "scripts/run_installed_canary.py").read_text(encoding="utf-8")
    assert 'shutil.which("bun")' in runner_text
    assert '"build",' in runner_text
    assert 'manifest["canonical_digests"]' in runner_text


def test_slice_manifest_uses_only_repo_relative_deliverables() -> None:
    manifest = _mapping(cast(object, json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))))

    assert manifest["schema_version"] == "hol-guard.release-slice-manifest.v1"
    slices = [_mapping(item) for item in _sequence(manifest["slices"])]
    assert [item["id"] for item in slices] == ["CDX-070", "CDX-072", "CDX-074"]
    for item in slices:
        for path_value in _sequence(item["deliverables"]):
            path = Path(_text(path_value))
            assert not path.is_absolute()
            assert ".." not in path.parts
            assert (ROOT / path).exists()
