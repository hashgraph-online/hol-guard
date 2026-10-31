"""Desktop Core sidecars for pull request alphas, whose source main never contains."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import subprocess
import zipfile
from pathlib import Path

import pytest

from scripts.release import verify_pull_request_alpha_source as verifier
from scripts.release import wait_for_core_publication as wait_module

ROOT = Path(__file__).resolve().parents[1]
AUTHORIZE = ROOT / "scripts" / "release" / "authorize_macos_core_source.sh"
REPOSITORY = "hashgraph-online/hol-guard"
ALPHA = "3.4.0a2"
RUN_ID = "4242"
WHEEL_NAME = f"hol_guard-{ALPHA}-py3-none-macosx_11_0_arm64.whl"
MANIFEST = "codex_plugin_scanner/_native/runtime-manifest.json"


def _git(repo: Path, *args: str) -> str:
    env = {**os.environ, "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1"}
    identity = ["-c", "user.name=t", "-c", "user.email=t@example.com", "-c", "commit.gpgsign=false"]
    return subprocess.run(
        ["git", "-C", str(repo), *identity, *args], check=True, capture_output=True, text=True, env=env
    ).stdout.strip()


def _wheel(path: Path, source: str, version: str = ALPHA) -> Path:
    manifest = {"schema": "hol-guard-native-runtime.v1", "source_sha": source, "package_version": version}
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr(MANIFEST, json.dumps(manifest))
    return path


def _bundle(path: Path, wheel: Path, commit: str, *, ref: str = "refs/heads/main", run_id: str = RUN_ID) -> Path:
    statement = {
        "subject": [{"name": wheel.name, "digest": {"sha256": hashlib.sha256(wheel.read_bytes()).hexdigest()}}],
        "predicate": {
            "buildDefinition": {
                "externalParameters": {"workflow": {"path": ".github/workflows/publish.yml", "ref": ref}},
                "resolvedDependencies": [{"digest": {"gitCommit": commit}}],
            },
            "runDetails": {
                "metadata": {"invocationId": f"https://github.com/{REPOSITORY}/actions/runs/{run_id}/attempts/1"}
            },
        },
    }
    payload = base64.b64encode(json.dumps(statement).encode()).decode()
    path.write_text(json.dumps({"dsseEnvelope": {"payload": payload}}) + "\n", encoding="utf-8")
    return path


def _run(head_sha: str, **overrides: object) -> dict[str, object]:
    return {
        "path": ".github/workflows/publish.yml",
        "event": "workflow_dispatch",
        "head_branch": "main",
        "head_sha": head_sha,
        "conclusion": None,
        **overrides,
    }


# --- verifier ----------------------------------------------------------------------------


@pytest.fixture
def published(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, object]:
    source, commit = "a" * 40, "b" * 40
    wheel = _wheel(tmp_path / WHEEL_NAME, source)
    world: dict[str, object] = {
        "source": source,
        "commit": commit,
        "wheel": wheel,
        "bundle": _bundle(tmp_path / "bundle.jsonl", wheel, commit),
        "run": _run(commit),
        "jobs": ["success"],
    }

    def api(command: list[str], **kwargs: object) -> str:
        endpoint = next(part for part in command if part.startswith("repos/"))
        if endpoint.endswith("/jobs?per_page=100"):
            assert 'select(.name == "Authorize pull request alpha")' in command[-1]
            return "\n".join(world["jobs"])  # type: ignore[arg-type]
        assert endpoint == f"repos/{REPOSITORY}/actions/runs/{RUN_ID}"
        return json.dumps(world["run"])

    monkeypatch.setattr(subprocess, "check_output", api)
    return world


def _verify(world: dict[str, object], **overrides: object) -> None:
    arguments = {
        "wheel": world["wheel"],
        "bundle": world["bundle"],
        "repo": REPOSITORY,
        "run_id": RUN_ID,
        "source_sha": world["source"],
        "version": ALPHA,
        "attested_commit": world["commit"],
        **overrides,
    }
    verifier.verify(**arguments)  # type: ignore[arg-type]


def test_pull_request_alpha_source_is_bound_by_its_publication(published: dict[str, object]) -> None:
    _verify(published)


def test_wheel_built_from_another_source_is_rejected(published: dict[str, object], tmp_path: Path) -> None:
    wheel = _wheel(tmp_path / "other.whl", "c" * 40)
    published["wheel"] = wheel
    published["bundle"] = _bundle(tmp_path / "other.jsonl", wheel, published["commit"])  # type: ignore[arg-type]
    with pytest.raises(verifier.SourceBindingError, match="not built from the tagged pull request source"):
        _verify(published)


def test_provenance_for_another_wheel_is_rejected(published: dict[str, object], tmp_path: Path) -> None:
    other = _wheel(tmp_path / "other.whl", published["source"], version="3.4.0a3")  # type: ignore[arg-type]
    published["bundle"] = _bundle(tmp_path / "other.jsonl", other, published["commit"])  # type: ignore[arg-type]
    with pytest.raises(verifier.SourceBindingError, match="does not bind the native wheel"):
        _verify(published)


@pytest.mark.parametrize(
    ("bundle_overrides", "message"),
    [
        ({"ref": "refs/heads/feature"}, "not the main publish workflow"),
        ({"ref": "refs/tags/alpha/v3.4.0a2"}, "not the main publish workflow"),
        ({"run_id": "999"}, "not come from the dispatched publication run"),
        ({"commit": "d" * 40}, "does not name the attested main commit"),
    ],
)
def test_provenance_outside_the_dispatched_main_run_is_rejected(
    published: dict[str, object], tmp_path: Path, bundle_overrides: dict[str, str], message: str
) -> None:
    commit = bundle_overrides.pop("commit", published["commit"])
    published["bundle"] = _bundle(tmp_path / "b.jsonl", published["wheel"], commit, **bundle_overrides)  # type: ignore[arg-type]
    with pytest.raises(verifier.SourceBindingError, match=message):
        _verify(published)


def test_ambiguous_provenance_is_rejected(published: dict[str, object]) -> None:
    bundle: Path = published["bundle"]  # type: ignore[assignment]
    bundle.write_text(bundle.read_text() * 2, encoding="utf-8")
    with pytest.raises(verifier.SourceBindingError, match="ambiguous"):
        _verify(published)


@pytest.mark.parametrize(
    "run_overrides",
    [{"head_branch": "feature"}, {"event": "push"}, {"path": ".github/workflows/other.yml"}, {"head_sha": "e" * 40}],
)
def test_publication_run_must_be_the_main_dispatch_that_signed_the_wheel(
    published: dict[str, object], run_overrides: dict[str, str]
) -> None:
    published["run"] = {**_run(published["commit"]), **run_overrides}  # type: ignore[arg-type]
    with pytest.raises(verifier.SourceBindingError, match="not a main dispatch"):
        _verify(published)


@pytest.mark.parametrize("jobs", [[], ["skipped"], ["failure"], ["success", "success"]])
def test_publication_run_must_have_authorized_a_pull_request_alpha(
    published: dict[str, object], jobs: list[str]
) -> None:
    published["jobs"] = jobs
    with pytest.raises(verifier.SourceBindingError, match="did not authorize a pull request alpha"):
        _verify(published)


@pytest.mark.parametrize(
    "overrides",
    [{"run_id": "0"}, {"source_sha": "A" * 40}, {"attested_commit": "short"}, {"version": "3.4.0"}],
)
def test_malformed_inputs_are_rejected(published: dict[str, object], overrides: dict[str, str]) -> None:
    with pytest.raises(verifier.SourceBindingError):
        _verify(published, **overrides)


# --- publication readiness ---------------------------------------------------------------


def _ready_api(monkeypatch: pytest.MonkeyPatch, *, authorize: list[str]) -> None:
    def api(command: list[str], **kwargs: object) -> str:
        endpoint = next(part for part in command if part.startswith("repos/"))
        if "/compare/" in endpoint:
            return json.dumps({"status": "diverged", "base_commit": {"sha": "a" * 40}, "merge_base_commit": {}})
        if "/attempts/1/jobs" in endpoint:
            return "\n".join(authorize if "Authorize pull request alpha" in command[-1] else ["success"])
        return json.dumps(_run("b" * 40))

    monkeypatch.setattr(subprocess, "check_output", api)


def test_pull_request_alpha_publication_is_ready_with_its_sealed_source(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _ready_api(monkeypatch, authorize=["success"])
    wheel = _wheel(tmp_path / WHEEL_NAME, "a" * 40)
    assert wait_module.publication_ready(REPOSITORY, RUN_ID, "a" * 40, "alpha", wheel=wheel) is True


@pytest.mark.parametrize(("authorize", "sealed"), [(["success"], "c" * 40), ([], "a" * 40), (["skipped"], "a" * 40)])
def test_unauthorized_or_mismatched_pull_request_alpha_is_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, authorize: list[str], sealed: str
) -> None:
    _ready_api(monkeypatch, authorize=authorize)
    wheel = _wheel(tmp_path / WHEEL_NAME, sealed)
    with pytest.raises(ValueError, match="alpha publication run is not an authorized"):
        wait_module.publication_ready(REPOSITORY, RUN_ID, "a" * 40, "alpha", wheel=wheel)


def test_pull_request_alpha_needs_the_wheel_to_prove_its_source(monkeypatch: pytest.MonkeyPatch) -> None:
    _ready_api(monkeypatch, authorize=["success"])
    with pytest.raises(ValueError, match="alpha publication run is not an authorized"):
        wait_module.publication_ready(REPOSITORY, RUN_ID, "a" * 40, "alpha")


# --- source authorization ----------------------------------------------------------------

FAKE_GH = r"""#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >> "$FAKE_LOG"
case "$1" in
  release)
    pattern="" dir=""
    while [[ $# -gt 0 ]]; do
      case "$1" in --pattern) pattern="$2"; shift ;; --dir) dir="$2"; shift ;; esac
      shift
    done
    for asset in "$FAKE_ASSETS"/*; do
      # shellcheck disable=SC2053
      if [[ "$(basename "$asset")" == $pattern ]]; then cp "$asset" "$dir/"; fi
    done
    ;;
  attestation)
    if [[ -n "${FAKE_UNSIGNED_DIGEST:-}" && "$*" == *"--signer-digest $FAKE_UNSIGNED_DIGEST"* ]]; then exit 1; fi
    exit "${FAKE_ATTESTATION_STATUS:-0}"
    ;;
  api)
    case "$*" in
      *"/jobs?per_page=100"*) printf '%s\n' "$FAKE_AUTHORIZE_JOB" ;;
      *) cat "$FAKE_RUN" ;;
    esac
    ;;
esac
"""


@pytest.fixture
def origin(tmp_path: Path) -> dict[str, str]:
    repo = tmp_path / "origin"
    repo.mkdir()
    _git(repo, "init", "-q", "-b", "main")
    _git(repo, "commit", "-q", "--allow-empty", "-m", "base")
    _git(repo, "checkout", "-q", "-b", "pull")
    _git(repo, "commit", "-q", "--allow-empty", "-m", "pr")
    source = _git(repo, "rev-parse", "HEAD")
    _git(repo, "tag", f"alpha/v{ALPHA}", source)
    _git(repo, "checkout", "-q", "main")
    _git(repo, "commit", "-q", "--allow-empty", "-m", "main")
    commit = _git(repo, "rev-parse", "HEAD")
    _git(repo, "commit", "-q", "--allow-empty", "-m", "later")
    stray = _git(repo, "rev-parse", "pull")
    return {"repo": str(repo), "source": source, "commit": commit, "stray": stray}


def _authorize(tmp_path: Path, origin: dict[str, str], *, attested: str | None = None, **overrides: str):
    assets = tmp_path / "assets"
    assets.mkdir(exist_ok=True)
    wheel = _wheel(assets / WHEEL_NAME, origin["source"])
    _bundle(assets / f"hol-guard-v{ALPHA}.intoto.jsonl", wheel, attested or origin["commit"])
    (tmp_path / "run.json").write_text(json.dumps(_run(attested or origin["commit"])), encoding="utf-8")
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(exist_ok=True)
    (bin_dir / "gh").write_text(FAKE_GH, encoding="utf-8")
    (bin_dir / "gh").chmod(0o755)
    runner = tmp_path / "runner"
    runner.mkdir(exist_ok=True)
    env = {
        "PATH": f"{bin_dir}{os.pathsep}{os.environ['PATH']}",
        "HOME": str(tmp_path),
        "GIT_CONFIG_COUNT": "2",
        "GIT_CONFIG_KEY_0": f"url.file://{origin['repo']}.insteadOf",
        "GIT_CONFIG_VALUE_0": f"https://github.com/{REPOSITORY}.git",
        "GIT_CONFIG_KEY_1": "uploadpack.allowAnySHA1InWant",
        "GIT_CONFIG_VALUE_1": "true",
        "CORE_TAG": f"alpha/v{ALPHA}",
        "CORE_VERSION": ALPHA,
        "RELEASE_BRANCH": "main",
        "RELEASE_CHANNEL": "alpha",
        "GITHUB_REPOSITORY": REPOSITORY,
        "GITHUB_OUTPUT": str(runner / "out"),
        "GITHUB_ENV": str(runner / "env"),
        "RUNNER_TEMP": str(runner),
        "PUBLICATION_RUN_ID": RUN_ID,
        "PUBLICATION_SOURCE_SHA": origin["source"],
        "FAKE_LOG": str(tmp_path / "gh.log"),
        "FAKE_ASSETS": str(assets),
        "FAKE_RUN": str(tmp_path / "run.json"),
        "FAKE_AUTHORIZE_JOB": "success",
        **overrides,
    }
    env = {key: value for key, value in env.items() if value != "<unset>"}
    result = subprocess.run(["bash", str(AUTHORIZE)], cwd=ROOT, env=env, capture_output=True, text=True, check=False)
    log = (tmp_path / "gh.log").read_text(encoding="utf-8") if (tmp_path / "gh.log").exists() else ""
    return result, log, runner


def test_pull_request_alpha_source_is_authorized_from_its_main_publication(
    tmp_path: Path, origin: dict[str, str]
) -> None:
    result, log, runner = _authorize(tmp_path, origin)
    assert result.returncode == 0, result.stderr
    assert (runner / "out").read_text(encoding="utf-8") == f"sha={origin['source']}\n"
    assert (runner / "attested-macos-arm64.whl").is_file()
    verify = next(line for line in log.splitlines() if line.startswith("attestation verify"))
    assert f"--signer-digest {origin['commit']} --source-digest {origin['commit']}" in verify
    assert "--source-ref refs/heads/main" in verify
    assert f"repos/{REPOSITORY}/actions/runs/{RUN_ID}" in log


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"RELEASE_CHANNEL": "stable", "CORE_TAG": "v3.4.0", "CORE_VERSION": "3.4.0"}, "not on the release branch"),
        ({"PUBLICATION_RUN_ID": "<unset>"}, "needs its publication run"),
        ({"FAKE_AUTHORIZE_JOB": "skipped"}, "did not authorize a pull request alpha"),
        ({"FAKE_ATTESTATION_STATUS": "1"}, ""),
    ],
)
def test_pull_request_alpha_source_without_its_publication_proof_is_rejected(
    tmp_path: Path, origin: dict[str, str], overrides: dict[str, str], message: str
) -> None:
    if overrides.get("RELEASE_CHANNEL") == "stable":
        _git(Path(origin["repo"]), "tag", "v3.4.0", origin["source"])
    result, _, runner = _authorize(tmp_path, origin, **overrides)
    assert result.returncode != 0
    assert message in result.stderr
    assert not (runner / "out").exists()


def test_pull_request_alpha_attested_by_a_commit_outside_main_is_rejected(
    tmp_path: Path, origin: dict[str, str]
) -> None:
    result, _, runner = _authorize(tmp_path, origin, attested=origin["stray"])
    assert result.returncode != 0
    assert "was not published by a main commit" in result.stderr
    assert not (runner / "out").exists()


def test_pull_request_alpha_merged_into_main_after_publication_is_still_authorized(
    tmp_path: Path, origin: dict[str, str]
) -> None:
    _git(Path(origin["repo"]), "merge", "-q", "--no-ff", "-m", "merge pull request", "pull")
    result, log, runner = _authorize(tmp_path, origin, FAKE_UNSIGNED_DIGEST=origin["source"])
    assert result.returncode == 0, result.stderr
    assert (runner / "out").read_text(encoding="utf-8") == f"sha={origin['source']}\n"
    assert f"--signer-digest {origin['commit']}" in log
    assert f"repos/{REPOSITORY}/actions/runs/{RUN_ID}" in log
