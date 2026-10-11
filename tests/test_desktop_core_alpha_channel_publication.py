"""Alpha publication, registry and source-authorization checks for the Desktop Core macOS feed."""

from __future__ import annotations

import hashlib
import io
import json
import os
import subprocess
import urllib.error
from pathlib import Path

import pytest

from scripts.release import wait_for_core_publication as wait_module

ROOT = Path(__file__).resolve().parents[1]
AUTHORIZE = ROOT / "scripts" / "release" / "authorize_macos_core_source.sh"
REPOSITORY = "hashgraph-online/hol-guard"
ALPHA = "3.4.0a2"
ALPHA_TAG = f"alpha/v{ALPHA}"
SOURCE = "a" * 40
NEWER = "b" * 40


# --- publication verification ------------------------------------------------------------


def _publication_api(
    monkeypatch: pytest.MonkeyPatch,
    *,
    run: dict[str, object],
    jobs: list[str],
    comparison: dict[str, object] | None = None,
) -> list[list[str]]:
    calls: list[list[str]] = []

    def api(command: list[str], **kwargs: object) -> str:
        calls.append(command)
        endpoint = next(part for part in command if part.startswith("repos/"))
        if "/compare/" in endpoint:
            assert comparison is not None, "compare must not be called"
            return json.dumps(comparison)
        if "/attempts/1/jobs" in endpoint:
            return "\n".join(jobs)
        return json.dumps(run)

    monkeypatch.setattr(subprocess, "check_output", api)
    return calls


def _run(**overrides: object) -> dict[str, object]:
    return {
        "path": ".github/workflows/publish.yml",
        "event": "workflow_dispatch",
        "head_branch": "main",
        "head_sha": SOURCE,
        "conclusion": None,
        **overrides,
    }


def _ancestor(base: str = SOURCE) -> dict[str, object]:
    return {"status": "ahead", "base_commit": {"sha": base}, "merge_base_commit": {"sha": base}}


def test_alpha_publication_waits_for_the_alpha_pypi_job(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = _publication_api(monkeypatch, run=_run(), jobs=["success"])
    assert wait_module.publication_ready(REPOSITORY, "123", SOURCE, "alpha") is True
    jobs_call = next(call for call in calls if any("attempts/1/jobs" in part for part in call))
    assert 'select(.name == "Publish alpha to PyPI")' in jobs_call[-1]
    assert not any("compare" in part for call in calls for part in call)


def test_alpha_publication_is_pending_until_the_job_concludes(monkeypatch: pytest.MonkeyPatch) -> None:
    _publication_api(monkeypatch, run=_run(), jobs=["null"])
    assert wait_module.publication_ready(REPOSITORY, "123", SOURCE, "alpha") is False


@pytest.mark.parametrize("conclusion", ["failure", "cancelled", "skipped"])
def test_failed_or_skipped_alpha_publication_withholds_assets(monkeypatch: pytest.MonkeyPatch, conclusion: str) -> None:
    _publication_api(monkeypatch, run=_run(), jobs=[conclusion])
    with pytest.raises(ValueError, match="alpha registry publication failed"):
        wait_module.publication_ready(REPOSITORY, "123", SOURCE, "alpha")


def test_alpha_publication_without_the_alpha_job_never_falls_back_to_the_whole_run(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _publication_api(monkeypatch, run=_run(conclusion="success"), jobs=[])
    assert wait_module.publication_ready(REPOSITORY, "123", SOURCE, "alpha") is False


def test_alpha_run_may_be_newer_than_the_alpha_source_when_the_source_is_an_ancestor(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = _publication_api(monkeypatch, run=_run(head_sha=NEWER), jobs=["success"], comparison=_ancestor())
    assert wait_module.publication_ready(REPOSITORY, "123", SOURCE, "alpha") is True
    assert any(f"repos/{REPOSITORY}/compare/{SOURCE}...{NEWER}" in part for call in calls for part in call)


@pytest.mark.parametrize(
    "comparison",
    [
        {"status": "diverged", "base_commit": {"sha": SOURCE}, "merge_base_commit": {"sha": "c" * 40}},
        {"status": "behind", "base_commit": {"sha": SOURCE}, "merge_base_commit": {"sha": NEWER}},
        {"status": "ahead", "base_commit": {"sha": "c" * 40}, "merge_base_commit": {"sha": SOURCE}},
        {"status": "ahead", "base_commit": {"sha": SOURCE}, "merge_base_commit": {"sha": "c" * 40}},
    ],
)
def test_alpha_source_that_is_not_an_ancestor_of_the_run_is_rejected(
    monkeypatch: pytest.MonkeyPatch, comparison: dict[str, object]
) -> None:
    _publication_api(monkeypatch, run=_run(head_sha=NEWER), jobs=["success"], comparison=comparison)
    with pytest.raises(ValueError, match="alpha publication run is not an authorized"):
        wait_module.publication_ready(REPOSITORY, "123", SOURCE, "alpha")


@pytest.mark.parametrize(
    "run",
    [
        _run(head_branch="release/3.0"),
        _run(head_branch="feature"),
        _run(event="push"),
        _run(event="schedule"),
        _run(path=".github/workflows/other.yml"),
    ],
)
def test_alpha_publication_must_be_a_main_dispatch_of_publish_yml(
    monkeypatch: pytest.MonkeyPatch, run: dict[str, object]
) -> None:
    _publication_api(monkeypatch, run=run, jobs=["success"], comparison=_ancestor())
    with pytest.raises(ValueError, match=r"not the authorized|not an authorized"):
        wait_module.publication_ready(REPOSITORY, "123", SOURCE, "alpha")


def test_stable_publication_still_requires_the_exact_source_sha(monkeypatch: pytest.MonkeyPatch) -> None:
    _publication_api(monkeypatch, run=_run(head_sha=NEWER), jobs=["success"], comparison=_ancestor())
    with pytest.raises(ValueError, match="not the authorized release dispatch"):
        wait_module.publication_ready(REPOSITORY, "123", SOURCE)
    _publication_api(monkeypatch, run=_run(), jobs=["success"])
    assert wait_module.publication_ready(REPOSITORY, "123", SOURCE) is True


def test_stable_publication_still_reads_the_main_release_job(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = _publication_api(monkeypatch, run=_run(), jobs=["success"])
    assert wait_module.publication_ready(REPOSITORY, "123", SOURCE, "stable") is True
    jobs_call = next(call for call in calls if any("attempts/1/jobs" in part for part in call))
    assert "Publish main release to PyPI" in jobs_call[-1]


def test_unknown_publication_channel_is_rejected() -> None:
    with pytest.raises(ValueError, match="channel"):
        wait_module.publication_ready(REPOSITORY, "123", SOURCE, "beta")


NATIVE = f"hol_guard-{ALPHA}-py3-none-macosx_11_0_arm64.whl"
PURE = f"hol_guard-{ALPHA}-py3-none-any.whl"
PURE_DIGEST = "c" * 64


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _alpha_world(
    monkeypatch: pytest.MonkeyPatch,
    *,
    native_digest: str | None,
    release: dict[str, object] | None = None,
    pypi_files: dict[str, str] | None = None,
    pypi_version: str = ALPHA,
    pypi_status: int | None = None,
) -> list[str]:
    """Fake the live alpha prerelease (via gh) and PyPI; return the requested endpoints."""
    requested: list[str] = []
    assets = [{"name": PURE, "state": "uploaded", "digest": f"sha256:{PURE_DIGEST}"}]
    if native_digest is not None:
        assets.append({"name": NATIVE, "state": "uploaded", "digest": f"sha256:{native_digest}"})
    payload = {"tag_name": ALPHA_TAG, "draft": False, "prerelease": True, "assets": assets, **(release or {})}

    def api(command: list[str], **kwargs: object) -> str:
        requested.append(command[-1])
        return json.dumps(payload)

    metadata = {
        "info": {"version": pypi_version},
        "urls": [
            {"filename": name, "digests": {"sha256": digest}}
            for name, digest in (pypi_files if pypi_files is not None else {PURE: PURE_DIGEST}).items()
        ],
    }

    def urlopen(url: str, **kwargs: object) -> io.BytesIO:
        requested.append(url)
        if pypi_status is not None:
            raise urllib.error.HTTPError(url, pypi_status, "error", {}, None)  # type: ignore[arg-type]
        return io.BytesIO(json.dumps(metadata).encode())

    monkeypatch.setattr(subprocess, "check_output", api)
    monkeypatch.setattr("urllib.request.urlopen", urlopen)
    return requested


def _native_wheel(tmp_path: Path) -> Path:
    wheel = tmp_path / "attested-macos-arm64.whl"
    wheel.write_bytes(b"attested alpha wheel")
    return wheel


def _alpha_ready(wheel: Path) -> bool:
    return wait_module.registry_ready(ALPHA, wheel, NATIVE, "alpha", repo=REPOSITORY)


def test_alpha_ready_when_prerelease_asset_matches_and_pypi_has_the_pure_wheel(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    wheel = _native_wheel(tmp_path)
    requested = _alpha_world(monkeypatch, native_digest=_sha(wheel.read_bytes()))
    assert _alpha_ready(wheel) is True
    assert requested == [
        f"repos/{REPOSITORY}/releases/tags/{ALPHA_TAG}",
        f"https://pypi.org/pypi/hol-guard/{ALPHA}/json",
    ]


def test_alpha_does_not_require_the_native_wheel_on_pypi(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    wheel = _native_wheel(tmp_path)
    _alpha_world(monkeypatch, native_digest=_sha(wheel.read_bytes()), pypi_files={PURE: PURE_DIGEST})
    assert _alpha_ready(wheel) is True


def test_alpha_filename_defaults_to_the_wheel_name(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    wheel = tmp_path / NATIVE
    wheel.write_bytes(b"attested alpha wheel")
    _alpha_world(monkeypatch, native_digest=_sha(wheel.read_bytes()))
    assert wait_module.registry_ready(ALPHA, wheel, None, "alpha", repo=REPOSITORY) is True


def test_alpha_not_ready_when_the_prerelease_asset_is_missing(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    requested = _alpha_world(monkeypatch, native_digest=None)
    assert _alpha_ready(_native_wheel(tmp_path)) is False
    assert requested == [f"repos/{REPOSITORY}/releases/tags/{ALPHA_TAG}"]


def test_alpha_ignores_assets_that_are_not_uploaded(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    wheel = _native_wheel(tmp_path)
    _alpha_world(
        monkeypatch,
        native_digest=None,
        release={
            "assets": [
                {"name": NATIVE, "state": "starter", "digest": f"sha256:{_sha(wheel.read_bytes())}"},
                {"name": PURE, "state": "uploaded", "digest": f"sha256:{PURE_DIGEST}"},
            ]
        },
    )
    assert _alpha_ready(wheel) is False


def test_alpha_prerelease_asset_digest_mismatch_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _alpha_world(monkeypatch, native_digest="0" * 64)
    with pytest.raises(ValueError, match="digest mismatch"):
        _alpha_ready(_native_wheel(tmp_path))


def test_alpha_prerelease_asset_without_a_digest_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _alpha_world(
        monkeypatch,
        native_digest=None,
        release={"assets": [{"name": NATIVE, "state": "uploaded", "digest": None}]},
    )
    with pytest.raises(ValueError, match="digest mismatch"):
        _alpha_ready(_native_wheel(tmp_path))


@pytest.mark.parametrize(
    "release",
    [{"draft": True}, {"prerelease": False}, {"tag_name": "alpha/v3.4.0a1"}],
)
def test_alpha_requires_a_live_published_prerelease(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, release: dict[str, object]
) -> None:
    wheel = _native_wheel(tmp_path)
    _alpha_world(monkeypatch, native_digest=_sha(wheel.read_bytes()), release=release)
    with pytest.raises(ValueError, match="not published"):
        _alpha_ready(wheel)


def test_alpha_not_ready_until_pypi_exposes_the_pure_wheel(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    wheel = _native_wheel(tmp_path)
    digest = _sha(wheel.read_bytes())
    _alpha_world(monkeypatch, native_digest=digest, pypi_status=404)
    assert _alpha_ready(wheel) is False
    # A native wheel on PyPI is irrelevant: only the pure wheel proves alpha publication.
    _alpha_world(monkeypatch, native_digest=digest, pypi_files={NATIVE: digest})
    assert _alpha_ready(wheel) is False


def test_alpha_not_ready_when_the_prerelease_lacks_the_pure_wheel(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    wheel = _native_wheel(tmp_path)
    _alpha_world(
        monkeypatch,
        native_digest=None,
        release={"assets": [{"name": NATIVE, "state": "uploaded", "digest": f"sha256:{_sha(wheel.read_bytes())}"}]},
    )
    assert _alpha_ready(wheel) is False


def test_alpha_pypi_failures_fail_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    wheel = _native_wheel(tmp_path)
    digest = _sha(wheel.read_bytes())
    _alpha_world(monkeypatch, native_digest=digest, pypi_files={PURE: "0" * 64})
    with pytest.raises(ValueError, match="pure wheel does not match"):
        _alpha_ready(wheel)
    _alpha_world(monkeypatch, native_digest=digest, pypi_version="3.4.0a1")
    with pytest.raises(ValueError, match="PyPI version mismatch"):
        _alpha_ready(wheel)
    _alpha_world(monkeypatch, native_digest=digest, pypi_status=403)
    with pytest.raises(urllib.error.HTTPError):
        _alpha_ready(wheel)


def test_alpha_registry_check_requires_the_release_repository(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="release repository"):
        wait_module.registry_ready(ALPHA, tmp_path / "wheel", NATIVE, "alpha")


def test_stable_registry_check_never_reads_the_alpha_prerelease(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    wheel = tmp_path / "hol_guard-3.4.0-py3-none-macosx_11_0_arm64.whl"
    wheel.write_bytes(b"stable wheel")
    metadata = {
        "info": {"version": "3.4.0"},
        "urls": [{"filename": wheel.name, "digests": {"sha256": _sha(b"stable wheel")}}],
    }
    requested: list[str] = []

    def urlopen(url: str, **kwargs: object) -> io.BytesIO:
        requested.append(url)
        return io.BytesIO(json.dumps(metadata).encode())

    def forbidden(*args: object, **kwargs: object) -> str:
        raise AssertionError("stable readiness must not call gh")

    monkeypatch.setattr("urllib.request.urlopen", urlopen)
    monkeypatch.setattr(subprocess, "check_output", forbidden)
    assert wait_module.registry_ready("3.4.0", wheel) is True
    assert requested == ["https://pypi.org/pypi/hol-guard/3.4.0/json"]


@pytest.mark.parametrize("version", ["3.4.0", "3.4.0a0", "v3.4.0a2", "4.0.0a1", "3.4.0a2.post1"])
def test_alpha_registry_check_rejects_non_alpha_versions(tmp_path: Path, version: str) -> None:
    with pytest.raises(ValueError, match="invalid alpha version"):
        wait_module.registry_ready(version, tmp_path / "wheel", None, "alpha")


def test_stable_registry_check_rejects_alpha_versions(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="invalid stable version"):
        wait_module.registry_ready(ALPHA, tmp_path / "wheel")


def test_alpha_wait_requires_the_publishing_run_identity(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("PUBLICATION_RUN_ID", raising=False)
    monkeypatch.setattr(wait_module.time, "sleep", lambda *args: None)
    with pytest.raises(ValueError, match="alpha publication requires the publishing run identity"):
        wait_module.wait(ALPHA, tmp_path / "wheel", timeout=1, channel="alpha")


def test_alpha_wait_passes_the_channel_through(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    for key, value in {
        "PUBLICATION_RUN_ID": "123",
        "PUBLICATION_SOURCE_SHA": SOURCE,
        "GITHUB_REPOSITORY": REPOSITORY,
    }.items():
        monkeypatch.setenv(key, value)
    seen: list[tuple[object, ...]] = []

    def ready(*args: object) -> bool:
        seen.append(args)
        return True

    monkeypatch.setattr(wait_module, "publication_ready", ready)
    monkeypatch.setattr(
        wait_module, "registry_ready", lambda *args, **kwargs: bool(seen.append((*args, kwargs)) or True)
    )
    wait_module.wait(ALPHA, tmp_path / "wheel", timeout=1, channel="alpha")
    assert seen[0] == (REPOSITORY, "123", SOURCE, "alpha")
    assert seen[1][3] == "alpha"
    assert seen[1][-1] == {"repo": REPOSITORY}


def test_alpha_wait_retries_transient_registry_errors(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    for key, value in {
        "PUBLICATION_RUN_ID": "123",
        "PUBLICATION_SOURCE_SHA": SOURCE,
        "GITHUB_REPOSITORY": REPOSITORY,
    }.items():
        monkeypatch.setenv(key, value)
    attempts: list[int] = []

    def ready(*args: object) -> bool:
        attempts.append(1)
        if len(attempts) == 1:
            raise urllib.error.URLError("temporary")
        return True

    monkeypatch.setattr(wait_module, "publication_ready", ready)
    monkeypatch.setattr(wait_module, "registry_ready", lambda *args, **kwargs: True)
    monkeypatch.setattr(wait_module.time, "sleep", lambda *args: None)
    wait_module.wait(ALPHA, tmp_path / "wheel", timeout=1, channel="alpha")
    assert len(attempts) == 2


# --- source authorization ----------------------------------------------------------------


def _authorize(tmp_path: Path, **overrides: str) -> subprocess.CompletedProcess[str]:
    env = {
        "PATH": os.environ["PATH"],
        "RELEASE_BRANCH": "main",
        "CORE_TAG": ALPHA_TAG,
        "CORE_VERSION": ALPHA,
        "GITHUB_REPOSITORY": REPOSITORY,
        "GITHUB_OUTPUT": str(tmp_path / "out"),
        "RUNNER_TEMP": str(tmp_path),
        "RELEASE_CHANNEL": "alpha",
        "PUBLICATION_SOURCE_SHA": SOURCE,
        **overrides,
    }
    env = {key: value for key, value in env.items() if value != "<unset>"}
    return subprocess.run(["bash", str(AUTHORIZE)], cwd=ROOT, env=env, capture_output=True, text=True, check=False)


@pytest.mark.parametrize(
    "overrides",
    [
        {"RELEASE_BRANCH": "release/3.0"},
        {"CORE_TAG": "v3.4.0"},
        {"CORE_TAG": "alpha/v3.4.0a1"},
        {"PUBLICATION_SOURCE_SHA": ""},
        {"PUBLICATION_SOURCE_SHA": "A" * 40},
        {"PUBLICATION_SOURCE_SHA": "<unset>"},
        {"RELEASE_CHANNEL": "beta"},
    ],
)
def test_alpha_source_authorization_rejects_unbound_inputs_before_any_network_access(
    tmp_path: Path, overrides: dict[str, str]
) -> None:
    result = _authorize(tmp_path, **overrides)
    assert result.returncode != 0
    assert not (tmp_path / "core-trust.git").exists()
    assert not (tmp_path / "out").exists()
