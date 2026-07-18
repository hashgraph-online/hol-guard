from __future__ import annotations

import sys

import pytest

from scripts.validate_alpha_release import (
    ALPHA_BRANCHES,
    RELEASE_TRAINS,
    ReleaseChannel,
    ValidatedRelease,
    main,
    validate_alpha_release,
    validate_release_train,
    validate_release_train_alpha,
)

GITHUB_SHA = "0123456789abcdef0123456789abcdef01234567"


@pytest.mark.parametrize(
    ("git_ref", "version"),
    [
        ("refs/heads/release/2.2", "2.2.0a1"),
        ("refs/heads/release/2.2", "2.2.0a37"),
        ("refs/heads/release/3.1", "3.1.0a5"),
    ],
)
def test_accepts_exact_canonical_release_train_alphas(git_ref: str, version: str) -> None:
    release = validate_release_train_alpha(version, git_ref)

    assert release.version == version
    assert release.git_ref == git_ref


def test_generic_alpha_validator_returns_typed_sha_bound_release() -> None:
    release = validate_release_train(
        "2.2.0a2",
        "refs/heads/release/2.2",
        "alpha",
        existing_versions=["2.2.0a1"],
        github_sha=GITHUB_SHA,
        expected_sha=GITHUB_SHA,
    )

    assert release == ValidatedRelease(
        version="2.2.0a2",
        git_ref="refs/heads/release/2.2",
        source_ref="refs/heads/release/2.2",
        channel=ReleaseChannel.ALPHA,
        source_sha=GITHUB_SHA,
    )


def test_registry_preserves_release_31_and_adds_release_22() -> None:
    assert ALPHA_BRANCHES == (
        "refs/heads/release/2.2",
        "refs/heads/release/3.1",
    )
    assert RELEASE_TRAINS["refs/heads/release/2.2"].version_prefix == "2.2.0"
    assert RELEASE_TRAINS["refs/heads/release/2.2"].stable_enabled is False
    assert RELEASE_TRAINS["refs/heads/release/3.1"].version_prefix == "3.1.0"


@pytest.mark.parametrize(
    ("git_ref", "version"),
    [
        ("refs/heads/release/3.1", "3.1.0"),
    ],
)
def test_accepts_exact_stable_candidates_with_bound_source_sha(git_ref: str, version: str) -> None:
    release = validate_release_train(
        version,
        git_ref,
        ReleaseChannel.STABLE,
        actual_ref=f"refs/tags/v{version}",
        github_sha=GITHUB_SHA,
        expected_sha=GITHUB_SHA,
    )

    assert release == ValidatedRelease(
        version=version,
        git_ref=git_ref,
        source_ref=f"refs/tags/v{version}",
        channel=ReleaseChannel.STABLE,
        source_sha=GITHUB_SHA,
    )


def test_release_22_rejects_stable_channel_even_with_exact_tag_and_sha() -> None:
    with pytest.raises(ValueError, match=r"release/2\.2 is alpha-only"):
        validate_release_train(
            "2.2.0",
            "refs/heads/release/2.2",
            ReleaseChannel.STABLE,
            actual_ref="refs/tags/v2.2.0",
            github_sha=GITHUB_SHA,
            expected_sha=GITHUB_SHA,
        )


@pytest.mark.parametrize(
    ("git_ref", "version"),
    [
        ("refs/heads/release/3.1", "3.1.0a1"),
        ("refs/heads/release/3.1", "3.1.0b1"),
        ("refs/heads/release/3.1", "3.1.0rc1"),
        ("refs/heads/release/3.1", "3.1.1"),
        ("refs/heads/release/3.1", "2.2.0"),
        ("refs/heads/release/3.1", "3.0.0"),
        ("refs/heads/release/3.1", "3.2.0"),
        ("refs/heads/release/3.1", "3.1.0.dev1"),
        ("refs/heads/release/3.1", "3.1.0.post1"),
        ("refs/heads/release/3.1", "3.1.0+local"),
        ("refs/heads/release/3.1", "v3.1.0"),
        ("refs/heads/release/3.1", " 3.1.0 "),
        ("refs/heads/release/3.1", "3.1"),
    ],
)
def test_rejects_noncanonical_or_wrong_train_stable_candidates(git_ref: str, version: str) -> None:
    with pytest.raises(ValueError, match="canonical public PEP 440 stable"):
        validate_release_train(version, git_ref, ReleaseChannel.STABLE)


@pytest.mark.parametrize(
    ("git_ref", "version"),
    [
        ("refs/heads/release/2.2", "2.1.0a1"),
        ("refs/heads/release/2.2", "2.3.0a1"),
        ("refs/heads/release/2.2", "3.1.0a1"),
        ("refs/heads/release/2.2", "2.2.1a1"),
        ("refs/heads/release/3.1", "3.0.0a9"),
        ("refs/heads/release/3.1", "3.2.0a1"),
        ("refs/heads/release/3.1", "2.2.0a1"),
        ("refs/heads/release/3.1", "3.1.1a1"),
    ],
)
def test_rejects_wrong_train_major_minor_or_patch(git_ref: str, version: str) -> None:
    with pytest.raises(ValueError, match="exact release train"):
        validate_release_train_alpha(version, git_ref)


@pytest.mark.parametrize(
    "version",
    [
        "1!2.2.0a1",
        "2.2.0a0",
        "2.2.0b1",
        "2.2.0rc1",
        "2.2.0",
        "2.2.0a1.dev1",
        "2.2.0a1.post1",
        "2.2.0a1+local",
        "v2.2.0a1",
        " 2.2.0a1 ",
        "2.2a1",
        "2.2.0a01",
        "2.2.0-alpha1",
    ],
)
def test_rejects_non_public_or_noncanonical_alpha_versions(version: str) -> None:
    with pytest.raises(ValueError, match="canonical public PEP 440"):
        validate_release_train_alpha(version, "refs/heads/release/2.2")


def test_rejects_malformed_requested_version() -> None:
    with pytest.raises(ValueError, match="Requested version is not a valid PEP 440 version"):
        validate_release_train_alpha("not-a-version", "refs/heads/release/2.2")


@pytest.mark.parametrize(
    "git_ref",
    [
        "refs/heads/main",
        "refs/heads/release/2.3",
        "refs/tags/alpha/v2.2.0a1",
        "refs/pull/123/merge",
    ],
)
def test_rejects_unregistered_source_refs(git_ref: str) -> None:
    with pytest.raises(ValueError, match=r"release/2\.2.*release/3\.1"):
        validate_release_train_alpha("2.2.0a1", git_ref)


def test_rejects_unknown_release_channel() -> None:
    with pytest.raises(ValueError, match="alpha, stable"):
        validate_release_train("2.2.0a1", "refs/heads/release/2.2", "preview")


@pytest.mark.parametrize(
    ("channel", "version", "git_ref", "actual_ref", "expected"),
    [
        (
            ReleaseChannel.ALPHA,
            "2.2.0a1",
            "refs/heads/release/2.2",
            "refs/heads/main",
            "refs/heads/release/2.2",
        ),
        (ReleaseChannel.STABLE, "3.1.0", "refs/heads/release/3.1", None, "exact protected version tag"),
        (
            ReleaseChannel.STABLE,
            "3.1.0",
            "refs/heads/release/3.1",
            "refs/heads/main",
            "refs/tags/v3.1.0",
        ),
        (
            ReleaseChannel.STABLE,
            "3.1.0",
            "refs/heads/release/3.1",
            "refs/tags/v3.1.1",
            "refs/tags/v3.1.0",
        ),
    ],
)
def test_rejects_wrong_or_missing_actual_source_ref(
    channel: ReleaseChannel,
    version: str,
    git_ref: str,
    actual_ref: str | None,
    expected: str,
) -> None:
    with pytest.raises(ValueError, match=expected):
        validate_release_train(
            version,
            git_ref,
            channel,
            actual_ref=actual_ref,
        )


@pytest.mark.parametrize(
    ("github_sha", "expected_sha", "error"),
    [
        (GITHUB_SHA, None, "provided together"),
        (None, GITHUB_SHA, "provided together"),
        ("abc123", "abc123", "GitHub SHA must be exactly 40"),
        (GITHUB_SHA.upper(), GITHUB_SHA.upper(), "GitHub SHA must be exactly 40"),
        (GITHUB_SHA, "abc123", "Expected SHA must be exactly 40"),
        (GITHUB_SHA, "f" * 40, "does not match"),
    ],
)
def test_rejects_missing_noncanonical_or_mismatched_source_sha(
    github_sha: str | None, expected_sha: str | None, error: str
) -> None:
    with pytest.raises(ValueError, match=error):
        validate_release_train(
            "2.2.0a1",
            "refs/heads/release/2.2",
            ReleaseChannel.ALPHA,
            github_sha=github_sha,
            expected_sha=expected_sha,
        )


def test_rejects_duplicate_alpha_across_normalized_existing_versions() -> None:
    with pytest.raises(ValueError, match="already exists"):
        validate_release_train_alpha(
            "2.2.0a2",
            "refs/heads/release/2.2",
            existing_versions=["2.2.0-alpha2"],
        )


def test_rejects_duplicate_stable_candidate() -> None:
    with pytest.raises(ValueError, match=r"Stable version 3\.1\.0 already exists"):
        validate_release_train(
            "3.1.0",
            "refs/heads/release/3.1",
            ReleaseChannel.STABLE,
            existing_versions=["3.1.0"],
            actual_ref="refs/tags/v3.1.0",
        )


def test_rejects_non_monotonic_alpha() -> None:
    with pytest.raises(ValueError, match=r"must be newer than.*2\.2\.0a3"):
        validate_release_train_alpha(
            "2.2.0a2",
            "refs/heads/release/2.2",
            existing_versions=["2.2.0a1", "2.2.0a3"],
        )


def test_accepts_next_alpha_and_ignores_other_trains() -> None:
    release = validate_release_train_alpha(
        "2.2.0a4",
        "refs/heads/release/2.2",
        existing_versions=["2.2.0a3", "3.1.0a99", "2.1.0a200"],
    )

    assert release.version == "2.2.0a4"


def test_rejects_malformed_existing_version() -> None:
    with pytest.raises(ValueError, match="Existing version is not a valid PEP 440 version"):
        validate_release_train_alpha(
            "2.2.0a2",
            "refs/heads/release/2.2",
            existing_versions=["not-a-version"],
        )


def test_compatibility_wrapper_uses_generic_validator() -> None:
    release = validate_alpha_release(
        "3.1.0a5",
        "refs/heads/release/3.1",
        existing_versions=["3.1.0a4"],
    )

    assert release.version == "3.1.0a5"


def test_cli_accepts_repeated_existing_versions(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "validate_alpha_release.py",
            "--version",
            "2.2.0a3",
            "--git-ref",
            "refs/heads/release/2.2",
            "--existing-version",
            "2.2.0a1",
            "--existing-version",
            "2.2.0a2",
        ],
    )

    assert main() == 0
    captured = capsys.readouterr()
    assert captured.out == "2.2.0a3\n"
    assert captured.err == ""


def test_cli_reports_duplicate_without_traceback(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "validate_alpha_release.py",
            "--version",
            "2.2.0a2",
            "--git-ref",
            "refs/heads/release/2.2",
            "--existing-version",
            "2.2.0a2",
        ],
    )

    assert main() == 1
    captured = capsys.readouterr()
    assert "Error: Alpha version 2.2.0a2 already exists" in captured.err
    assert "Traceback" not in captured.err


def test_cli_accepts_stable_candidate_with_matching_sha_pair(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "validate_alpha_release.py",
            "--version",
            "3.1.0",
            "--git-ref",
            "refs/heads/release/3.1",
            "--channel",
            "stable",
            "--actual-ref",
            "refs/tags/v3.1.0",
            "--github-sha",
            GITHUB_SHA,
            "--expected-sha",
            GITHUB_SHA,
        ],
    )

    assert main() == 0
    captured = capsys.readouterr()
    assert captured.out == "3.1.0\n"
    assert captured.err == ""


def test_cli_requires_sha_pair_for_stable_candidate(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "validate_alpha_release.py",
            "--version",
            "3.1.0",
            "--git-ref",
            "refs/heads/release/3.1",
            "--channel",
            "stable",
        ],
    )

    assert main() == 1
    captured = capsys.readouterr()
    assert "Stable releases require --actual-ref, --github-sha, and --expected-sha" in captured.err
    assert "Traceback" not in captured.err
