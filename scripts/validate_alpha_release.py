from __future__ import annotations

import argparse
import re
import sys
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from enum import Enum
from types import MappingProxyType
from typing import Final

from packaging.version import InvalidVersion, Version


@dataclass(frozen=True)
class ReleaseTrain:
    git_ref: str
    major: int
    minor: int
    patch: int = 0
    stable_enabled: bool = False

    @property
    def version_prefix(self) -> str:
        return f"{self.major}.{self.minor}.{self.patch}"


@dataclass(frozen=True)
class AlphaRelease:
    version: str
    git_ref: str


class ReleaseChannel(str, Enum):
    ALPHA = "alpha"
    STABLE = "stable"


@dataclass(frozen=True)
class ValidatedRelease:
    version: str
    git_ref: str
    source_ref: str
    channel: ReleaseChannel
    source_sha: str | None


RELEASE_TRAINS: Final[Mapping[str, ReleaseTrain]] = MappingProxyType(
    {
        "refs/heads/release/2.1": ReleaseTrain(
            git_ref="refs/heads/release/2.1",
            major=2,
            minor=1,
        ),
        "refs/heads/release/2.2": ReleaseTrain(
            git_ref="refs/heads/release/2.2",
            major=2,
            minor=2,
            stable_enabled=True,
        ),
        "refs/heads/release/3.0": ReleaseTrain(
            git_ref="refs/heads/release/3.0",
            major=3,
            minor=0,
            patch=1,
            stable_enabled=False,
        ),
        "refs/heads/release/3.1": ReleaseTrain(
            git_ref="refs/heads/release/3.1",
            major=3,
            minor=1,
            stable_enabled=False,
        ),
    }
)
MAIN_REF: Final[str] = "refs/heads/main"
ALPHA_BRANCHES: Final[tuple[str, ...]] = (*RELEASE_TRAINS, MAIN_REF)
_CANONICAL_GIT_SHA: Final[re.Pattern[str]] = re.compile(r"[0-9a-f]{40}")


def _parse_version(version_text: str, *, label: str) -> Version:
    try:
        return Version(version_text)
    except InvalidVersion as exc:
        raise ValueError(f"{label} is not a valid PEP 440 version: {version_text!r}") from exc


def _is_train_alpha(version: Version, train: ReleaseTrain) -> bool:
    return (
        version.epoch == 0
        and version.release == (train.major, train.minor, train.patch)
        and version.pre is not None
        and version.pre[0] == "a"
        and version.pre[1] >= 1
        and version.dev is None
        and version.post is None
        and version.local is None
    )


def _is_train_stable(version: Version, train: ReleaseTrain) -> bool:
    return (
        version.epoch == 0
        and version.release == (train.major, train.minor, train.patch)
        and version.pre is None
        and version.dev is None
        and version.post is None
        and version.local is None
    )


def main_alpha_train(base_version: str) -> ReleaseTrain:
    """Return the alpha train for main: the minor after the current stable base."""

    base = _parse_version(base_version, label="Base version")
    if (
        str(base) != base_version
        or base.epoch != 0
        or len(base.release) != 3
        or base.pre is not None
        or base.dev is not None
        or base.post is not None
        or base.local is not None
    ):
        raise ValueError(f"Base version must be a canonical stable X.Y.Z version: {base_version!r}")
    return ReleaseTrain(git_ref=MAIN_REF, major=base.release[0], minor=base.release[1] + 1)


def _resolve_train(git_ref: str, channel: ReleaseChannel, base_version: str | None) -> ReleaseTrain:
    if git_ref == MAIN_REF:
        if channel is not ReleaseChannel.ALPHA:
            raise ValueError(f"{MAIN_REF} stable releases are cut by Release Please, not this validator")
        if base_version is None:
            raise ValueError(f"{MAIN_REF} alpha releases require --base-version")
        return main_alpha_train(base_version)
    train = RELEASE_TRAINS.get(git_ref)
    if train is None:
        raise ValueError(f"Releases must run from one of: {', '.join(ALPHA_BRANCHES)}")
    return train


def _parse_channel(channel: ReleaseChannel | str) -> ReleaseChannel:
    try:
        return ReleaseChannel(channel)
    except ValueError as exc:
        allowed = ", ".join(item.value for item in ReleaseChannel)
        raise ValueError(f"Release channel must be one of: {allowed}") from exc


def _validate_source_sha(
    *,
    github_sha: str | None,
    expected_sha: str | None,
) -> str | None:
    if github_sha is None and expected_sha is None:
        return None
    if github_sha is None or expected_sha is None:
        raise ValueError("--github-sha and --expected-sha must be provided together")
    if _CANONICAL_GIT_SHA.fullmatch(github_sha) is None:
        raise ValueError("GitHub SHA must be exactly 40 lowercase hexadecimal characters")
    if _CANONICAL_GIT_SHA.fullmatch(expected_sha) is None:
        raise ValueError("Expected SHA must be exactly 40 lowercase hexadecimal characters")
    if github_sha != expected_sha:
        raise ValueError("GitHub SHA does not match the expected release SHA")
    return github_sha


def _validate_source_ref(
    *,
    version: Version,
    train: ReleaseTrain,
    channel: ReleaseChannel,
    actual_ref: str | None,
) -> str:
    expected_ref = train.git_ref if channel is ReleaseChannel.ALPHA else f"refs/tags/v{version}"
    if actual_ref is None:
        if channel is ReleaseChannel.STABLE:
            raise ValueError("Stable releases require the exact protected version tag ref")
        return expected_ref
    if actual_ref != expected_ref:
        raise ValueError(f"{channel.value.title()} releases require source ref {expected_ref}")
    return actual_ref


def validate_release_train(
    version_text: str,
    git_ref: str,
    channel: ReleaseChannel | str,
    *,
    existing_versions: Iterable[str] = (),
    actual_ref: str | None = None,
    github_sha: str | None = None,
    expected_sha: str | None = None,
    base_version: str | None = None,
) -> ValidatedRelease:
    parsed_channel = _parse_channel(channel)
    train = _resolve_train(git_ref, parsed_channel, base_version)
    if parsed_channel is ReleaseChannel.STABLE and not train.stable_enabled:
        raise ValueError(f"{git_ref} is alpha-only; stable releases are disabled")

    source_sha = _validate_source_sha(github_sha=github_sha, expected_sha=expected_sha)
    version = _parse_version(version_text, label="Requested version")
    valid_for_channel = (
        _is_train_alpha(version, train) if parsed_channel is ReleaseChannel.ALPHA else _is_train_stable(version, train)
    )
    if version_text != str(version) or not valid_for_channel:
        example = f"{train.version_prefix}a1" if parsed_channel is ReleaseChannel.ALPHA else train.version_prefix
        raise ValueError(
            f"{git_ref} requires a canonical public PEP 440 {parsed_channel.value} version "
            f"for its exact release train, such as {example}"
        )

    source_ref = _validate_source_ref(
        version=version,
        train=train,
        channel=parsed_channel,
        actual_ref=actual_ref,
    )

    parsed_existing = [_parse_version(existing_text, label="Existing version") for existing_text in existing_versions]
    if version in parsed_existing:
        raise ValueError(f"{parsed_channel.value.title()} version {version} already exists")

    if parsed_channel is ReleaseChannel.ALPHA:
        closing = [
            existing
            for existing in parsed_existing
            if existing.epoch == 0
            and existing.release == (train.major, train.minor, train.patch)
            and not _is_train_alpha(existing, train)
        ]
        if closing:
            raise ValueError(f"Existing release {max(closing)} closes the {train.version_prefix} alpha train")
        train_alphas = [existing for existing in parsed_existing if _is_train_alpha(existing, train)]
        if train_alphas:
            latest = max(train_alphas)
            if version <= latest:
                raise ValueError(f"Alpha version {version} must be newer than existing {git_ref} alpha {latest}")

    return ValidatedRelease(
        version=str(version),
        git_ref=git_ref,
        source_ref=source_ref,
        channel=parsed_channel,
        source_sha=source_sha,
    )


def validate_release_train_alpha(
    version_text: str,
    git_ref: str,
    *,
    existing_versions: Iterable[str] = (),
) -> AlphaRelease:
    release = validate_release_train(
        version_text,
        git_ref,
        ReleaseChannel.ALPHA,
        existing_versions=existing_versions,
    )
    return AlphaRelease(version=release.version, git_ref=release.git_ref)


def validate_alpha_release(
    version_text: str,
    git_ref: str,
    *,
    existing_versions: Iterable[str] = (),
) -> AlphaRelease:
    """Compatibility wrapper for existing release workflow callers."""

    return validate_release_train_alpha(
        version_text,
        git_ref,
        existing_versions=existing_versions,
    )


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate a Guard release-train request")
    _ = parser.add_argument("--version", required=True)
    _ = parser.add_argument("--git-ref", required=True)
    _ = parser.add_argument(
        "--channel",
        choices=[channel.value for channel in ReleaseChannel],
        default=ReleaseChannel.ALPHA.value,
    )
    _ = parser.add_argument("--github-sha")
    _ = parser.add_argument("--expected-sha")
    _ = parser.add_argument("--actual-ref")
    _ = parser.add_argument("--base-version", help="Current stable base version; required for main alphas")
    _ = parser.add_argument(
        "--existing-version",
        action="append",
        default=[],
        help="Previously published version; repeat for every known version",
    )
    args = parser.parse_args()
    version_text = getattr(args, "version", None)
    git_ref = getattr(args, "git_ref", None)
    channel = getattr(args, "channel", None)
    github_sha = getattr(args, "github_sha", None)
    expected_sha = getattr(args, "expected_sha", None)
    actual_ref = getattr(args, "actual_ref", None)
    base_version = getattr(args, "base_version", None)
    existing_versions = getattr(args, "existing_version", None)
    if (
        not isinstance(version_text, str)
        or not isinstance(git_ref, str)
        or not isinstance(channel, str)
        or (github_sha is not None and not isinstance(github_sha, str))
        or (expected_sha is not None and not isinstance(expected_sha, str))
        or (actual_ref is not None and not isinstance(actual_ref, str))
        or (base_version is not None and not isinstance(base_version, str))
        or not isinstance(existing_versions, list)
        or not all(isinstance(value, str) for value in existing_versions)
    ):
        parser.error("release validator arguments must be strings")
    try:
        if channel == ReleaseChannel.STABLE.value and (
            github_sha is None or expected_sha is None or actual_ref is None
        ):
            raise ValueError("Stable releases require --actual-ref, --github-sha, and --expected-sha")
        release = validate_release_train(
            version_text,
            git_ref,
            channel,
            existing_versions=existing_versions,
            actual_ref=actual_ref,
            github_sha=github_sha,
            expected_sha=expected_sha,
            base_version=base_version,
        )
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    print(release.version)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
