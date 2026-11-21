"""Count the artifacts `hol-guard status` reports as needing review."""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path

from ..consumer.service import diff_artifact
from ..models import GuardArtifact
from ..native_artifact_content_hash import ArtifactContentHashUnavailableError, native_artifact_content_hashes
from ..native_consumer_artifact_project import NativeConsumerProjectError
from ..store import GuardStore


def count_review_artifacts(store: GuardStore, artifacts: tuple[GuardArtifact, ...], harness: str) -> int:
    if not artifacts:
        return 0
    previous_snapshots = store.list_snapshots(harness)
    guard_home = getattr(store, "guard_home", None)
    try:
        content_hashes = native_artifact_content_hashes(artifacts, guard_home=guard_home)
    except ArtifactContentHashUnavailableError:
        # Without hashes no diff is known, so every artifact needs review.
        return len(artifacts)
    return sum(
        1
        for artifact, content_hash in zip(artifacts, content_hashes, strict=True)
        if _artifact_needs_review(previous_snapshots, artifact, content_hash, guard_home)
    )


def _artifact_needs_review(
    previous_snapshots: Mapping[str, dict[str, object]],
    artifact: GuardArtifact,
    content_hash: str,
    guard_home: Path | None,
) -> bool:
    try:
        return bool(
            diff_artifact(
                previous_snapshots.get(artifact.artifact_id),
                artifact,
                guard_home=guard_home,
                content_hash=content_hash,
            )["changed"]
        )
    except NativeConsumerProjectError:
        # Status stays readable when the resident cannot answer; an artifact
        # whose diff is unknown is reported as needing review, never as clean.
        return True
