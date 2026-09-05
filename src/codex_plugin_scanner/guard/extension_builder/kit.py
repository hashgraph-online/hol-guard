"""Reproducible contribution kits with rebuild-based validation, not code imports."""

from __future__ import annotations

import os
import re
import shutil
import tempfile
from dataclasses import dataclass
from pathlib import Path

from . import BUILDER_VERSION
from .errors import BuilderError
from .io import canonical_json, checked_path, read_bytes, read_json, sha256
from .models import Discovery, load_discovery
from .render_native import (
    contribution_path,
    detector_path,
    render_contribution,
    render_detector,
    revision_digest,
    test_path,
)
from .render_tests import render_cli_tests, render_mcp_tests
from .review import Review, load_review

MANIFEST_SCHEMA = "guard.extension-kit.v1"
MAX_ARTIFACT_BYTES = 4_194_304
MAX_KIT_BYTES = 16_777_216


@dataclass(frozen=True, slots=True)
class Kit:
    discovery: Discovery
    review: Review
    files: tuple[tuple[str, str], ...]

    @property
    def revision(self) -> str:
        return revision_digest(self.discovery, self.review)

    def summary(self) -> dict[str, object]:
        decisions = [decision for _, decision in self.review.entries]
        return {
            "ok": True,
            "schemaVersion": MANIFEST_SCHEMA,
            "builderVersion": BUILDER_VERSION,
            "contributionId": self.discovery.metadata.contribution_id,
            "discoveryDigest": self.discovery.binding,
            "revisionDigest": self.revision,
            "discoveredOperations": len(self.discovery.operations),
            "reviewedOperations": sum(decision.reviewed for decision in decisions),
            "explicitBlocks": sum(decision.state == "block" for decision in decisions),
            "exactSafeInvocations": sum(len(decision.safe_argv) for decision in decisions),
            "activeProtectionChanged": False,
            "files": [name for name, _ in self.files],
        }

    def native_files(self) -> dict[str, str]:
        return {
            name.removeprefix("artifacts/"): content for name, content in self.files if name.startswith("artifacts/")
        }


def _report(discovery: Discovery, review: Review) -> dict[str, object]:
    decisions = review.by_id()
    return {
        "schemaVersion": "guard.extension-coverage-report.v1",
        "discoveryDigest": discovery.binding,
        "revisionDigest": revision_digest(discovery, review),
        "coverageMeaning": "Enumerated metadata only; not a security certification or proof of runtime completeness.",
        "upstreamVersion": discovery.metadata.upstream_version,
        "binaryIdentityVerified": False,
        "activeProtectionChanged": False,
        "unknownOperationBehavior": "review" if discovery.metadata.kind == "cli" else "inherit",
        "limitations": list(discovery.limitations),
        "discoveredOperations": len(discovery.operations),
        "reviewedOperations": sum(decision.reviewed for decision in decisions.values()),
        "operations": [
            {
                "id": row.operation_id,
                "path": list(row.path),
                "toolName": row.name,
                "untrustedHints": list(row.hints),
                "state": decisions[row.operation_id].state,
                "reviewed": decisions[row.operation_id].reviewed,
                "exactSafeInvocations": [list(argv) for argv in decisions[row.operation_id].safe_argv],
            }
            for row in discovery.operations
        ],
    }


def _readme(discovery: Discovery) -> str:
    metadata = discovery.metadata
    safe_name = re.sub(r"([\\`*_{}\[\]()#+.!|<>~-])", r"\\\1", metadata.name)
    return f"""# {safe_name}: Guard contribution kit

This is generated contributor knowledge, not a security certificate. The extension
is External, opt-in, and off until an administrator enables it. Generation and
validation never run the target or change Guard policy.

## Review first

Read `report.json` and inspect every operation against the upstream implementation.
Edit `review.json`, not the generated artifacts. Changed behavior needs
`reviewed: true`, rationale, and an HTTPS evidence reference. Names, descriptions,
help flags, and MCP annotations do not establish safety. Unknown CLI invocations
retain review; unknown MCP tools inherit existing Guard handling.

Recompile edits into a new directory from this kit's parent directory:

```sh
hol-guard extensions generate --from snapshot --input KIT/discovery.json --review KIT/review.json --output REVIEWED_KIT
hol-guard extensions validate REVIEWED_KIT
hol-guard extensions apply REVIEWED_KIT --repo /path/to/hol-guard
```

Replace `KIT`, `REVIEWED_KIT`, and the checkout path with your actual paths.
Inspect the plan, then explicitly add `--write` and optionally
`--expected-plan PLAN_DIGEST`. Apply never commits, activates, or submits a PR.
Existing manual edits are conflicts, not permission to overwrite work.

## Native verification in the destination checkout

```sh
python scripts/release/stage_guard_cloud_review_artifacts.py
python -m pytest {test_path(metadata)}
python -m pytest tests/test_guard_extension_contribution.py tests/test_guard_mcp_server_contribution.py
```

The generated cases exercise Guard's native parser and registry, not the target's
behavior. Add implementation-specific cases before submitting a contribution.
Never run destructive commands merely to satisfy a test. Review the full Git diff,
including publisher metadata, review rationales, and URLs, before making it public.

## Drift and boundaries

The snapshot records a claimed upstream version, not binary or server attestation.
Changed discovery invalidates review. The CLI rule revision binds the complete
discovery and review digest; it is an opaque content revision, not release order.
Exact safe invocations still rely on the surrounding Guard policy and installed
executable identity. They cannot suppress another rule or required safety floor.
Apply uses per-file replacement and rollback for ordinary errors, not a
crash-atomic filesystem transaction. After a crash, inspect Git status and the
`.hol-guard-extension-authoring.lock` before any retry.
"""


def build_kit(discovery: Discovery, review: Review) -> Kit:
    discovery = load_discovery(discovery.to_dict())
    review = load_review(review.to_dict(), discovery)
    metadata = discovery.metadata
    files: dict[str, str] = {
        "discovery.json": canonical_json(discovery.to_dict()),
        "review.json": canonical_json(review.to_dict()),
        "report.json": canonical_json(_report(discovery, review)),
        "README.md": _readme(discovery),
        f"artifacts/{contribution_path(metadata)}": render_contribution(discovery, review),
        f"artifacts/{test_path(metadata)}": (
            render_cli_tests(discovery, review) if metadata.kind == "cli" else render_mcp_tests(discovery, review)
        ),
    }
    if metadata.kind == "cli":
        files[f"artifacts/{detector_path(metadata)}"] = render_detector(discovery, review)
    manifest = {
        "schemaVersion": MANIFEST_SCHEMA,
        "builderVersion": BUILDER_VERSION,
        "contributionId": metadata.contribution_id,
        "discoveryDigest": discovery.binding,
        "revisionDigest": revision_digest(discovery, review),
        "files": {name: sha256(content.encode("utf-8")) for name, content in sorted(files.items())},
    }
    files["manifest.json"] = canonical_json(manifest)
    sizes = [len(content.encode("utf-8")) for content in files.values()]
    if max(sizes) > MAX_ARTIFACT_BYTES or sum(sizes) > MAX_KIT_BYTES:
        raise BuilderError("kit_limit", "Compiled kit exceeds the bounded artifact budget.")
    return Kit(discovery, review, tuple(sorted(files.items())))


def _listed_files(root: Path) -> set[str]:
    pending = [root]
    files: set[str] = set()
    visited = 0
    try:
        while pending:
            directory = pending.pop()
            for entry in directory.iterdir():
                visited += 1
                if visited > 64:
                    raise BuilderError("kit_files", "Kit contains unexpected or excessive filesystem entries.")
                checked_path(entry)
                if entry.is_dir():
                    pending.append(entry)
                else:
                    files.add(entry.relative_to(root).as_posix())
    except OSError as exc:
        raise BuilderError("kit_files", "Cannot inspect the contribution kit directory.") from exc
    return files


def load_kit(path: Path) -> Kit:
    root = checked_path(path)
    if not root.is_dir():
        raise BuilderError("kit_directory", "A kit must be an existing regular directory.")
    discovery = load_discovery(read_json(root / "discovery.json"))
    review = load_review(read_json(root / "review.json"), discovery)
    expected = build_kit(discovery, review)
    if _listed_files(root) != {name for name, _ in expected.files}:
        raise BuilderError(
            "kit_files", "Kit file set differs from the compiler output; regenerate into a new directory."
        )
    for name, content in expected.files:
        if read_bytes(root / name, limit=MAX_ARTIFACT_BYTES) != content.encode("utf-8"):
            raise BuilderError(
                "kit_changed", "Kit bytes differ from rebuilt output; recompile review edits into a new kit."
            )
    return expected


def write_kit(kit: Kit, path: Path) -> None:
    if build_kit(kit.discovery, kit.review).files != kit.files:
        raise BuilderError("kit_changed", "Only a reproducible compiled kit can be written.")
    output = checked_path(path)
    if output.exists():
        raise BuilderError("output_exists", "Output already exists; choose a new kit directory.", conflict=True)
    if not output.parent.is_dir():
        raise BuilderError("output_parent", "The output parent must be an existing directory.")
    staging: Path | None = None
    try:
        staging = Path(tempfile.mkdtemp(prefix=".hol-guard-kit-", dir=output.parent))
        for name, content in kit.files:
            target = staging / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content, encoding="utf-8", newline="\n")
        checked_path(output)
        if output.exists():
            raise BuilderError(
                "output_exists", "Output appeared during generation; choose a new directory.", conflict=True
            )
        os.rename(staging, output)
        staging = None
    except OSError as exc:
        raise BuilderError("output_write", "Unable to publish the completed contribution kit.", conflict=True) from exc
    finally:
        if staging is not None:
            shutil.rmtree(staging)


def diff_kits(previous: Kit, current: Kit) -> dict[str, object]:
    if previous.discovery.metadata.contribution_id != current.discovery.metadata.contribution_id:
        raise BuilderError("diff_identity", "Compare snapshots belonging to the same contribution ID.")
    before = {row.operation_id: row.to_dict() for row in previous.discovery.operations}
    after = {row.operation_id: row.to_dict() for row in current.discovery.operations}
    old_review = previous.review.by_id()
    new_review = current.review.by_id()
    common = set(before) & set(after)
    return {
        "ok": True,
        "changed": previous.files != current.files,
        "discoveryChanged": previous.discovery.binding != current.discovery.binding,
        "previousRevision": previous.revision,
        "currentRevision": current.revision,
        "addedOperations": sorted(set(after) - set(before)),
        "removedOperations": sorted(set(before) - set(after)),
        "changedOperations": sorted(key for key in common if before[key] != after[key]),
        "changedReviews": sorted(key for key in common if old_review[key] != new_review[key]),
        "metadataChanged": previous.discovery.metadata != current.discovery.metadata,
    }
