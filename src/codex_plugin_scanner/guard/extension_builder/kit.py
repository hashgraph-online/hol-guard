"""Reproducible contribution kits with rebuild-based validation, not code imports."""

from __future__ import annotations

import os
import re
import shutil
import tempfile
from dataclasses import dataclass
from importlib import resources
from pathlib import Path

from . import BUILDER_VERSION
from .errors import BuilderError
from .io import canonical_json, checked_path, parse_json, read_bytes, read_json, sha256
from .models import Discovery, load_discovery
from .native_source_compiler import NativeSourceCompilerError, compile_source, run_source_compiler
from .render_native import (
    COMMAND_FIXTURE_SCHEMA,
    command_fixture_path,
    command_source_path,
    contribution_path,
    render_command_fixture_cases,
    render_command_source,
    render_contribution,
    revision_digest,
    test_path,
)
from .render_tests import render_mcp_tests
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
    if metadata.kind == "cli":
        verification = f"""The command source is `{command_source_path(metadata)}` and its portable fixture
is `{command_fixture_path(metadata)}`. Kit validation compiles the source and
runs these cases with Rust. CLI kits do not generate a Python detector or a
Python test module.

After integration, follow the [native validation sequence](https://github.com/hashgraph-online/hol-guard/blob/main/docs/guard/extension-builder/VALIDATION.md):
regenerate the complete program, rebuild the native compiler and runtime, and
run the fixture with a build envelope assembled from the destination checkout's
canonical sources. The kit's `base: "packaged"` envelope is for a new addition;
it cannot replace an extension already embedded in the rebuilt compiler.
"""
    else:
        verification = f"""The MCP contribution is `{contribution_path(metadata)}`. Its generated Python
tests validate contribution metadata and native registration:

```sh
python -m pytest {test_path(metadata)}
```

Follow the [native validation sequence](https://github.com/hashgraph-online/hol-guard/blob/main/docs/guard/extension-builder/VALIDATION.md)
to regenerate and verify the complete catalog after integration.
"""
    return f"""# {safe_name}: Guard contribution kit

This is generated contributor knowledge, not a security certificate. The extension
is External, opt-in, and off until an administrator enables it. Generation and
validation never run the target or change Guard policy.

## Review first

Read `report.json` and inspect every operation against the upstream implementation.
Copy the review file from this kit's parent directory:

```sh
cp KIT/review.json REVIEW.json
```

Edit `REVIEW.json`. Changed behavior needs
`reviewed: true`, rationale, and an HTTPS evidence reference. Names, descriptions,
help flags, and MCP annotations do not establish safety. Unknown CLI invocations
retain review; unknown MCP tools inherit existing Guard handling.

Recompile edits into a new directory from this kit's parent directory:

```sh
hol-guard extensions generate --from snapshot --input KIT/discovery.json --review REVIEW.json --output REVIEWED_KIT
hol-guard extensions validate REVIEWED_KIT
hol-guard extensions apply REVIEWED_KIT --repo /path/to/hol-guard
```

Replace `KIT`, `REVIEW.json`, `REVIEWED_KIT`, and the checkout path with your actual paths.
Edit the copied review file before running snapshot generation. Inspect the plan,
then apply with `--expected-plan PLAN_DIGEST --write` using its printed digest.
Apply never commits, activates, or submits a PR.
Existing manual edits are conflicts, not permission to overwrite work.

## Native verification in the destination checkout

Stage the shared review resources before running contribution tests:

```sh
python scripts/release/stage_guard_cloud_review_artifacts.py
```

{verification}
Run the shared contribution checks:

```sh
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


def _trust_map() -> dict[str, object]:
    try:
        packaged = resources.files("codex_plugin_scanner.guard.contracts.data.extensions")
        value = parse_json((packaged / "trust-class-map.v1.json").read_bytes())
    except (FileNotFoundError, ModuleNotFoundError, OSError):
        path = Path(__file__).resolve().parents[4] / "contracts/extensions/trust-class-map.v1.json"
        value = read_json(path)
    if not isinstance(value, dict):
        raise BuilderError("native_trust", "The packaged extension trust map is invalid.")
    return value


def _compile_command_artifacts(discovery: Discovery, review: Review) -> dict[str, str]:
    metadata = discovery.metadata
    source_text = render_command_source(discovery, review)
    source = parse_json(source_text.encode("utf-8"))
    build = {
        "schema": "guard.command-extension-build.v1",
        "sources": [source],
        "trust": _trust_map(),
        "base": "packaged",
    }
    try:
        compiled = compile_source(build)
        fixture = {
            "schema": COMMAND_FIXTURE_SCHEMA,
            "build": build,
            "cases": render_command_fixture_cases(discovery, review),
        }
        fixture_result = run_source_compiler("test", fixture)
    except NativeSourceCompilerError as exc:
        location = f" at {exc.pointer}" if exc.pointer else ""
        raise BuilderError(
            "native_source", f"Native source validation failed{location}: {exc.code or str(exc)}"
        ) from exc
    if fixture_result.get("ok") is not True:
        raise BuilderError("native_fixtures", "Native source fixtures did not match the reviewed behavior.")
    descriptors = compiled.get("descriptors")
    if not isinstance(descriptors, list):
        raise BuilderError("native_descriptor", "Native source compiler omitted generated descriptors.")
    descriptor = next(
        (row for row in descriptors if isinstance(row, dict) and row.get("id") == metadata.catalog_id), None
    )
    if descriptor is None:
        raise BuilderError("native_descriptor", "Native source compiler omitted this contribution descriptor.")
    return {
        command_source_path(metadata): source_text,
        command_fixture_path(metadata): canonical_json(fixture),
        contribution_path(metadata): canonical_json(descriptor),
    }


def build_kit(discovery: Discovery, review: Review) -> Kit:
    # Normalization can expand a small source into a large document. Enforce the
    # same byte and structure budgets that subsequent on-disk replay will use.
    discovery = load_discovery(parse_json(canonical_json(discovery.to_dict()).encode("utf-8")))
    review = load_review(parse_json(canonical_json(review.to_dict()).encode("utf-8")), discovery)
    metadata = discovery.metadata
    files: dict[str, str] = {
        "discovery.json": canonical_json(discovery.to_dict()),
        "review.json": canonical_json(review.to_dict()),
        "report.json": canonical_json(_report(discovery, review)),
        "README.md": _readme(discovery),
    }
    if metadata.kind == "cli":
        artifacts = _compile_command_artifacts(discovery, review)
        files.update({f"artifacts/{path}": content for path, content in artifacts.items()})
    else:
        files[f"artifacts/{contribution_path(metadata)}"] = render_contribution(discovery, review)
        files[f"artifacts/{test_path(metadata)}"] = render_mcp_tests(discovery, review)
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


def _listed_files(root: Path, expected: set[str]) -> set[str]:
    allowed_directories = {
        parent.as_posix() for name in expected for parent in Path(name).parents if parent != Path(".")
    }
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
                relative = entry.relative_to(root).as_posix()
                if entry.is_dir():
                    if relative not in allowed_directories:
                        raise BuilderError("kit_files", "Kit contains a directory not owned by the compiler.")
                    pending.append(entry)
                else:
                    files.add(relative)
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
    expected_names = {name for name, _ in expected.files}
    if _listed_files(root, expected_names) != expected_names:
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
