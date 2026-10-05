"""Content-bound integration plans and managed-file ownership checks."""

from __future__ import annotations

import json
from dataclasses import dataclass
from functools import cache
from pathlib import Path

from . import BUILDER_VERSION
from .errors import BuilderError
from .io import (
    canonical_json,
    checked_path,
    digest,
    object_value,
    parse_json,
    read_bytes,
    read_json,
    sha256,
    text_from_bytes,
)
from .kit import MAX_ARTIFACT_BYTES, Kit, build_kit
from .models import Metadata, load_discovery
from .repository_edits import (
    PYPROJECT_PATH,
    STAGING_PATH,
    TRUST_PATH,
    conflict,
    edit_pyproject,
    edit_staging,
    edit_trust,
    trust_members,
)
from .review import load_review

OWNERSHIP_SCHEMA = "guard.extension-authoring-install.v1"
PLAN_SCHEMA = "guard.extension-integration-plan.v1"


@dataclass(frozen=True, slots=True)
class Change:
    path: str
    before: bytes | None
    after: bytes | None

    def to_dict(self) -> dict[str, object]:
        if self.after is None:
            action = "delete"
        elif self.before is None:
            action = "create"
        elif self.before == self.after:
            action = "unchanged"
        else:
            action = "update"
        return {
            "path": self.path,
            "action": action,
            "beforeSha256": sha256(self.before) if self.before is not None else None,
            "afterSha256": sha256(self.after) if self.after is not None else None,
        }


@dataclass(frozen=True, slots=True)
class IntegrationPlan:
    root: Path
    contribution_id: str
    revision: str
    changes: tuple[Change, ...]

    def to_dict(self) -> dict[str, object]:
        content: dict[str, object] = {
            "schemaVersion": PLAN_SCHEMA,
            "contributionId": self.contribution_id,
            "revisionDigest": self.revision,
            "activeProtectionChanged": False,
            "files": [change.to_dict() for change in self.changes],
        }
        return {"ok": True, **content, "planDigest": digest(content)}


def ownership_root(metadata: Metadata) -> str:
    return f"contributions/authoring/{metadata.contribution_id}"


def managed_files(kit: Kit) -> dict[str, bytes]:
    files = {path: content.encode("utf-8") for path, content in kit.native_files().items()}
    prefix = ownership_root(kit.discovery.metadata)
    kit_files = dict(kit.files)
    for name in ("discovery.json", "review.json", "report.json", "README.md"):
        files[f"{prefix}/{name}"] = kit_files[name].encode("utf-8")
    return files


def ownership_record(kit: Kit) -> bytes:
    return canonical_json(
        {
            "schemaVersion": OWNERSHIP_SCHEMA,
            "builderVersion": BUILDER_VERSION,
            "contributionId": kit.discovery.metadata.contribution_id,
            "revisionDigest": kit.revision,
            "managedFiles": {path: sha256(content) for path, content in sorted(managed_files(kit).items())},
        }
    ).encode("utf-8")


def _read_optional(path: Path) -> bytes | None:
    path = checked_path(path)
    return read_bytes(path, limit=MAX_ARTIFACT_BYTES) if path.exists() else None


def _legacy_generated_test_path(path: str) -> bool:
    if not path.startswith("tests/") or not path.endswith(".py"):
        return False
    name = path.rsplit("/", 1)[-1]
    return name.startswith("test_generated_") or (
        name.startswith("test_guard_mcp_") and name.endswith("_contribution.py")
    )


def _previous_kit(root: Path, metadata: Metadata) -> tuple[Kit | None, dict[str, str]]:
    prefix = root / ownership_root(metadata)
    record = _read_optional(prefix / "record.json")
    if record is None:
        return None, {}
    payload = object_value(read_json(prefix / "record.json"))
    if payload.get("schemaVersion") != OWNERSHIP_SCHEMA or payload.get("builderVersion") != BUILDER_VERSION:
        raise conflict("The prior authoring record uses an unsupported builder contract; migrate it explicitly.")
    managed = payload.get("managedFiles")
    if isinstance(managed, dict) and any(
        isinstance(path, str) and (path.endswith("_extensions.py") or path.startswith("tests/test_generated_cli_"))
        for path in managed
    ):
        raise conflict(
            "The prior kit contains generated Python detector artifacts; regenerate it as a declarative "
            "command source and review the resulting native diff before applying."
        )
    discovery = load_discovery(read_json(prefix / "discovery.json"))
    if discovery.metadata.contribution_id != metadata.contribution_id:
        raise conflict("The existing authoring record belongs to a different contribution.")
    review = load_review(read_json(prefix / "review.json"), discovery)
    previous = build_kit(discovery, review)
    legacy_orphans: dict[str, str] = {}
    if record != ownership_record(previous):
        # Builders that emitted a per-MCP generated test module recorded it in
        # managedFiles; current builders no longer generate that file. A record
        # that differs only by those legacy test entries still proves ownership.
        expected_payload = object_value(parse_json(ownership_record(previous)))
        expected_managed = object_value(expected_payload.get("managedFiles"))
        stored_managed = object_value(payload.get("managedFiles"))
        extra = set(stored_managed) - set(expected_managed)
        if (
            not extra
            or any(not _legacy_generated_test_path(path) for path in extra)
            or {key: value for key, value in payload.items() if key != "managedFiles"}
            != {key: value for key, value in expected_payload.items() if key != "managedFiles"}
            or {path: stored_managed[path] for path in stored_managed if path not in extra} != expected_managed
        ):
            raise conflict("The existing authoring ownership record does not match its reviewed source contracts.")
        legacy_orphans = {path: str(stored_managed[path]) for path in extra}
    for path, expected in managed_files(previous).items():
        if _read_optional(root / path) != expected:
            raise conflict(
                "An installed generated file was edited or removed; preserve it and resolve the conflict manually."
            )
    return previous, legacy_orphans


def _executable_identity(value: str) -> str:
    name = value.replace("\\", "/").rsplit("/", 1)[-1].lower()
    return name.removesuffix(".exe").removesuffix(".cmd")


def _installed_executable_collision(metadata: Metadata) -> None:
    # This is the installed Guard registry, never code imported from the destination
    # checkout. Destination-only contributions are checked separately as JSON data.
    # Core domains such as Git and Docker keep their executable names on the native
    # program rules, not on the catalog extension record.
    from ..runtime.command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY

    wanted = _executable_identity(metadata.executable)
    covered: set[str] = set()
    for extension in BUILT_IN_COMMAND_EXTENSION_REGISTRY.extensions:
        if extension.extension_id == metadata.catalog_id:
            continue
        covered.update(_executable_identity(name) for name in extension.executables)
    for extension_id, names in _native_program_executables().items():
        if extension_id == metadata.catalog_id:
            continue
        covered.update(names)
    if wanted in covered:
        raise conflict("This executable already has Guard coverage; extend its existing contribution instead.")


@cache
def _native_program_executables() -> dict[str, frozenset[str]]:
    from ..native_command_control_binding import _program_path

    content = _program_path().read_bytes()
    if len(content) > 4_000_000:
        raise conflict("Installed command coverage could not be read.")
    program = json.loads(content)
    rules = program.get("rules") if isinstance(program, dict) else None
    covered: dict[str, set[str]] = {}
    if isinstance(rules, list):
        for rule in rules:
            if not isinstance(rule, dict):
                continue
            extension_id = rule.get("extension_id")
            names = rule.get("candidate_executables")
            if not isinstance(extension_id, str) or not isinstance(names, list):
                continue
            bucket = covered.setdefault(extension_id, set())
            bucket.update(_executable_identity(name) for name in names if isinstance(name, str))
    return {key: frozenset(value) for key, value in covered.items()}


def _contribution_collisions(root: Path, metadata: Metadata) -> None:
    family = "extensions" if metadata.kind == "cli" else "mcp-servers"
    directory = checked_path(root / "contributions" / family)
    if not directory.is_dir():
        raise conflict("The destination contribution directory is missing.")
    seen = 0
    for path in directory.iterdir():
        if path.suffix != ".json":
            continue
        seen += 1
        if seen > 512:
            raise conflict("The destination contribution inventory exceeds the supported catalog limit.")
        payload = object_value(read_json(path))
        if payload.get("id") == metadata.contribution_id:
            continue
        if metadata.kind == "mcp":
            package = object_value(payload.get("launch")).get("package")
            if isinstance(package, str) and package.strip().lower() == metadata.package.lower():
                raise conflict("This MCP package already has a contribution; update that contribution instead.")
        else:
            values = payload.get("executables")
            if not isinstance(values, list) or any(not isinstance(item, str) for item in values):
                raise conflict("An existing CLI contribution has an invalid executable inventory.")
            if any(_executable_identity(str(item)) == _executable_identity(metadata.executable) for item in values):
                raise conflict("This executable is already owned by another source contribution.")
    if metadata.kind == "cli":
        _installed_executable_collision(metadata)


def _shared_files(root: Path, metadata: Metadata) -> dict[str, str]:
    paths = [PYPROJECT_PATH, TRUST_PATH, STAGING_PATH]
    return {path: text_from_bytes(read_bytes(root / path)) for path in paths}


def _edited_shared(files: dict[str, str], metadata: Metadata) -> dict[str, str]:
    edited = {
        TRUST_PATH: edit_trust(files[TRUST_PATH], metadata),
        PYPROJECT_PATH: edit_pyproject(files[PYPROJECT_PATH], metadata),
        STAGING_PATH: edit_staging(files[STAGING_PATH], metadata),
    }
    return edited


def plan_repository(kit: Kit, repository: Path) -> IntegrationPlan:
    root = checked_path(repository)
    if not root.is_dir():
        raise BuilderError("repository_directory", "The destination must be an existing HOL Guard checkout.")
    verified = build_kit(kit.discovery, kit.review)
    if verified.files != kit.files:
        raise BuilderError("kit_changed", "Only a reproducible, validated kit can be integrated.")
    metadata = kit.discovery.metadata
    previous, legacy_orphans = _previous_kit(root, metadata)
    shared = _shared_files(root, metadata)
    classes = trust_members(shared[TRUST_PATH])
    if previous is None and any(metadata.catalog_id in values for values in classes.values()):
        raise conflict("This catalog ID already exists and is not owned by this authoring workflow.")
    if previous is not None and _edited_shared(shared, previous.discovery.metadata) != shared:
        raise conflict(
            "An installed registration or packaging entry was removed; reconcile the shared-file edit first."
        )
    _contribution_collisions(root, metadata)
    native = managed_files(kit)
    native[f"{ownership_root(metadata)}/record.json"] = ownership_record(kit)
    changes: list[Change] = []
    for path, after in native.items():
        before = _read_optional(root / path)
        if previous is None and before is not None:
            raise conflict("A new contribution would overwrite an existing file without an authoring ownership record.")
        changes.append(Change(path, before, after))
    for path, after in _edited_shared(shared, metadata).items():
        changes.append(Change(path, shared[path].encode("utf-8"), after.encode("utf-8")))
    # Legacy generated test modules are no longer managed outputs: remove each
    # accepted orphan only while its contents still match the ownership digest,
    # so a contributor-edited file is never deleted.
    for path, expected_digest in sorted(legacy_orphans.items()):
        before = _read_optional(root / path)
        if before is not None and sha256(before) == expected_digest:
            changes.append(Change(path, before, None))
    return IntegrationPlan(
        root, metadata.contribution_id, kit.revision, tuple(sorted(changes, key=lambda item: item.path))
    )
