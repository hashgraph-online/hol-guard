"""Content-bound integration plans and managed-file ownership checks."""

from __future__ import annotations

from dataclasses import dataclass
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
    BINDINGS_DIR,
    PYPROJECT_PATH,
    STAGING_PATH,
    conflict,
    edit_pyproject,
    edit_staging,
    project_trust_map,
    trust_binding_content,
    trust_binding_path,
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


def _contribution_collisions(root: Path, metadata: Metadata) -> None:
    from .native_source_compiler import NativeSourceCompilerError, run_source_compiler

    messages = {
        "authoring_contribution_directory_missing": "The destination contribution directory is missing.",
        "authoring_mcp_package_collision": (
            "This MCP package already has a contribution; update that contribution instead."
        ),
        "authoring_executable_inventory_invalid": "An existing CLI contribution has an invalid executable inventory.",
        "authoring_executable_contribution_collision": (
            "This executable is already owned by another source contribution."
        ),
        "authoring_installed_executable_collision": (
            "This executable already has Guard coverage; extend its existing contribution instead."
        ),
        "authoring_installed_coverage_invalid": "Installed command coverage could not be read.",
    }
    try:
        run_source_compiler(
            "authoring-admission",
            {
                "root": str(root.resolve()),
                "kind": metadata.kind,
                "contribution_id": metadata.contribution_id,
                "catalog_id": metadata.catalog_id,
                "executable": metadata.executable,
                "package": metadata.package,
            },
        )
    except NativeSourceCompilerError as exc:
        raise conflict(
            messages.get(exc.code or "", "The destination contribution inventory could not be validated.")
        ) from exc


def _shared_files(root: Path, metadata: Metadata) -> dict[str, str]:
    paths = [PYPROJECT_PATH, STAGING_PATH]
    core = "contracts/extensions/core-defaults.v1.json"
    if (root / core).exists() or (root / core).is_symlink():
        paths.append(core)
    files = {path: text_from_bytes(read_bytes(root / path)) for path in paths}
    bindings_dir = root / BINDINGS_DIR
    if bindings_dir.is_dir():
        for binding in sorted(bindings_dir.glob("*.v1.json")):
            files[str(binding.relative_to(root)).replace("\\", "/")] = text_from_bytes(read_bytes(binding))
    return files


def _edited_shared(files: dict[str, str], metadata: Metadata) -> dict[str, str]:
    # Author only the reviewed binding; package builds derive the aggregate.
    binding_path = trust_binding_path(metadata)
    binding_content = trust_binding_content(metadata)
    bindings = {path: content for path, content in files.items() if path.startswith(f"{BINDINGS_DIR}/")}
    # Guard against reclassifying an existing trusted extension.
    classes = trust_members(project_trust_map(bindings))
    if metadata.catalog_id in classes["first-party"] or metadata.catalog_id in classes["trusted-library"]:
        raise conflict("The builder cannot modify an existing trusted extension or change its trust class.")
    if metadata.catalog_id not in classes["external"]:
        bindings[binding_path] = binding_content
    edited = {
        PYPROJECT_PATH: edit_pyproject(
            files[PYPROJECT_PATH], metadata, core_profile="contracts/extensions/core-defaults.v1.json" in files
        ),
        STAGING_PATH: edit_staging(files[STAGING_PATH], metadata),
    }
    if binding_path in bindings and binding_path not in files:
        edited[binding_path] = binding_content
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
    classes = trust_members(project_trust_map({p: c for p, c in shared.items() if p.startswith(f"{BINDINGS_DIR}/")}))
    if previous is None and any(metadata.catalog_id in values for values in classes.values()):
        raise conflict("This catalog ID already exists and is not owned by this authoring workflow.")
    if previous is not None and any(
        shared.get(path) != edited for path, edited in _edited_shared(shared, previous.discovery.metadata).items()
    ):
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
        before_text = shared.get(path)
        before = before_text.encode("utf-8") if before_text is not None else None
        changes.append(Change(path, before, after.encode("utf-8")))
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
