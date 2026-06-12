"""Shared AIBOM artifact discovery and content hashing for Guard inventory."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Literal

from ..marketplace_support import extract_marketplace_source, load_marketplace_context
from ..path_support import is_safe_relative_path, iter_safe_matching_files, resolves_within_root
from .codex_skill_config import load_codex_skill_config_rules, resolve_codex_skill_enabled
from .inventory_contract import fingerprint_mapping, fingerprint_path_tree, fingerprint_text
from .models import GuardArtifact, HarnessDetection

InstructionRole = Literal[
    "agents_md",
    "cursor_rules",
    "claude_md",
    "design_md",
    "mcp_json",
    "product_md",
]
INVENTORY_ITEM_KINDS: tuple[str, ...] = (
    "agent",
    "daemon_plugin",
    "harness",
    "model_provider",
    "package",
    "prompt_pack",
    "skill",
    "mcp_server",
    "mcp_tool",
    "plugin",
    "channel",
    "hook",
    "overlay",
    "repository",
    "container_image",
    "policy",
    "secret_reference",
    "network_endpoint",
)

_READ_CHUNK_BYTES = 65536
_CURSOR_RULE_PATTERNS = ("*.mdc", "*.md")
_CODEX_WORKSPACE_SKILL_ROOTS = (".agents/skills",)
_CODEX_HOME_SKILL_ROOTS = (".codex/skills", ".agents/skills")
_STANDARDS_CONTEXT_ROOTS = (".", ".agents/context", "docs")
_STANDARDS_INSTRUCTION_FILES: tuple[tuple[str, InstructionRole], ...] = (
    ("PRODUCT.md", "product_md"),
    ("DESIGN.md", "design_md"),
    ("CLAUDE.md", "claude_md"),
)


def file_content_hash(path: Path, *, max_bytes: int | None = None) -> str | None:
    """Return a SHA-256 digest of the full file bytes used for approval drift detection.

    When ``max_bytes`` is set, only that prefix is hashed. Production callers must
    leave ``max_bytes`` unset so tail edits cannot bypass change detection.
    """
    try:
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            if max_bytes is None:
                while True:
                    chunk = handle.read(_READ_CHUNK_BYTES)
                    if not chunk:
                        break
                    digest.update(chunk)
            else:
                digest.update(handle.read(max_bytes))
        return digest.hexdigest()
    except OSError:
        return None


def directory_content_hash(root: Path, *, home_dir: Path) -> str:
    return fingerprint_path_tree(root, home_dir=home_dir)


def mcp_server_content_hash(
    *,
    command: str | None,
    args: tuple[str, ...],
    url: str | None,
    transport: str | None,
    env_keys: tuple[str, ...] = (),
) -> str:
    return fingerprint_mapping(
        {
            "command": command,
            "args": list(args),
            "url": url,
            "transport": transport,
            "env_keys": sorted(env_keys),
        }
    )


def version_info_metadata(*, content_hash: str, version_label: str) -> dict[str, object]:
    return {
        "versionInfo": {
            "versionLabel": version_label,
            "hashBasis": "content",
            "contentHash": content_hash,
            "changedFields": [],
        }
    }


def instruction_role_for_path(path: Path) -> InstructionRole | None:
    name = path.name.lower()
    if name == "agents.md":
        return "agents_md"
    if name == "claude.md":
        return "claude_md"
    if name == "design.md":
        return "design_md"
    if name == "product.md":
        return "product_md"
    if name == "mcp.json":
        return "mcp_json"
    if path.suffix.lower() in {".md", ".mdc"}:
        parts = path.parts
        for index, part in enumerate(parts):
            if part == ".cursor" and index + 1 < len(parts) and parts[index + 1] == "rules":
                return "cursor_rules"
    return None


def discover_shared_workspace_aibom_artifacts(
    harness: str,
    *,
    home_dir: Path,
    workspace_dir: Path,
) -> tuple[GuardArtifact, ...]:
    if not workspace_dir.is_dir():
        return ()
    try:
        workspace_dir = workspace_dir.resolve()
    except OSError:
        return ()
    artifacts: list[GuardArtifact] = []
    artifacts.extend(_discover_agents_md(harness, workspace_dir=workspace_dir))
    artifacts.extend(_discover_standards_context_files(harness, workspace_dir=workspace_dir))
    artifacts.extend(_discover_cursor_rules(harness, workspace_dir=workspace_dir))
    if harness != "codex":
        artifacts.extend(
            _discover_codex_skills(
                harness,
                workspace_dir=workspace_dir,
                home_dir=home_dir,
                skill_roots=_CODEX_WORKSPACE_SKILL_ROOTS,
                source_scope="project",
                artifact_scope="project",
            )
        )
    artifacts.extend(_discover_codex_marketplace_plugins(harness, workspace_dir=workspace_dir))
    return tuple(artifacts)


def _discover_agents_md(harness: str, *, workspace_dir: Path) -> list[GuardArtifact]:
    agents_md = workspace_dir / "AGENTS.md"
    if not agents_md.is_file() or agents_md.is_symlink():
        return []
    if not resolves_within_root(workspace_dir, agents_md, require_exists=True):
        return []
    return [_instruction_artifact(harness, agents_md, role="agents_md", scope="project")]


def _discover_standards_context_files(harness: str, *, workspace_dir: Path) -> list[GuardArtifact]:
    artifacts: list[GuardArtifact] = []
    seen_paths: set[str] = set()
    for relative_root in _STANDARDS_CONTEXT_ROOTS:
        search_root = workspace_dir if relative_root == "." else workspace_dir / relative_root
        if relative_root != "." and not search_root.is_dir():
            continue
        if not resolves_within_root(workspace_dir, search_root, require_exists=True):
            continue
        for filename, role in _STANDARDS_INSTRUCTION_FILES:
            path = search_root / filename
            if path.is_symlink() or not path.is_file():
                continue
            if not resolves_within_root(workspace_dir, path, require_exists=True):
                continue
            normalized_path = path.resolve().as_posix()
            if normalized_path in seen_paths:
                continue
            seen_paths.add(normalized_path)
            relative_id = path.relative_to(workspace_dir).as_posix()
            display_name = path.name if relative_root == "." else f"{path.name} ({relative_root})"
            artifact_suffix = relative_id.replace("/", ":")
            legacy_artifact_id: str | None = None
            if harness == "claude-code" and relative_id == "CLAUDE.md":
                legacy_artifact_id = f"{harness}:project:instruction:claude-md"
            artifacts.append(
                _instruction_artifact(
                    harness,
                    path,
                    role=role,
                    scope="project",
                    display_name=display_name,
                    artifact_name=artifact_suffix,
                    artifact_id=legacy_artifact_id,
                )
            )
    return artifacts


def _discover_cursor_rules(harness: str, *, workspace_dir: Path) -> list[GuardArtifact]:
    rules_dir = workspace_dir / ".cursor" / "rules"
    if not rules_dir.is_dir() or not resolves_within_root(workspace_dir, rules_dir, require_exists=True):
        return []
    artifacts: list[GuardArtifact] = []
    for pattern in _CURSOR_RULE_PATTERNS:
        for rule_path in iter_safe_matching_files(workspace_dir, rules_dir, pattern):
            artifacts.append(
                _instruction_artifact(
                    harness,
                    rule_path,
                    role="cursor_rules",
                    scope="project",
                    display_name=rule_path.stem,
                )
            )
    return artifacts


def discover_codex_skill_artifacts(
    harness: str,
    *,
    home_dir: Path,
    workspace_dir: Path | None,
) -> tuple[GuardArtifact, ...]:
    artifacts: list[GuardArtifact] = []
    if workspace_dir is not None:
        artifacts.extend(
            _discover_codex_skills(
                harness,
                workspace_dir=workspace_dir,
                home_dir=home_dir,
                skill_roots=_CODEX_WORKSPACE_SKILL_ROOTS,
                source_scope="project",
                artifact_scope="project",
            )
        )
    artifacts.extend(
        _discover_codex_skills(
            harness,
            workspace_dir=home_dir,
            home_dir=home_dir,
            skill_roots=_CODEX_HOME_SKILL_ROOTS,
            source_scope="global",
            artifact_scope="global",
        )
    )
    rules = load_codex_skill_config_rules(home_dir=home_dir, workspace_dir=workspace_dir)
    if not rules:
        return tuple(artifacts)
    enriched: list[GuardArtifact] = []
    for artifact in artifacts:
        if artifact.artifact_type != "skill":
            enriched.append(artifact)
            continue
        metadata = dict(artifact.metadata)
        metadata["enabled"] = resolve_codex_skill_enabled(
            config_path=artifact.config_path,
            display_name=artifact.name,
            rules=rules,
            home_dir=home_dir,
        )
        enriched.append(
            GuardArtifact(
                artifact_id=artifact.artifact_id,
                name=artifact.name,
                harness=artifact.harness,
                artifact_type=artifact.artifact_type,
                source_scope=artifact.source_scope,
                config_path=artifact.config_path,
                command=artifact.command,
                args=artifact.args,
                url=artifact.url,
                transport=artifact.transport,
                metadata=metadata,
            )
        )
    return tuple(enriched)


def _discover_codex_skills(
    harness: str,
    *,
    workspace_dir: Path,
    home_dir: Path,
    skill_roots: tuple[str, ...],
    source_scope: str,
    artifact_scope: str,
) -> list[GuardArtifact]:
    artifacts: list[GuardArtifact] = []
    for relative_root in skill_roots:
        skill_root = workspace_dir / relative_root
        if not skill_root.is_dir() or not resolves_within_root(workspace_dir, skill_root, require_exists=True):
            continue
        for skill_md in sorted(skill_root.rglob("SKILL.md")):
            if skill_md.is_symlink() or not skill_md.is_file():
                continue
            if not resolves_within_root(workspace_dir, skill_md, require_exists=True):
                continue
            skill_dir = skill_md.parent
            relative_id = skill_dir.relative_to(skill_root).as_posix()
            content_hash = directory_content_hash(skill_dir, home_dir=home_dir)
            digest = file_content_hash(skill_md)
            metadata: dict[str, object] = {
                "enabled": True,
                "skill_root": relative_root,
                "content_hash": digest,
                "directory_hash": content_hash,
                **version_info_metadata(content_hash=content_hash, version_label=relative_id or skill_dir.name),
            }
            artifacts.append(
                GuardArtifact(
                    artifact_id=f"{harness}:{artifact_scope}:skill:{relative_root}:{relative_id or skill_dir.name}",
                    name=relative_id or skill_dir.name,
                    harness=harness,
                    artifact_type="skill",
                    source_scope=source_scope,
                    config_path=str(skill_md),
                    metadata=metadata,
                )
            )
    return artifacts


def _discover_codex_marketplace_plugins(harness: str, *, workspace_dir: Path) -> list[GuardArtifact]:
    context = load_marketplace_context(workspace_dir)
    if context is None:
        return []
    plugins = context.payload.get("plugins")
    if not isinstance(plugins, list):
        return []
    manifest_hash = file_content_hash(context.file_path)
    artifacts: list[GuardArtifact] = []
    marketplace_id = hashlib.sha256(str(context.file_path).encode()).hexdigest()[:12]
    if manifest_hash is not None:
        artifacts.append(
            GuardArtifact(
                artifact_id=f"{harness}:project:marketplace:{marketplace_id}",
                name="marketplace.json",
                harness=harness,
                artifact_type="plugin",
                source_scope="project",
                config_path=str(context.file_path),
                metadata={
                    "marketplace_root": True,
                    "content_hash": manifest_hash,
                    **version_info_metadata(content_hash=manifest_hash, version_label="marketplace.json"),
                },
            )
        )
    for index, entry in enumerate(plugins):
        if not isinstance(entry, dict):
            continue
        plugin_name = entry.get("name")
        if not isinstance(plugin_name, str) or not plugin_name.strip():
            plugin_name = f"plugin_{index}"
        source_ref, source_path = extract_marketplace_source(entry)
        metadata: dict[str, object] = {
            "enabled": entry.get("enabled", True) is not False,
            "marketplace_index": index,
            "source_ref": source_ref,
            "source_path": source_path,
        }
        plugin_manifest: Path | None = None
        if source_path and source_path.startswith("./"):
            relative = source_path[2:]
            if is_safe_relative_path(workspace_dir, relative, require_exists=False):
                candidate = workspace_dir / relative
                if candidate.is_dir() and resolves_within_root(
                    workspace_dir,
                    candidate,
                    require_exists=True,
                ):
                    for manifest_name in ("plugin.json", ".codex-plugin/plugin.json"):
                        manifest_candidate = candidate / manifest_name
                        if manifest_candidate.is_file() and resolves_within_root(
                            workspace_dir,
                            manifest_candidate,
                            require_exists=True,
                        ):
                            plugin_manifest = manifest_candidate
                            break
        if plugin_manifest is not None and plugin_manifest.is_file():
            manifest_digest = file_content_hash(plugin_manifest)
            if manifest_digest is not None:
                metadata["content_hash"] = manifest_digest
                metadata.update(
                    version_info_metadata(content_hash=manifest_digest, version_label=plugin_name),
                )
        artifacts.append(
            GuardArtifact(
                artifact_id=f"{harness}:project:marketplace-plugin:{marketplace_id}:{plugin_name}",
                name=plugin_name,
                harness=harness,
                artifact_type="plugin",
                source_scope="project",
                config_path=str(plugin_manifest or context.file_path),
                metadata=metadata,
            )
        )
    return artifacts


def _instruction_artifact(
    harness: str,
    path: Path,
    *,
    role: InstructionRole,
    scope: str,
    display_name: str | None = None,
    artifact_name: str | None = None,
    artifact_id: str | None = None,
) -> GuardArtifact:
    content_hash = file_content_hash(path) or fingerprint_text(path.name)
    name = display_name or path.name
    artifact_suffix = artifact_name or name
    resolved_artifact_id = artifact_id or f"{harness}:{scope}:instruction:{role}:{artifact_suffix}"
    return GuardArtifact(
        artifact_id=resolved_artifact_id,
        name=name,
        harness=harness,
        artifact_type="instruction",
        source_scope=scope,
        config_path=str(path),
        metadata={
            "instructionRole": role,
            "content_hash": content_hash,
            **version_info_metadata(content_hash=content_hash, version_label=name),
        },
    )


def extend_codex_runtime_inventory(
    detection: HarnessDetection,
    *,
    home_dir: Path,
    workspace_dir: Path | None,
) -> HarnessDetection:
    """Replace Codex skill inventory with home + workspace discovery and enablement rules."""

    if detection.harness != "codex":
        return detection
    skill_artifacts = discover_codex_skill_artifacts(
        detection.harness,
        home_dir=home_dir,
        workspace_dir=workspace_dir,
    )
    merged = [artifact for artifact in detection.artifacts if artifact.artifact_type != "skill"]
    found_paths = list(detection.config_paths)
    for artifact in skill_artifacts:
        merged.append(artifact)
        config_path = getattr(artifact, "config_path", None)
        if isinstance(config_path, str):
            found_paths.append(config_path)
    return HarnessDetection(
        harness=detection.harness,
        installed=detection.installed,
        command_available=detection.command_available,
        config_paths=tuple(dict.fromkeys(found_paths)),
        artifacts=tuple(merged),
        warnings=detection.warnings,
    )


def _is_claude_rules_instruction_replacement_target(
    existing: GuardArtifact,
    workspace_dir: Path,
) -> bool:
    if existing.artifact_type != "instruction" or existing.harness != "claude-code":
        return False
    config_path = getattr(existing, "config_path", None)
    if not isinstance(config_path, str):
        return False
    try:
        resolved = Path(config_path).resolve()
        rules_dir = (workspace_dir / ".claude" / "rules").resolve()
        return resolved.is_relative_to(rules_dir)
    except (OSError, ValueError):
        return False


def _is_workspace_root_claude_md(artifact: GuardArtifact, workspace_dir: Path) -> bool:
    metadata = artifact.metadata if isinstance(artifact.metadata, dict) else {}
    if metadata.get("instructionRole") != "claude_md":
        return False
    config_path = getattr(artifact, "config_path", None)
    if not isinstance(config_path, str):
        return False
    try:
        return Path(config_path).resolve() == (workspace_dir / "CLAUDE.md").resolve()
    except OSError:
        return False


def extend_detection_with_workspace_aibom(
    detection: HarnessDetection,
    *,
    home_dir: Path,
    workspace_dir: Path | None,
) -> HarnessDetection:
    if workspace_dir is None:
        return detection
    extra = discover_shared_workspace_aibom_artifacts(
        detection.harness,
        home_dir=home_dir,
        workspace_dir=workspace_dir,
    )
    if not extra:
        return detection
    existing_ids = {artifact.artifact_id for artifact in detection.artifacts}
    merged = list(detection.artifacts)
    artifact_index_by_id = {artifact.artifact_id: index for index, artifact in enumerate(merged)}
    found_paths = list(detection.config_paths)
    for artifact in extra:
        if artifact.artifact_id in existing_ids:
            if _is_workspace_root_claude_md(artifact, workspace_dir):
                existing_index = artifact_index_by_id[artifact.artifact_id]
                existing = merged[existing_index]
                if _is_claude_rules_instruction_replacement_target(existing, workspace_dir):
                    merged[existing_index] = artifact
                    config_path = getattr(artifact, "config_path", None)
                    if isinstance(config_path, str):
                        found_paths.append(config_path)
            continue
        merged.append(artifact)
        existing_ids.add(artifact.artifact_id)
        artifact_index_by_id[artifact.artifact_id] = len(merged) - 1
        config_path = getattr(artifact, "config_path", None)
        if isinstance(config_path, str):
            found_paths.append(config_path)
    return HarnessDetection(
        harness=detection.harness,
        installed=detection.installed,
        command_available=detection.command_available,
        config_paths=tuple(dict.fromkeys(found_paths)),
        artifacts=tuple(merged),
        warnings=detection.warnings,
    )


def enrich_mcp_server_metadata(
    metadata: dict[str, object],
    *,
    command: str | None,
    args: tuple[str, ...],
    url: str | None,
    transport: str | None,
) -> dict[str, object]:
    env_keys = metadata.get("env_keys")
    normalized_env_keys: tuple[str, ...] = ()
    if isinstance(env_keys, list):
        normalized_env_keys = tuple(str(key) for key in env_keys if isinstance(key, str))
    content_hash = mcp_server_content_hash(
        command=command,
        args=args,
        url=url,
        transport=transport,
        env_keys=normalized_env_keys,
    )
    enriched = dict(metadata)
    enriched["content_hash"] = content_hash
    enriched.update(version_info_metadata(content_hash=content_hash, version_label=str(metadata.get("name", "mcp"))))
    return enriched
