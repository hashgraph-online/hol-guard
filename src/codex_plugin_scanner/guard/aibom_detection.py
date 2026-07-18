"""Shared AIBOM artifact discovery and content hashing for Guard inventory."""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from pathlib import Path
from typing import Literal

from ..marketplace_support import extract_marketplace_source, load_marketplace_context
from ..path_support import is_safe_relative_path, iter_safe_matching_files, resolves_within_root
from .codex_skill_config import load_codex_skill_config_rules, resolve_codex_skill_enabled
from .inventory_contract import fingerprint_mapping, fingerprint_path_tree, fingerprint_text
from .models import GuardArtifact, HarnessDetection
from .runtime.approval_context import build_configured_environment_hash, build_configured_header_values_hash

InstructionRole = Literal[
    "agents_md",
    "cursor_rules",
    "claude_md",
    "mcp_json",
    "design_md",
    "product_md",
    "roadmap_md",
    "security_md",
    "policy_md",
    "standards_md",
    "unknown_instruction",
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

# Harnesses that natively discover skills from the shared ``.agents/skills``
# workspace directory.  Other harnesses (e.g. Hermes, Copilot) use their own
# skill directories and must not pick up Codex/OpenClaw-style workspace skills.
# Keep this set in sync with CANONICAL_HARNESS_VALUES in product_model.py.
_WORKSPACE_CODEX_SKILL_HARNESSES = frozenset(
    {
        "codex",
        "openclaw",
        "opencode",
        "claude-code",
        "cursor",
        "gemini",
        "pi",
    }
)
_STANDARDS_CONTEXT_ROOTS = (".", ".agents/context", "docs")
_ROOT_INSTRUCTION_ROLE_NAMES: tuple[tuple[str, InstructionRole], ...] = (
    ("CLAUDE.md", "claude_md"),
    ("DESIGN.md", "design_md"),
    ("PRODUCT.md", "product_md"),
    ("ROADMAP.md", "roadmap_md"),
    ("SECURITY.md", "security_md"),
    ("POLICY.md", "policy_md"),
    ("POLICIES.md", "policy_md"),
    ("STANDARDS.md", "standards_md"),
)
_DOC_DIRECTORY_ROLES: tuple[tuple[str, InstructionRole], ...] = (
    ("design", "design_md"),
    ("product", "product_md"),
    ("standards", "standards_md"),
    ("policy", "policy_md"),
    ("policies", "policy_md"),
    ("security", "security_md"),
    ("roadmap", "roadmap_md"),
)
_STANDARDS_INSTRUCTION_FILES = _ROOT_INSTRUCTION_ROLE_NAMES


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
    env_values_hash: str | None = None,
    headers_keys: tuple[str, ...] = (),
    header_values_hash: str | None = None,
) -> str:
    return fingerprint_mapping(
        {
            "command": command,
            "args": list(args),
            "url": url,
            "transport": transport,
            "env_keys": sorted(env_keys),
            "env_values_hash": env_values_hash,
            "headers_keys": sorted(headers_keys),
            "header_values_hash": header_values_hash,
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
    if name == "roadmap.md":
        return "roadmap_md"
    if name == "security.md":
        return "security_md"
    if name in {"policy.md", "policies.md"}:
        return "policy_md"
    if name == "standards.md":
        return "standards_md"
    if name == "mcp.json":
        return "mcp_json"
    if path.suffix.lower() in {".md", ".mdc"}:
        parts = path.parts
        for index, part in enumerate(parts):
            if part == ".cursor" and index + 1 < len(parts) and parts[index + 1] == "rules":
                return "cursor_rules"
            if part == "docs" and index + 1 < len(parts):
                child = parts[index + 1].lower()
                for directory_name, role in _DOC_DIRECTORY_ROLES:
                    if child == directory_name:
                        return role
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
    if harness in _WORKSPACE_CODEX_SKILL_HARNESSES:
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
        docs_root = search_root / "docs"
        if not docs_root.is_dir() or not resolves_within_root(workspace_dir, docs_root, require_exists=True):
            continue
        for directory_name, _role in _DOC_DIRECTORY_ROLES:
            base_dir = docs_root / directory_name
            if not base_dir.is_dir() or not resolves_within_root(workspace_dir, base_dir, require_exists=True):
                continue
            for doc_path in _iter_recursive_markdown_files(workspace_dir, base_dir):
                normalized_path = doc_path.resolve().as_posix()
                if normalized_path in seen_paths:
                    continue
                seen_paths.add(normalized_path)
                role = instruction_role_for_path(doc_path) or "unknown_instruction"
                relative_id = doc_path.relative_to(workspace_dir).as_posix()
                artifacts.append(
                    _instruction_artifact(
                        harness,
                        doc_path,
                        role=role,
                        scope="project",
                        display_name=relative_id,
                        artifact_name=relative_id.replace("/", ":"),
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


def _iter_recursive_markdown_files(root: Path, base_dir: Path) -> tuple[Path, ...]:
    return tuple(
        candidate
        for candidate in sorted(base_dir.rglob("*.md"))
        if candidate.is_file()
        and not candidate.is_symlink()
        and resolves_within_root(root, candidate, require_exists=True)
    )


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
    content_digest = file_content_hash(path) or fingerprint_text(path.name)
    content_hash = f"sha256:{content_digest}"
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
    # Defense-in-depth: only Claude rules markdown may be replaced by workspace-root
    # CLAUDE.md when IDs collide. MCP servers are namespaced under mcp:, and current
    # rule discovery uses rules-{stem}, but legacy inventories may still carry the
    # pre-prefix rules ID at the CLAUDE.md legacy artifact_id.
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
    configured_environment: Mapping[str, object] | None = None,
    configured_headers: Mapping[str, object] | None = None,
) -> dict[str, object]:
    normalized_env_keys = _canonical_mcp_configured_keys(metadata.get("env_keys"))
    raw_env = configured_environment if configured_environment is not None else metadata.get("env")
    normalized_env = _canonical_mcp_configured_values(raw_env)
    if not normalized_env_keys and normalized_env:
        normalized_env_keys = tuple(sorted(normalized_env))
    raw_env_values_hash = metadata.get("env_values_hash")
    env_values_hash = (
        raw_env_values_hash.strip()
        if isinstance(raw_env_values_hash, str) and raw_env_values_hash.strip()
        else build_configured_environment_hash(
            normalized_env,
            configured_keys=normalized_env_keys,
        )
    )
    normalized_headers_keys = _canonical_mcp_configured_keys(metadata.get("headers_keys"))
    raw_headers = configured_headers if configured_headers is not None else metadata.get("headers")
    normalized_headers = _canonical_mcp_configured_values(raw_headers)
    if not normalized_headers_keys and normalized_headers:
        normalized_headers_keys = tuple(sorted(normalized_headers))
    raw_header_values_hash = metadata.get("header_values_hash")
    header_values_hash = (
        raw_header_values_hash.strip()
        if isinstance(raw_header_values_hash, str) and raw_header_values_hash.strip()
        else build_configured_header_values_hash(
            normalized_headers,
            configured_keys=normalized_headers_keys,
        )
    )
    content_hash = mcp_server_content_hash(
        command=command,
        args=args,
        url=url,
        transport=transport,
        env_keys=normalized_env_keys,
        env_values_hash=env_values_hash,
        headers_keys=normalized_headers_keys,
        header_values_hash=header_values_hash,
    )
    enriched = dict(metadata)
    enriched["env_keys"] = list(normalized_env_keys)
    enriched["headers_keys"] = list(normalized_headers_keys)
    enriched["env_values_hash"] = env_values_hash
    enriched["header_values_hash"] = header_values_hash
    enriched["content_hash"] = content_hash
    enriched.update(version_info_metadata(content_hash=content_hash, version_label=str(metadata.get("name", "mcp"))))
    return enriched


def _canonical_mcp_configured_key(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    normalized = value.strip()
    return normalized or None


def _canonical_mcp_configured_keys(value: object) -> tuple[str, ...]:
    if not isinstance(value, (list, tuple)):
        return ()
    normalized = {key for item in value if (key := _canonical_mcp_configured_key(item)) is not None}
    return tuple(sorted(normalized))


def _canonical_mcp_configured_values(value: object) -> dict[str, str]:
    if not isinstance(value, Mapping):
        return {}
    normalized: dict[str, str] = {}
    for raw_key, raw_value in value.items():
        key = _canonical_mcp_configured_key(raw_key)
        if key is not None and isinstance(raw_value, str):
            normalized[key] = raw_value
    return normalized
