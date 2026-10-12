"""Shared AIBOM artifact discovery facade for Guard inventory.

The native resident owns every discovery rule: instruction and standards
documents, cursor rules, Codex skill inventory and enablement rules, the Codex
marketplace, the detection merge plan and the MCP server digests. This module
only anchors paths, ships typed inputs through ``native_runner_authority`` and
applies the returned plan to the caller's own artifacts. Discovery, merge and
skill inventory fail closed with :class:`NativeAibomError` when the resident
cannot answer; MCP metadata degrades to unbound sentinels that can never
validate as approval context.
"""

from __future__ import annotations

import os
import time
from collections.abc import Mapping
from pathlib import Path
from typing import Any, Literal

from .models import GuardArtifact, HarnessDetection
from .native_context import _UNBOUND_PREFIX
from .native_path_anchor import anchor_to_process_directory
from .native_runner_authority import NativeRunnerAuthorityError, native_runner_authority
from .runtime.approval_context import _unbound_context_digest
from .skill_directory_identity import (
    discover_skill_documents,
    inspect_skill_directory,
    skill_directory_identity_metadata,
)

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

_CODEX_WORKSPACE_SKILL_ROOTS = (".agents/skills",)
_CODEX_HOME_SKILL_ROOTS = (".codex/skills", ".agents/skills")

# Harnesses that natively discover skills from the shared ``.agents/skills``
# workspace directory; keep in sync with ``WORKSPACE_SKILL_HARNESSES`` in the
# resident's ``aibom_discovery.rs``. Only the portable skill walk reads this.
_WORKSPACE_CODEX_SKILL_HARNESSES = frozenset(
    {"codex", "openclaw", "opencode", "claude-code", "cursor", "gemini", "pi", "omp"}
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
_NAME_ROLES: dict[str, InstructionRole] = {
    "agents.md": "agents_md",
    "claude.md": "claude_md",
    "design.md": "design_md",
    "product.md": "product_md",
    "roadmap.md": "roadmap_md",
    "security.md": "security_md",
    "policy.md": "policy_md",
    "policies.md": "policy_md",
    "standards.md": "standards_md",
    "mcp.json": "mcp_json",
}


class NativeAibomError(ValueError):
    """The native resident could not supply a bound AIBOM discovery answer."""


def instruction_role_for_path(path: Path) -> InstructionRole | None:
    name = path.name.lower()
    role = _NAME_ROLES.get(name)
    if role is not None:
        return role
    if path.suffix.lower() in {".md", ".mdc"}:
        parts = path.parts
        for index, part in enumerate(parts):
            if part == ".cursor" and index + 1 < len(parts) and parts[index + 1] == "rules":
                return "cursor_rules"
            if part == "docs" and index + 1 < len(parts):
                child = parts[index + 1].lower()
                for directory_name, doc_role in _DOC_DIRECTORY_ROLES:
                    if child == directory_name:
                        return doc_role
    return None


# Discovery kinds hash instruction documents, walk docs/* and compute skill
# directory identities in one resident call, so they get a wider budget than
# the default launch-path deadline while staying inside the envelope cap.
_AIBOM_DISCOVERY_TIMEOUT_SECONDS = 8.0


def _native(kind: str, args: Mapping[str, Any]) -> dict[str, Any]:
    try:
        return native_runner_authority(kind, args, timeout_seconds=_AIBOM_DISCOVERY_TIMEOUT_SECONDS)
    except NativeRunnerAuthorityError as error:
        raise NativeAibomError(str(error)) from error


def _artifact_wire(artifact: GuardArtifact) -> dict[str, object]:
    return {
        "artifact_id": artifact.artifact_id,
        "name": artifact.name,
        "harness": artifact.harness,
        "artifact_type": artifact.artifact_type,
        "source_scope": artifact.source_scope,
        "config_path": artifact.config_path,
        "command": artifact.command,
        "args": list(artifact.args),
        "url": artifact.url,
        "transport": artifact.transport,
        "publisher": artifact.publisher,
        "metadata": dict(artifact.metadata),
    }


def _artifact_from_wire(item: object) -> GuardArtifact:
    if not isinstance(item, dict):
        raise NativeAibomError("native_runner_authority_result_invalid")
    texts = ("artifact_id", "name", "harness", "artifact_type", "source_scope", "config_path")
    optional = ("command", "url", "transport", "publisher")
    args = item.get("args")
    metadata = item.get("metadata")
    if (
        not all(isinstance(item.get(key), str) for key in texts)
        or not all(item.get(key) is None or isinstance(item.get(key), str) for key in optional)
        or not isinstance(args, list)
        or not all(isinstance(value, str) for value in args)
        or not isinstance(metadata, dict)
    ):
        raise NativeAibomError("native_runner_authority_result_invalid")
    return GuardArtifact(
        artifact_id=item["artifact_id"],
        name=item["name"],
        harness=item["harness"],
        artifact_type=item["artifact_type"],
        source_scope=item["source_scope"],
        config_path=item["config_path"],
        command=item["command"],
        args=tuple(args),
        url=item["url"],
        transport=item["transport"],
        publisher=item["publisher"],
        metadata=metadata,
    )


def native_adapter_detection(
    kind: str, request: Mapping[str, Any]
) -> tuple[tuple[GuardArtifact, ...], tuple[str, ...]]:
    """Run a native adapter-detection kind and return its artifacts and found paths."""

    artifacts, found_paths, _warnings = native_adapter_detection_with_warnings(kind, request)
    return artifacts, found_paths


def native_adapter_detection_with_warnings(
    kind: str, request: Mapping[str, Any]
) -> tuple[tuple[GuardArtifact, ...], tuple[str, ...], tuple[str, ...]]:
    """Run a native adapter-detection kind and return artifacts, found paths and warnings."""

    payload = _native(kind, request)
    found_paths = payload.get("found_paths")
    if not isinstance(found_paths, list) or not all(isinstance(path, str) for path in found_paths):
        raise NativeAibomError("native_runner_authority_result_invalid")
    warnings = payload.get("warnings", [])
    if not isinstance(warnings, list) or not all(isinstance(warning, str) for warning in warnings):
        raise NativeAibomError("native_runner_authority_result_invalid")
    return _artifacts_from_payload(payload), tuple(found_paths), tuple(warnings)


def _artifacts_from_payload(payload: Mapping[str, Any]) -> tuple[GuardArtifact, ...]:
    items = payload.get("artifacts")
    if not isinstance(items, list):
        raise NativeAibomError("native_runner_authority_result_invalid")
    return tuple(_artifact_from_wire(item) for item in items)


def _needs_portable_walk() -> bool:
    """Whether the resident's unix file-descriptor skill walk cannot serve this host."""

    return os.name == "nt"


def _portable_skill_artifacts(
    harness: str,
    *,
    scope_dir: Path,
    skill_roots: tuple[str, ...],
    scope: str,
) -> list[dict[str, object]]:
    """Finished skill artifacts for roots the resident cannot walk itself."""

    artifacts: list[GuardArtifact] = []
    for relative_root in skill_roots:
        skill_root = scope_dir / relative_root
        discovery = discover_skill_documents(skill_root)
        for skill_md in discovery.documents:
            skill_dir = skill_md.parent
            relative_id = skill_dir.relative_to(skill_root).as_posix()
            identity = inspect_skill_directory(skill_md, scope_root=scope_dir)
            metadata: dict[str, object] = {
                "enabled": True,
                "skill_root": relative_root,
                **skill_directory_identity_metadata(identity, version_label=relative_id or skill_dir.name),
            }
            artifacts.append(
                GuardArtifact(
                    artifact_id=f"{harness}:{scope}:skill:{relative_root}:{relative_id or skill_dir.name}",
                    name=relative_id or skill_dir.name,
                    harness=harness,
                    artifact_type="skill",
                    source_scope=scope,
                    config_path=str(skill_md),
                    metadata=metadata,
                )
            )
        for issue in discovery.issues:
            relative_id = f".guard-discovery/{issue.issue_id}"
            metadata = {
                "enabled": True,
                "skill_root": relative_root,
                **skill_directory_identity_metadata(issue.identity, version_label=relative_id),
            }
            artifacts.append(
                GuardArtifact(
                    artifact_id=f"{harness}:{scope}:skill-discovery:{relative_root}:{issue.issue_id}",
                    name="Incomplete skill discovery",
                    harness=harness,
                    artifact_type="skill",
                    source_scope=scope,
                    config_path=str(issue.path),
                    metadata=metadata,
                )
            )
    return [_artifact_wire(artifact) for artifact in artifacts]


def _workspace_request(harness: str, workspace_dir: Path) -> dict[str, object]:
    request: dict[str, object] = {"harness": harness, "workspace_dir": anchor_to_process_directory(workspace_dir)}
    if harness in _WORKSPACE_CODEX_SKILL_HARNESSES and _needs_portable_walk():
        try:
            resolved = workspace_dir.resolve()
        except OSError:
            return request
        if resolved.is_dir():
            request["skills"] = _portable_skill_artifacts(
                harness,
                scope_dir=resolved,
                skill_roots=_CODEX_WORKSPACE_SKILL_ROOTS,
                scope="project",
            )
    return request


def discover_shared_workspace_aibom_artifacts(
    harness: str,
    *,
    home_dir: Path,
    workspace_dir: Path,
) -> tuple[GuardArtifact, ...]:
    _ = home_dir  # Retained for API compatibility; skill containment is workspace-relative.
    payload = _native("aibom_workspace_artifacts", _workspace_request(harness, workspace_dir))
    return _artifacts_from_payload(payload)


def discover_codex_skill_artifacts(
    harness: str,
    *,
    home_dir: Path,
    workspace_dir: Path | None,
) -> tuple[GuardArtifact, ...]:
    user_home = os.path.expanduser("~")
    request: dict[str, object] = {
        "harness": harness,
        "home_dir": anchor_to_process_directory(home_dir),
        "workspace_dir": None if workspace_dir is None else anchor_to_process_directory(workspace_dir),
        "user_home": None if user_home == "~" else user_home,
    }
    if workspace_dir is not None and _needs_portable_walk():
        request["project_skills"] = _portable_skill_artifacts(
            harness,
            scope_dir=workspace_dir,
            skill_roots=_CODEX_WORKSPACE_SKILL_ROOTS,
            scope="project",
        )
    if _needs_portable_walk():
        request["global_skills"] = _portable_skill_artifacts(
            harness,
            scope_dir=home_dir,
            skill_roots=_CODEX_HOME_SKILL_ROOTS,
            scope="global",
        )
    return _artifacts_from_payload(_native("aibom_codex_skills", request))


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
        found_paths.append(artifact.config_path)
    return HarnessDetection(
        harness=detection.harness,
        installed=detection.installed,
        command_available=detection.command_available,
        config_paths=tuple(dict.fromkeys(found_paths)),
        artifacts=tuple(merged),
        warnings=detection.warnings,
    )


def _merge_plan(detection: HarnessDetection, workspace_dir: Path) -> dict[str, Any]:
    request = _workspace_request(detection.harness, workspace_dir)
    request["existing"] = [
        {
            "artifact_id": artifact.artifact_id,
            "artifact_type": artifact.artifact_type,
            "harness": artifact.harness,
            "config_path": artifact.config_path if isinstance(artifact.config_path, str) else None,
        }
        for artifact in detection.artifacts
    ]
    return _native("aibom_workspace_plan", request)


def extend_detection_with_workspace_aibom(
    detection: HarnessDetection,
    *,
    home_dir: Path,
    workspace_dir: Path | None,
) -> HarnessDetection:
    if workspace_dir is None:
        return detection
    plan = _merge_plan(detection, workspace_dir)
    extra_count = plan.get("extra_count")
    replacements = plan.get("replacements")
    appended = plan.get("appended")
    found_paths = plan.get("found_paths")
    if (
        not isinstance(extra_count, int)
        or not isinstance(replacements, list)
        or not isinstance(appended, list)
        or not isinstance(found_paths, list)
        or not all(isinstance(path, str) for path in found_paths)
    ):
        raise NativeAibomError("native_runner_authority_result_invalid")
    if extra_count == 0:
        return detection
    merged = list(detection.artifacts)
    for replacement in replacements:
        index = replacement.get("index") if isinstance(replacement, dict) else None
        if not isinstance(index, int) or isinstance(index, bool) or not 0 <= index < len(merged):
            raise NativeAibomError("native_runner_authority_result_invalid")
        merged[index] = _artifact_from_wire(replacement.get("artifact"))
    merged.extend(_artifact_from_wire(item) for item in appended)
    return HarnessDetection(
        harness=detection.harness,
        installed=detection.installed,
        command_available=detection.command_available,
        config_paths=tuple(dict.fromkeys([*detection.config_paths, *found_paths])),
        artifacts=tuple(merged),
        warnings=detection.warnings,
    )


def _string_items(value: object) -> list[str]:
    return [item for item in value if isinstance(item, str)] if isinstance(value, (list, tuple)) else []


def _string_pairs(value: object) -> list[list[str]] | None:
    if not isinstance(value, Mapping):
        return None
    return [[key, item] for key, item in value.items() if isinstance(key, str) and isinstance(item, str)]


def _explicit_hash(value: object) -> str | None:
    return value if isinstance(value, str) else None


def _unbound_keys(configured: object, pairs: object) -> list[str]:
    keys = sorted({key.strip() for key in _string_items(configured) if key.strip()})
    if keys or not isinstance(pairs, list):
        return keys
    return sorted({pair[0].strip() for pair in pairs if pair[0].strip()})


def _unbound_mcp_digests(request: Mapping[str, object]) -> dict[str, object]:
    """Sentinel digests for an unreachable resident; never valid as context proof."""

    env_hash = _explicit_hash(request["env_values_hash"])
    header_hash = _explicit_hash(request["header_values_hash"])
    env_hash = env_hash.strip() if env_hash and env_hash.strip() else f"{_UNBOUND_PREFIX}configured-environment"
    header_hash = header_hash.strip() if header_hash and header_hash.strip() else f"{_UNBOUND_PREFIX}configured-headers"
    env_keys = _unbound_keys(request["env_keys"], request["env"])
    header_keys = _unbound_keys(request["headers_keys"], request["headers"])
    content_hash = _unbound_context_digest(
        "mcp-server",
        material={
            "command": request["command"],
            "args": request["args"],
            "url": request["url"],
            "transport": request["transport"],
            "env_keys": env_keys,
            "env_values_hash": env_hash,
            "headers_keys": header_keys,
            "header_values_hash": header_hash,
        },
    )
    return {
        "env_keys": env_keys,
        "headers_keys": header_keys,
        "env_values_hash": env_hash,
        "header_values_hash": header_hash,
        "content_hash": content_hash,
        "versionInfo": {
            "versionLabel": request["label"],
            "hashBasis": "content",
            "contentHash": content_hash,
            "changedFields": [],
        },
    }


# One resident outage should not cost a full deadline per configured server:
# after the first failure the remaining enrichments fall back to unbound
# digests until the retry window passes. Only outage-class errors open the
# latch — per-request failures (oversized or unencodable envelopes) and bound
# refusals either precede resident contact or prove the resident answered, so
# they must not suppress the next server's enrichment.
_MCP_NATIVE_RETRY_SECONDS = 30.0
_MCP_OUTAGE_CODES = frozenset(
    {
        "native_runner_authority_unavailable",
        "native_runner_authority_prerequisite_unavailable",
        "native_runner_authority_resident_unavailable",
        "native_runner_authority_result_invalid",
        "native_overloaded",
    }
)
_mcp_native_backoff_until = 0.0


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
    global _mcp_native_backoff_until
    raw_env = configured_environment if configured_environment is not None else metadata.get("env")
    raw_headers = configured_headers if configured_headers is not None else metadata.get("headers")
    request: dict[str, object] = {
        "command": command,
        "args": list(args),
        "url": url,
        "transport": transport,
        "env_keys": _string_items(metadata.get("env_keys")),
        "headers_keys": _string_items(metadata.get("headers_keys")),
        "env": _string_pairs(raw_env),
        "headers": _string_pairs(raw_headers),
        "env_values_hash": _explicit_hash(metadata.get("env_values_hash")),
        "header_values_hash": _explicit_hash(metadata.get("header_values_hash")),
        "label": str(metadata.get("name", "mcp")),
    }
    answer = None
    if time.monotonic() >= _mcp_native_backoff_until:
        try:
            answer = native_runner_authority("aibom_mcp_metadata", request)
        except NativeRunnerAuthorityError as error:
            if str(error).startswith("native_runner_authority_aibom_"):
                raise NativeAibomError(str(error)) from error
            if str(error).split(":", 1)[0] in _MCP_OUTAGE_CODES:
                _mcp_native_backoff_until = time.monotonic() + _MCP_NATIVE_RETRY_SECONDS
    if answer is None:
        answer = _unbound_mcp_digests(request)
    enriched = dict(metadata)
    for key in ("env_keys", "headers_keys", "env_values_hash", "header_values_hash", "content_hash", "versionInfo"):
        if key not in answer:
            raise NativeAibomError("native_runner_authority_result_invalid")
        enriched[key] = answer[key]
    return enriched
