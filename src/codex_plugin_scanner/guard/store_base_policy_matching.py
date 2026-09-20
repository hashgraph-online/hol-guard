"""Implementation definitions reexported by the StoreBase facade."""

from __future__ import annotations

from .store_base_definition import preserve_store_base_module as _preserve_module


@_preserve_module
def _path_within_workspace(config_path: str, workspace: str) -> bool:
    normalized_config = _base._normalized_workspace_path(config_path)
    normalized_workspace = _base._normalized_workspace_path(workspace)
    if not normalized_config or not normalized_workspace:
        return False
    if normalized_workspace == "/":
        return normalized_config.startswith("/")
    return normalized_config == normalized_workspace or normalized_config.startswith(f"{normalized_workspace}/")


@_preserve_module
def _normalized_workspace_path(value: str) -> str:
    normalized = value.strip().replace("\\", "/")
    while len(normalized) > 1 and normalized.endswith("/"):
        normalized = normalized[:-1]
    if len(normalized) >= 2 and normalized[1] == ":":
        normalized = normalized.lower()
    return normalized


@_preserve_module
def _workspace_policy_key(workspace: str | None) -> str | None:
    if workspace is None or not workspace.strip():
        return None
    normalized = _base._normalized_workspace_path(workspace)
    digest = _base.sha256(normalized.encode("utf-8")).hexdigest()
    return f"{_base._WORKSPACE_POLICY_KEY_PREFIX}{digest}"


@_preserve_module
def _stored_workspace_policy_key(workspace: str) -> str:
    if workspace.startswith(_base._WORKSPACE_POLICY_KEY_PREFIX):
        return workspace
    policy_key = _base._workspace_policy_key(workspace)
    if policy_key is None:
        msg = "Workspace policy key cannot be empty"
        raise ValueError(msg)
    return policy_key


@_preserve_module
def _validate_scoped_policy_artifact_target(scope: str, artifact_id: str | None) -> None:
    if scope not in {"harness", "global"}:
        return
    if artifact_id is None or not artifact_id.strip():
        return
    if not artifact_id.startswith("family:"):
        return
    family = artifact_id.removeprefix("family:").strip().lower()
    if family not in _base._SCOPED_HARNESS_FAMILIES:
        msg = "unsupported_scoped_policy_family"
        raise ValueError(msg)


@_preserve_module
def _runtime_scoped_exact_match_key(
    artifact_id: str | None,
    runtime_exact_match_context: str | None = None,
) -> str | None:
    if artifact_id is None or not artifact_id.strip() or artifact_id.startswith("family:"):
        return None
    family_key = _base._artifact_family_key(artifact_id)
    if family_key is None or _base._family_key_value(family_key) not in _base._SCOPED_RUNTIME_EXACT_FAMILIES:
        return None
    if runtime_exact_match_context is None:
        digest = _base.sha256(artifact_id.encode("utf-8")).hexdigest()
    else:
        digest = _base.sha256(
            _base.json.dumps(
                {
                    "artifact_id": artifact_id,
                    "context": runtime_exact_match_context,
                    "version": 2,
                },
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest()
    return f"{_base._RUNTIME_SCOPED_EXACT_MATCH_PREFIX}{digest}"


@_preserve_module
def _global_runtime_scoped_exact_match_key(
    artifact_id: str | None,
    runtime_exact_match_context: str | None = None,
) -> str | None:
    family_key = _base._artifact_family_key(artifact_id)
    if family_key is None or _base._family_key_value(family_key) not in _base._SCOPED_RUNTIME_EXACT_FAMILIES:
        return None
    canonical_artifact_id = f"global:portable:{_base._family_key_value(family_key)}"
    return _base._runtime_scoped_exact_match_key(canonical_artifact_id, runtime_exact_match_context)


@_preserve_module
def runtime_tool_action_policy_artifact_id(artifact_id: str | None) -> str | None:
    """Return a scoped family identity for one exact runtime tool action."""

    if artifact_id is None or not artifact_id.strip():
        return None
    family_key = _base._artifact_family_key(artifact_id)
    if family_key is not None and _base._family_key_value(family_key) in _base._SCOPED_RUNTIME_EXACT_FAMILIES:
        return artifact_id
    digest = _base.sha256(artifact_id.strip().encode("utf-8")).hexdigest()
    return f"guard:runtime:tool-action:{digest}"


@_preserve_module
def runtime_tool_action_exact_match_context(
    *,
    config_path: str | None,
    source_scope: str | None,
    raw_command_text: str | None = None,
    wrapper_chain: Sequence[object] | None = None,
    permission_mode: str | None = None,
) -> str | None:
    if not config_path and not source_scope and not raw_command_text and not wrapper_chain and not permission_mode:
        return None
    payload: dict[str, object] = {
        "config_path": str(_base.Path(config_path).expanduser()) if config_path else None,
        "source_scope": source_scope,
        "raw_command_text": raw_command_text,
        "wrapper_chain": [item for item in wrapper_chain or () if isinstance(item, str) and item],
        "permission_mode": permission_mode,
    }
    return _base.json.dumps(payload, sort_keys=True, separators=(",", ":"))


@_preserve_module
def runtime_tool_action_portable_match_context(runtime_exact_match_context: str | None) -> str | None:
    """Remove project location while retaining the exact executable action."""

    if runtime_exact_match_context is None:
        return None
    try:
        payload = _base.json.loads(runtime_exact_match_context)
    except (TypeError, ValueError):
        return None
    if not isinstance(payload, _base.Mapping):
        return None
    raw_command_text = payload.get("raw_command_text")
    if not isinstance(raw_command_text, str) or not raw_command_text:
        return None
    wrapper_chain = payload.get("wrapper_chain")
    permission_mode = payload.get("permission_mode")
    normalized_wrapper_chain = (
        wrapper_chain if isinstance(wrapper_chain, _base.Sequence) and not isinstance(wrapper_chain, str) else None
    )
    return _base.runtime_tool_action_exact_match_context(
        config_path=None,
        source_scope=None,
        raw_command_text=raw_command_text,
        wrapper_chain=normalized_wrapper_chain,
        permission_mode=permission_mode if isinstance(permission_mode, str) and permission_mode else None,
    )


@_preserve_module
def browser_mcp_exact_match_context(
    *,
    intent: str | None,
    operation: str | None,
    target_origin: str | None,
    target_path_prefix: str | None,
    profile_mode: str | None,
    mcp_server_identity_hash: str | None,
    mcp_tool_identity_hash: str | None,
    mcp_schema_hash: str | None,
    sensitive_surface_flags: Sequence[object] | None = None,
) -> str | None:
    """Build a browser MCP exact-match context for stable identity dedup.

    The context captures security-relevant fields (intent, origin, path,
    profile, sensitive surfaces) while volatile fields are already stripped
    by the browser intent normalizer.
    """
    if not intent and not operation and not target_origin:
        return None
    flags: list[str] = []
    if sensitive_surface_flags is not None:
        flags = sorted(str(f) for f in sensitive_surface_flags if isinstance(f, str) and f)
    payload: dict[str, object] = {
        "intent": intent,
        "operation": operation,
        "target_origin": target_origin,
        "target_path_prefix": target_path_prefix,
        "profile_mode": profile_mode,
        "server_identity_hash": mcp_server_identity_hash,
        "tool_identity_hash": mcp_tool_identity_hash,
        "schema_hash": mcp_schema_hash,
        "sensitive_surface_flags": flags,
    }
    return _base.json.dumps(payload, sort_keys=True, separators=(",", ":"))


@_preserve_module
def _is_runtime_scoped_exact_match_key(value: str | None) -> bool:
    return isinstance(value, str) and value.startswith(_base._RUNTIME_SCOPED_EXACT_MATCH_PREFIX)


@_preserve_module
def _is_approval_context_token(value: object) -> bool:
    return _base.parse_approval_context_token(value) is not None


@_preserve_module
def _scoped_runtime_row_requires_exact_match(
    *,
    scope: str,
    stored_artifact_id: str | None,
    stored_artifact_hash: str | None,
    source: str,
    requested_artifact_id: str | None,
    requested_artifact_hash: str | None = None,
    requested_runtime_exact_match_key: str | None = None,
    requested_portable_exact_match_key: str | None = None,
    requested_global_exact_match_key: str | None = None,
) -> bool:
    if scope not in {"harness", "global"}:
        return False
    if source in _base.REMOTE_POLICY_SOURCES:
        return False
    family_key = _base._artifact_family_key(stored_artifact_id)
    if family_key is None or _base._family_key_value(family_key) not in _base._SCOPED_RUNTIME_EXACT_FAMILIES:
        return False
    expected_exact_keys = {
        key
        for key in (
            requested_artifact_hash if _base._is_approval_context_token(requested_artifact_hash) else None,
            _base._runtime_scoped_exact_match_key(requested_artifact_id),
            requested_runtime_exact_match_key,
            requested_portable_exact_match_key,
            requested_global_exact_match_key,
        )
        if key is not None
    }
    if not expected_exact_keys:
        return True
    return stored_artifact_hash not in expected_exact_keys


@_preserve_module
def _warn_only_policy_integrity_status(status: str, state: Mapping[str, object], *, source: str = "local") -> bool:
    if state.get("enforcement") != "warn":
        return False
    if source != "approval-gate":
        return False
    if status == "missing_integrity":
        return True
    if status != "degraded_mode":
        return False
    reasons = state.get("degraded_reasons")
    if not isinstance(reasons, list):
        return False
    if not reasons:
        return False
    allowed_reasons = {
        "system_keyring_unavailable",
        "policy_integrity_key_unavailable",
        "policy_integrity_control_unavailable",
    }
    return all(isinstance(reason, str) and reason in allowed_reasons for reason in reasons)


@_preserve_module
def _policy_integrity_ready_for_local_write(payload: Mapping[str, object]) -> bool:
    trust = payload.get("trust_status")
    if not isinstance(trust, _base.Mapping):
        return False
    counts = payload.get("counts")
    if not isinstance(counts, _base.Mapping):
        return False
    invalid_rows = 0
    for status in _base._POLICY_INTEGRITY_STATUSES:
        if status == "valid":
            continue
        count = counts.get(status)
        if isinstance(count, int) and count > 0:
            invalid_rows += count
    return payload.get("mode") == "protected" and trust.get("remembered_rules") == "enforced" and invalid_rows == 0


@_preserve_module
def _policy_integrity_setup_safe_for_local_write(payload: Mapping[str, object]) -> bool:
    counts = payload.get("counts")
    if not isinstance(counts, _base.Mapping):
        return False
    eligible_invalid_rows = 0
    for status in _base._POLICY_INTEGRITY_MIGRATION_ELIGIBLE_STATUSES:
        count = counts.get(status)
        if isinstance(count, int) and count > 0:
            eligible_invalid_rows += count
    return eligible_invalid_rows > 0


@_preserve_module
def _family_key_value(family_key: str) -> str:
    if family_key.startswith("family:"):
        return family_key.removeprefix("family:")
    return family_key


# Bind dependencies after declarations so each owner can be imported first.
from . import store_base as _base  # noqa: E402
from .store_base import Mapping, Sequence  # noqa: E402
