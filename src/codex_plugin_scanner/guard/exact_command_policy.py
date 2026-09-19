"""Require an exact command predicate alongside an original artifact selector."""

from __future__ import annotations

from .exact_command import validate_exact_command_selector


def exact_command_policy_digest(selector: object, artifact_id: object, *, scope: object) -> str:
    """Reject unsupported projection instead of retaining a broader artifact rule."""
    digest = validate_exact_command_selector(selector)
    if (
        not isinstance(scope, str)
        or scope not in {"artifact", "workspace"}
        or not isinstance(artifact_id, str)
        or not artifact_id
        or artifact_id != artifact_id.strip()
        or artifact_id == "*"
        or artifact_id.startswith("family:")
        or any(ord(character) < 32 or ord(character) == 127 for character in artifact_id)
    ):
        raise ValueError("exact_command_artifact_scope_required")
    try:
        _ = artifact_id.encode("utf-8")
    except UnicodeEncodeError as error:
        raise ValueError("exact_command_artifact_scope_required") from error
    return digest
