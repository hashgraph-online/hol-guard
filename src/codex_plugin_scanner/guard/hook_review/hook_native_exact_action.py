"""Exact-action identity and review binding answered by the native runtime.

A persistent "Always" decision needs an identity that survives new sessions
while changing whenever the code that would run, the files it reads, the git
configuration it would consult or the Rust rules that judged it change. The
short-lived retry binding of one native review needs the Rust request digest.
The resident owns every one of those proofs. The edge answers them in the
same round trip as the review (``review_evidence``), from the hook payload,
native verdict and receipt it judged.

Python only reads that answer. There is no Python fallback: when the edge
sends no evidence, the review fails closed, and when it proves no token, the
review stays once-only. The separate delivery contract decides whether a
once retry is executable.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from pathlib import Path
from typing import cast

from ..hook_execution_environment import HOOK_EXECUTION_ENVIRONMENT_KEY

UNPROVEN_LAUNCH = "unproven_launch"
_ONCE_ONLY_REASONS = frozenset(
    {
        "no_command_identity",
        "mutable_launcher",
        "compound_command",
        "guard_control",
        "package_action",
        "non_overridable",
        "unproven_launch",
        "sensitive_path",
        "broad_scope",
        "destructive_command",
        "git_helper_config",
        "node_package_manifest_unproven",
        "node_package_entrypoint_unproven",
        "node_package_exports_unproven",
        "node_package_native_addon_unproven",
        "node_runtime_package_mutation_unproven",
        "runner_code_closure_unproven",
        "python_runtime_module_unproven",
        "python_runtime_bootstrap_unproven",
        "script_execution_binding_unavailable",
    }
)


def launch_cwd(payload: Mapping[str, object], workspace: Path | None) -> Path | None:
    """The absolute, existing directory a hook action would launch in."""

    raw = payload.get("cwd")
    candidate = Path(raw) if isinstance(raw, str) and raw.strip() else workspace
    if candidate is None or not candidate.is_absolute():
        return None
    try:
        resolved = candidate.resolve(strict=True)
    except (OSError, RuntimeError):
        return None
    return resolved if os.path.isdir(resolved) else None


def launch_path(payload: Mapping[str, object]) -> str | None:
    """The ``PATH`` the hook stamped from the agent's own environment, if any."""

    stamped = payload.get(HOOK_EXECUTION_ENVIRONMENT_KEY)
    path = stamped.get("path") if isinstance(stamped, Mapping) else None
    return path if isinstance(path, str) and path and "\0" not in path else None


def review_evidence_parts(
    evidence: Mapping[str, object] | None,
) -> tuple[bool, str | None, str | None, str | None] | None:
    """Whether the review's policy binding holds, its retry binding, exact-action token and once-only reason.

    ``evidence`` is the edge's ``review_evidence``, already shape-checked by the
    edge decoder. ``None`` means the edge proved nothing, so the caller fails
    closed. A token and a once-only reason are exclusive, and a reason must be
    one Guard knows; anything else stays once-only as an unproven launch.
    """

    if evidence is None:
        return None
    valid, binding = evidence.get("policy_binding_valid"), evidence.get("binding")
    token, reason = evidence.get("token"), evidence.get("once_only_reason")
    if not isinstance(valid, bool) or not (binding is None or isinstance(binding, str)):
        return None
    known_reason = reason is None or (isinstance(reason, str) and reason in _ONCE_ONLY_REASONS)
    if not known_reason or not isinstance(token, str | None) or (token is None) == (reason is None):
        return valid, binding, None, UNPROVEN_LAUNCH
    return valid, binding, cast("str | None", token), cast("str | None", reason)


__all__ = [
    "UNPROVEN_LAUNCH",
    "launch_cwd",
    "launch_path",
    "review_evidence_parts",
]
