"""Proof-gated policy relaxation for routine Codex workspace patches."""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import cast

from ..native_hook_adapter import NativeHookAdapterError
from ..runtime.actions import apply_patch_target_paths
from ..runtime.secret_sensitivity import classify_secret_path
from .commands_support_codex_git_config import git_common_dir, git_dir_from_file

_AGENT_INSTRUCTION_FILE_NAMES = frozenset(
    {
        "agents.md",
        "claude.md",
        "copilot-instructions.md",
        ".clinerules",
        ".cursorrules",
        ".windsurfrules",
    }
)
_AGENT_INSTRUCTION_DIRECTORIES = frozenset({".agents", ".claude", ".codex", ".cursor"})
_PROTECTED_WORKSPACE_METADATA_DIRECTORIES = frozenset({".bzr", ".git", ".hg", ".jj", ".pijul", ".svn", "_darcs"})


def _linked_worktree_root(candidate: Path, *, workspace: Path) -> Path | None:
    """Return a sibling worktree only when Git metadata binds it to workspace."""

    for worktree_root in (candidate, *candidate.parents):
        git_file = worktree_root / ".git"
        if not git_file.is_file():
            continue
        try:
            git_dir = git_dir_from_file(git_file)
            if git_dir is None or not git_dir.is_dir():
                return None
            backlink = (git_dir / "gitdir").read_text(encoding="utf-8").strip()
            backlink_path = Path(backlink).expanduser()
            if not backlink_path.is_absolute():
                backlink_path = git_dir / backlink_path
            if backlink_path.resolve(strict=True) != git_file.resolve(strict=True):
                return None
            common_dir = git_common_dir(git_dir).resolve(strict=True)
            if not common_dir.is_dir():
                return None
            repository_root = common_dir.parent
            if repository_root.is_relative_to(workspace) and candidate.is_relative_to(worktree_root):
                return worktree_root
        except (OSError, RuntimeError, UnicodeError, ValueError):
            return None
        return None
    return None


def verified_non_sensitive_codex_apply_patch(
    *,
    canonical_harness: str,
    event_name: str | None,
    home_dir: Path | None,
    payload: Mapping[str, object],
    runtime_artifact_checked: bool,
    runtime_workspace: Path | None,
) -> bool:
    """Allow parsed workspace patches only after Guard's sensitive checks."""

    if (
        not runtime_artifact_checked
        or runtime_workspace is None
        or canonical_harness != "codex"
        or event_name != "PreToolUse"
    ):
        return False
    tool_name = payload.get("tool_name")
    if not isinstance(tool_name, str) or tool_name.strip().lower() != "apply_patch":
        return False
    tool_input = payload.get("tool_input", payload.get("arguments"))
    if not isinstance(tool_input, Mapping):
        return False
    typed_input = cast(Mapping[str, object], tool_input)
    patch_texts = tuple(
        value
        for key in ("patch", "input", "command")
        if isinstance((value := typed_input.get(key)), str) and value.strip()
    )
    if not patch_texts or any("*** Delete File:" in text or "*** Move to:" in text for text in patch_texts):
        return False
    try:
        target_paths = apply_patch_target_paths(typed_input)
    except NativeHookAdapterError:
        # No authoritative parse means the patch cannot be proven non-sensitive.
        return False
    if not target_paths:
        return False
    try:
        workspace = runtime_workspace.resolve()
        for target_path in target_paths:
            candidate = Path(target_path).expanduser()
            if not candidate.is_absolute():
                candidate = workspace / candidate
            resolved = candidate.resolve(strict=False)
            try:
                relative = resolved.relative_to(workspace)
            except ValueError:
                linked_root = _linked_worktree_root(resolved, workspace=workspace)
                if linked_root is None:
                    return False
                relative = resolved.relative_to(linked_root)
            if (
                classify_secret_path(str(resolved), cwd=workspace, home_dir=home_dir) is not None
                or resolved.name.lower() in _AGENT_INSTRUCTION_FILE_NAMES
                or {part.lower() for part in relative.parts} & _AGENT_INSTRUCTION_DIRECTORIES
                or {part.lower() for part in relative.parts} & _PROTECTED_WORKSPACE_METADATA_DIRECTORIES
            ):
                return False
    except (OSError, RuntimeError, ValueError):
        return False
    return True


__all__ = ["verified_non_sensitive_codex_apply_patch"]
