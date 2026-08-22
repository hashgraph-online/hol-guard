"""Narrow allowlist for bounded reads of verified local agent guidance."""

from __future__ import annotations

import re
from pathlib import Path

from ..false_positive_rules import target_is_known_skill_doc_path
from ..shell_execution_context import model_shell_execution_context

_AGENT_DOC_PATHS = frozenset(
    {
        ".codex/docs/harness-engineering.md",
        ".codex/docs/token-discipline.md",
    }
)


def is_benign_agent_guidance_read(command_text: str, cwd: Path | None, home_dir: Path) -> bool:
    if any(marker in command_text for marker in ("$(", "`", "<(", ">(")):
        return False
    context = model_shell_execution_context(
        command_text,
        cwd=cwd,
        workspace_root=cwd,
        home_dir=home_dir,
    )
    if not context.complete or not 1 <= len(context.segments) <= 8:
        return False
    for segment in context.segments:
        controls = (*segment.control_before, *segment.control_after)
        if any(operator != "&&" for operator in controls) or segment.directory_operation is not None:
            return False
        target = _bounded_sed_read_target(list(segment.tokens))
        if target is None:
            return False
        if _is_approved_agent_doc_target(target, home_dir=home_dir):
            continue
        if _is_guard_safety_doc_target(target, home_dir=home_dir):
            continue
        return False
    return True


def _bounded_sed_read_target(parts: list[str]) -> str | None:
    if len(parts) != 4 or parts[:2] != ["sed", "-n"]:
        return None
    match = re.fullmatch(r"([1-9][0-9]{0,3}),([1-9][0-9]{0,3})p", parts[2])
    if match is None:
        return None
    start, end = map(int, match.groups())
    return parts[3] if start <= end and end - start + 1 <= 500 else None


def _is_approved_agent_doc_target(target: str, *, home_dir: Path) -> bool:
    normalized = target.replace("\\", "/").rstrip("/")
    if normalized.endswith("/SKILL.md"):
        return target_is_known_skill_doc_path(target, home_dir=home_dir)
    expected_paths = {f"~/{path}" for path in _AGENT_DOC_PATHS} | {str(home_dir / path) for path in _AGENT_DOC_PATHS}
    if target not in expected_paths:
        return False
    candidate = home_dir / target[2:] if target.startswith("~/") else Path(target)
    return _is_regular_file_without_symlink_components(candidate, home_dir=home_dir)


def _is_guard_safety_doc_target(target: str, *, home_dir: Path) -> bool:
    expected = home_dir / ".hol-support" / "SAFETY.md"
    candidate = home_dir / target[2:] if target.startswith("~/") else Path(target)
    return candidate.absolute() == expected.absolute() and _is_regular_file_without_symlink_components(
        expected,
        home_dir=home_dir,
    )


def _is_regular_file_without_symlink_components(candidate: Path, *, home_dir: Path) -> bool:
    try:
        resolved_home = home_dir.resolve(strict=True)
        candidate.relative_to(home_dir)
        current = home_dir
        for part in candidate.relative_to(home_dir).parts:
            current /= part
            if current.is_symlink():
                return False
        resolved_candidate = candidate.resolve(strict=True)
        return resolved_candidate.is_relative_to(resolved_home) and resolved_candidate.is_file()
    except (OSError, RuntimeError, ValueError):
        return False
