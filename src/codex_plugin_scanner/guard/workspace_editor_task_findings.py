"""Project the native editor task check into workspace findings and coverage.

The native snapshot reads the project's root editor and dev container
configuration: ``.vscode/tasks.json``, a root ``.code-workspace`` file,
``.devcontainer.json`` and ``devcontainer.json`` in ``.devcontainer`` or one
folder below it. It flags a task set to run when the folder is opened and a dev
container ``initializeCommand``, which runs on the host. It decides each
finding's stable ``finding_id``, the rule's severity and whether the check was
complete. A finding carries only the rule's fixed title and reason and the
file's root-relative path, never a task name or command. This module checks
that shape and copies it into the stored finding; a finding that does not
match is dropped and leaves the detector incomplete instead of silently
complete.

Editor task findings are dashboard warnings. They never block or ask.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Final

from .workspace_rule_findings import (
    MAX_RULE_FINDINGS,
    WORKSPACE_SOURCE_KIND,
    RuleScan,
    project_rule_findings,
    with_rule_coverage,
)

EDITOR_TASK_DETECTOR: Final = "editor_task_v1"
EDITOR_TASK_SOURCE_KIND: Final = WORKSPACE_SOURCE_KIND
EDITOR_TASKS_RESULT_SCHEMA: Final = "guard.workspace-editor-tasks.v1"
MAX_EDITOR_TASK_FINDINGS: Final = MAX_RULE_FINDINGS

# Each rule reads one kind of file.
_RULE_PATHS: Final = {
    "editor.task.folder-open": re.compile(r"\.vscode/tasks\.json|[^/\0]*\.code-workspace"),
    "devcontainer.initialize-command": re.compile(
        r"\.devcontainer\.json|\.devcontainer/(?:[^/\0]+/)?devcontainer\.json"
    ),
}
_MAX_PATH_BYTES: Final = 4096


def project_editor_task_findings(result: object) -> list[dict[str, object]]:
    """Return the well-formed findings of a native editor task result."""

    return project_rule_findings(_SCAN, result)


def with_editor_task_coverage(coverage: dict[str, object], result: object) -> dict[str, object]:
    """Add the editor task detector to a run's coverage.

    A runtime without the check leaves the detector not run; a check that
    could not read or parse every configuration, or a malformed reply, leaves
    it incomplete. Both make the run partial. A worktree without editor or dev
    container configuration has no inputs.
    """

    return with_rule_coverage(_SCAN, coverage, result)


def _editor_task_fields(item: Mapping[str, object]) -> dict[str, object] | None:
    rule_id = item.get("rule_id")
    path = item.get("path")
    pattern = _RULE_PATHS.get(rule_id) if isinstance(rule_id, str) else None
    if (
        pattern is None
        or not isinstance(path, str)
        or len(path.encode("utf-8", "surrogatepass")) > _MAX_PATH_BYTES
        or not pattern.fullmatch(path)
    ):
        return None
    return {}


# A reply without its scan counts cannot show that nothing was found.
_SCAN: Final = RuleScan(
    detector=EDITOR_TASK_DETECTOR,
    result_schema=EDITOR_TASKS_RESULT_SCHEMA,
    summary_key="editor_task",
    incomplete_reason="editor_task_incomplete",
    counters=("files_scanned",),
    inputs_counter="files_scanned",
    skip_kinds=("oversize", "not_text", "unparsed", "unread", "linked"),
    finding_fields=_editor_task_fields,
    strict_counts=True,
)


__all__ = [
    "EDITOR_TASK_DETECTOR",
    "EDITOR_TASK_SOURCE_KIND",
    "MAX_EDITOR_TASK_FINDINGS",
    "project_editor_task_findings",
    "with_editor_task_coverage",
]
