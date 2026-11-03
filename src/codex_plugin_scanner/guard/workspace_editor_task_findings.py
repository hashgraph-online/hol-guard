"""Project the native editor task check into workspace findings and coverage.

The native snapshot reads the project's root editor and dev container
configuration: ``.vscode/tasks.json``, a root ``.code-workspace`` file,
``.devcontainer.json`` and ``devcontainer.json`` in ``.devcontainer`` or one
folder below it. It flags a task set to run when the folder is opened and a
dev container ``initializeCommand``, which runs on the host. It decides each
finding's stable ``finding_id``, the rule's severity and whether the check was
complete. A finding carries only the rule's fixed title and reason and the
file's root-relative path, never a task name or command. The native
``workspace_rule_findings`` kind checks that shape and copies it into the
stored finding; a finding that does not match is dropped and leaves the
detector incomplete instead of silently complete.

Editor task findings are dashboard warnings. They never block or ask.
"""

from __future__ import annotations

from typing import Final

EDITOR_TASK_DETECTOR: Final = "editor_task_v1"


__all__ = [
    "EDITOR_TASK_DETECTOR",
]
