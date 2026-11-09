"""Project the native CI workflow check into workspace findings and coverage.

The native snapshot reads every GitHub Actions workflow directly in the
worktree's ``.github/workflows`` directory and runs it through the shared
workflow rules: a privileged trigger that checks out pull request code, a
``write-all`` token and actions not pinned to a commit. It decides each
finding's stable ``finding_id``, the rule's severity and whether the check was
complete. A finding carries only the rule's fixed title and reason and the
workflow's root-relative path, never an action name, ref or command. The
native ``workspace_rule_findings`` kind checks that shape and copies it into
the stored finding; a finding that does not match is dropped and leaves the
detector incomplete instead of silently complete.

Workflow findings are dashboard warnings. They never block or ask.
"""

from __future__ import annotations

from typing import Final

CI_WORKFLOW_DETECTOR: Final = "ci_workflow_v1"


__all__ = [
    "CI_WORKFLOW_DETECTOR",
]
