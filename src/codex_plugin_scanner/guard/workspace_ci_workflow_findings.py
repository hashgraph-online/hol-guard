"""Project the native CI workflow check into workspace findings and coverage.

The native snapshot reads every GitHub Actions workflow directly in the
worktree's ``.github/workflows`` directory and runs it through the shared
workflow rules: a privileged trigger that checks out pull request code, a
``write-all`` token and actions not pinned to a commit. It decides each
finding's stable ``finding_id``, the rule's severity and whether the check was
complete. A finding carries only the rule's fixed title and reason and the
workflow's root-relative path, never an action name, ref or command. This
module checks that shape and copies it into the stored finding; a finding that
does not match is dropped and leaves the detector incomplete instead of
silently complete.

Workflow findings are dashboard warnings. They never block or ask.
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

CI_WORKFLOW_DETECTOR: Final = "ci_workflow_v1"
CI_WORKFLOW_SOURCE_KIND: Final = WORKSPACE_SOURCE_KIND
WORKFLOWS_RESULT_SCHEMA: Final = "guard.workspace-workflows.v1"
MAX_CI_WORKFLOW_FINDINGS: Final = MAX_RULE_FINDINGS

_RULE_IDS: Final = frozenset(
    {"ci.workflow.untrusted-checkout", "ci.workflow.write-all-permissions", "ci.workflow.unpinned-action"}
)
# Any `.yml` or `.yaml` file directly in the root workflows directory, within
# the native snapshot's path bound.
_WORKFLOW_FILE = re.compile(r"\.github/workflows/[^/\0]*\.ya?ml")
_MAX_PATH_BYTES: Final = 4096


def project_ci_workflow_findings(result: object) -> list[dict[str, object]]:
    """Return the well-formed findings of a native workflow result."""

    return project_rule_findings(_SCAN, result)


def with_ci_workflow_coverage(coverage: dict[str, object], result: object) -> dict[str, object]:
    """Add the CI workflow detector to a run's coverage.

    A runtime without the check leaves the detector not run; a check that
    could not read every workflow, or a malformed reply, leaves it incomplete.
    Both make the run partial. A worktree without workflows has no inputs.
    """

    return with_rule_coverage(_SCAN, coverage, result)


def _workflow_fields(item: Mapping[str, object]) -> dict[str, object] | None:
    rule_id = item.get("rule_id")
    path = item.get("path")
    if (
        not isinstance(rule_id, str)
        or rule_id not in _RULE_IDS
        or not isinstance(path, str)
        or len(path.encode("utf-8", "surrogatepass")) > _MAX_PATH_BYTES
        or not _WORKFLOW_FILE.fullmatch(path)
    ):
        return None
    return {}


# A reply without its scan counts cannot show that nothing was found.
_SCAN: Final = RuleScan(
    detector=CI_WORKFLOW_DETECTOR,
    result_schema=WORKFLOWS_RESULT_SCHEMA,
    summary_key="ci_workflow",
    incomplete_reason="ci_workflow_incomplete",
    counters=("files_scanned",),
    inputs_counter="files_scanned",
    skip_kinds=("oversize", "not_text", "unread", "linked"),
    finding_fields=_workflow_fields,
    strict_counts=True,
)


__all__ = [
    "CI_WORKFLOW_DETECTOR",
    "CI_WORKFLOW_SOURCE_KIND",
    "MAX_CI_WORKFLOW_FINDINGS",
    "project_ci_workflow_findings",
    "with_ci_workflow_coverage",
]
