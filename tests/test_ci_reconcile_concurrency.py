"""Ignored review comments must not cancel the PR's required reconciliation."""

from __future__ import annotations

import ast
import json
from pathlib import Path

import pytest
import yaml

WORKFLOW = Path(__file__).resolve().parents[1] / ".github/workflows/gitar-managed-state.yml"


def _evaluate(expression: str, context: dict[str, object]) -> object:
    for key, value in sorted(context.items(), key=lambda item: -len(item[0])):
        expression = expression.replace(key, repr(value))
    expression = expression.replace("&&", " and ").replace("||", " or ")
    expression = expression.replace("!(", "not (").replace("null", "None")
    tree = ast.parse("(" + expression + ")", mode="eval")
    permitted = (
        ast.Expression,
        ast.BoolOp,
        ast.And,
        ast.Or,
        ast.UnaryOp,
        ast.Not,
        ast.Compare,
        ast.Eq,
        ast.NotEq,
        ast.Constant,
        ast.Call,
        ast.Name,
        ast.Load,
    )
    assert all(isinstance(node, permitted) for node in ast.walk(tree))
    return eval(
        compile(tree, "<reconcile-policy>", "eval"),
        {"__builtins__": {}},
        {
            "contains": lambda container, value: (
                value.casefold() in container.casefold() if isinstance(container, str) else value in container
            ),
            "fromJSON": json.loads,
            "format": lambda pattern, value: pattern.format(value),
        },
    )


@pytest.mark.parametrize(
    ("event", "login", "association", "body", "is_pr", "expected"),
    [
        ("pull_request_target", "bot", "NONE", "", True, True),
        ("workflow_dispatch", "maintainer", "OWNER", "", False, True),
        ("issue_comment", "bot", "NONE", "Use gitar auto-apply:on", True, False),
        ("issue_comment", "stranger", "NONE", "gitar auto-apply:off", True, False),
        ("issue_comment", "author", "NONE", "gitar auto-apply:on", True, True),
        ("issue_comment", "maintainer", "OWNER", "GITAR AUTO-APPLY:OFF", True, True),
        ("issue_comment", "maintainer", "MEMBER", "gitar auto-apply:on", True, True),
        ("issue_comment", "maintainer", "COLLABORATOR", "gitar auto-apply:on", True, True),
        ("issue_comment", "author", "NONE", "ordinary review", True, False),
        ("issue_comment", "maintainer", "OWNER", "gitar auto-apply:on", False, False),
    ],
)
def test_only_authorized_directives_can_run_and_cancel_pr_reconciliation(
    event,
    login,
    association,
    body,
    is_pr,
    expected,
):
    workflow = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    context = {
        "github.event_name": event,
        "github.event.comment.user.login": login,
        "github.event.comment.author_association": association,
        "github.event.comment.body": body,
        "github.event.issue.user.login": "author",
        "github.event.issue.pull_request": "pull-url" if is_pr else None,
        "github.event.issue.number": 17 if event == "issue_comment" else None,
        "github.event.issue.state": "open",
        "github.event.pull_request.number": 17 if event == "pull_request_target" else None,
        "github.event.pull_request.state": "open" if event == "pull_request_target" else None,
        "github.run_id": 123,
        "inputs.pr_number": "17" if event == "workflow_dispatch" else None,
    }
    assert bool(_evaluate(workflow["jobs"]["reconcile"]["if"], context)) is expected
    group = workflow["concurrency"]["group"]
    identity = group.split("${{", 1)[1].split("}}", 1)[0]
    assert _evaluate(identity, context) == (
        17 if expected and event != "workflow_dispatch" else "17" if expected else "skip-123"
    )
