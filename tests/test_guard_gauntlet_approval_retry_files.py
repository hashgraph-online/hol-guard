"""Approval-retry identity and outcome checks for native file tools."""

from ci.gauntlet.approval_retry import pinned_retry_outcome, retry_assessment
from ci.gauntlet.approval_retry_action import input_path, pinned_file_tool

REVIEW_REASON = "native_policy_review_required"


def _file_decision(tool: str, path: str, decision: str) -> dict:
    """A decision row for a file tool, which carries no command text at all."""
    return {
        "event": "PreToolUse",
        "tool": tool,
        "command": None,
        "path": path,
        "decision": decision,
        "policy_action": "review" if decision != "allow" else "allow",
        "reason_code": REVIEW_REASON,
        "receipt_decision": "deny" if decision != "allow" else "allow",
        "receipt_harness": "claude-code",
        "observe_mode": False,
    }


def _file_grant(tool: str, target: str) -> dict:
    """The approval row Guard queues for a reviewed file-tool call.

    ``hook_direct_review_request`` records the tool as the row's artifact name and the
    file as its launch target, and omits the command text a shell row carries.
    """
    return {
        "granted": [{"request_id": "req-0", "target": target, "tool": tool}],
        "errors": [],
        "poll_errors": [],
        "sweeps": 3,
        "scope": "artifact",
        "persist_policy": False,
    }


def test_an_approved_file_read_retried_once_passes():
    """A file tool's repeated call rides its approval the way a command's does."""
    case = {
        "approval_grants": _file_grant("Read", "{{workspace}}/README.md"),
        "guard_decisions": [
            _file_decision("Read", "README.md", "deny"),
            _file_decision("Read", "README.md", "allow"),
        ],
    }
    outcome, reason = retry_assessment(case)
    assert outcome == "pass"
    assert "no second review" in reason


def test_a_file_read_reviewed_again_after_its_grant_fails():
    case = {
        "approval_grants": {
            "granted": [
                {"request_id": "req-0", "target": "{{workspace}}/README.md", "tool": "Read"},
                {"request_id": "req-1", "target": "{{workspace}}/README.md", "tool": "Read"},
            ],
            "errors": [],
            "poll_errors": [],
            "sweeps": 3,
            "scope": "artifact",
            "persist_policy": False,
        },
        "guard_decisions": [
            _file_decision("Read", "README.md", "deny"),
            _file_decision("Read", "README.md", "deny"),
            _file_decision("Read", "README.md", "allow"),
        ],
    }
    outcome, reason = retry_assessment(case)
    assert outcome == "fail"
    assert "approve the same action 2 times" in reason


def test_a_read_that_came_back_on_another_file_is_not_the_retry():
    """Two files are two actions, so reading a different one is not the retry.

    An approval binds the file it was queued for. If the lane keyed a file-tool call by
    its tool alone, a call on any other path would look like the approved action coming
    back and the case would pass without the agent ever reaching the file it was stopped
    on.
    """
    case = {
        "approval_grants": _file_grant("Read", "{{workspace}}/README.md"),
        "guard_decisions": [
            _file_decision("Read", "README.md", "deny"),
            _file_decision("Read", "docs/README.md", "allow"),
        ],
    }
    outcome, reason = retry_assessment(case)
    assert outcome == "not-exercised"
    assert "routed around the reviewed action" in reason


def test_a_pinned_file_case_needs_an_allowed_call_on_the_file_it_named():
    allowed = [_file_decision("Read", "README.md", "allow")]
    assert pinned_retry_outcome((), allowed, "README.md") is None
    elsewhere = [_file_decision("Read", "docs/README.md", "allow")]
    outcome, reason = pinned_retry_outcome((), elsewhere, "README.md")
    assert outcome == "not-exercised"
    assert "the file the case pinned" in reason


def test_a_pinned_file_case_needs_the_tool_it_named_not_another_one():
    """An edit of the pinned file does not stand in for the read the case pins.

    Both calls name the same path and both ride the same approval, so the path alone
    would pass a run in which the read this case exists to drive never happened.
    """
    edited = [_file_decision("Edit", "README.md", "allow")]
    outcome, reason = pinned_retry_outcome((), edited, "README.md", "read")
    assert outcome == "not-exercised"
    assert "the file the case pinned" in reason
    assert pinned_retry_outcome((), [_file_decision("Read", "README.md", "allow")], "README.md", "read") is None
    # A case that names no single file tool keeps the path-only pin it had before.
    assert pinned_retry_outcome((), edited, "README.md") is None


def test_a_pinned_tool_comes_from_a_case_whose_tools_are_all_file_tools():
    assert pinned_file_tool(("read",)) == "read"
    assert pinned_file_tool(("Read",)) == "read"
    assert pinned_file_tool(("read", "bash")) is None
    assert pinned_file_tool(("read", "write")) is None
    assert pinned_file_tool(()) is None


def test_a_file_tool_call_names_its_path_in_whichever_key_the_harness_used():
    assert input_path({"file_path": "{{workspace}}/README.md"}) == "{{workspace}}/README.md"
    assert input_path({"filePath": "README.md"}) == "README.md"
    assert input_path({"path": "README.md"}) == "README.md"
    assert input_path({"command": "cat README.md"}) is None
    assert input_path({"file_path": "   "}) is None
    assert input_path(None) is None
