"""The replay lane's strict judge, without the native runtime."""

from __future__ import annotations

from pathlib import Path

import pytest

from ci.gauntlet.approval_rows import REDACTED_GROUP, _opaque_group
from ci.gauntlet.catalog import Scenario, load_catalog, retain_trusted_cases
from ci.gauntlet.interruptions import (
    case_interruptions,
    observation_interruptions,
    rendered_fields,
    summarize_interruptions,
)
from ci.gauntlet.qualify import retryable, summarize_attempt
from codex_plugin_scanner.guard.blocked_request_mode import SAFE_ALTERNATIVE_GUIDANCE, connector_setup_reason
from tests.gauntlet_replay import ReplayCase, expand, judge


def _case(expect: str, harness: str = "claude-code", contained_ok: bool = False) -> ReplayCase:
    return ReplayCase(
        f"x@{harness}", "x", harness, "shell", {"command": "ls"}, "worktree", expect, contained_ok=contained_ok
    )


_QUIET = {"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "allow"}}


def test_quiet_allow_passes() -> None:
    assert judge(_case("quiet"), _QUIET, []) is None


def test_warn_with_rendered_text_fails_ordinary_work() -> None:
    warned = {**_QUIET, "policy_action": "warn", "systemMessage": "Guard warning"}
    assert judge(_case("quiet"), warned, []) is not None


def test_warn_without_text_is_quiet() -> None:
    assert (
        judge(_case("quiet"), {**_QUIET, "policy_action": "warn", "reason_code": "native_policy_warning"}, []) is None
    )


def test_approval_row_fails_ordinary_work() -> None:
    assert judge(_case("quiet"), _QUIET, [{"tool_name": "Bash", "reason_code": "r"}]) is not None


def test_ask_fails_ordinary_work() -> None:
    asked = {"hookSpecificOutput": {"permissionDecision": "ask", "permissionDecisionReason": "review"}}
    assert judge(_case("quiet"), asked, []) is not None


def test_always_needs_a_persistent_allow_in_the_contract() -> None:
    asked = {"hookSpecificOutput": {"permissionDecision": "ask"}}
    once = {"tool_name": "Bash", "always_available": False, "exact_context_token_present": True}
    offered = {
        "tool_name": "Bash",
        "always_available": True,
        "exact_action_persistence_eligible": True,
        "exact_context_token_present": True,
    }
    assert judge(_case("always"), asked, [once]) is not None
    assert judge(_case("always"), asked, [offered]) is None


@pytest.mark.parametrize("base_id", ["find-exec-literal-interpreter-argument", "find-exec-escaped-regex-argument"])
def test_named_find_cases_accept_quiet_work_in_the_replay(base_id: str) -> None:
    case = next(case for case in expand() if case.base_id == base_id)
    assert judge(case, _QUIET, []) is None


def test_named_child_review_still_requires_always_allow() -> None:
    asked = {"hookSpecificOutput": {"permissionDecision": "ask"}}
    once = {"tool_name": "Bash", "always_available": False, "exact_context_token_present": True}
    offered = {
        "tool_name": "Bash",
        "always_available": True,
        "exact_action_persistence_eligible": True,
        "exact_context_token_present": True,
    }
    case = _case("quiet_or_always")
    assert judge(case, asked, [offered]) is None
    assert judge(case, asked, [once]) is not None
    assert judge(case, {"hookSpecificOutput": {"permissionDecision": "deny"}}, []) is not None
    assert judge(case, {**_QUIET, "systemMessage": "Guard warning"}, []) is not None


def test_attack_must_not_be_allowed() -> None:
    denied = {"hookSpecificOutput": {"permissionDecision": "deny"}}
    assert judge(_case("block"), _QUIET, []) is not None
    assert judge(_case("block"), denied, []) is None


_ROUTED = {**_QUIET, "reason_code": "native_contained_execution_routed"}


def test_containment_protects_only_the_case_that_says_so() -> None:
    # The workspace sandbox still writes inside the workspace, so a contained run is not protection
    # against an attack on the worktree itself. Only a case whose harm is network, home or
    # credential reach counts it.
    assert judge(_case("block"), _ROUTED, []) is not None
    assert judge(_case("block", contained_ok=True), _ROUTED, []) is None


def test_a_contained_omp_receipt_needs_the_same_marker(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("tests.gauntlet_replay.sys.platform", "darwin")
    workspace = {
        "decision": "deny",
        "policy_action": "sandbox-required",
        "reason_code": "native_workspace_containment_required",
        "required_execution_profile": "workspace-contained-v1",
    }
    assert judge(_case("block", "omp"), workspace, []) is not None
    assert judge(_case("block", "omp", contained_ok=True), workspace, []) is None


def test_only_the_marked_cases_may_pass_on_containment() -> None:
    marked = {c.base_id for c in expand() if c.expect == "block" and c.contained_ok}
    assert marked == {
        "neg-cargo-check-locked-host-toolchain",
        # A filter whose grammar the read recognizer rejects: the operands stay inside the
        # workspace, so the contained run reaches nothing, and the case pins the rejection
        # rather than an approval prompt an in-worktree write would never raise.
        "neg-cut-without-selection",
        # A service log read under the daemon: a contained run reaches no daemon socket,
        # so no log content leaves the sandbox.
        "neg-docker-compose-logs-service",
        # A key read under the home: a contained run has no home access, so the pattern
        # matches nothing and no key material is printed.
        "neg-egrep-reads-private-key",
        "neg-env-bare-set-then-list",
        "neg-env-git-dir-then-list",
        "neg-env-ld-preload-then-list",
        "neg-env-pager-names-program",
        # A pager option that carries its own shell escape: a contained run gives the
        # escape nothing outside the workspace to reach.
        "neg-env-pager-option-escape-export",
        # A `find` that is not limited to regular files hands a link to `grep`, which opens its
        # target; the contained run reaches nothing outside the workspace.
        "neg-find-exec-grep-l-edge-clone-without-type-f",
        # A signing program named outside the workspace: a contained run cannot reach that
        # path, so the amend runs no program the sandbox does not hold.
        "neg-git-amend-signed-program-override",
        # A ref write under the worktree's own admin directory, which a contained run
        # keeps inside the sandbox.
        "neg-git-branch-create",
        # The sandbox has no network for the push to reach the remote over, and no home access
        # for the widened search, so a contained run sends nothing and prints no key.
        "neg-git-push-to-tmp-chain",
        # `gh config set` changes only the CLI configuration under the home directory, which a
        # contained run cannot write.
        "neg-github-config-set",
        # A listing below a hidden home directory: a contained run has no home access, so it
        # names nothing the home keeps there.
        "neg-ls-home-dot-glob",
        "neg-ls-home-missing-hidden-store",
        # A pattern that is a credential word and an unconstrained tail expands onto the
        # command line as the files beside it, so the second one becomes the file the
        # filter opens; a contained run has no home access and reads none of them.
        "neg-grep-credential-bare-wildcard-pattern",
        "neg-ls-home-missing-key-in-hidden-directory",
        # A file listing of a home service lane or credential store: a contained run has no
        # home access, so it prints no name the home keeps there.
        "neg-rg-content-search-service-lane",
        # A credential word and a wildcard in the path position selects names the home may
        # keep; a contained run has no home access, so it prints none of them.
        "neg-rg-credential-word-wildcard-as-path-operand",
        # The same bare credential wildcard in a ripgrep pattern position.
        "neg-rg-secret-bare-wildcard-pattern",
        "neg-rg-files-hidden-service-lane",
        "neg-rg-files-home-credential-store",
        "neg-rg-files-no-ignore-service-lane",
        "neg-rg-path-before-files-flag-credential-store",
        "neg-rg-replace-widens-home-search",
        # A sibling checkout's workflows and test runner: a contained run reads only the
        # workspace, so `-exec cat`, a preloaded module or a dotfile probe reaches no secret.
        "neg-sibling-find-github-exec-cat",
        "neg-sibling-ls-missing-env-below-github",
        "neg-sibling-node-heap-require-other-checkout",
        # The same rejection for a filter that names an output file. `neg-sort-output-file`
        # and `neg-uniq-output-operand` carry the strict direction with an escaping path;
        # these keep the in-worktree shape on record, where the write cannot leave the
        # workspace and the contained run is the designed outcome.
        "neg-sort-output-file-in-worktree",
        "neg-tr-file-operand",
        "neg-uniq-output-operand-in-worktree",
    }


_SETUP_RESULT = {
    "policy_action": "block",
    "decision": "deny",
    "reason": f"{connector_setup_reason('lanectl', 'cli', ask=False)} Review it at http://127.0.0.1:9/requests/r1.",
}
_SETUP_ROW = {
    "reason_code": "native_command_review_required",
    "queue_group_id": f"connector:{'a' * 64}:{'b' * 16}",
}


def test_setup_needs_the_connector_outcome_not_a_generic_review() -> None:
    assert judge(_case("setup"), _SETUP_RESULT, [_SETUP_ROW]) is None
    generic = {"policy_action": "block", "decision": "deny", "reason": "Guard requires review of this command."}
    assert judge(_case("setup"), generic, [_SETUP_ROW]) is not None
    assert judge(_case("setup"), _SETUP_RESULT, [{**_SETUP_ROW, "queue_group_id": ""}]) is not None
    assert judge(_case("setup"), _SETUP_RESULT, [_SETUP_ROW, _SETUP_ROW]) is not None
    assert judge(_case("setup"), _SETUP_RESULT, [{**_SETUP_ROW, "reason_code": "native_policy_block"}]) is not None
    assert judge(_case("setup"), _QUIET, []) is not None
    # A local CLI is approvable: sending the agent to a safe alternative instead of the approval is wrong.
    redirected = {**_SETUP_RESULT, "reason": f"{_SETUP_RESULT['reason']} {SAFE_ALTERNATIVE_GUIDANCE}"}
    assert "redirect the agent" in str(judge(_case("setup"), redirected, [_SETUP_ROW]))


def test_a_setup_case_is_replayed_as_setup() -> None:
    expected = {c.expect for c in expand() if c.base_id == "lanectl-status"}
    assert expected == {"setup"}


def test_expansion_covers_pi_and_every_harness() -> None:
    cases = expand()
    assert {c.harness for c in cases} == {"codex", "zcode", "claude-code", "omp", "pi", "cursor"}
    ids = {c.case_id for c in cases}
    assert "omp-todo-phases@omp" in ids
    assert "omp-todo-phases@pi" not in ids  # Pi ships no todo tool


def test_silent_always_allow_fails_the_review_by_design_case() -> None:
    assert judge(_case("always"), _QUIET, []) is not None
    offered = {
        "tool_name": "Bash",
        "always_available": True,
        "exact_action_persistence_eligible": True,
        "exact_context_token_present": True,
    }
    assert judge(_case("always"), {"hookSpecificOutput": {"permissionDecision": "ask"}}, [offered]) is None


def _benign() -> Scenario:
    return next(s for s in load_catalog() if s.expectation == "allow" and s.oracle == "native-tools")


@pytest.mark.parametrize(
    "row",
    [
        {"observer_error": True, "event": "PreToolUse"},
        {"transport_error": True, "event": "PreToolUse"},
        {"event": "PreToolUse", "decision": "allow", "rendered_fields": [], "http_status": 500},
        {"event": "PreToolUse", "rendered_fields": []},
        {"decision": "allow", "rendered_fields": []},
    ],
)
def test_rows_that_cannot_prove_quiet_are_unproven_on_benign_work(row: dict) -> None:
    record = case_interruptions(_benign(), [row], [], 0, "omp")
    assert record["benign"] and [e["kind"] for e in record["events"]] == ["unproven"]
    assert record["quiet_decisions"] == 0


def test_a_proven_quiet_row_is_not_an_interruption() -> None:
    row = {"event": "PreToolUse", "decision": "allow", "rendered_fields": [], "http_status": 200}
    assert case_interruptions(_benign(), [row], [], 0, "omp")["events"] == []


def test_post_tool_rendered_text_counts() -> None:
    row = {
        "response": {"systemMessage": "note"},
        "payload": {"tool_name": "bash", "hook_event_name": "PostToolUse"},
    }
    assert [e["kind"] for e in case_interruptions(_benign(), [row], [], 0, "codex")["events"]] == ["rendered"]


def test_empty_top_level_text_does_not_shadow_nested_text() -> None:
    response = {"additionalContext": "", "hookSpecificOutput": {"additionalContext": "warn"}}
    assert rendered_fields(response) == ["additionalContext"]
    assert rendered_fields({"systemMessage": "x", "hookSpecificOutput": {"systemMessage": ""}}) == ["systemMessage"]


def test_nested_decision_wins_over_top_level() -> None:
    nested_ask = {"permissionDecision": "allow", "hookSpecificOutput": {"permissionDecision": "ask"}}
    nested_allow = {"permissionDecision": "ask", "hookSpecificOutput": {"permissionDecision": "allow"}}
    assert [e["kind"] for e in observation_interruptions({"response": nested_ask, "payload": _EVENT})] == ["decision"]
    assert observation_interruptions({"response": nested_allow, "payload": _EVENT}) == []


_EVENT = {"tool_name": "bash", "hook_event_name": "PreToolUse"}


def test_unknown_permission_string_is_a_decision() -> None:
    found = observation_interruptions({"response": {"permissionDecision": "defer"}, "payload": _EVENT})
    assert [e["kind"] for e in found] == ["decision"] and found[0]["decision"] == "defer"


def test_exemption_comes_from_trusted_ids_not_the_supplied_oracle() -> None:
    watch = next(s for s in load_catalog() if s.oracle == "watch-command")
    assert not case_interruptions(watch, [], [], 0)["benign"]
    from dataclasses import replace

    forged = replace(_benign(), id="new-case", oracle="watch-command")
    assert case_interruptions(forged, [], [], 0)["benign"]
    with pytest.raises(ValueError, match="exempt oracle"):
        retain_trusted_cases((*load_catalog(), forged), load_catalog())


def _summary(benign_cases: int, interrupted: int) -> dict:
    return {
        "pass": True,
        "merge_qualified": True,
        "cases": [],
        "interruptions": {"benign_cases": benign_cases, "benign_interruptions": interrupted},
    }


def test_qualify_rejects_interruptions_and_zero_benign_cases() -> None:
    assert summarize_attempt(1, Path("e"), 0, 1.0, _summary(3, 0))["pass"] is True
    assert summarize_attempt(1, Path("e"), 0, 1.0, _summary(3, 1))["pass"] is False
    assert summarize_attempt(1, Path("e"), 0, 1.0, _summary(0, 0))["pass"] is False


def test_an_interrupted_case_is_never_retried() -> None:
    quiet = {"outcome": "harness-error", "interrupted": False}
    assert retryable([quiet], 1, 3)
    assert not retryable([{**quiet, "interrupted": True}], 1, 3)


def test_summary_counts_unproven_as_benign_interruptions() -> None:
    record = case_interruptions(_benign(), [{"observer_error": True}], [], 0, "omp")
    assert summarize_interruptions([{"interruptions": record}])["benign_interruptions"] == 1


_RECEIPT = {
    "decision": "deny",
    "policy_action": "sandbox-required",
    "reason_code": "native_pytest_readonly_containment_required",
    "reason": "Run in the read-only sandbox.",
    "required_execution_profile": "pytest-readonly-v2",
}


def test_omp_containment_receipt_is_quiet_where_omp_routes_it(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("tests.gauntlet_replay.sys.platform", "darwin")
    assert judge(_case("quiet", "omp"), _RECEIPT, []) is None
    assert judge(_case("always", "omp"), _RECEIPT, []) is None


@pytest.mark.parametrize(
    ("harness", "platform", "receipt"),
    [
        ("omp", "linux", _RECEIPT),
        ("codex", "darwin", _RECEIPT),
        ("omp", "darwin", {**_RECEIPT, "required_execution_profile": "vitest-readonly-v1"}),
        ("omp", "darwin", {**_RECEIPT, "observe_mode": True}),
    ],
)
def test_containment_receipt_interrupts_where_nothing_routes_it(
    monkeypatch: pytest.MonkeyPatch, harness: str, platform: str, receipt: dict[str, object]
) -> None:
    monkeypatch.setattr("tests.gauntlet_replay.sys.platform", platform)
    assert judge(_case("quiet", harness), receipt, []) is not None


def test_a_routed_run_satisfies_an_always_case() -> None:
    # Z Code and Claude Code route in the hook path and Codex in its bridge.
    routed = {**_QUIET, "reason_code": "native_contained_execution_routed"}
    for harness in ("zcode", "claude-code", "codex"):
        assert judge(_case("always", harness), routed, []) is None
    assert judge(_case("always", "codex"), _QUIET, []) is not None


def test_approval_rows_keep_only_opaque_connector_groups() -> None:
    group = f"connector:{'a' * 64}:{'b' * 16}"
    assert _opaque_group(group) == group
    assert _opaque_group("") == ""
    assert _opaque_group(None) == ""
    assert _opaque_group("connector:/home/dev/project") == REDACTED_GROUP
    assert _opaque_group(f"{group}/extra") == REDACTED_GROUP
