//! Workflows that check out pull request code with privileges, grant
//! write-all or use actions not pinned to a commit.
use super::*;

const PIN: &str = "11bd71901bbe5b1630ceea73d27597364c9af683";

fn ids(text: &str) -> Vec<&'static str> {
    detect_ci_workflow_risk(text)
        .into_iter()
        .map(|rule| rule.id)
        .collect()
}

fn pinned_checkout_step(with_ref: &str) -> String {
    format!(
        "    steps:\n      - uses: actions/checkout@{PIN}\n        with:\n          ref: {with_ref}\n"
    )
}

#[test]
fn a_privileged_trigger_that_checks_out_the_pull_request_head_is_reported() {
    for (trigger, with_ref) in [
        (
            "on:\n  pull_request_target:\n",
            "${{ github.event.pull_request.head.sha }}",
        ),
        (
            "on: pull_request_target\n",
            "${{ github.event.pull_request.head.ref }}",
        ),
        (
            "on:\n  workflow_run:\n    workflows: [CI]\n",
            "${{ github.event.workflow_run.head_sha }}",
        ),
        ("on: [pull_request_target]\n", "${{ github.head_ref }}"),
        (
            "on: pull_request_target\n",
            "refs/pull/${{ github.event.pull_request.number }}/merge",
        ),
        (
            "on: workflow_run\n",
            "${{ github.event.workflow_run.head_branch }}",
        ),
        (
            "on: [push, workflow_run]\n",
            "${{ github.event.pull_request.merge_commit_sha }}",
        ),
    ] {
        let text = format!(
            "{trigger}jobs:\n  build:\n{}",
            pinned_checkout_step(with_ref)
        );
        assert_eq!(ids(&text), ["ci.workflow.untrusted-checkout"], "{text}");
    }
}

#[test]
fn a_git_checkout_of_the_head_in_a_privileged_run_step_is_reported() {
    let text = "on: pull_request_target\njobs:\n  t:\n    steps:\n      - run: git fetch origin && git checkout ${{ github.event.pull_request.head.sha }}\n";
    assert_eq!(ids(text), ["ci.workflow.untrusted-checkout"]);
}

#[test]
fn a_shell_checkout_of_the_head_by_branch_or_pr_number_is_reported() {
    for run in [
        "git fetch origin \"$GITHUB_HEAD_REF\" && git checkout \"$GITHUB_HEAD_REF\"",
        "gh pr checkout ${{ github.event.pull_request.number }}",
    ] {
        let text =
            format!("on: pull_request_target\njobs:\n  t:\n    steps:\n      - run: {run}\n");
        assert_eq!(ids(&text), ["ci.workflow.untrusted-checkout"], "{text}");
    }
}

#[test]
fn checking_out_the_head_without_a_privileged_trigger_is_quiet() {
    let text = format!(
        "on: pull_request\njobs:\n  b:\n{}",
        pinned_checkout_step("${{ github.event.pull_request.head.sha }}")
    );
    assert!(ids(&text).is_empty());
}

#[test]
fn a_privileged_trigger_that_checks_out_the_base_branch_is_quiet() {
    let text = format!(
        "on: pull_request_target\npermissions:\n  pull-requests: write\njobs:\n  label:\n    steps:\n      - uses: actions/checkout@{PIN}\n      - uses: actions/labeler@{PIN}\n"
    );
    assert!(ids(&text).is_empty());
}

#[test]
fn a_head_ref_outside_the_checkout_is_quiet() {
    let text = format!(
        "on: pull_request_target\nconcurrency:\n  group: ${{{{ github.workflow }}}}-${{{{ github.head_ref || github.run_id }}}}\njobs:\n  label:\n    steps:\n      - uses: actions/checkout@{PIN}\n      - run: echo \"head ${{{{ github.event.pull_request.head.sha }}}}\"\n"
    );
    assert!(ids(&text).is_empty(), "{text}");
}

#[test]
fn a_commented_out_trigger_is_quiet() {
    let text = format!(
        "on:\n  pull_request:\n  # pull_request_target:\njobs:\n  b:\n{}",
        pinned_checkout_step("${{ github.event.pull_request.head.sha }}")
    );
    assert!(ids(&text).is_empty());
}

#[test]
fn write_all_permissions_are_reported_at_workflow_or_job_level() {
    for text in [
        "on: push\npermissions: write-all\njobs: {}\n",
        "on: push\njobs:\n  b:\n    permissions: \"write-all\"\n",
        "on: push\njobs:\n  b:\n    permissions: write-all # broad\n",
        "on: push\n\"permissions\": write-all\n",
        "on: push\njobs:\n  b:\n    'permissions': 'write-all'\n",
        "on: push\njobs:\n  b:\n    steps:\n      - uses: ./a\n        with:\n          x: 1\n    permissions: write-all\n",
    ] {
        assert_eq!(ids(text), ["ci.workflow.write-all-permissions"], "{text}");
    }
}

#[test]
fn narrow_or_read_all_permissions_are_quiet() {
    for text in [
        "on: push\npermissions: read-all\n",
        "on: push\npermissions:\n  contents: write\n",
        "on: push\n# permissions: write-all\n",
        "on: push\njobs:\n  b:\n    steps:\n      - uses: ./local-action\n        with:\n          permissions: write-all\n",
        "on: push\njobs:\n  b:\n    steps:\n      - with:\n\n          permissions: write-all\n        uses: ./local-action\n",
        "on: push\njobs:\n  b:\n    steps:\n      - uses: ./local-action\n        with: # inputs\n          permissions: write-all\n",
    ] {
        assert!(ids(text).is_empty(), "{text}");
    }
}

#[test]
fn an_action_referenced_by_tag_branch_or_short_sha_is_unpinned() {
    for uses in [
        "actions/checkout@v4",
        "\"actions/setup-node@main\"",
        "owner/repo/.github/workflows/ci.yml@v1",
        "actions/cache@11bd719",
        "owner/action",
    ] {
        let text = format!("on: push\njobs:\n  b:\n    steps:\n      - uses: {uses}\n");
        assert_eq!(ids(&text), ["ci.workflow.unpinned-action"], "{uses}");
    }
}

#[test]
fn pinned_local_and_container_actions_are_quiet() {
    let text = format!(
        "on: push\njobs:\n  b:\n    uses: owner/repo/.github/workflows/ci.yml@{PIN}\n  c:\n    steps:\n      - uses: actions/checkout@{PIN} # v4.2.2\n      - uses: './.github/actions/setup'\n      - uses: docker://alpine:3.20\n      # - uses: actions/cache@v4\n"
    );
    assert!(ids(&text).is_empty());
}

#[test]
fn each_rule_is_reported_once_in_rule_order() {
    let text = "on: pull_request_target\npermissions: write-all\njobs:\n  b:\n    steps:\n      - uses: actions/checkout@v4\n        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n      - uses: actions/setup-node@v4\n";
    assert_eq!(
        ids(text),
        [
            "ci.workflow.untrusted-checkout",
            "ci.workflow.write-all-permissions",
            "ci.workflow.unpinned-action",
        ]
    );
}

#[test]
fn an_empty_or_plain_workflow_is_quiet() {
    assert!(ids("").is_empty());
    let text = format!(
        "name: CI\non: [push, pull_request]\njobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@{PIN}\n      - run: cargo test\n"
    );
    assert!(ids(&text).is_empty());
}
