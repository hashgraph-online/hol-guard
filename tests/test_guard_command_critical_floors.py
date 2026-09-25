from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard.models import GuardAction
from codex_plugin_scanner.guard.native_command_model import _canonical_command_from_native, _request_payload
from codex_plugin_scanner.guard.runtime.command_critical_floors import command_critical_floor_factors
from codex_plugin_scanner.guard.runtime.command_evaluation import evaluate_command
from codex_plugin_scanner.guard.runtime.command_model import parse_shell_command
from codex_plugin_scanner.guard.runtime.effect_decision import EffectDecisionRequest, evaluate_effect_decision
from tests.native_command_test_support import real_native_review_fixture


def _native_action(command: str) -> tuple[GuardAction, str | None]:
    fixture = real_native_review_fixture(command, cwd=Path("workspace"), home_dir=Path("home"))
    evidence = fixture.payload["command_extensions"]
    assert isinstance(evidence, dict)
    error = evidence["evaluation_error"]
    if error is not None:
        assert error == "native_command_evaluation_failed"
        assert evidence["observations"] == []
        assert evidence["permission_observations"] == []
        assert evidence["binding"]["observation_count"] == 0
        assert fixture.payload["minimum_action"] == "block"
        return "block", error
    canonical = _canonical_command_from_native(command, fixture.payload["command_model"])
    assert canonical is not None
    evaluation = evaluate_command(
        command,
        canonical_command=canonical,
        cwd=Path("workspace"),
        home_dir=Path("home"),
        extension_control_snapshot=fixture.snapshot,
        native_extension_evidence=fixture.payload,
    )
    return evaluation.decision_plane.action, None


def _critical_factor_action(command: str) -> GuardAction:
    canonical = parse_shell_command(command, cwd=Path("workspace"), home_dir=Path("home"))
    factors = command_critical_floor_factors(canonical)
    return evaluate_effect_decision(EffectDecisionRequest(factors=factors)).action


CRITICAL_COMMAND_FLOORS: tuple[tuple[str, GuardAction], ...] = (
    ("aws route53 delete-hosted-zone --id zone --output json", "block"),
    ("aws --profile prod route53 delete-hosted-zone --id zone", "block"),
    ("aws route53 --profile prod delete-hosted-zone --id zone", "block"),
    ("aws route53 --region us-east-1 delete-hosted-zone --id zone", "block"),
    ("aws route53 --no-cli-pager delete-hosted-zone --id zone", "block"),
    ("aws route53 --prof prod delete-hosted-zone --id zone", "block"),
    ("aws route53 --reg us-east-1 delete-hosted-zone --id zone", "block"),
    ("aws route53 --prof=prod delete-hosted-zone --id zone", "block"),
    (
        "aws route53 --cli-binary-format raw-in-base64-out delete-hosted-zone --id zone",
        "block",
    ),
    (
        "aws route53 --cli-binary-format=raw-in-base64-out delete-hosted-zone --id zone",
        "block",
    ),
    ("stripe products delete product --description=--help", "block"),
    ("stripe --api-key key products delete product", "block"),
    ("stripe products --api-key key delete product", "block"),
    ("env sh -c 'rm -rf workspace/target'", "block"),
    ("rm -rf ./BUILD", "block"),
    ("rm --recurs --for workspace/target", "block"),
    ("xargs rm -rf BUILD", "block"),
    ("timeout 5 bash -lc 'rm -rf workspace/target'", "block"),
    ("timeout 5 /bin/bash -lc 'rm -rf workspace/target'", "block"),
    ("timeout 5 /bin/sh -c 'rm -rf workspace/target'", "block"),
    ("timeout 5 /usr/bin/dash -c 'rm -rf workspace/target'", "block"),
    ("timeout 5 /usr/bin/zsh -c 'rm -rf workspace/target'", "block"),
    ("timeout 5 /bin/ash -c 'rm -rf workspace/target'", "block"),
    ("timeout 5 env -S '/bin/bash -c' 'rm -rf workspace/target'", "block"),
    ("timeout 5 env -S'/bin/bash -c' 'rm -rf workspace/target'", "block"),
    ("timeout 5 env --split-string='/bin/bash -c' 'rm -rf workspace/target'", "block"),
    ("timeout 5 env --debug -i -v -S '/bin/bash -c' 'rm -rf workspace/target'", "block"),
    ("timeout 5 env -iv -S '/bin/bash -c' 'rm -rf workspace/target'", "block"),
    (
        "timeout 5 env --ignore-environment --null --list-signal-handling "
        + "-S '/bin/bash -c' 'rm -rf workspace/target'",
        "block",
    ),
    ("timeout 5 env -0ivS'/bin/bash -c' 'rm -rf workspace/target'", "block"),
    ("timeout 5 env -u TOKEN -S '/bin/bash -c' 'rm -rf workspace/target'", "block"),
    (
        "timeout 5 env -C workspace -P /bin -a shell -u TOKEN -S '/bin/bash -c' 'rm -rf workspace/target'",
        "block",
    ),
    (
        "timeout 5 env -Cworkspace -P/bin -ashell -uTOKEN -S '/bin/bash -c' 'rm -rf workspace/target'",
        "block",
    ),
    (
        "timeout 5 env --chdir workspace --argv0 shell --unset TOKEN -S '/bin/bash -c' 'rm -rf workspace/target'",
        "block",
    ),
    (
        "timeout 5 env --chdir=workspace --argv0=shell --unset=TOKEN -S '/bin/bash -c' 'rm -rf workspace/target'",
        "block",
    ),
    ("timeout 5 env -vS '/bin/bash -c' 'rm -rf workspace/target'", "block"),
    ("timeout 5 env -iS'/bin/bash -c' 'rm -rf workspace/target'", "block"),
    ("timeout 5 env -S'bash -c \"rm -rf /\"'", "block"),
    ("timeout 5 env --split-string='bash -c \"rm -rf /\"'", "block"),
    ("timeout 5 bash --noprofile -c 'rm -rf workspace/target'", "block"),
    ("timeout 5 bash -O extglob -c 'rm -rf workspace/target'", "block"),
    ("sh <<'EOF'\nrm -rf workspace/target\nEOF", "block"),
    ("gh api graphql -f query='mutation{deletePackageVersion(input:{packageVersionId:\"x\"}){success}}'", "block"),
    (
        "gh api --hostname github.com graphql "
        + "-f query='mutation{deletePackageVersion(input:{packageVersionId:\"x\"}){success}}'",
        "block",
    ),
    (
        "gh --repo example/repo api graphql "
        + "-f query='mutation{deletePackageVersion(input:{packageVersionId:\"x\"}){success}}'",
        "block",
    ),
    ("hol-guard capability consume --capability-id x --replay-sequence 2", "block"),
    ("hol-guard capability --verbose consume --capability-id x", "block"),
    ("hol-guard uninstall --all", "block"),
    ("hol-guard policy disable", "block"),
    ("hol-guard clear --all", "block"),
    ("xargs hol-guard uninstall --all", "block"),
    ("xargs -P 4 hol-guard uninstall --all", "block"),
    ("xargs -P4 hol-guard uninstall --all", "block"),
    ("xargs -I {} hol-guard uninstall --all", "block"),
    ("xargs -J % hol-guard uninstall --all", "block"),
    ("xargs -R 2 hol-guard uninstall --all", "block"),
    ("xargs -S 128 hol-guard uninstall --all", "block"),
    (
        "xargs xargs xargs xargs hol-guard uninstall --all",
        "block",
    ),
    ("parallel -j 4 hol-guard uninstall --all", "block"),
    ("parallel --jobs 4 hol-guard uninstall --all", "block"),
    ("parallel --colsep ' +' hol-guard uninstall --all", "block"),
    ("parallel --colsep=' +' hol-guard uninstall --all", "block"),
    ("parallel --header : hol-guard uninstall --all", "block"),
    ("parallel --header=: hol-guard uninstall --all", "block"),
    ("parallel --tagstring '{#}' hol-guard uninstall --all", "block"),
    ("parallel --tagstring='{#}' hol-guard uninstall --all", "block"),
    ("parallel --load 75% hol-guard uninstall --all", "block"),
    ("parallel --load=75% hol-guard uninstall --all", "block"),
    ("parallel --tagstring tag rm -rf / ::: x", "block"),
    ("parallel --header : rm -rf / ::: x", "block"),
    ("parallel --colsep value rm -rf / ::: x", "block"),
    ("parallel --load 100% rm -rf / ::: x", "block"),
    ("parallel --unknown parallel rm -rf / ::: x", "block"),
    ("find workspace -exec hol-guard uninstall --all {} ';'", "block"),
    (
        "find workspace -exec echo {} ';' -exec hol-guard uninstall --all {} ';'",
        "block",
    ),
    ("xargs sh -c 'hol-guard uninstall --all'", "block"),
    ("find workspace -exec sh -c 'hol-guard uninstall --all' ';'", "block"),
    ("parallel sh -c 'hol-guard uninstall --all'", "block"),
    ("xargs aws route53 delete-hosted-zone --id zone", "block"),
    ("xargs gh pr merge 17 --repo example/repo --squash", "require-reapproval"),
    ("sh -c 'gh pr merge 17 --repo example/repo --squash'", "require-reapproval"),
    ("bash -lc 'gh pr merge 17 --repo example/repo --squash'", "require-reapproval"),
    ("aws.exe route53 delete-hosted-zone --id zone", "block"),
    ("/usr/bin/stripe.exe products delete product", "block"),
    ("hol-guard.exe uninstall --all", "block"),
    ("rm.exe -rf workspace/target", "block"),
    ("gh.exe pr merge 17 --repo example/repo --squash", "require-reapproval"),
    ("PATH=scratch/bin:$PATH hol-guard status", "require-reapproval"),
    ("export PATH=scratch/bin:$PATH; hol-guard status", "require-reapproval"),
    ("npx --package tsc@file:./package tsc --noEmit", "require-reapproval"),
    ("printf '%s' \"$(cat workspace/sensitive)\"", "require-reapproval"),
    ("cat workspace/sensitive | tee scratch/output", "require-reapproval"),
    ("keyring get service user", "require-reapproval"),
    ("gh pr merge 17 --repo example/repo --squash --delete-branch", "review"),
    ("npm view typescript@5.0.0 dist.integrity", "review"),
    ("docker compose ps", "review"),
    ("docker inspect container --format '{{.State.Status}}'", "review"),
    ("aws sts get-caller-identity --profile profile --output json", "review"),
    ("gcloud projects describe project --format=json", "review"),
    ("getfacl workspace/service", "review"),
    ("systemctl status service", "review"),
    ("hol-guard uninstall --help --installation-id fixture", "review"),
    ("hol-guard help uninstall", "review"),
    (
        "gh api graphql -f query='mutation($threadId:ID!){resolveReviewThread"
        + "(input:{threadId:$threadId}){thread{id}}}' -f threadId=T",
        "review",
    ),
)


@pytest.mark.parametrize(("command", "expected"), CRITICAL_COMMAND_FLOORS)
def test_security_critical_commands_retain_exact_floors(command: str, expected: GuardAction) -> None:
    assert _critical_factor_action(command) == expected


def test_launcher_ambiguity_fanout_fails_closed() -> None:
    options = " ".join(f"--unknown value-{index}" for index in range(300))
    assert _critical_factor_action(f"parallel {options} printf safe") == "block"


def test_native_command_model_rejects_input_above_transport_budget() -> None:
    assert (
        _request_payload(
            "x" * (64 * 1024),
            dialect="posix",
            transport="shell_string",
            extraction_provenance="guard-shell",
        )
        is None
    )


# Frozen native baseline dispositions that are intentionally stricter than the
# independent host factor. These preserve the pre-migration Rust behavior.
NATIVE_STRICTER_CRITICAL_COMMANDS = frozenset(
    {
        "xargs gh pr merge 17 --repo example/repo --squash",
        "sh -c 'gh pr merge 17 --repo example/repo --squash'",
        "bash -lc 'gh pr merge 17 --repo example/repo --squash'",
        "PATH=scratch/bin:$PATH hol-guard status",
        "printf '%s' \"$(cat workspace/sensitive)\"",
        "docker compose ps",
        "docker inspect container --format '{{.State.Status}}'",
        (
            "gh api graphql -f query='mutation($threadId:ID!){resolveReviewThread"
            "(input:{threadId:$threadId}){thread{id}}}' -f threadId=T"
        ),
    }
)


@pytest.mark.parametrize(("command", "factor_floor"), CRITICAL_COMMAND_FLOORS)
def test_real_native_critical_floor_matches_frozen_baseline(
    command: str, factor_floor: GuardAction
) -> None:
    action, error = _native_action(command)
    expected = "block" if command in NATIVE_STRICTER_CRITICAL_COMMANDS else factor_floor
    assert action == expected
    if error is not None:
        assert action == "block"


CRITICAL_NEAR_MISS_COMMANDS: tuple[str, ...] = (
    "gh pr view 17 --repo example/repo",
    "rm -r workspace/cache",
    "rm -rf ./build",
    "rm --recursive --force ./dist ./coverage",
    "printf '%s' workspace/sensitive",
    "git diff --name-only | jq -R .",
    "npm view",
    "docker compose version",
    "rm -- -rf",
    "rm -f -- -r",
    "rm -r -- -f",
    "timeout 5 bash --norc 'rm -rf workspace/target'",
    "timeout 5 env -S '/bin/bash -c' 'printf safe'",
    "timeout 5 env -s '/bin/bash -c' 'rm -rf workspace/target'",
    "timeout 5 env --split-string '/bin/bash -c",
    "timeout 5 env -u -S '/bin/bash -c' 'rm -rf workspace/target'",
    "timeout 5 env -xS'/bin/bash -c' 'rm -rf workspace/target'",
    "timeout 5 env --debugging -S '/bin/bash -c' 'rm -rf workspace/target'",
    "timeout 5 env --debug=1 -S '/bin/bash -c' 'rm -rf workspace/target'",
    "timeout 5 env --chdir= -S '/bin/bash -c' 'rm -rf workspace/target'",
    "timeout 5 env --unset-name TOKEN -S '/bin/bash -c' 'rm -rf workspace/target'",
    "timeout 5 env -C -S '/bin/bash -c' 'rm -rf workspace/target'",
    "timeout 5 env -Something 'bash -c' 'rm -rf /'",
    "timeout 5 env --split-strings='bash -c \"rm -rf /\"'",
    "gh api graphql -f query='mutation{updateIssue(input:{title:\"do not delete\"}){issue{id}}}'",
    "gh api graphql -f query='mutation($removeLabel:String!){updateIssue(input:{title:$removeLabel}){issue{id}}}'",
    "aws --profile route53 sts get-caller-identity --output delete-hosted-zone",
    "aws route53 --cli value delete-hosted-zone --id zone",
    "stripe --api-key products customers list delete",
    "xargs echo hol-guard uninstall --all",
    "find workspace -exec echo hol-guard uninstall --all {} ';'",
    "xargs sh -c 'printf safe'",
    "find workspace -exec sh -c 'printf safe' ';'",
    "parallel sh -c 'printf safe'",
    "not-gh.exe pr merge 17 --repo example/repo --squash",
)

NATIVE_STRICTER_NEAR_MISSES = frozenset(
    {
        "rm -r workspace/cache",
        "rm -rf ./build",
        "rm --recursive --force ./dist ./coverage",
        "docker compose version",
        "rm -- -rf",
        "rm -f -- -r",
        "rm -r -- -f",
        "gh api graphql -f query='mutation{updateIssue(input:{title:\"do not delete\"}){issue{id}}}'",
        "gh api graphql -f query='mutation($removeLabel:String!){updateIssue(input:{title:$removeLabel}){issue{id}}}'",
    }
)


@pytest.mark.parametrize("command", CRITICAL_NEAR_MISS_COMMANDS)
def test_security_floors_do_not_widen_near_misses_to_block(command: str) -> None:
    assert _critical_factor_action(command) != "block"


@pytest.mark.parametrize("command", CRITICAL_NEAR_MISS_COMMANDS)
def test_real_native_near_miss_matches_frozen_baseline(command: str) -> None:
    action, error = _native_action(command)
    if command in NATIVE_STRICTER_NEAR_MISSES or error is not None:
        assert action == "block"
    else:
        assert action != "block"
