from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard.models import GuardAction
from codex_plugin_scanner.guard.runtime.command_evaluation import evaluate_command


@pytest.mark.parametrize(
    ("command", "expected"),
    (
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
        ("gh pr merge 17 --repo example/repo --squash --delete-branch", "require-reapproval"),
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
    ),
)
def test_security_critical_commands_retain_exact_floors(command: str, expected: GuardAction) -> None:
    evaluation = evaluate_command(command, cwd=Path("workspace"), home_dir=Path("home"))
    assert evaluation.decision_plane.action == expected


@pytest.mark.parametrize(
    "command",
    (
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
    ),
)
def test_security_floors_do_not_widen_near_misses_to_block(command: str) -> None:
    evaluation = evaluate_command(command, cwd=Path("workspace"), home_dir=Path("home"))
    assert evaluation.decision_plane.action != "block"
