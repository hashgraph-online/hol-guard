"""Regression coverage for common CLI review findings on release 3.2."""

from __future__ import annotations

from pathlib import Path
from typing import cast

from codex_plugin_scanner.guard.runtime.command_inspection import inspect_command
from tests.command_extension_contracts import assert_reviewed_command_cases, assert_safe_command_cases

REVIEWED_GAP_CASES: tuple[tuple[str, str, str], ...] = (
    (
        "npx cdk destroy",
        "infrastructure destructive command",
        "command.infrastructure-as-code.runner-alias-teardown",
    ),
    (
        "npm exec -- cdk destroy",
        "infrastructure destructive command",
        "command.infrastructure-as-code.runner-alias-teardown",
    ),
    (
        "npm exec --package=aws-cdk -- cdk destroy",
        "infrastructure destructive command",
        "command.infrastructure-as-code.runner-alias-teardown",
    ),
    (
        "npx sls remove",
        "infrastructure destructive command",
        "command.infrastructure-as-code.runner-alias-teardown",
    ),
    (
        "bunx sls remove",
        "infrastructure destructive command",
        "command.infrastructure-as-code.runner-alias-teardown",
    ),
    (
        "pnpm dlx sls remove",
        "infrastructure destructive command",
        "command.infrastructure-as-code.runner-alias-teardown",
    ),
    (
        "npx railway up",
        "Railway production command",
        "command.platform.railway.runner-alias-change",
    ),
    (
        "npm exec --package=@railway/cli -- railway variables set API_TOKEN=value",
        "Railway production command",
        "command.platform.railway.runner-alias-change",
    ),
    (
        "npx railway delete --yes",
        "Railway destructive command",
        "command.platform.railway.runner-alias-destructive",
    ),
    (
        "dotnet add MyApp.csproj package Newtonsoft.Json",
        ".NET package mutation command",
        "command.package-dotnet.positional-project-package",
    ),
    (
        "yarn publish",
        "package publication command",
        "command.package-publication.additional-publish-or-yank",
    ),
    (
        "pnpm unpublish example-package@1.0.0",
        "package publication command",
        "command.package-publication.additional-publish-or-yank",
    ),
    (
        'psql --command="DROP DATABASE production"',
        "PostgreSQL destructive command",
        "command.database.postgresql.direct-drop",
    ),
    (
        "psql '-cDROP TABLE users'",
        "PostgreSQL destructive command",
        "command.database.postgresql.direct-drop",
    ),
    (
        'mysql --execute="TRUNCATE TABLE users"',
        "MySQL destructive command",
        "command.database.mysql.direct-drop",
    ),
    (
        "mysql '-eDELETE FROM users'",
        "MySQL destructive command",
        "command.database.mysql.direct-drop",
    ),
    (
        "mongosh app --eval 'db.users.deleteMany({})'",
        "MongoDB destructive command",
        "command.database.mongodb.direct-client-mutation",
    ),
    (
        "sqlite3 app.db 'DROP TABLE users'",
        "SQLite destructive command",
        "command.database.sqlite.direct-client-mutation",
    ),
    (
        "sqlite3 'DELETE FROM users'",
        "SQLite destructive command",
        "command.database.sqlite.direct-client-mutation",
    ),
    (
        "podman volume rm production-data",
        "docker-sensitive command",
        "command.container-runtime.alternate-runtime-resource-removal",
    ),
    (
        "nerdctl network rm private",
        "docker-sensitive command",
        "command.container-runtime.alternate-runtime-resource-removal",
    ),
    (
        "podman exec web sh",
        "docker-sensitive command",
        "command.container-runtime.alternate-runtime-execution",
    ),
    (
        "nerdctl run alpine true",
        "docker-sensitive command",
        "command.container-runtime.alternate-runtime-execution",
    ),
    (
        "oc rollout restart deployment/api",
        "Kubernetes destructive command",
        "command.kubernetes-operations.openshift-mutation",
    ),
    (
        "oc apply -f deployment.yaml",
        "Kubernetes destructive command",
        "command.kubernetes-operations.openshift-mutation",
    ),
    (
        "npx firebase functions:secrets:set API_TOKEN",
        "Firebase production command",
        "command.platform.firebase.secret-mutation",
    ),
    (
        "fly machines destroy 1234abcd",
        "Fly.io destructive command",
        "command.platform.fly.additional-destructive",
    ),
    (
        "fly releases rollback v42",
        "Fly.io production command",
        "command.platform.fly.additional-production-change",
    ),
    (
        "glab ci variable get DEPLOY_TOKEN",
        "GitLab variable command",
        "command.gitlab.ci-variable",
    ),
    (
        "argocd app set production --revision main",
        "Argo CD reconciliation command",
        "command.gitops.argocd.additional-reconciliation",
    ),
    (
        "vault kv undelete -versions=3 secret/app",
        "Vault secret mutation command",
        "command.secrets.vault.additional-mutation",
    ),
)


def test_review_findings_have_exact_structured_coverage(tmp_path: Path) -> None:
    assert_reviewed_command_cases(REVIEWED_GAP_CASES, tmp_path)


SAFE_GAP_CASES: tuple[str, ...] = (
    "ansible --version",
    "ansible all --list-hosts",
    "ansible-playbook production.yml --syntax-check",
    "ansible-playbook production.yml --list-tasks",
    "ansible-playbook production.yml --list-tags",
    "oc delete deployment api --dry-run=client",
    "oc delete deployment api --dry-run=server",
    "oc apply -f deployment.yaml --dry-run=client",
    "oc patch deployment api --type merge -p '{}' --dry-run=server",
    'psql --command="SELECT 1"',
    "psql '-cSELECT 1'",
    'mysql --execute="SELECT 1"',
    "mysql '-eSELECT 1'",
    "mongosh app --eval 'db.users.findOne({})'",
    "sqlite3 app.db 'SELECT * FROM users'",
    "sqlite3 'SELECT 1'",
    "npx cdk destroy --help",
    "npx sls remove --help",
    "npx railway up --help",
    "dotnet add MyApp.csproj package --help",
    "yarn publish --help",
    "pnpm unpublish --help",
    "podman volume rm --help",
    "nerdctl exec --help",
    "npx firebase functions:secrets:set --help",
    "fly machines destroy --help",
    "glab ci variable get --help",
    "argocd app set --help",
    "vault kv undelete --help",
)


def test_review_findings_preserve_read_only_and_preview_forms(tmp_path: Path) -> None:
    assert_safe_command_cases(SAFE_GAP_CASES, tmp_path)


def test_ansible_check_mode_is_not_globally_exempt(tmp_path: Path) -> None:
    payload = inspect_command(
        "ansible-playbook production.yml --check",
        cwd=tmp_path,
        home_dir=tmp_path,
    )

    assert payload["status"] == "review"
    rules = cast(list[dict[str, object]], payload["rules"])
    assert "command.configuration-management.ansible.remote-execution" in {rule["rule_id"] for rule in rules}


def test_invalid_openshift_dry_run_value_does_not_create_safe_bypass(tmp_path: Path) -> None:
    payload = inspect_command(
        "oc apply -f deployment.yaml --dry-run=maybe",
        cwd=tmp_path,
        home_dir=tmp_path,
    )

    assert payload["status"] == "review"
    rules = cast(list[dict[str, object]], payload["rules"])
    assert "command.kubernetes-operations.openshift-mutation" in {rule["rule_id"] for rule in rules}
