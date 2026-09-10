"""First-class common CLI Extension coverage for release 3.2."""

from __future__ import annotations

from pathlib import Path

from codex_plugin_scanner.guard.runtime.command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY
from tests.command_extension_contracts import (
    assert_review_required_cases,
    assert_reviewed_command_cases,
    assert_safe_command_cases,
)

NEW_EXTENSION_REVIEW_CASES: tuple[tuple[str, str, str], ...] = (
    ("wrangler d1 delete production-db", "Cloudflare destructive command", "command.platform.cloudflare.destructive"),
    ("npx wrangler deploy", "Cloudflare production command", "command.platform.cloudflare.remote-change"),
    ("wrangler secret put API_TOKEN", "Cloudflare production command", "command.platform.cloudflare.remote-change"),
    ("glab repo delete group/project", "GitLab destructive command", "command.gitlab.destructive"),
    ("glab mr merge 42", "GitLab merge command", "command.gitlab.merge"),
    ("glab variable get DEPLOY_TOKEN", "GitLab variable command", "command.gitlab.variable"),
    ("vault kv get secret/app", "Vault secret read command", "command.secrets.vault.secret-read"),
    (
        "vault kv destroy -versions=3 secret/app",
        "Vault secret mutation command",
        "command.secrets.vault.secret-mutation",
    ),
    (
        "vault policy delete legacy",
        "Vault security administration command",
        "command.secrets.vault.security-administration",
    ),
    ("npx prisma migrate reset", "Prisma destructive command", "command.database.prisma.destructive"),
    ("npx prisma db push --accept-data-loss", "Prisma destructive command", "command.database.prisma.destructive"),
    ("npx prisma migrate deploy", "Prisma production migration command", "command.database.prisma.production-migrate"),
    ("firebase deploy", "Firebase production command", "command.platform.firebase.production-deploy"),
    ("firebase functions:delete worker", "Firebase destructive command", "command.platform.firebase.destructive"),
    ("argocd app delete production", "Argo CD destructive command", "command.gitops.argocd.destructive"),
    ("argocd app sync production", "Argo CD reconciliation command", "command.gitops.argocd.reconciliation"),
    ("flux delete kustomization production", "Flux destructive command", "command.gitops.flux.destructive"),
    ("flux reconcile kustomization production", "Flux reconciliation command", "command.gitops.flux.reconciliation"),
    ("dotnet package add Newtonsoft.Json", ".NET package mutation command", "command.package-dotnet.package-mutation"),
    ("dotnet nuget push package.nupkg", ".NET package publication command", "command.package-dotnet.publication"),
    ("bq rm -r -f project:dataset", "BigQuery destructive command", "command.database.bigquery.destructive"),
    (
        "bq load --replace project:dataset.table gs://bucket/data.json",
        "BigQuery destructive command",
        "command.database.bigquery.destructive",
    ),
    ("fly apps destroy production", "Fly.io destructive command", "command.platform.fly.destructive"),
    ("flyctl deploy", "Fly.io production command", "command.platform.fly.production-change"),
    ("fly secrets set API_TOKEN=value", "Fly.io production command", "command.platform.fly.production-change"),
    ("railway delete --yes", "Railway destructive command", "command.platform.railway.destructive"),
    ("railway up", "Railway production command", "command.platform.railway.remote-change"),
    ("railway shell", "Railway production command", "command.platform.railway.remote-change"),
    (
        "ansible-playbook -i inventory production.yml",
        "Ansible remote execution command",
        "command.configuration-management.ansible.remote-execution",
    ),
    (
        "ansible-vault view group_vars/prod.yml",
        "Ansible Vault secret command",
        "command.configuration-management.ansible.vault-secret",
    ),
    (
        "doctl compute droplet delete 123456",
        "DigitalOcean destructive command",
        "command.cloud.digitalocean.resource-deletion",
    ),
    ("op read op://Production/API/token", "1Password secret read command", "command.secrets.1password.secret-read"),
    ("op run -- env", "1Password secret injection command", "command.secrets.1password.secret-injection"),
    ("op item delete credential-id", "1Password destructive command", "command.secrets.1password.destructive"),
    ("npm publish", "package publication command", "command.package-publication.publish-or-yank"),
    (
        "aws secretsmanager get-secret-value --secret-id production/api",
        "cloud secret read command",
        "command.cloud-secrets.secret-read",
    ),
    (
        "aws iam create-access-key --user-name deployer",
        "cloud credential mutation command",
        "command.cloud-secrets.credential-mutation",
    ),
)


def test_common_cli_extensions_feed_inspection_and_runtime(tmp_path: Path) -> None:
    assert_reviewed_command_cases(NEW_EXTENSION_REVIEW_CASES, tmp_path)


EXPANSION_REVIEW_CASES: tuple[str, ...] = (
    "podman system prune",
    "nerdctl run --privileged alpine",
    "oc delete deployment api",
    "oc exec deployment/api -- sh",
    "oc port-forward service/api 8080:80",
    "oc rsync ./out pod:/tmp/out",
    "npx aws-cdk destroy",
    "sam delete",
    "npx serverless remove",
    'psql -c "DROP DATABASE production"',
    'mysql -e "DROP DATABASE production"',
)


def test_existing_extensions_gain_common_cli_coverage(tmp_path: Path) -> None:
    assert_review_required_cases(EXPANSION_REVIEW_CASES, tmp_path)


SAFE_COMMANDS: tuple[str, ...] = (
    "wrangler d1 delete --help",
    "wrangler d1 list",
    "glab repo delete --help",
    "glab repo view group/project",
    "vault kv get --help",
    "vault kv list secret/",
    "npx prisma migrate reset --help",
    "npx prisma migrate status",
    "firebase deploy --help",
    "firebase projects:list",
    "argocd app delete --help",
    "argocd app get production",
    "flux delete kustomization --help",
    "flux get kustomizations",
    "dotnet nuget push --help",
    "dotnet --info",
    "bq rm --help",
    "bq ls",
    "fly apps destroy --help",
    "fly status",
    "railway delete --help",
    "railway status",
    "ansible --version",
    "ansible-vault view --help",
    "doctl compute droplet delete --help",
    "doctl account get",
    "op read --help",
    "op whoami",
    "npm publish --help",
    "npm view left-pad version",
    "aws secretsmanager get-secret-value --help",
    "aws secretsmanager list-secrets",
    "podman system prune --help",
    "podman ps",
    "oc delete --help",
    "oc get pods",
    "npx aws-cdk destroy --help",
    "cdk list",
    'psql -c "SELECT 1"',
    'mysql -e "SELECT 1"',
)


def test_common_cli_help_and_observer_commands_remain_safe(tmp_path: Path) -> None:
    assert_safe_command_cases(SAFE_COMMANDS, tmp_path)


NEW_EXTENSION_IDS = (
    "command.platform.cloudflare",
    "command.gitlab",
    "command.secrets.vault",
    "command.database.prisma",
    "command.platform.firebase",
    "command.gitops.argocd",
    "command.gitops.flux",
    "command.package-dotnet",
    "command.database.bigquery",
    "command.platform.fly",
    "command.platform.railway",
    "command.configuration-management.ansible",
    "command.cloud.digitalocean",
    "command.secrets.1password",
    "command.package-publication",
    "command.cloud-secrets",
)


def test_common_cli_extensions_are_first_class_and_referenced() -> None:
    for extension_id in NEW_EXTENSION_IDS:
        extension = BUILT_IN_COMMAND_EXTENSION_REGISTRY.get(extension_id)
        assert extension is not None
        assert extension.rules
        assert extension.reference_urls
        assert all(url.startswith("https://") for url in extension.reference_urls)


def test_existing_extension_metadata_matches_expanded_authority() -> None:
    kubernetes = BUILT_IN_COMMAND_EXTENSION_REGISTRY.get("command.kubernetes-operations")
    infrastructure = BUILT_IN_COMMAND_EXTENSION_REGISTRY.get("command.infrastructure-as-code")
    container = BUILT_IN_COMMAND_EXTENSION_REGISTRY.get("command.container-runtime")

    assert kubernetes is not None
    assert set(kubernetes.action_classes) >= {
        "Kubernetes destructive command",
        "Kubernetes remote execution command",
        "Kubernetes network tunnel command",
        "Kubernetes remote file transfer command",
    }
    assert infrastructure is not None
    assert any("cdk" in url.lower() for url in infrastructure.reference_urls)
    assert container is not None
    assert any(rule.rule_id == "command.container-runtime.alternate-runtime-cleanup" for rule in container.rules)
