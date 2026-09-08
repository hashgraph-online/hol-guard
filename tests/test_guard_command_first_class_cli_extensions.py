"""Regression coverage for release 3.2 first-class CLI expansion."""

from __future__ import annotations

from pathlib import Path

from codex_plugin_scanner.guard.runtime.command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY
from tests.command_extension_contracts import assert_reviewed_command_cases, assert_safe_command_cases

REVIEW_CASES: tuple[tuple[str, str, str], ...] = (
    ("wrangler deploy", "Cloudflare production command", "command.platform.cloudflare.high-impact"),
    ("npx wrangler pages project delete docs", "Cloudflare production command", "command.platform.cloudflare.high-impact"),
    ("bunx wrangler secret put API_KEY", "Cloudflare production command", "command.platform.cloudflare.high-impact"),
    ("glab repo delete group/project", "GitLab administrative command", "command.gitlab.high-impact"),
    ("glab ci variable get TOKEN", "GitLab administrative command", "command.gitlab.high-impact"),
    ("vault kv get secret/prod", "Vault secret administration command", "command.secrets.vault.high-impact"),
    ("vault kv destroy -versions=1 secret/prod", "Vault secret administration command", "command.secrets.vault.high-impact"),
    ("prisma migrate reset", "Prisma database command", "command.database.prisma.high-impact"),
    ("pnpm dlx prisma db push --accept-data-loss", "Prisma database command", "command.database.prisma.high-impact"),
    ("firebase deploy --project production", "Firebase production command", "command.platform.firebase.high-impact"),
    ("npx firebase functions:secrets:set API_KEY", "Firebase production command", "command.platform.firebase.high-impact"),
    ("argocd app sync web --prune", "Argo CD production command", "command.gitops.argocd.high-impact"),
    ("argocd app delete web", "Argo CD production command", "command.gitops.argocd.high-impact"),
    ("flux reconcile kustomization production", "Flux production command", "command.gitops.flux.high-impact"),
    ("flux uninstall", "Flux production command", "command.gitops.flux.high-impact"),
    ("bq rm -r -f prod_dataset", "BigQuery destructive command", "command.database.bigquery.high-impact"),
    ("fly apps destroy web", "Fly.io production command", "command.platform.fly.high-impact"),
    ("flyctl secrets set API_KEY=value", "Fly.io production command", "command.platform.fly.high-impact"),
    ("railway delete --yes", "Railway production command", "command.platform.railway.high-impact"),
    ("railway variables set API_KEY=value", "Railway production command", "command.platform.railway.high-impact"),
    ("ansible all -m shell -a 'systemctl restart api'", "Ansible remote execution command", "command.configuration-management.ansible.high-impact"),
    ("ansible-playbook deploy.yml", "Ansible remote execution command", "command.configuration-management.ansible.high-impact"),
    ("ansible-vault view group_vars/prod.yml", "Ansible remote execution command", "command.configuration-management.ansible.high-impact"),
    ("doctl kubernetes cluster delete prod", "DigitalOcean destructive command", "command.cloud.digitalocean.high-impact"),
    ("doctl compute droplet delete 1234", "DigitalOcean destructive command", "command.cloud.digitalocean.high-impact"),
    ("op read op://Production/API/token", "1Password secret command", "command.secrets.1password.high-impact"),
    ("op run -- env", "1Password secret command", "command.secrets.1password.high-impact"),
    ("wrangler.cmd deploy", "Cloudflare production command", "command.platform.cloudflare.high-impact"),
    ("argocd.exe app delete web", "Argo CD production command", "command.gitops.argocd.high-impact"),
    ("flyctl.cmd apps destroy web", "Fly.io production command", "command.platform.fly.high-impact"),
    ("podman system prune", "docker-sensitive command", "command.container-runtime.system-prune"),
    ("nerdctl rm -f web", "docker-sensitive command", "command.container-runtime.forced-container-removal"),
    ("podman run --privileged alpine", "docker-sensitive command", "command.container-runtime.privileged-run"),
    ("oc delete deployment web -n prod", "Kubernetes destructive command", "command.kubernetes-operations.delete-resources"),
    ("oc adm drain node-1", "Kubernetes destructive command", "command.kubernetes-operations.drain-node"),
    ("oc rollout restart deployment/web", "Kubernetes destructive command", "command.kubernetes-operations.openshift-mutation"),
    ("cdk destroy --all", "infrastructure destructive command", "command.infrastructure-as-code.destroy"),
    ("sam delete --stack-name web", "infrastructure destructive command", "command.infrastructure-as-code.destroy"),
    ("serverless remove --stage prod", "infrastructure destructive command", "command.infrastructure-as-code.destroy"),
    ("cdk deploy WebStack", "infrastructure destructive command", "command.infrastructure-as-code.production-change"),
    ("psql -d app -c 'DROP TABLE users'", "PostgreSQL destructive command", "command.database.postgresql.direct-client-mutation"),
    ("mysql app -e 'TRUNCATE users'", "MySQL destructive command", "command.database.mysql.direct-client-mutation"),
    ("mongosh app --eval 'db.users.deleteMany({})'", "MongoDB destructive command", "command.database.mongodb.direct-client-mutation"),
    ("sqlite3 app.db 'DROP TABLE users'", "SQLite destructive command", "command.database.sqlite.direct-client-mutation"),
)


def test_first_class_cli_rules_feed_inspection_and_runtime_hooks(tmp_path: Path) -> None:
    assert_reviewed_command_cases(REVIEW_CASES, tmp_path)


SAFE_CASES: tuple[str, ...] = (
    "wrangler deploy --help",
    "npx wrangler pages project delete --help",
    "glab repo delete --help",
    "vault kv get --help",
    "prisma migrate reset --help",
    "firebase deploy --help",
    "argocd app delete --help",
    "flux uninstall --help",
    "bq rm --help",
    "fly apps destroy --help",
    "railway delete --help",
    "ansible-vault view --help",
    "doctl compute droplet delete --help",
    "op read --help",
    "podman system prune --help",
    "nerdctl rm --help",
    "oc delete deployment web --dry-run=client",
    "helm uninstall web --dry-run",
    "cdk destroy --help",
    "pulumi destroy --preview-only",
    "psql -d app -c 'SELECT * FROM users'",
    "mysql app -e 'SELECT 1'",
    "mongosh app --eval 'db.users.findOne({})'",
    "sqlite3 app.db 'SELECT * FROM users'",
)


def test_first_class_cli_help_and_preview_variants_remain_safe(tmp_path: Path) -> None:
    assert_safe_command_cases(SAFE_CASES, tmp_path)


def test_first_class_cli_extensions_publish_references() -> None:
    extension_ids = (
        "command.platform.cloudflare",
        "command.gitlab",
        "command.secrets.vault",
        "command.database.prisma",
        "command.platform.firebase",
        "command.gitops.argocd",
        "command.gitops.flux",
        "command.database.bigquery",
        "command.platform.fly",
        "command.platform.railway",
        "command.configuration-management.ansible",
        "command.cloud.digitalocean",
        "command.secrets.1password",
    )
    for extension_id in extension_ids:
        extension = BUILT_IN_COMMAND_EXTENSION_REGISTRY.get(extension_id)
        assert extension is not None
        assert extension.reference_urls
        assert all(url.startswith("https://") for url in extension.reference_urls)


def test_dotnet_package_extension_is_delegated_to_package_firewall() -> None:
    extension = BUILT_IN_COMMAND_EXTENSION_REGISTRY.get("command.package.dotnet")
    assert extension is not None
    assert extension.delegated_protection == "package-firewall"
    assert set(extension.executables) == {"dotnet", "nuget"}
