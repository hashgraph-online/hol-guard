"""First-class command protection for high-impact modern developer CLIs."""

from __future__ import annotations

from .command_extension_matchers import executable_matcher, executable_path_set_matcher, safe_flag_variant
from .command_extension_specs import CommandExtensionSpec
from .command_rules import AnyMatcher, CommandRuleSeverity, CommandSafetyRule

_COMMON_OPTIONS = frozenset(
    {
        "--account",
        "--app",
        "--config",
        "--context",
        "--cwd",
        "--env",
        "--environment",
        "--host",
        "--hostname",
        "--namespace",
        "--org",
        "--organization",
        "--output",
        "--profile",
        "--project",
        "--region",
        "--repo",
        "--site",
        "--subscription",
        "--team",
        "--token",
        "--vault",
        "-a",
        "-e",
        "-n",
        "-o",
        "-p",
        "-R",
    }
)
_COMMON_FLAGS = frozenset({"--debug", "--help", "--json", "--quiet", "--verbose", "-q"})
_NODE_RUNNER_OPTIONS = frozenset({"--package", "--cache", "--dir", "--filter", "--workspace", "-C", "-F"})
_NODE_RUNNER_FLAGS = frozenset({"--yes", "-y", "--silent"})


def _paths(executable: str, paths: tuple[tuple[str, ...], ...], *, node_wrapped: bool = False) -> AnyMatcher:
    matchers = [
        executable_path_set_matcher(
            executable,
            paths,
            global_options_with_values=_COMMON_OPTIONS,
            global_flags=_COMMON_FLAGS,
            fail_secure_unknown_options=True,
        )
    ]
    if node_wrapped:
        runner_options = _COMMON_OPTIONS | _NODE_RUNNER_OPTIONS
        runner_flags = _COMMON_FLAGS | _NODE_RUNNER_FLAGS
        for runner, prefix in (
            ("npx", (executable,)),
            ("bunx", (executable,)),
            ("pnpm", (executable,)),
            ("yarn", (executable,)),
            ("npm", ("exec", executable)),
            ("pnpm", ("dlx", executable)),
            ("yarn", ("dlx", executable)),
        ):
            matchers.append(
                executable_path_set_matcher(
                    runner,
                    tuple((*prefix, *path) for path in paths),
                    global_options_with_values=runner_options,
                    global_flags=runner_flags,
                    fail_secure_unknown_options=True,
                )
            )
    return AnyMatcher(matchers=tuple(matchers))


def _ansible_root(executable: str, *, read_only_flags: frozenset[str]) -> AnyMatcher:
    return AnyMatcher(
        matchers=(
            executable_matcher(
                executable,
                forbidden_flags=read_only_flags | {"--help"},
                global_options_with_values=_COMMON_OPTIONS,
                global_flags=_COMMON_FLAGS | read_only_flags,
                fail_secure_unknown_options=False,
            ),
        )
    )


def _rule(
    *,
    extension_id: str,
    title: str,
    matcher: AnyMatcher,
    action_class: str,
    risk_classes: tuple[str, ...],
    safer_alternative: str,
    severity: CommandRuleSeverity = "critical",
) -> CommandSafetyRule:
    return CommandSafetyRule(
        rule_id=f"{extension_id}.high-impact",
        title=title,
        description=f"Identifies high-impact {title.lower()} operations through the supported CLI grammar.",
        severity=severity,
        risk_classes=risk_classes,
        action_classes=(action_class,),
        safer_alternatives=(safer_alternative,),
        matcher=matcher,
        safe_variants=(safe_flag_variant(matcher, variant_id="help", title="Command help", flag="--help"),),
    )


_CLOUDFLARE = _paths(
    "wrangler",
    (
        ("deploy",),
        ("delete",),
        ("pages", "deploy"),
        ("pages", "project", "delete"),
        ("d1", "delete"),
        ("d1", "execute"),
        ("kv", "namespace", "delete"),
        ("kv", "key", "delete"),
        ("r2", "bucket", "delete"),
        ("r2", "object", "delete"),
        ("queues", "delete"),
        ("secret", "put"),
        ("secret", "delete"),
        ("secret", "bulk"),
    ),
    node_wrapped=True,
)
_GITLAB = _paths(
    "glab",
    (
        ("repo", "delete"),
        ("mr", "merge"),
        ("mr", "rebase"),
        ("release", "delete"),
        ("variable", "get"),
        ("variable", "set"),
        ("variable", "delete"),
        ("ci", "variable", "get"),
        ("ci", "variable", "set"),
        ("ci", "variable", "delete"),
    ),
)
_VAULT = _paths(
    "vault",
    (
        ("kv", "get"),
        ("kv", "put"),
        ("kv", "delete"),
        ("kv", "destroy"),
        ("kv", "undelete"),
        ("token", "revoke"),
        ("policy", "write"),
        ("policy", "delete"),
        ("secrets", "disable"),
        ("auth", "disable"),
    ),
)
_PRISMA = _paths(
    "prisma",
    (("migrate", "deploy"), ("migrate", "reset"), ("migrate", "resolve"), ("db", "push"), ("db", "execute")),
    node_wrapped=True,
)
_FIREBASE = _paths(
    "firebase",
    (
        ("deploy",),
        ("hosting:disable",),
        ("hosting:sites:delete",),
        ("functions:delete",),
        ("database:remove",),
        ("firestore:delete",),
        ("apphosting:backends:delete",),
        ("functions:secrets:set",),
        ("functions:secrets:destroy",),
    ),
    node_wrapped=True,
)
_ARGOCD = _paths(
    "argocd",
    (
        ("app", "sync"),
        ("app", "delete"),
        ("app", "rollback"),
        ("app", "patch"),
        ("app", "set"),
        ("app", "terminate-op"),
        ("app", "actions", "run"),
        ("appset", "delete"),
        ("proj", "delete"),
    ),
)
_FLUX = _paths("flux", (("reconcile",), ("delete",), ("suspend",), ("resume",), ("uninstall",)))
_BIGQUERY = _paths("bq", (("rm",), ("remove",)))
_FLY_PATHS = (
    ("apps", "destroy"),
    ("machines", "destroy"),
    ("machine", "destroy"),
    ("volumes", "destroy"),
    ("volume", "destroy"),
    ("deploy",),
    ("releases", "rollback"),
    ("secrets", "set"),
    ("secrets", "unset"),
)
_FLY = AnyMatcher(matchers=(*_paths("fly", _FLY_PATHS).matchers, *_paths("flyctl", _FLY_PATHS).matchers))
_RAILWAY = _paths(
    "railway",
    (
        ("delete",),
        ("down",),
        ("redeploy",),
        ("restart",),
        ("up",),
        ("variables", "set"),
        ("variables", "delete"),
        ("variable", "set"),
        ("variable", "delete"),
        ("volume", "delete"),
        ("shell",),
    ),
)
_ANSIBLE = AnyMatcher(
    matchers=(
        *_ansible_root("ansible", read_only_flags=frozenset({"--version", "--list-hosts"})).matchers,
        *_ansible_root(
            "ansible-playbook",
            read_only_flags=frozenset({"--version", "--syntax-check", "--list-hosts", "--list-tasks", "--list-tags"}),
        ).matchers,
        *_ansible_root("ansible-pull", read_only_flags=frozenset({"--version"})).matchers,
        *_paths("ansible-vault", (("view",), ("decrypt",), ("edit",), ("rekey",))).matchers,
    )
)
_DOCTL = _paths(
    "doctl",
    (
        ("compute", "droplet", "delete"),
        ("compute", "volume", "delete"),
        ("compute", "snapshot", "delete"),
        ("compute", "load-balancer", "delete"),
        ("compute", "firewall", "delete"),
        ("kubernetes", "cluster", "delete"),
        ("databases", "delete"),
        ("apps", "delete"),
        ("registry", "delete"),
    ),
)
_ONEPASSWORD = _paths(
    "op",
    (
        ("read",),
        ("run",),
        ("inject",),
        ("item", "get"),
        ("item", "delete"),
        ("document", "get"),
        ("document", "delete"),
        ("vault", "delete"),
    ),
)

FIRST_CLASS_CLI_COMMAND_RULES = (
    _rule(
        extension_id="command.platform.cloudflare",
        title="Cloudflare production control-plane mutation",
        matcher=_CLOUDFLARE,
        action_class="Cloudflare production command",
        risk_classes=("destructive_shell", "network_egress", "local_secret_read", "execution"),
        safer_alternative="Inspect the target Worker, Pages project, storage resource, and active account before mutation.",
    ),
    _rule(
        extension_id="command.gitlab",
        title="GitLab remote administration",
        matcher=_GITLAB,
        action_class="GitLab administrative command",
        risk_classes=("destructive_shell", "network_egress", "local_secret_read"),
        safer_alternative="Inspect the exact project, merge request, release, or CI variable before changing it.",
    ),
    _rule(
        extension_id="command.secrets.vault",
        title="Vault secret and policy administration",
        matcher=_VAULT,
        action_class="Vault secret administration command",
        risk_classes=("local_secret_read", "destructive_shell", "network_egress"),
        safer_alternative="Read metadata first and scope secret or policy operations to the narrowest path.",
    ),
    _rule(
        extension_id="command.database.prisma",
        title="Prisma database mutation",
        matcher=_PRISMA,
        action_class="Prisma database command",
        risk_classes=("destructive_shell", "network_egress"),
        safer_alternative="Inspect migration status and back up the selected database before destructive schema operations.",
    ),
    _rule(
        extension_id="command.platform.firebase",
        title="Firebase production mutation",
        matcher=_FIREBASE,
        action_class="Firebase production command",
        risk_classes=("destructive_shell", "network_egress", "local_secret_read", "execution"),
        safer_alternative="Inspect the active project, deployment targets, rules, and secrets before applying remote changes.",
    ),
    _rule(
        extension_id="command.gitops.argocd",
        title="Argo CD reconciliation and deletion",
        matcher=_ARGOCD,
        action_class="Argo CD production command",
        risk_classes=("destructive_shell", "network_egress", "execution"),
        safer_alternative="Inspect application diff and target revision before sync, rollback, patch, or deletion.",
    ),
    _rule(
        extension_id="command.gitops.flux",
        title="Flux reconciliation and deletion",
        matcher=_FLUX,
        action_class="Flux production command",
        risk_classes=("destructive_shell", "network_egress", "execution"),
        safer_alternative="Inspect source and reconciliation status before forcing, suspending, resuming, or deleting resources.",
    ),
    _rule(
        extension_id="command.database.bigquery",
        title="BigQuery destructive data operation",
        matcher=_BIGQUERY,
        action_class="BigQuery destructive command",
        risk_classes=("destructive_shell", "network_egress"),
        safer_alternative="Inspect the exact dataset or table before deletion.",
    ),
    _rule(
        extension_id="command.platform.fly",
        title="Fly.io production mutation",
        matcher=_FLY,
        action_class="Fly.io production command",
        risk_classes=("destructive_shell", "network_egress", "local_secret_read", "execution"),
        safer_alternative="Inspect the active app, machines, volumes, release, and secret names before mutation.",
    ),
    _rule(
        extension_id="command.platform.railway",
        title="Railway production mutation",
        matcher=_RAILWAY,
        action_class="Railway production command",
        risk_classes=("destructive_shell", "network_egress", "local_secret_read", "execution"),
        safer_alternative="Inspect the linked project, environment, service, volume, and variables before mutation.",
    ),
    _rule(
        extension_id="command.configuration-management.ansible",
        title="Ansible remote execution and vault access",
        matcher=_ANSIBLE,
        action_class="Ansible remote execution command",
        risk_classes=("execution", "network_egress", "local_secret_read", "destructive_shell"),
        safer_alternative="Limit inventory scope, inspect the playbook, and verify secret inputs before remote execution.",
        severity="high",
    ),
    _rule(
        extension_id="command.cloud.digitalocean",
        title="DigitalOcean resource deletion",
        matcher=_DOCTL,
        action_class="DigitalOcean destructive command",
        risk_classes=("destructive_shell", "network_egress"),
        safer_alternative="Inspect resource identity and attached state before deleting DigitalOcean resources.",
    ),
    _rule(
        extension_id="command.secrets.1password",
        title="1Password secret access and mutation",
        matcher=_ONEPASSWORD,
        action_class="1Password secret command",
        risk_classes=("local_secret_read", "network_egress", "execution", "destructive_shell"),
        safer_alternative="Request only the required field and avoid injecting broad vault contents into child processes.",
        severity="high",
    ),
)


def _spec(
    extension_id: str,
    name: str,
    description: str,
    action_class: str,
    risk_classes: tuple[str, ...],
    safer_alternative: str,
    reference_url: str,
) -> CommandExtensionSpec:
    return CommandExtensionSpec(
        extension_id=extension_id,
        name=name,
        description=description,
        action_classes=(action_class,),
        risk_classes=risk_classes,
        safer_alternatives=(safer_alternative,),
        reference_urls=(reference_url,),
    )


FIRST_CLASS_CLI_COMMAND_EXTENSION_SPECS = (
    _spec("command.platform.cloudflare", "Cloudflare command protection", "Reviews high-impact Wrangler production operations.", "Cloudflare production command", ("destructive_shell", "network_egress", "local_secret_read", "execution"), "Inspect the selected account and resource before mutation.", "https://developers.cloudflare.com/workers/wrangler/commands/"),
    _spec("command.gitlab", "GitLab command protection", "Reviews high-impact GitLab repository, merge, release, and CI variable operations.", "GitLab administrative command", ("destructive_shell", "network_egress", "local_secret_read"), "Inspect the selected GitLab resource before remote mutation.", "https://docs.gitlab.com/cli/"),
    _spec("command.secrets.vault", "HashiCorp Vault command protection", "Reviews remote Vault secret access and destructive policy/auth administration.", "Vault secret administration command", ("local_secret_read", "destructive_shell", "network_egress"), "Scope Vault operations to the narrowest secret or policy path.", "https://developer.hashicorp.com/vault/docs/commands"),
    _spec("command.database.prisma", "Prisma command protection", "Reviews Prisma schema and migration operations that can alter or discard database state.", "Prisma database command", ("destructive_shell", "network_egress"), "Inspect migration state and back up the selected database first.", "https://www.prisma.io/docs/orm/reference/prisma-cli-reference"),
    _spec("command.platform.firebase", "Firebase command protection", "Reviews Firebase deploy, deletion, data, and secret operations.", "Firebase production command", ("destructive_shell", "network_egress", "local_secret_read", "execution"), "Inspect the active Firebase project and exact deployment target first.", "https://firebase.google.com/docs/cli"),
    _spec("command.gitops.argocd", "Argo CD command protection", "Reviews application synchronization, rollback, patch, and deletion operations.", "Argo CD production command", ("destructive_shell", "network_egress", "execution"), "Inspect application diff and target revision before reconciliation.", "https://argo-cd.readthedocs.io/en/stable/user-guide/commands/argocd_app/"),
    _spec("command.gitops.flux", "Flux command protection", "Reviews GitOps reconciliation, suspension, deletion, and uninstall operations.", "Flux production command", ("destructive_shell", "network_egress", "execution"), "Inspect source and reconciliation status before mutation.", "https://fluxcd.io/flux/cmd/"),
    _spec("command.database.bigquery", "BigQuery command protection", "Reviews bq resource deletion that can remove remote datasets and data objects.", "BigQuery destructive command", ("destructive_shell", "network_egress"), "Inspect the exact dataset or table before destructive operations.", "https://cloud.google.com/bigquery/docs/reference/bq-cli-reference"),
    _spec("command.platform.fly", "Fly.io command protection", "Reviews app, machine, volume, deployment, release, and secret mutations.", "Fly.io production command", ("destructive_shell", "network_egress", "local_secret_read", "execution"), "Inspect the active Fly app and attached state first.", "https://fly.io/docs/flyctl/"),
    _spec("command.platform.railway", "Railway command protection", "Reviews project, service, volume, deployment, shell, and variable mutations.", "Railway production command", ("destructive_shell", "network_egress", "local_secret_read", "execution"), "Inspect the linked Railway project and environment first.", "https://docs.railway.com/guides/cli"),
    _spec("command.configuration-management.ansible", "Ansible command protection", "Reviews remote Ansible execution and ansible-vault secret access/mutation.", "Ansible remote execution command", ("execution", "network_egress", "local_secret_read", "destructive_shell"), "Limit inventory scope and inspect playbooks and vault inputs first.", "https://docs.ansible.com/ansible/latest/command_guide/"),
    _spec("command.cloud.digitalocean", "DigitalOcean command protection", "Reviews destructive doctl operations across major DigitalOcean resource families.", "DigitalOcean destructive command", ("destructive_shell", "network_egress"), "Inspect resource identity and dependencies before deletion.", "https://docs.digitalocean.com/reference/doctl/"),
    _spec("command.secrets.1password", "1Password command protection", "Reviews secret reads, injection/execution, and destructive vault/item operations.", "1Password secret command", ("local_secret_read", "network_egress", "execution", "destructive_shell"), "Request only the required field and avoid broad secret injection.", "https://developer.1password.com/docs/cli/"),
)
