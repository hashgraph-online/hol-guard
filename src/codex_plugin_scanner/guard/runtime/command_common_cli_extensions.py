"""First-class coverage for common production, secrets, GitOps, and package CLIs."""

from __future__ import annotations

from .command_database_matchers import ArgumentCommandMatcher
from .command_extension_matchers import (
    executable_matcher,
    executable_names,
    executable_path_set_matcher,
    safe_flag_variant,
)
from .command_extension_specs import CommandExtensionSpec
from .command_rules import AnyMatcher, CommandRuleSeverity, CommandSafetyRule, CommandSafeVariant

_EMPTY: frozenset[str] = frozenset()
_RUNNER_OPTIONS = frozenset(
    {
        "--cache",
        "--call",
        "--dir",
        "--filter",
        "--package",
        "--reporter",
        "--workspace",
        "-C",
        "-F",
        "-c",
        "-p",
        "-w",
    }
)
_RUNNER_FLAGS = frozenset(
    {"--aggregate-output", "--silent", "--stream", "--use-stderr", "--workspace-root", "--yes", "-y"}
)
_AWS_OPTIONS = frozenset(
    {
        "--ca-bundle",
        "--cli-binary-format",
        "--cli-connect-timeout",
        "--cli-read-timeout",
        "--color",
        "--endpoint-url",
        "--output",
        "--profile",
        "--query",
        "--region",
    }
)
_AWS_FLAGS = frozenset(
    {
        "--cli-auto-prompt",
        "--debug",
        "--no-cli-auto-prompt",
        "--no-cli-pager",
        "--no-color",
        "--no-paginate",
        "--no-sign-request",
        "--no-verify-ssl",
    }
)
_GCLOUD_OPTIONS = frozenset(
    {
        "--access-token-file",
        "--account",
        "--billing-project",
        "--configuration",
        "--filter",
        "--flags-file",
        "--flatten",
        "--format",
        "--impersonate-service-account",
        "--limit",
        "--page-size",
        "--project",
        "--sort-by",
        "--trace-token",
        "--verbosity",
    }
)
_GCLOUD_FLAGS = frozenset(
    {"--log-http", "--no-log-http", "--quiet", "-q", "--user-output-enabled", "--no-user-output-enabled"}
)
_AZURE_OPTIONS = frozenset({"--output", "-o", "--query", "--subscription"})
_AZURE_FLAGS = frozenset({"--debug", "--help", "--only-show-errors", "--verbose", "-h"})


def _path_bundle(
    executables: tuple[str, ...],
    paths: tuple[tuple[str, ...], ...],
    *,
    options: frozenset[str] = _EMPTY,
    flags: frozenset[str] = _EMPTY,
) -> AnyMatcher:
    return AnyMatcher(
        matchers=tuple(
            executable_path_set_matcher(
                executable,
                paths,
                global_options_with_values=options,
                global_flags=flags,
                fail_secure_unknown_options=True,
            )
            for executable in executables
        )
    )


def _flag_bundle(
    executables: tuple[str, ...],
    paths: tuple[tuple[str, ...], ...],
    *,
    required_flags: frozenset[str],
    options: frozenset[str] = _EMPTY,
    flags: frozenset[str] = _EMPTY,
) -> AnyMatcher:
    return AnyMatcher(
        matchers=tuple(
            executable_matcher(
                executable,
                *path,
                required_flags=required_flags,
                global_options_with_values=options,
                global_flags=flags,
                fail_secure_unknown_options=True,
            )
            for executable in executables
            for path in paths
        )
    )


def _prefixed(prefix: tuple[str, ...], paths: tuple[tuple[str, ...], ...]) -> tuple[tuple[str, ...], ...]:
    return tuple((*prefix, *path) for path in paths)


def _node_bundle(
    executable: str,
    package_names: tuple[str, ...],
    paths: tuple[tuple[str, ...], ...],
    *,
    options: frozenset[str] = _EMPTY,
    flags: frozenset[str] = _EMPTY,
) -> AnyMatcher:
    combined_options = options | _RUNNER_OPTIONS
    combined_flags = flags | _RUNNER_FLAGS
    matchers = [
        executable_path_set_matcher(
            executable,
            paths,
            global_options_with_values=options,
            global_flags=flags,
            fail_secure_unknown_options=True,
        )
    ]
    for package in package_names:
        matchers.extend(
            (
                executable_path_set_matcher(
                    "npx",
                    _prefixed((package,), paths),
                    global_options_with_values=combined_options,
                    global_flags=combined_flags,
                    fail_secure_unknown_options=True,
                ),
                executable_path_set_matcher(
                    "bunx",
                    _prefixed((package,), paths),
                    global_options_with_values=combined_options,
                    global_flags=combined_flags,
                    fail_secure_unknown_options=True,
                ),
                executable_path_set_matcher(
                    "npm",
                    _prefixed(("exec", package), paths),
                    global_options_with_values=combined_options,
                    global_flags=combined_flags,
                    fail_secure_unknown_options=True,
                ),
                executable_path_set_matcher(
                    "pnpm",
                    (*_prefixed(("exec", package), paths), *_prefixed(("dlx", package), paths)),
                    global_options_with_values=combined_options,
                    global_flags=combined_flags,
                    fail_secure_unknown_options=True,
                ),
                executable_path_set_matcher(
                    "yarn",
                    _prefixed(("dlx", package), paths),
                    global_options_with_values=combined_options,
                    global_flags=combined_flags,
                    fail_secure_unknown_options=True,
                ),
            )
        )
    return AnyMatcher(matchers=tuple(matchers))


def _node_flag_bundle(
    executable: str,
    package_names: tuple[str, ...],
    paths: tuple[tuple[str, ...], ...],
    *,
    required_flags: frozenset[str],
    options: frozenset[str] = _EMPTY,
    flags: frozenset[str] = _EMPTY,
) -> AnyMatcher:
    combined_options = options | _RUNNER_OPTIONS
    combined_flags = flags | _RUNNER_FLAGS
    matchers = [
        executable_matcher(
            executable,
            *path,
            required_flags=required_flags,
            global_options_with_values=options,
            global_flags=flags,
            fail_secure_unknown_options=True,
        )
        for path in paths
    ]
    for package in package_names:
        for path in paths:
            for launcher, prefix in (
                ("npx", (package,)),
                ("bunx", (package,)),
                ("npm", ("exec", package)),
                ("pnpm", ("exec", package)),
                ("pnpm", ("dlx", package)),
                ("yarn", ("dlx", package)),
            ):
                matchers.append(
                    executable_matcher(
                        launcher,
                        *prefix,
                        *path,
                        required_flags=required_flags,
                        global_options_with_values=combined_options,
                        global_flags=combined_flags,
                        fail_secure_unknown_options=True,
                    )
                )
    return AnyMatcher(matchers=tuple(matchers))


def _help_variants(matcher: AnyMatcher, *, short: bool = False) -> tuple[CommandSafeVariant, ...]:
    variants = [safe_flag_variant(matcher, variant_id="help", title="Command help", flag="--help")]
    if short:
        variants.append(safe_flag_variant(matcher, variant_id="short-help", title="Command help", flag="-h"))
    return tuple(variants)


def _rule(
    *,
    extension_id: str,
    suffix: str,
    title: str,
    description: str,
    matcher: AnyMatcher | ArgumentCommandMatcher,
    action_class: str,
    risk_classes: tuple[str, ...],
    safer_alternative: str,
    severity: CommandRuleSeverity = "high",
    safe_variants: tuple[CommandSafeVariant, ...] = (),
    example_command: str | None = None,
) -> CommandSafetyRule:
    return CommandSafetyRule(
        rule_id=f"{extension_id}.{suffix}",
        title=title,
        description=description,
        severity=severity,
        risk_classes=risk_classes,
        action_classes=(action_class,),
        safer_alternatives=(safer_alternative,),
        matcher=matcher,
        safe_variants=safe_variants,
        example_command=example_command,
    )


def _spec(
    extension_id: str,
    name: str,
    description: str,
    action_classes: tuple[str, ...],
    risk_classes: tuple[str, ...],
    safer_alternative: str,
    references: tuple[str, ...],
) -> CommandExtensionSpec:
    return CommandExtensionSpec(
        extension_id=extension_id,
        name=name,
        description=description,
        action_classes=action_classes,
        risk_classes=risk_classes,
        safer_alternatives=(safer_alternative,),
        reference_urls=references,
    )


# Cloudflare Wrangler
_WRANGLER_OPTIONS = frozenset({"--config", "-c", "--cwd", "--env", "-e"})
_WRANGLER_FLAGS = frozenset({"--help", "-h"})
_WRANGLER_DESTRUCTIVE = _node_bundle(
    "wrangler",
    ("wrangler",),
    (
        ("delete",),
        ("pages", "project", "delete"),
        ("pages", "deployment", "delete"),
        ("d1", "delete"),
        ("kv", "namespace", "delete"),
        ("r2", "bucket", "delete"),
        ("queues", "delete"),
        ("hyperdrive", "delete"),
    ),
    options=_WRANGLER_OPTIONS,
    flags=_WRANGLER_FLAGS,
)
_WRANGLER_CHANGE = _node_bundle(
    "wrangler",
    ("wrangler",),
    (("deploy",), ("pages", "deploy"), ("secret", "put"), ("secret", "delete"), ("secret", "bulk")),
    options=_WRANGLER_OPTIONS,
    flags=_WRANGLER_FLAGS,
)

# GitLab CLI
_GLAB_OPTIONS = frozenset({"--repo", "-R", "--hostname"})
_GLAB_FLAGS = frozenset({"--help", "-h"})
_GLAB_DESTRUCTIVE = _path_bundle(
    ("glab",),
    (("repo", "delete"), ("release", "delete"), ("variable", "delete")),
    options=_GLAB_OPTIONS,
    flags=_GLAB_FLAGS,
)
_GLAB_MERGE = _path_bundle(
    ("glab",), (("mr", "merge"), ("mr", "rebase")), options=_GLAB_OPTIONS, flags=_GLAB_FLAGS
)
_GLAB_VARIABLE = _path_bundle(
    ("glab",), (("variable", "get"), ("variable", "set")), options=_GLAB_OPTIONS, flags=_GLAB_FLAGS
)

# HashiCorp Vault
_VAULT_OPTIONS = frozenset({"-address", "-namespace", "-output-format"})
_VAULT_FLAGS = frozenset({"-h", "--help"})
_VAULT_READ = _path_bundle(
    ("vault",), (("kv", "get"), ("read",)), options=_VAULT_OPTIONS, flags=_VAULT_FLAGS
)
_VAULT_MUTATION = _path_bundle(
    ("vault",),
    (("kv", "put"), ("kv", "patch"), ("kv", "delete"), ("kv", "destroy"), ("kv", "rollback"), ("delete",)),
    options=_VAULT_OPTIONS,
    flags=_VAULT_FLAGS,
)
_VAULT_ADMIN = _path_bundle(
    ("vault",),
    (("token", "revoke"), ("policy", "delete"), ("auth", "disable"), ("secrets", "disable")),
    options=_VAULT_OPTIONS,
    flags=_VAULT_FLAGS,
)

# Prisma
_PRISMA_OPTIONS = frozenset({"--schema"})
_PRISMA_FLAGS = frozenset({"--help", "-h"})
_PRISMA_RESET = _node_bundle(
    "prisma", ("prisma",), (("migrate", "reset"), ("db", "execute")), options=_PRISMA_OPTIONS, flags=_PRISMA_FLAGS
)
_PRISMA_PUSH = _node_flag_bundle(
    "prisma",
    ("prisma",),
    (("db", "push"),),
    required_flags=frozenset({"--accept-data-loss"}),
    options=_PRISMA_OPTIONS,
    flags=_PRISMA_FLAGS,
)
_PRISMA_DESTRUCTIVE = AnyMatcher(matchers=(*_PRISMA_RESET.matchers, *_PRISMA_PUSH.matchers))
_PRISMA_DEPLOY = _node_bundle(
    "prisma", ("prisma",), (("migrate", "deploy"),), options=_PRISMA_OPTIONS, flags=_PRISMA_FLAGS
)

# Firebase
_FIREBASE_OPTIONS = frozenset({"--project", "-P", "--config", "--token", "--account"})
_FIREBASE_FLAGS = frozenset({"--help", "-h", "--non-interactive"})
_FIREBASE_DEPLOY = _node_bundle(
    "firebase", ("firebase-tools", "firebase"), (("deploy",),), options=_FIREBASE_OPTIONS, flags=_FIREBASE_FLAGS
)
_FIREBASE_DESTRUCTIVE = _node_bundle(
    "firebase",
    ("firebase-tools", "firebase"),
    (
        ("functions:delete",),
        ("firestore:delete",),
        ("database:remove",),
        ("hosting:disable",),
        ("hosting:sites:delete",),
    ),
    options=_FIREBASE_OPTIONS,
    flags=_FIREBASE_FLAGS,
)

# GitOps
_ARGO_OPTIONS = frozenset({"--server", "--grpc-web-root-path", "--config", "--auth-token", "--context"})
_ARGO_FLAGS = frozenset({"--help", "-h", "--grpc-web", "--insecure", "--plaintext"})
_ARGO_DESTRUCTIVE = _path_bundle(
    ("argocd",),
    (("app", "delete"), ("appset", "delete"), ("cluster", "rm"), ("repo", "rm")),
    options=_ARGO_OPTIONS,
    flags=_ARGO_FLAGS,
)
_ARGO_RECONCILE = _path_bundle(
    ("argocd",),
    (("app", "sync"), ("app", "rollback"), ("app", "patch"), ("app", "terminate-op")),
    options=_ARGO_OPTIONS,
    flags=_ARGO_FLAGS,
)
_FLUX_OPTIONS = frozenset({"--kubeconfig", "--context", "--namespace", "-n"})
_FLUX_FLAGS = frozenset({"--help", "-h", "--verbose"})
_FLUX_DESTRUCTIVE = _path_bundle(
    ("flux",),
    (
        ("uninstall",),
        ("delete", "kustomization"),
        ("delete", "helmrelease"),
        ("delete", "source", "git"),
        ("delete", "source", "bucket"),
        ("delete", "source", "oci"),
    ),
    options=_FLUX_OPTIONS,
    flags=_FLUX_FLAGS,
)
_FLUX_RECONCILE = _path_bundle(
    ("flux",),
    (
        ("reconcile", "kustomization"),
        ("reconcile", "helmrelease"),
        ("reconcile", "source", "git"),
        ("suspend", "kustomization"),
        ("suspend", "helmrelease"),
        ("resume", "kustomization"),
        ("resume", "helmrelease"),
    ),
    options=_FLUX_OPTIONS,
    flags=_FLUX_FLAGS,
)

# .NET / NuGet
_DOTNET_OPTIONS = frozenset({"--project", "--source", "-s", "--configfile", "--framework", "-f"})
_DOTNET_FLAGS = frozenset({"--help", "-h"})
_DOTNET_PACKAGE = _path_bundle(
    ("dotnet",), (("add", "package"), ("package", "add"), ("restore",)), options=_DOTNET_OPTIONS, flags=_DOTNET_FLAGS
)
_NUGET_PACKAGE = _path_bundle(("nuget",), (("install",), ("restore",)), flags=_DOTNET_FLAGS)
_DOTNET_MUTATION = AnyMatcher(matchers=(*_DOTNET_PACKAGE.matchers, *_NUGET_PACKAGE.matchers))
_DOTNET_PUBLISH = _path_bundle(
    ("dotnet",), (("nuget", "push"), ("nuget", "delete")), options=_DOTNET_OPTIONS, flags=_DOTNET_FLAGS
)
_NUGET_PUBLISH = _path_bundle(("nuget",), (("push",), ("delete",)), flags=_DOTNET_FLAGS)
_DOTNET_PUBLICATION = AnyMatcher(matchers=(*_DOTNET_PUBLISH.matchers, *_NUGET_PUBLISH.matchers))

# BigQuery
_BQ_OPTIONS = frozenset({"--project_id", "--location", "--format", "--dataset_id"})
_BQ_FLAGS = frozenset({"--help", "-h", "--quiet", "-q"})
_BQ_REMOVE = _path_bundle(("bq",), (("rm",),), options=_BQ_OPTIONS, flags=_BQ_FLAGS)
_BQ_REPLACE = _flag_bundle(
    ("bq",),
    (("load",),),
    required_flags=frozenset({"--replace"}),
    options=_BQ_OPTIONS,
    flags=_BQ_FLAGS,
)
_BQ_DESTRUCTIVE = AnyMatcher(matchers=(*_BQ_REMOVE.matchers, *_BQ_REPLACE.matchers))

# Hosting platforms
_FLY_OPTIONS = frozenset({"--app", "-a", "--config", "-c", "--org"})
_FLY_FLAGS = frozenset({"--help", "-h", "--verbose"})
_FLY_DESTRUCTIVE = _path_bundle(
    ("fly", "flyctl"),
    (("apps", "destroy"), ("machine", "destroy"), ("volumes", "destroy"), ("ips", "release")),
    options=_FLY_OPTIONS,
    flags=_FLY_FLAGS,
)
_FLY_CHANGE = _path_bundle(
    ("fly", "flyctl"),
    (("deploy",), ("secrets", "set"), ("secrets", "unset"), ("secrets", "import")),
    options=_FLY_OPTIONS,
    flags=_FLY_FLAGS,
)
_RAILWAY_OPTIONS = frozenset({"--project", "--service", "--environment", "-e"})
_RAILWAY_FLAGS = frozenset({"--help", "-h", "--yes", "-y"})
_RAILWAY_DESTRUCTIVE = _node_bundle(
    "railway", ("@railway/cli",), (("delete",), ("volume", "delete")), options=_RAILWAY_OPTIONS, flags=_RAILWAY_FLAGS
)
_RAILWAY_CHANGE = _node_bundle(
    "railway",
    ("@railway/cli",),
    (("up",), ("redeploy",), ("variables", "set"), ("variables", "delete"), ("shell",)),
    options=_RAILWAY_OPTIONS,
    flags=_RAILWAY_FLAGS,
)

# Ansible
_ANSIBLE_OPTIONS = frozenset(
    {"-i", "--inventory", "-l", "--limit", "-u", "--user", "--private-key", "--vault-password-file"}
)
_ANSIBLE_FLAGS = frozenset({"--help", "-h", "--version"})
_ANSIBLE_EXECUTION = AnyMatcher(
    matchers=tuple(
        executable_matcher(
            executable,
            global_options_with_values=_ANSIBLE_OPTIONS,
            global_flags=_ANSIBLE_FLAGS,
            fail_secure_unknown_options=True,
        )
        for executable in ("ansible", "ansible-playbook", "ansible-pull")
    )
)
_ANSIBLE_VAULT = _path_bundle(
    ("ansible-vault",),
    (("view",), ("decrypt",), ("edit",), ("rekey",)),
    options=frozenset({"--vault-id", "--vault-password-file"}),
    flags=_ANSIBLE_FLAGS,
)

# DigitalOcean and 1Password
_DOCTL_OPTIONS = frozenset({"--access-token", "--context", "--output", "--format"})
_DOCTL_FLAGS = frozenset({"--help", "-h", "--verbose"})
_DOCTL_DELETE = _path_bundle(
    ("doctl",),
    (
        ("compute", "droplet", "delete"),
        ("compute", "load-balancer", "delete"),
        ("compute", "volume", "delete"),
        ("compute", "firewall", "delete"),
        ("compute", "domain", "delete"),
        ("kubernetes", "cluster", "delete"),
        ("databases", "delete"),
        ("apps", "delete"),
    ),
    options=_DOCTL_OPTIONS,
    flags=_DOCTL_FLAGS,
)
_OP_OPTIONS = frozenset({"--account", "--cache", "--config", "--session"})
_OP_FLAGS = frozenset({"--help", "-h", "--no-color"})
_OP_READ = _path_bundle(
    ("op",), (("read",), ("item", "get"), ("document", "get")), options=_OP_OPTIONS, flags=_OP_FLAGS
)
_OP_INJECT = _path_bundle(("op",), (("run",), ("inject",)), options=_OP_OPTIONS, flags=_OP_FLAGS)
_OP_DELETE = _path_bundle(
    ("op",), (("item", "delete"), ("document", "delete"), ("vault", "delete")), options=_OP_OPTIONS, flags=_OP_FLAGS
)

# Package publication and cloud credentials
_PACKAGE_PUBLISH = AnyMatcher(
    matchers=(
        *_path_bundle(("npm",), (("publish",), ("unpublish",))).matchers,
        *_path_bundle(("pnpm",), (("publish",),)).matchers,
        *_path_bundle(("yarn",), (("npm", "publish"),)).matchers,
        *_path_bundle(("cargo",), (("publish",), ("yank",))).matchers,
        *_path_bundle(("gem",), (("push",), ("yank",))).matchers,
        *_path_bundle(("twine",), (("upload",),)).matchers,
        *_path_bundle(("poetry",), (("publish",),)).matchers,
    )
)
_CLOUD_SECRET_READ = AnyMatcher(
    matchers=(
        executable_matcher(
            "aws",
            "secretsmanager",
            "get-secret-value",
            global_options_with_values=_AWS_OPTIONS,
            global_flags=_AWS_FLAGS,
            fail_secure_unknown_options=True,
        ),
        executable_matcher(
            "aws",
            "ssm",
            "get-parameter",
            required_flags=frozenset({"--with-decryption"}),
            global_options_with_values=_AWS_OPTIONS,
            global_flags=_AWS_FLAGS,
            fail_secure_unknown_options=True,
        ),
        executable_matcher(
            "gcloud",
            "secrets",
            "versions",
            "access",
            global_options_with_values=_GCLOUD_OPTIONS,
            global_flags=_GCLOUD_FLAGS,
            fail_secure_unknown_options=True,
        ),
        executable_matcher(
            "az",
            "keyvault",
            "secret",
            "show",
            global_options_with_values=_AZURE_OPTIONS,
            global_flags=_AZURE_FLAGS,
            fail_secure_unknown_options=True,
        ),
    )
)
_CLOUD_CREDENTIAL_MUTATION = AnyMatcher(
    matchers=(
        executable_matcher(
            "aws",
            "iam",
            "create-access-key",
            global_options_with_values=_AWS_OPTIONS,
            global_flags=_AWS_FLAGS,
            fail_secure_unknown_options=True,
        ),
        executable_matcher(
            "aws",
            "iam",
            "delete-access-key",
            global_options_with_values=_AWS_OPTIONS,
            global_flags=_AWS_FLAGS,
            fail_secure_unknown_options=True,
        ),
        executable_matcher(
            "gcloud",
            "iam",
            "service-accounts",
            "keys",
            "create",
            global_options_with_values=_GCLOUD_OPTIONS,
            global_flags=_GCLOUD_FLAGS,
            fail_secure_unknown_options=True,
        ),
        executable_matcher(
            "gcloud",
            "iam",
            "service-accounts",
            "keys",
            "delete",
            global_options_with_values=_GCLOUD_OPTIONS,
            global_flags=_GCLOUD_FLAGS,
            fail_secure_unknown_options=True,
        ),
        executable_matcher(
            "az",
            "ad",
            "app",
            "credential",
            "reset",
            global_options_with_values=_AZURE_OPTIONS,
            global_flags=_AZURE_FLAGS,
            fail_secure_unknown_options=True,
        ),
    )
)

# Existing-extension expansions
_ALT_CONTAINER_CLEANUP = _path_bundle(
    ("podman", "nerdctl"), (("system", "prune"), ("container", "prune"), ("image", "prune"), ("volume", "prune"))
)
_ALT_CONTAINER_PRIVILEGED = _flag_bundle(
    ("podman", "nerdctl"), (("run",),), required_flags=frozenset({"--privileged"})
)
_OC_OPTIONS = frozenset(
    {"--as", "--as-group", "--cluster", "--context", "--kubeconfig", "--namespace", "-n", "--server", "--user"}
)
_OC_FLAGS = frozenset({"--help", "-h"})
_OC_DESTRUCTIVE = _path_bundle(
    ("oc",), (("delete",), ("adm", "drain")), options=_OC_OPTIONS, flags=_OC_FLAGS
)
_OC_EXECUTION = _path_bundle(("oc",), (("exec",), ("rsh",)), options=_OC_OPTIONS, flags=_OC_FLAGS)
_OC_TUNNEL = _path_bundle(("oc",), (("port-forward",),), options=_OC_OPTIONS, flags=_OC_FLAGS)
_OC_TRANSFER = _path_bundle(("oc",), (("rsync",),), options=_OC_OPTIONS, flags=_OC_FLAGS)
_CDK_DESTROY = _node_bundle("cdk", ("aws-cdk",), (("destroy",),))
_SERVERLESS_REMOVE = _node_bundle("serverless", ("serverless",), (("remove",),))
_IAC_EXPANSION = AnyMatcher(
    matchers=(
        *_CDK_DESTROY.matchers,
        *_SERVERLESS_REMOVE.matchers,
        *_path_bundle(("sls",), (("remove",),)).matchers,
        *_path_bundle(("sam",), (("delete",),)).matchers,
    )
)
_PSQL_DROP = ArgumentCommandMatcher(
    executables=executable_names("psql"), command="drop", minimum_abbreviation_length=4, minimum_position=1
)
_MYSQL_DROP = ArgumentCommandMatcher(
    executables=executable_names("mysql"), command="drop", minimum_abbreviation_length=4, minimum_position=1
)


COMMON_CLI_COMMAND_RULES: tuple[CommandSafetyRule, ...] = (
    _rule(
        extension_id="command.platform.cloudflare",
        suffix="destructive",
        title="Cloudflare resource deletion",
        description="Identifies Wrangler operations that permanently remove Cloudflare resources.",
        matcher=_WRANGLER_DESTRUCTIVE,
        action_class="Cloudflare destructive command",
        risk_classes=("destructive_shell", "network_egress"),
        safer_alternative="Inspect the exact account, environment, and resource before deletion.",
        severity="critical",
        safe_variants=_help_variants(_WRANGLER_DESTRUCTIVE, short=True),
        example_command="wrangler d1 delete production-db",
    ),
    _rule(
        extension_id="command.platform.cloudflare",
        suffix="remote-change",
        title="Cloudflare deployment or secret change",
        description="Identifies Wrangler deployment and secret mutation operations.",
        matcher=_WRANGLER_CHANGE,
        action_class="Cloudflare production command",
        risk_classes=("execution", "network_egress"),
        safer_alternative="Review the target environment, deployment, and secret names before publishing.",
        safe_variants=_help_variants(_WRANGLER_CHANGE, short=True),
        example_command="wrangler deploy",
    ),
    _rule(
        extension_id="command.gitlab",
        suffix="destructive",
        title="GitLab destructive administration",
        description="Identifies project, release, or variable deletion through glab.",
        matcher=_GLAB_DESTRUCTIVE,
        action_class="GitLab destructive command",
        risk_classes=("destructive_shell", "network_egress"),
        safer_alternative="Inspect the exact GitLab project and resource before deletion.",
        severity="critical",
        safe_variants=_help_variants(_GLAB_DESTRUCTIVE, short=True),
        example_command="glab repo delete group/project",
    ),
    _rule(
        extension_id="command.gitlab",
        suffix="merge",
        title="GitLab merge request mutation",
        description="Identifies merge or rebase operations that change remote GitLab repository state.",
        matcher=_GLAB_MERGE,
        action_class="GitLab merge command",
        risk_classes=("execution", "network_egress"),
        safer_alternative="Review the head, target branch, and pipeline state before merging or rebasing.",
        safe_variants=_help_variants(_GLAB_MERGE, short=True),
        example_command="glab mr merge 42",
    ),
    _rule(
        extension_id="command.gitlab",
        suffix="variable",
        title="GitLab CI/CD variable access",
        description="Identifies reads or writes of GitLab variables that may contain credentials.",
        matcher=_GLAB_VARIABLE,
        action_class="GitLab variable command",
        risk_classes=("local_secret_read", "network_egress"),
        safer_alternative="Use only the required variable and confirm the exact project or group scope.",
        safe_variants=_help_variants(_GLAB_VARIABLE, short=True),
        example_command="glab variable get DEPLOY_TOKEN",
    ),
    _rule(
        extension_id="command.secrets.vault",
        suffix="secret-read",
        title="Vault secret read",
        description="Identifies Vault reads that can return secret material to the invoking agent.",
        matcher=_VAULT_READ,
        action_class="Vault secret read command",
        risk_classes=("local_secret_read", "network_egress"),
        safer_alternative="Request only the specific secret path and fields required for the task.",
        safe_variants=_help_variants(_VAULT_READ, short=True),
        example_command="vault kv get secret/app",
    ),
    _rule(
        extension_id="command.secrets.vault",
        suffix="secret-mutation",
        title="Vault secret mutation",
        description="Identifies Vault operations that write, delete, destroy, or roll back secret data.",
        matcher=_VAULT_MUTATION,
        action_class="Vault secret mutation command",
        risk_classes=("destructive_shell", "network_egress"),
        safer_alternative="Confirm the mount, path, version, and recovery plan before changing secret state.",
        severity="critical",
        safe_variants=_help_variants(_VAULT_MUTATION, short=True),
        example_command="vault kv destroy -versions=3 secret/app",
    ),
    _rule(
        extension_id="command.secrets.vault",
        suffix="security-administration",
        title="Vault security administration",
        description="Identifies token revocation and disabling of policies, auth methods, or secrets engines.",
        matcher=_VAULT_ADMIN,
        action_class="Vault security administration command",
        risk_classes=("destructive_shell", "network_egress"),
        safer_alternative="Inspect active leases, policies, and mount dependencies before disabling them.",
        severity="critical",
        safe_variants=_help_variants(_VAULT_ADMIN, short=True),
        example_command="vault token revoke accessor-value",
    ),
    _rule(
        extension_id="command.database.prisma",
        suffix="destructive",
        title="Prisma destructive database operation",
        description="Identifies resets, direct SQL execution, and data-loss-accepted schema pushes.",
        matcher=_PRISMA_DESTRUCTIVE,
        action_class="Prisma destructive command",
        risk_classes=("destructive_shell", "network_egress", "execution"),
        safer_alternative="Inspect the schema diff and take a current backup before destructive Prisma operations.",
        severity="critical",
        safe_variants=_help_variants(_PRISMA_DESTRUCTIVE, short=True),
        example_command="npx prisma migrate reset",
    ),
    _rule(
        extension_id="command.database.prisma",
        suffix="production-migrate",
        title="Prisma production migration",
        description="Identifies Prisma migration deployment against the selected database.",
        matcher=_PRISMA_DEPLOY,
        action_class="Prisma production migration command",
        risk_classes=("execution", "network_egress"),
        safer_alternative="Review pending migration files and verify the target database before deployment.",
        safe_variants=_help_variants(_PRISMA_DEPLOY, short=True),
        example_command="npx prisma migrate deploy",
    ),
    _rule(
        extension_id="command.platform.firebase",
        suffix="production-deploy",
        title="Firebase production deployment",
        description="Identifies deployment of Firebase application resources and security configuration.",
        matcher=_FIREBASE_DEPLOY,
        action_class="Firebase production command",
        risk_classes=("execution", "network_egress"),
        safer_alternative="Confirm the active Firebase project and deploy target before publishing.",
        safe_variants=_help_variants(_FIREBASE_DEPLOY, short=True),
        example_command="firebase deploy",
    ),
    _rule(
        extension_id="command.platform.firebase",
        suffix="destructive",
        title="Firebase destructive operation",
        description="Identifies deletion of functions, application data, or Hosting state.",
        matcher=_FIREBASE_DESTRUCTIVE,
        action_class="Firebase destructive command",
        risk_classes=("destructive_shell", "network_egress"),
        safer_alternative="Inspect the exact Firebase project, target, and recovery options before deletion.",
        severity="critical",
        safe_variants=_help_variants(_FIREBASE_DESTRUCTIVE, short=True),
        example_command="firebase functions:delete worker",
    ),
    _rule(
        extension_id="command.gitops.argocd",
        suffix="destructive",
        title="Argo CD destructive operation",
        description="Identifies application, ApplicationSet, cluster, or repository removal through argocd.",
        matcher=_ARGO_DESTRUCTIVE,
        action_class="Argo CD destructive command",
        risk_classes=("destructive_shell", "network_egress"),
        safer_alternative="Inspect the selected application and cascade behavior before deletion.",
        severity="critical",
        safe_variants=_help_variants(_ARGO_DESTRUCTIVE, short=True),
        example_command="argocd app delete production",
    ),
    _rule(
        extension_id="command.gitops.argocd",
        suffix="reconciliation",
        title="Argo CD reconciliation mutation",
        description="Identifies sync, rollback, patch, and operation termination through argocd.",
        matcher=_ARGO_RECONCILE,
        action_class="Argo CD reconciliation command",
        risk_classes=("execution", "network_egress"),
        safer_alternative="Inspect application diff and health before changing live reconciliation state.",
        safe_variants=_help_variants(_ARGO_RECONCILE, short=True),
        example_command="argocd app sync production",
    ),
    _rule(
        extension_id="command.gitops.flux",
        suffix="destructive",
        title="Flux destructive operation",
        description="Identifies uninstall and deletion of Flux reconciliation resources.",
        matcher=_FLUX_DESTRUCTIVE,
        action_class="Flux destructive command",
        risk_classes=("destructive_shell", "network_egress"),
        safer_alternative="Inspect ownership and prune behavior before deleting or uninstalling Flux resources.",
        severity="critical",
        safe_variants=_help_variants(_FLUX_DESTRUCTIVE, short=True),
        example_command="flux delete kustomization production",
    ),
    _rule(
        extension_id="command.gitops.flux",
        suffix="reconciliation",
        title="Flux reconciliation mutation",
        description="Identifies reconcile, suspend, and resume operations that change live GitOps behavior.",
        matcher=_FLUX_RECONCILE,
        action_class="Flux reconciliation command",
        risk_classes=("execution", "network_egress"),
        safer_alternative="Inspect source revision and reconciliation status before forcing or suspending changes.",
        safe_variants=_help_variants(_FLUX_RECONCILE, short=True),
        example_command="flux reconcile kustomization production",
    ),
    _rule(
        extension_id="command.package.dotnet",
        suffix="package-mutation",
        title=".NET package dependency mutation",
        description="Identifies .NET and NuGet package addition, install, and restore operations.",
        matcher=_DOTNET_MUTATION,
        action_class=".NET package mutation command",
        risk_classes=("supply_chain", "network_egress", "execution"),
        safer_alternative="Use locked dependencies and inspect package provenance before changing dependencies.",
        safe_variants=_help_variants(_DOTNET_MUTATION, short=True),
        example_command="dotnet package add Example.Package",
    ),
    _rule(
        extension_id="command.package.dotnet",
        suffix="publication",
        title="NuGet publication mutation",
        description="Identifies push or deletion of NuGet package versions.",
        matcher=_DOTNET_PUBLICATION,
        action_class=".NET package publication command",
        risk_classes=("supply_chain", "network_egress", "destructive_shell"),
        safer_alternative="Verify package, version, feed, and signing before changing published state.",
        severity="critical",
        safe_variants=_help_variants(_DOTNET_PUBLICATION, short=True),
        example_command="dotnet nuget push package.nupkg",
    ),
    _rule(
        extension_id="command.database.bigquery",
        suffix="destructive",
        title="BigQuery destructive operation",
        description="Identifies resource deletion and replace-enabled load operations through bq.",
        matcher=_BQ_DESTRUCTIVE,
        action_class="BigQuery destructive command",
        risk_classes=("destructive_shell", "network_egress"),
        safer_alternative="Inspect the exact project, dataset, table, and destination before destructive changes.",
        severity="critical",
        safe_variants=_help_variants(_BQ_DESTRUCTIVE, short=True),
        example_command="bq rm -r -f project:dataset",
    ),
    _rule(
        extension_id="command.platform.fly",
        suffix="destructive",
        title="Fly.io destructive operation",
        description="Identifies app, Machine, volume, or IP destruction through flyctl.",
        matcher=_FLY_DESTRUCTIVE,
        action_class="Fly.io destructive command",
        risk_classes=("destructive_shell", "network_egress"),
        safer_alternative="Inspect the exact app and dependent resource before destruction.",
        severity="critical",
        safe_variants=_help_variants(_FLY_DESTRUCTIVE, short=True),
        example_command="fly apps destroy production",
    ),
    _rule(
        extension_id="command.platform.fly",
        suffix="production-change",
        title="Fly.io deployment or secret change",
        description="Identifies Fly.io deploy and application secret mutation operations.",
        matcher=_FLY_CHANGE,
        action_class="Fly.io production command",
        risk_classes=("execution", "network_egress"),
        safer_alternative="Confirm app, organization, deployment, and secret scope before remote changes.",
        safe_variants=_help_variants(_FLY_CHANGE, short=True),
        example_command="fly deploy",
    ),
    _rule(
        extension_id="command.platform.railway",
        suffix="destructive",
        title="Railway destructive operation",
        description="Identifies project or volume deletion through Railway CLI.",
        matcher=_RAILWAY_DESTRUCTIVE,
        action_class="Railway destructive command",
        risk_classes=("destructive_shell", "network_egress"),
        safer_alternative="Confirm project, service, environment, and persistent data before deletion.",
        severity="critical",
        safe_variants=_help_variants(_RAILWAY_DESTRUCTIVE, short=True),
        example_command="railway delete --yes",
    ),
    _rule(
        extension_id="command.platform.railway",
        suffix="remote-change",
        title="Railway deployment, variable, or shell operation",
        description="Identifies deploys, variable mutation, and secret-populated shells through Railway CLI.",
        matcher=_RAILWAY_CHANGE,
        action_class="Railway production command",
        risk_classes=("execution", "network_egress", "local_secret_read"),
        safer_alternative="Confirm the exact project, service, environment, and variable scope first.",
        safe_variants=_help_variants(_RAILWAY_CHANGE, short=True),
        example_command="railway up",
    ),
    _rule(
        extension_id="command.configuration-management.ansible",
        suffix="remote-execution",
        title="Ansible remote execution",
        description="Identifies ad-hoc, playbook, or pull-based Ansible execution.",
        matcher=_ANSIBLE_EXECUTION,
        action_class="Ansible remote execution command",
        risk_classes=("execution", "network_egress", "destructive_shell"),
        safer_alternative="Limit inventory and hosts and inspect playbook changes before execution.",
        safe_variants=(
            safe_flag_variant(_ANSIBLE_EXECUTION, variant_id="help", title="Command help", flag="--help"),
            safe_flag_variant(_ANSIBLE_EXECUTION, variant_id="short-help", title="Command help", flag="-h"),
            safe_flag_variant(_ANSIBLE_EXECUTION, variant_id="version", title="Version display", flag="--version"),
        ),
        example_command="ansible-playbook -i production site.yml",
    ),
    _rule(
        extension_id="command.configuration-management.ansible",
        suffix="vault-secret",
        title="Ansible Vault secret access",
        description="Identifies decrypting, viewing, editing, or rekeying encrypted Ansible Vault data.",
        matcher=_ANSIBLE_VAULT,
        action_class="Ansible Vault secret command",
        risk_classes=("local_secret_read", "destructive_shell"),
        safer_alternative="Decrypt only the required file in a controlled context and avoid persisting plaintext.",
        safe_variants=_help_variants(_ANSIBLE_VAULT, short=True),
        example_command="ansible-vault view group_vars/prod.yml",
    ),
    _rule(
        extension_id="command.cloud.digitalocean",
        suffix="resource-deletion",
        title="DigitalOcean resource deletion",
        description="Identifies deletion of compute, Kubernetes, database, network, storage, and app resources.",
        matcher=_DOCTL_DELETE,
        action_class="DigitalOcean destructive command",
        risk_classes=("destructive_shell", "network_egress"),
        safer_alternative="Inspect the exact context, resource, dependent data, and backups before deletion.",
        severity="critical",
        safe_variants=_help_variants(_DOCTL_DELETE, short=True),
        example_command="doctl compute droplet delete 123456",
    ),
    _rule(
        extension_id="command.secrets.1password",
        suffix="secret-read",
        title="1Password secret read",
        description="Identifies reads that can return item or document secret material through op.",
        matcher=_OP_READ,
        action_class="1Password secret read command",
        risk_classes=("local_secret_read", "network_egress"),
        safer_alternative="Read only the required field or secret reference rather than the full item.",
        safe_variants=_help_variants(_OP_READ, short=True),
        example_command="op read op://Production/API/token",
    ),
    _rule(
        extension_id="command.secrets.1password",
        suffix="secret-injection",
        title="1Password secret injection",
        description="Identifies injecting secrets into subprocesses or rendered configuration.",
        matcher=_OP_INJECT,
        action_class="1Password secret injection command",
        risk_classes=("local_secret_read", "execution"),
        safer_alternative="Inject only required references into the narrowest subprocess or destination.",
        safe_variants=_help_variants(_OP_INJECT, short=True),
        example_command="op run -- env",
    ),
    _rule(
        extension_id="command.secrets.1password",
        suffix="destructive",
        title="1Password destructive operation",
        description="Identifies deletion of items, documents, or vaults through op.",
        matcher=_OP_DELETE,
        action_class="1Password destructive command",
        risk_classes=("destructive_shell", "network_egress"),
        safer_alternative="Inspect the exact object and recovery options before deleting it.",
        severity="critical",
        safe_variants=_help_variants(_OP_DELETE, short=True),
        example_command="op item delete credential-id",
    ),
    _rule(
        extension_id="command.package-publication",
        suffix="publish-or-yank",
        title="Package registry publication mutation",
        description="Identifies package publish, unpublish, yank, and upload operations across common registries.",
        matcher=_PACKAGE_PUBLISH,
        action_class="package publication command",
        risk_classes=("supply_chain", "network_egress", "destructive_shell"),
        safer_alternative="Verify package identity, version, registry, provenance, and signing before publication.",
        severity="critical",
        safe_variants=_help_variants(_PACKAGE_PUBLISH),
        example_command="npm publish",
    ),
    _rule(
        extension_id="command.cloud-secrets",
        suffix="secret-read",
        title="Cloud secret read",
        description="Identifies secret retrieval through AWS, Google Cloud, or Azure CLIs.",
        matcher=_CLOUD_SECRET_READ,
        action_class="cloud secret read command",
        risk_classes=("local_secret_read", "network_egress"),
        safer_alternative="Request only the exact secret or decrypted parameter required for the operation.",
        safe_variants=_help_variants(_CLOUD_SECRET_READ),
        example_command="aws secretsmanager get-secret-value --secret-id production/api",
    ),
    _rule(
        extension_id="command.cloud-secrets",
        suffix="credential-mutation",
        title="Cloud credential mutation",
        description="Identifies access-key or service-account credential creation, deletion, or reset.",
        matcher=_CLOUD_CREDENTIAL_MUTATION,
        action_class="cloud credential mutation command",
        risk_classes=("destructive_shell", "network_egress"),
        safer_alternative="Confirm principal scope, active credentials, and rotation plan before mutation.",
        severity="critical",
        safe_variants=_help_variants(_CLOUD_CREDENTIAL_MUTATION),
        example_command="aws iam create-access-key --user-name deployer",
    ),
    _rule(
        extension_id="command.container-runtime",
        suffix="alternate-runtime-cleanup",
        title="Alternate container runtime cleanup",
        description="Identifies broad Podman and nerdctl prune operations.",
        matcher=_ALT_CONTAINER_CLEANUP,
        action_class="docker-sensitive command",
        risk_classes=("destructive_shell",),
        safer_alternative="List exact resources and prune the narrowest resource class first.",
        severity="critical",
        safe_variants=_help_variants(_ALT_CONTAINER_CLEANUP),
        example_command="podman system prune",
    ),
    _rule(
        extension_id="command.container-runtime",
        suffix="alternate-runtime-privileged-run",
        title="Alternate container privileged execution",
        description="Identifies Podman or nerdctl containers launched with broad host privileges.",
        matcher=_ALT_CONTAINER_PRIVILEGED,
        action_class="docker-sensitive command",
        risk_classes=("destructive_shell", "network_egress"),
        safer_alternative="Grant only required capabilities and keep host devices and filesystems isolated.",
        severity="critical",
        safe_variants=_help_variants(_ALT_CONTAINER_PRIVILEGED),
        example_command="podman run --privileged alpine",
    ),
    _rule(
        extension_id="command.kubernetes-operations",
        suffix="openshift-destructive",
        title="OpenShift destructive operation",
        description="Identifies resource deletion and node drains through oc.",
        matcher=_OC_DESTRUCTIVE,
        action_class="Kubernetes destructive command",
        risk_classes=("destructive_shell", "network_egress"),
        safer_alternative="Review the exact project, resource, or node before destructive operations.",
        severity="critical",
        safe_variants=_help_variants(_OC_DESTRUCTIVE, short=True),
        example_command="oc delete deployment api",
    ),
    _rule(
        extension_id="command.kubernetes-operations",
        suffix="openshift-remote-execution",
        title="OpenShift remote execution",
        description="Identifies remote command execution through oc exec or oc rsh.",
        matcher=_OC_EXECUTION,
        action_class="Kubernetes remote execution command",
        risk_classes=("execution", "network_egress"),
        safer_alternative="Use the narrowest pod, container, and remote command required for diagnostics.",
        safe_variants=_help_variants(_OC_EXECUTION, short=True),
        example_command="oc exec deployment/api -- sh",
    ),
    _rule(
        extension_id="command.kubernetes-operations",
        suffix="openshift-port-forward",
        title="OpenShift network tunnel",
        description="Identifies local-to-cluster network tunnels created through oc port-forward.",
        matcher=_OC_TUNNEL,
        action_class="Kubernetes network tunnel command",
        risk_classes=("network_egress",),
        safer_alternative="Bind only the required local interface and port for the shortest duration.",
        safe_variants=_help_variants(_OC_TUNNEL, short=True),
        example_command="oc port-forward service/api 8080:80",
    ),
    _rule(
        extension_id="command.kubernetes-operations",
        suffix="openshift-file-transfer",
        title="OpenShift remote file transfer",
        description="Identifies file synchronization between local and cluster filesystems through oc rsync.",
        matcher=_OC_TRANSFER,
        action_class="Kubernetes remote file transfer command",
        risk_classes=("network_egress",),
        safer_alternative="Transfer only reviewed paths and confirm direction and destination first.",
        safe_variants=_help_variants(_OC_TRANSFER, short=True),
        example_command="oc rsync ./out pod:/tmp/out",
    ),
    _rule(
        extension_id="command.infrastructure-as-code",
        suffix="additional-teardown",
        title="Additional infrastructure teardown",
        description="Identifies AWS CDK, SAM, and Serverless Framework teardown commands.",
        matcher=_IAC_EXPANSION,
        action_class="infrastructure destructive command",
        risk_classes=("destructive_shell", "network_egress"),
        safer_alternative="Review the exact stack, stage, account, and region before teardown.",
        severity="critical",
        safe_variants=_help_variants(_IAC_EXPANSION),
        example_command="npx cdk destroy",
    ),
    _rule(
        extension_id="command.database.postgresql",
        suffix="direct-drop",
        title="PostgreSQL direct destructive SQL",
        description="Identifies direct psql arguments beginning with DROP.",
        matcher=_PSQL_DROP,
        action_class="PostgreSQL destructive command",
        risk_classes=("destructive_shell", "network_egress"),
        safer_alternative="Inspect the target object and current backup before executing DROP through psql.",
        severity="critical",
        example_command='psql -c "DROP DATABASE production"',
    ),
    _rule(
        extension_id="command.database.mysql",
        suffix="direct-drop",
        title="MySQL direct destructive SQL",
        description="Identifies direct mysql arguments beginning with DROP.",
        matcher=_MYSQL_DROP,
        action_class="MySQL destructive command",
        risk_classes=("destructive_shell", "network_egress"),
        safer_alternative="Inspect the target object and current backup before executing DROP through mysql.",
        severity="critical",
        example_command='mysql -e "DROP DATABASE production"',
    ),
)


COMMON_CLI_COMMAND_EXTENSION_SPECS: tuple[CommandExtensionSpec, ...] = (
    _spec(
        "command.platform.cloudflare",
        "Cloudflare Wrangler command protection",
        "Reviews Cloudflare deployment, resource deletion, and secret mutation through Wrangler.",
        ("Cloudflare destructive command", "Cloudflare production command"),
        ("destructive_shell", "network_egress", "execution"),
        "Confirm account, environment, resource, and deployment scope before remote changes.",
        ("https://developers.cloudflare.com/workers/wrangler/commands/",),
    ),
    _spec(
        "command.gitlab",
        "GitLab command protection",
        "Reviews GitLab deletion, merge/rebase, and CI/CD variable access through glab.",
        ("GitLab destructive command", "GitLab merge command", "GitLab variable command"),
        ("destructive_shell", "network_egress", "execution", "local_secret_read"),
        "Inspect the exact project, merge request, and variable scope before remote changes.",
        ("https://docs.gitlab.com/cli/",),
    ),
    _spec(
        "command.secrets.vault",
        "HashiCorp Vault command protection",
        "Reviews Vault secret reads, destructive secret mutation, and security administration.",
        ("Vault secret read command", "Vault secret mutation command", "Vault security administration command"),
        ("local_secret_read", "network_egress", "destructive_shell"),
        "Use the narrowest path, version, token, and mount required for the operation.",
        ("https://developer.hashicorp.com/vault/docs/commands",),
    ),
    _spec(
        "command.database.prisma",
        "Prisma command protection",
        "Reviews destructive resets, direct SQL, data-loss pushes, and production migrations.",
        ("Prisma destructive command", "Prisma production migration command"),
        ("destructive_shell", "network_egress", "execution"),
        "Review schema and migration diffs and verify the selected database before mutation.",
        ("https://www.prisma.io/docs/orm/reference/prisma-cli-reference",),
    ),
    _spec(
        "command.platform.firebase",
        "Firebase command protection",
        "Reviews production deployment and destructive Firebase application and data operations.",
        ("Firebase production command", "Firebase destructive command"),
        ("execution", "network_egress", "destructive_shell"),
        "Confirm the active Firebase project, target, and recovery path before remote changes.",
        ("https://firebase.google.com/docs/cli",),
    ),
    _spec(
        "command.gitops.argocd",
        "Argo CD command protection",
        "Reviews destructive GitOps administration and live reconciliation mutations through argocd.",
        ("Argo CD destructive command", "Argo CD reconciliation command"),
        ("destructive_shell", "network_egress", "execution"),
        "Inspect application diff, health, ownership, and cascade behavior before mutation.",
        ("https://argo-cd.readthedocs.io/en/stable/user-guide/commands/argocd/",),
    ),
    _spec(
        "command.gitops.flux",
        "Flux command protection",
        "Reviews destructive Flux administration and forced reconciliation state changes.",
        ("Flux destructive command", "Flux reconciliation command"),
        ("destructive_shell", "network_egress", "execution"),
        "Inspect source revision, prune behavior, and reconciliation status before mutation.",
        ("https://fluxcd.io/flux/cmd/",),
    ),
    _spec(
        "command.package.dotnet",
        ".NET and NuGet package command protection",
        "Reviews package dependency ingress plus NuGet publication and deletion.",
        (".NET package mutation command", ".NET package publication command"),
        ("supply_chain", "network_egress", "execution", "destructive_shell"),
        "Use locked dependencies and verify package/feed identity before installation or publication.",
        (
            "https://learn.microsoft.com/dotnet/core/tools/",
            "https://learn.microsoft.com/nuget/reference/nuget-exe-cli-reference",
        ),
    ),
    _spec(
        "command.database.bigquery",
        "BigQuery command protection",
        "Reviews bq operations that remove resources or replace destination data.",
        ("BigQuery destructive command",),
        ("destructive_shell", "network_egress"),
        "Inspect the exact project, dataset, table, and load destination before destructive changes.",
        ("https://cloud.google.com/bigquery/docs/reference/bq-cli-reference",),
    ),
    _spec(
        "command.platform.fly",
        "Fly.io command protection",
        "Reviews Fly.io production deploys, destructive resource operations, and secret mutation.",
        ("Fly.io destructive command", "Fly.io production command"),
        ("destructive_shell", "network_egress", "execution"),
        "Confirm app, organization, resource, and secret scope before remote changes.",
        ("https://fly.io/docs/flyctl/",),
    ),
    _spec(
        "command.platform.railway",
        "Railway command protection",
        "Reviews Railway deployment, deletion, variable mutation, and secret-populated shell access.",
        ("Railway destructive command", "Railway production command"),
        ("destructive_shell", "network_egress", "execution", "local_secret_read"),
        "Confirm project, service, environment, and variable scope before remote changes.",
        ("https://docs.railway.com/reference/cli-api",),
    ),
    _spec(
        "command.configuration-management.ansible",
        "Ansible command protection",
        "Reviews remote Ansible execution and access to encrypted Ansible Vault material.",
        ("Ansible remote execution command", "Ansible Vault secret command"),
        ("execution", "network_egress", "destructive_shell", "local_secret_read"),
        "Limit inventory and hosts and inspect playbook changes and Vault scope before execution.",
        ("https://docs.ansible.com/ansible/latest/command_guide/",),
    ),
    _spec(
        "command.cloud.digitalocean",
        "DigitalOcean command protection",
        "Reviews destructive DigitalOcean control-plane operations through doctl.",
        ("DigitalOcean destructive command",),
        ("destructive_shell", "network_egress"),
        "Inspect context, resource dependencies, and backups before deletion.",
        ("https://docs.digitalocean.com/reference/doctl/reference/",),
    ),
    _spec(
        "command.secrets.1password",
        "1Password command protection",
        "Reviews secret reads, secret injection, and destructive object deletion through op.",
        ("1Password secret read command", "1Password secret injection command", "1Password destructive command"),
        ("local_secret_read", "network_egress", "execution", "destructive_shell"),
        "Use the narrowest secret reference and subprocess scope required for the task.",
        ("https://developer.1password.com/docs/cli/",),
    ),
    _spec(
        "command.package-publication",
        "Package registry publication protection",
        "Reviews publish, upload, unpublish, and yank operations across common package ecosystems.",
        ("package publication command",),
        ("supply_chain", "network_egress", "destructive_shell"),
        "Verify package identity, version, registry, provenance, and signing before publication changes.",
        (
            "https://docs.npmjs.com/cli/commands/npm-publish",
            "https://doc.rust-lang.org/cargo/commands/cargo-publish.html",
            "https://twine.readthedocs.io/",
        ),
    ),
    _spec(
        "command.cloud-secrets",
        "Cloud secret and credential protection",
        "Reviews secret retrieval and credential lifecycle mutations across AWS, Google Cloud, and Azure CLIs.",
        ("cloud secret read command", "cloud credential mutation command"),
        ("local_secret_read", "network_egress", "destructive_shell"),
        "Use the narrowest principal, secret, and credential scope required for the task.",
        (
            "https://docs.aws.amazon.com/cli/latest/reference/secretsmanager/get-secret-value.html",
            "https://cloud.google.com/sdk/gcloud/reference/secrets/versions/access",
            "https://learn.microsoft.com/cli/azure/keyvault/secret",
        ),
    ),
    _spec(
        "command.kubernetes-operations",
        "Kubernetes and OpenShift operation protection",
        "Reviews destructive Kubernetes/OpenShift operations plus OpenShift execution, tunnels, and file transfer.",
        (
            "Kubernetes destructive command",
            "Kubernetes remote execution command",
            "Kubernetes network tunnel command",
            "Kubernetes remote file transfer command",
        ),
        ("destructive_shell", "network_egress", "execution"),
        "Use explicit projects and the narrowest remote operation required before cluster mutation.",
        (
            "https://kubernetes.io/docs/reference/kubectl/",
            (
                "https://docs.redhat.com/en/documentation/openshift_container_platform/latest/"
                "html/cli_tools/openshift-cli-oc"
            ),
        ),
    ),
    _spec(
        "command.infrastructure-as-code",
        "Infrastructure-as-code protection",
        "Reviews teardown through Terraform, OpenTofu, Pulumi, AWS CDK, AWS SAM, and Serverless Framework.",
        ("infrastructure destructive command",),
        ("destructive_shell", "network_egress"),
        "Create and inspect a plan or preview and confirm stack, stage, account, and region before teardown.",
        (
            "https://developer.hashicorp.com/terraform/cli/commands/destroy",
            "https://opentofu.org/docs/cli/commands/destroy/",
            "https://www.pulumi.com/docs/iac/cli/commands/pulumi_destroy/",
            "https://docs.aws.amazon.com/cdk/v2/guide/ref-cli-cmd-destroy.html",
            (
                "https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/"
                "sam-cli-command-reference-sam-delete.html"
            ),
        ),
    ),
)
