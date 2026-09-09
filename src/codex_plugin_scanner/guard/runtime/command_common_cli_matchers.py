"""Structured matchers for common production, secrets, GitOps, and package CLIs."""

from __future__ import annotations

from .command_common_cli_support import (
    _AWS_FLAGS,
    _AWS_OPTIONS,
    _AZURE_FLAGS,
    _AZURE_OPTIONS,
    _GCLOUD_FLAGS,
    _GCLOUD_OPTIONS,
    _flag_bundle,
    _node_bundle,
    _node_flag_bundle,
    _path_bundle,
)
from .command_database_matchers import ArgumentCommandMatcher
from .command_extension_matchers import executable_matcher, executable_names
from .command_rules import AnyMatcher

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
_GLAB_MERGE = _path_bundle(("glab",), (("mr", "merge"), ("mr", "rebase")), options=_GLAB_OPTIONS, flags=_GLAB_FLAGS)
_GLAB_VARIABLE = _path_bundle(
    ("glab",), (("variable", "get"), ("variable", "set")), options=_GLAB_OPTIONS, flags=_GLAB_FLAGS
)

# HashiCorp Vault
_VAULT_OPTIONS = frozenset({"-address", "-namespace", "-output-format"})
_VAULT_FLAGS = frozenset({"-h", "--help"})
_VAULT_READ = _path_bundle(("vault",), (("kv", "get"), ("read",)), options=_VAULT_OPTIONS, flags=_VAULT_FLAGS)
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
_ALT_CONTAINER_PRIVILEGED = _flag_bundle(("podman", "nerdctl"), (("run",),), required_flags=frozenset({"--privileged"}))
_OC_OPTIONS = frozenset(
    {"--as", "--as-group", "--cluster", "--context", "--kubeconfig", "--namespace", "-n", "--server", "--user"}
)
_OC_FLAGS = frozenset({"--help", "-h"})
_OC_DESTRUCTIVE = _path_bundle(("oc",), (("delete",), ("adm", "drain")), options=_OC_OPTIONS, flags=_OC_FLAGS)
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
