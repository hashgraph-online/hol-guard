"""Common CLI command rules, release/3.2 gap-closure batch."""

from __future__ import annotations

from .command_common_cli_matchers import _OC_FLAGS, _OC_OPTIONS
from .command_common_cli_matchers_extra import (
    _ARGO_ADDITIONAL_RECONCILE,
    _CDK_ALIAS_DESTROY,
    _FIREBASE_SECRET_CHANGE,
    _FLY_ADDITIONAL_CHANGE,
    _FLY_ADDITIONAL_DESTRUCTIVE,
    _GITLAB_CI_VARIABLE,
    _PACKAGE_PUBLICATION_GAPS,
    _RAILWAY_ALIAS_CHANGE,
    _RAILWAY_ALIAS_DESTRUCTIVE,
    _SLS_ALIAS_REMOVE,
    _VAULT_ADDITIONAL_MUTATION,
    DOTNET_POSITIONAL_PACKAGE,
    MONGOSH_MUTATION,
    SQLITE_MUTATION,
)
from .command_common_cli_rule_support import help_variants, rule
from .command_common_cli_support import _path_bundle
from .command_extension_matchers import executable_matcher, safe_option_variant
from .command_rules import AnyMatcher, CommandSafetyRule

_RAILWAY_WRAPPER_DESTRUCTIVE = AnyMatcher(matchers=_RAILWAY_ALIAS_DESTRUCTIVE.matchers[1:])
_RAILWAY_WRAPPER_CHANGE = AnyMatcher(matchers=_RAILWAY_ALIAS_CHANGE.matchers[1:])
_IAC_RUNNER_ALIAS_TEARDOWN = AnyMatcher(matchers=(*_CDK_ALIAS_DESTROY.matchers[1:], *_SLS_ALIAS_REMOVE.matchers[1:]))
_ALT_CONTAINER_RESOURCE_REMOVAL = _path_bundle(
    ("podman", "nerdctl"),
    (("rm",), ("container", "rm"), ("image", "rm"), ("volume", "rm"), ("network", "rm")),
)
_ALT_CONTAINER_EXECUTION = AnyMatcher(
    matchers=tuple(
        matcher
        for executable in ("podman", "nerdctl")
        for matcher in (
            executable_matcher(executable, "run", forbidden_flags=frozenset({"--privileged"})),
            executable_matcher(executable, "exec"),
        )
    )
)
_OC_MUTATION_STRUCTURED = _path_bundle(
    ("oc",),
    (("apply",), ("patch",), ("scale",), ("rollout", "restart")),
    options=_OC_OPTIONS,
    flags=_OC_FLAGS,
)

COMMON_CLI_COMMAND_RULES_5: tuple[CommandSafetyRule, ...] = (
    rule(
        extension_id="command.platform.railway",
        suffix="runner-alias-destructive",
        title="Railway runner-alias destructive operation",
        description="Identifies destructive Railway operations when Node runners invoke the `railway` binary name.",
        matcher=_RAILWAY_WRAPPER_DESTRUCTIVE,
        action_class="Railway destructive command",
        risk_classes=("destructive_shell", "network_egress"),
        safer_alternative="Confirm project, environment, service, and persistent data before deletion.",
        severity="critical",
        safe_variants=help_variants(_RAILWAY_WRAPPER_DESTRUCTIVE, short=True),
        example_command="npx railway delete --yes",
    ),
    rule(
        extension_id="command.platform.railway",
        suffix="runner-alias-change",
        title="Railway runner-alias production operation",
        description=(
            "Identifies deploy, restart, down, variable, and shell operations through the Railway binary alias."
        ),
        matcher=_RAILWAY_WRAPPER_CHANGE,
        action_class="Railway production command",
        risk_classes=("execution", "network_egress", "local_secret_read"),
        safer_alternative="Confirm project, service, environment, and variable scope before remote changes.",
        safe_variants=help_variants(_RAILWAY_WRAPPER_CHANGE, short=True),
        example_command="npx railway up",
    ),
    rule(
        extension_id="command.infrastructure-as-code",
        suffix="runner-alias-teardown",
        title="Infrastructure runner-alias teardown",
        description="Identifies CDK and Serverless teardown when Node runners invoke `cdk` or `sls` binary aliases.",
        matcher=_IAC_RUNNER_ALIAS_TEARDOWN,
        action_class="infrastructure destructive command",
        risk_classes=("destructive_shell", "network_egress"),
        safer_alternative="Review the exact stack, stage, account, and region before teardown.",
        severity="critical",
        safe_variants=help_variants(_IAC_RUNNER_ALIAS_TEARDOWN),
        example_command="npx cdk destroy",
    ),
    rule(
        extension_id="command.package-publication",
        suffix="additional-publish-or-yank",
        title="Additional package publication mutation",
        description="Identifies Yarn direct publication and pnpm unpublish operations.",
        matcher=_PACKAGE_PUBLICATION_GAPS,
        action_class="package publication command",
        risk_classes=("supply_chain", "network_egress", "destructive_shell"),
        safer_alternative=(
            "Verify package identity, version, registry, provenance, and signing before publication changes."
        ),
        severity="critical",
        safe_variants=help_variants(_PACKAGE_PUBLICATION_GAPS),
        example_command="pnpm unpublish example-package@1.0.0",
    ),
    rule(
        extension_id="command.package.dotnet",
        suffix="positional-project-package",
        title=".NET positional-project package mutation",
        description="Identifies `dotnet add <PROJECT> package <PACKAGE>` dependency ingress.",
        matcher=DOTNET_POSITIONAL_PACKAGE,
        action_class=".NET package mutation command",
        risk_classes=("supply_chain", "network_egress", "execution"),
        safer_alternative="Use locked dependencies and inspect package provenance before changing dependencies.",
        example_command="dotnet add MyApp.csproj package Newtonsoft.Json",
    ),
    rule(
        extension_id="command.container-runtime",
        suffix="alternate-runtime-resource-removal",
        title="Alternate container runtime resource removal",
        description="Identifies Podman and nerdctl container, image, volume, and network removal operations.",
        matcher=_ALT_CONTAINER_RESOURCE_REMOVAL,
        action_class="docker-sensitive command",
        risk_classes=("destructive_shell",),
        safer_alternative="List exact container runtime resources before removing the narrowest target set.",
        severity="critical",
        safe_variants=help_variants(_ALT_CONTAINER_RESOURCE_REMOVAL),
        example_command="podman volume rm production-data",
    ),
    rule(
        extension_id="command.container-runtime",
        suffix="alternate-runtime-execution",
        title="Alternate container runtime execution",
        description=(
            "Identifies ordinary Podman and nerdctl run or exec operations that can mutate container or "
            "host-adjacent state."
        ),
        matcher=_ALT_CONTAINER_EXECUTION,
        action_class="docker-sensitive command",
        risk_classes=("destructive_shell", "network_egress"),
        safer_alternative="Use a pinned image, minimal privileges, and the narrowest command and mount scope.",
        safe_variants=help_variants(_ALT_CONTAINER_EXECUTION),
        example_command="nerdctl exec web sh",
    ),
    rule(
        extension_id="command.kubernetes-operations",
        suffix="openshift-mutation",
        title="OpenShift resource mutation",
        description="Identifies oc apply, patch, scale, and rollout restart operations.",
        matcher=_OC_MUTATION_STRUCTURED,
        action_class="Kubernetes destructive command",
        risk_classes=("destructive_shell", "network_egress"),
        safer_alternative="Inspect the exact project and resource diff before changing live cluster state.",
        safe_variants=(
            *help_variants(_OC_MUTATION_STRUCTURED, short=True),
            safe_option_variant(
                _OC_MUTATION_STRUCTURED,
                variant_id="dry-run",
                title="OpenShift mutation preview",
                option="--dry-run",
                allowed_values=frozenset({"client", "server"}),
            ),
        ),
        example_command="oc rollout restart deployment/api",
    ),
    rule(
        extension_id="command.database.mongodb",
        suffix="direct-client-mutation",
        title="MongoDB direct destructive operation",
        description="Identifies destructive mongosh operations supplied through --eval/-e.",
        matcher=MONGOSH_MUTATION,
        action_class="MongoDB destructive command",
        risk_classes=("destructive_shell", "network_egress"),
        safer_alternative="Inspect the selected database and collection set before destructive evaluation.",
        severity="critical",
        example_command="mongosh app --eval 'db.users.deleteMany({})'",
    ),
    rule(
        extension_id="command.database.sqlite",
        suffix="direct-client-mutation",
        title="SQLite direct destructive operation",
        description="Identifies destructive SQLite positional SQL plus restore/import mutation commands.",
        matcher=SQLITE_MUTATION,
        action_class="SQLite destructive command",
        risk_classes=("destructive_shell",),
        safer_alternative="Copy the database and test destructive statements against the copy first.",
        severity="critical",
        example_command="sqlite3 app.db 'DROP TABLE users'",
    ),
    rule(
        extension_id="command.platform.firebase",
        suffix="secret-mutation",
        title="Firebase secret mutation",
        description=(
            "Identifies Firebase Functions secret set and destroy operations across direct and Node-runner forms."
        ),
        matcher=_FIREBASE_SECRET_CHANGE,
        action_class="Firebase production command",
        risk_classes=("execution", "network_egress"),
        safer_alternative="Confirm the active project and exact secret name before changing remote secret state.",
        safe_variants=help_variants(_FIREBASE_SECRET_CHANGE, short=True),
        example_command="npx firebase functions:secrets:set API_TOKEN",
    ),
    rule(
        extension_id="command.platform.fly",
        suffix="additional-destructive",
        title="Additional Fly.io destructive operation",
        description="Identifies plural Machine and volume destruction forms through fly/flyctl.",
        matcher=_FLY_ADDITIONAL_DESTRUCTIVE,
        action_class="Fly.io destructive command",
        risk_classes=("destructive_shell", "network_egress"),
        safer_alternative="Inspect the exact app, Machine, volume, and dependent state before destruction.",
        severity="critical",
        safe_variants=help_variants(_FLY_ADDITIONAL_DESTRUCTIVE, short=True),
        example_command="fly machines destroy 1234abcd",
    ),
    rule(
        extension_id="command.platform.fly",
        suffix="additional-production-change",
        title="Additional Fly.io production change",
        description="Identifies release rollback and Machine restart operations through fly/flyctl.",
        matcher=_FLY_ADDITIONAL_CHANGE,
        action_class="Fly.io production command",
        risk_classes=("execution", "network_egress"),
        safer_alternative="Inspect the active release and Machine state before rollback or restart.",
        safe_variants=help_variants(_FLY_ADDITIONAL_CHANGE, short=True),
        example_command="fly releases rollback v42",
    ),
    rule(
        extension_id="command.gitlab",
        suffix="ci-variable",
        title="GitLab CI variable operation",
        description="Identifies CI-scoped GitLab variable reads, writes, and deletion through glab.",
        matcher=_GITLAB_CI_VARIABLE,
        action_class="GitLab variable command",
        risk_classes=("local_secret_read", "network_egress"),
        safer_alternative="Use only the required variable and confirm the exact project scope.",
        safe_variants=help_variants(_GITLAB_CI_VARIABLE, short=True),
        example_command="glab ci variable get DEPLOY_TOKEN",
    ),
    rule(
        extension_id="command.gitops.argocd",
        suffix="additional-reconciliation",
        title="Additional Argo CD reconciliation mutation",
        description="Identifies application setting changes and explicit action execution through argocd.",
        matcher=_ARGO_ADDITIONAL_RECONCILE,
        action_class="Argo CD reconciliation command",
        risk_classes=("execution", "network_egress"),
        safer_alternative="Inspect application diff, action parameters, and live health before mutation.",
        safe_variants=help_variants(_ARGO_ADDITIONAL_RECONCILE, short=True),
        example_command="argocd app set production --revision main",
    ),
    rule(
        extension_id="command.secrets.vault",
        suffix="additional-mutation",
        title="Additional Vault mutation",
        description="Identifies secret undelete and policy write operations through Vault CLI.",
        matcher=_VAULT_ADDITIONAL_MUTATION,
        action_class="Vault secret mutation command",
        risk_classes=("destructive_shell", "network_egress"),
        safer_alternative="Confirm the exact secret version or policy contents and target path before mutation.",
        safe_variants=help_variants(_VAULT_ADDITIONAL_MUTATION, short=True),
        example_command="vault kv undelete -versions=3 secret/app",
    ),
)
