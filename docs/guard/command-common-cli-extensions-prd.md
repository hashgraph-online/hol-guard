# PRD: Common CLI First-Class Extensions for HOL Guard 3.2

Status: implementation target
Base branch: `release/3.2`

## Problem

HOL Guard 3.2 already has typed command Extensions for core shell safety, Git, Docker, Kubernetes, Terraform/OpenTofu/Pulumi, the major cloud CLIs, storage, databases, CI/CD, and several hosting platforms. A material gap remains around modern production control planes, GitOps, secrets managers, package publication, and several high-frequency developer CLIs.

Unlisted CLI discovery is useful for operator-created or uncommon tools, but it is not a substitute for first-class policy. A built-in Extension owns a stable ID, rules, action classes, risk classes, safer alternatives, references, and deterministic matcher semantics. It also handles wrappers, reordered global options, safe help forms, compound commands, Windows launchers, and policy controls without relying on per-machine discovery.

## Goals

1. Add first-class built-in coverage for the highest-value missing production and secrets CLIs.
2. Expand existing capability boundaries instead of creating duplicate identities where the existing Extension already owns the risk.
3. Preserve parse-once structured matching. No regex scanning of raw command text and no new command parser.
4. Review destructive, production-changing, secret-access, remote-execution, and publication actions while keeping help and read-only counterparts non-reviewable.
5. Support direct executables and common Node launchers where those CLIs are routinely invoked through `npx`, `bunx`, `npm exec`, `pnpm exec/dlx`, or `yarn dlx`.
6. Keep registry authority monotonic and compatible with managed Extension controls.

## New stable Extensions

| Extension ID | Primary executables | Security boundary |
| --- | --- | --- |
| `command.platform.cloudflare` | `wrangler` | Cloudflare deploy, delete, and secret mutation |
| `command.gitlab` | `glab` | GitLab project/release deletion, MR merge/rebase, CI/CD variable access |
| `command.secrets.vault` | `vault` | Vault secret reads/mutations and security administration |
| `command.database.prisma` | `prisma` | Destructive schema/data operations and production migration deployment |
| `command.platform.firebase` | `firebase` | Firebase production deploy and destructive app/data operations |
| `command.gitops.argocd` | `argocd` | Argo CD deletion and reconciliation mutations |
| `command.gitops.flux` | `flux` | Flux deletion/uninstall and reconciliation state changes |
| `command.package.dotnet` | `dotnet`, `nuget` | .NET/NuGet package ingress and package publication/deletion |
| `command.database.bigquery` | `bq` | BigQuery dataset/resource removal and replace-load |
| `command.platform.fly` | `fly`, `flyctl` | Fly.io deploy, destructive resource operations, secret mutation |
| `command.platform.railway` | `railway` | Railway deploy/delete, variable mutation, secret-populated shell |
| `command.configuration-management.ansible` | `ansible`, `ansible-playbook`, `ansible-pull`, `ansible-vault` | Remote host execution and Vault secret access |
| `command.cloud.digitalocean` | `doctl` | DigitalOcean destructive control-plane operations |
| `command.secrets.1password` | `op` | 1Password secret reads/injection and destructive object deletion |
| `command.package-publication` | `npm`, `pnpm`, `yarn`, `cargo`, `gem`, `twine`, `poetry` | Registry publish, upload, unpublish, and yank authority |
| `command.cloud-secrets` | `aws`, `gcloud`, `az` | Cross-provider secret reads and credential lifecycle changes |

## Existing Extension expansions

### `command.container-runtime`

Add Podman and nerdctl coverage for broad pruning and privileged container launch. Keep the existing stable Extension ID because the authority boundary is still container runtime control.

### `command.kubernetes-operations`

Add OpenShift `oc` support. The 3.2 metadata is upgraded to own:

- destructive operations (`oc delete`, `oc adm drain`)
- remote execution (`oc exec`, `oc rsh`)
- network tunnels (`oc port-forward`)
- remote file transfer (`oc rsync`)

The Extension remains Kubernetes/OpenShift operational authority rather than creating a parallel OpenShift identity.

### `command.infrastructure-as-code`

Add destructive teardown through:

- AWS CDK: `cdk destroy`, including Node package launchers
- AWS SAM: `sam delete`
- Serverless Framework: `serverless remove`, `sls remove`, including Node package launchers

### Database direct-client expansion

Add direct destructive SQL coverage for PostgreSQL `psql` and MySQL `mysql` one-shot command arguments beginning with `DROP`. Existing database Extension IDs remain authoritative.

## Operation families

### Cloudflare Wrangler

Review:
- Worker/Pages deployment
- Worker, Pages, D1, KV namespace, R2 bucket, Queue, and Hyperdrive deletion
- Worker secret set/delete/bulk changes

Safe:
- help
- listing/inspection commands

### GitLab

Review:
- repository/release/variable deletion
- MR merge and rebase
- variable get/set because values can contain credentials

Safe:
- repository/MR inspection
- help

### Vault and 1Password

Review secret reads as well as writes. The threat is disclosure to the agent, not only permanent deletion.

### GitOps

Review both destructive operations and reconciliation commands. A forced sync/reconcile can mutate production even when the command does not contain a delete verb.

### Package publication

Publication is a separate supply-chain authority from package installation. An agent that publishes, unpublishes, yanks, or uploads a package can affect downstream consumers. Dotnet/NuGet publication remains owned by `command.package.dotnet`; other major ecosystems are owned by `command.package-publication` to avoid duplicate action ownership.

### Ansible

Do not treat `--check` as a globally safe variant. Individual tasks can opt out of check mode. Only help/version observer forms are explicitly safe at the command boundary.

## Matching architecture

Implementation must:

- use `ExecutableMatcher` / `ExecutablePathSetMatcher` and existing database structured matchers;
- preserve canonical shell parsing and compound-command semantics;
- use conservative executable/keyword index hints;
- recognize `.cmd` and `.exe` launchers via shared matcher helpers;
- explicitly model common Node CLI wrappers instead of parsing raw command text;
- use safe variants only for documented side-effect-free forms;
- allow multiple Extensions to emit evidence, with existing policy precedence deciding the final action.

The direct-extension catalog is assembled from one shared rule set so an augmentation rule can attach to an existing direct Extension without duplicating its stable metadata. Later specs override earlier metadata for the same ID, which allows release-specific capability expansion while retaining one registry identity.

Core Extensions are assembled separately; common CLI rules are also supplied to core assembly so Podman/nerdctl rules attach to `command.container-runtime`.

## Safety requirements

For every operation family:

- destructive/production/secret forms must reach inspection and runtime review;
- `--help` and supported short-help forms must remain `no_match`;
- read/list/status operations must remain `no_match` unless an existing independent rule requires review;
- global options before or after the operation must not bypass matching;
- Node launchers must preserve the same security result as direct execution;
- compound commands must retain every independent dangerous match;
- malformed or unknown option placement must never imply safety;
- no command text, secret value, path, or environment value is persisted in Extension metadata.

## Compatibility

- Existing IDs are not renamed.
- Existing rules are retained.
- New action classes are introduced only for new capability boundaries and the expanded Kubernetes/OpenShift boundary.
- Package Firewall behavior for already-supported ecosystems is unchanged.
- `.NET/NuGet` is a direct command Extension in this increment; full NuGet advisory/lockfile Package Firewall support is a separate supply-chain engine expansion and is not required to land first-class command authority.

## Non-goals

This increment does not attempt to first-class every executable on a developer workstation. Common read-only utilities such as `grep`, `jq`, `sed`, `awk`, formatters, bundlers, and ordinary build tools remain governed by existing shell/filesystem/data-flow protections when they participate in a risky flow.

The following are intentionally left as a subsequent wave unless they are required to fix a discovered overlap while implementing this PR: SOPS, Doppler, Infisical, Django management commands, Rails DB commands, `dotnet ef`, Alembic, Flyway/Liquibase, dbt, Oracle OCI CLI, Hetzner `hcloud`, Nix, SwiftPM, Dart/Flutter Pub, Hex/Mix, Conan, and vcpkg.

## Acceptance criteria

- All listed new Extension IDs are present in the built-in registry with rules and authoritative reference URLs.
- Podman/nerdctl rules are owned by `command.container-runtime`.
- OpenShift rules are owned by `command.kubernetes-operations`, whose metadata declares every new action/risk class.
- CDK/SAM/Serverless teardown is owned by `command.infrastructure-as-code`.
- direct PostgreSQL/MySQL DROP execution is owned by the existing database Extensions.
- direct and Node-wrapper forms are covered where applicable.
- focused regression tests prove reviewed and safe forms.
- registry/catalog/permission tests pass.
- formatting, lint, type, security, Sonar, and the full release/3.2 CI matrix pass without exclusions or weakened thresholds.
