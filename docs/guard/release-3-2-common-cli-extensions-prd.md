# PRD: Release 3.2 common CLI first-class Extensions

## Status

Target branch: `release/3.2`

This PRD defines first-class command safety coverage for common production, secrets, GitOps, database, infrastructure, package, and hosting CLIs that were not fully modeled by the existing built-in Extension catalog.

## Problem

HOL Guard already has strong first-class coverage for Git/GitHub, Docker, Kubernetes/Helm, Terraform/OpenTofu/Pulumi, AWS/GCP/Azure, common databases, storage, CI/CD, and major package ecosystems. The remaining high-value gaps are CLIs that can deploy production code, mutate credentials, destroy remote state, execute across fleets, or alter package publication state.

Generic unlisted-CLI handling is intentionally narrower than a first-class Extension: it cannot safely model provider-specific subcommands, safe variants, package-runner wrappers, operation-specific risk classes, or stable permission identities. These capabilities need typed Extensions using the canonical parsed-command model.

## Goals

1. Add stable first-class Extension identities for common CLIs with distinct durable capability boundaries.
2. Expand existing Extension identities when a CLI belongs to an already-owned capability rather than creating duplicate policy ownership.
3. Preserve parse-once command semantics and structured matcher evidence.
4. Cover Windows launcher suffixes and supported Node runner forms where relevant.
5. Review destructive, secret-reading, remote-execution, production deployment, publication, and credential-lifecycle operations while preserving documented help, preview, and observer forms.
6. Keep every implementation file within repository size limits and keep catalog, tests, and documentation synchronized.

## New first-class Extension identities

- `command.platform.cloudflare`: Wrangler deployment, deletion, storage/database resource removal, and secret mutation.
- `command.gitlab`: GitLab project/release deletion, merge/rebase, and variable operations through `glab`.
- `command.secrets.vault`: HashiCorp Vault secret reads, mutation, token revocation, policy deletion, and auth/secrets-engine administration.
- `command.database.prisma`: Prisma destructive reset/direct execution/data-loss pushes and production migrations.
- `command.platform.firebase`: Firebase production deployment, destructive data/function/hosting operations, and secret mutation.
- `command.gitops.argocd`: Argo CD destructive administration and live reconciliation operations.
- `command.gitops.flux`: Flux destructive administration and reconciliation state changes.
- `command.package.dotnet`: .NET/NuGet dependency ingress and package publication/deletion.
- `command.database.bigquery`: `bq` dataset/table removal and replacement-style data loads.
- `command.platform.fly`: Fly.io app/Machine/volume destruction, deployment, rollback, and secret mutation.
- `command.platform.railway`: Railway project/volume destruction, deploy/redeploy/restart/down, variables, and secret-populated shells.
- `command.configuration-management.ansible`: Ansible remote execution and `ansible-vault` secret access/mutation.
- `command.cloud.digitalocean`: destructive `doctl` operations across compute, Kubernetes, database, network, storage, and app resources.
- `command.secrets.1password`: 1Password secret reads, injection/execution, and destructive object deletion.
- `command.package-publication`: publish/unpublish/yank/upload operations across npm/pnpm/Yarn/Cargo/RubyGems/Twine/Poetry and related package tooling.
- `command.cloud-secrets`: cloud secret retrieval and credential lifecycle operations spanning AWS, Google Cloud, and Azure CLIs.

## Existing Extension expansions

### `command.container-runtime`

Add Podman and nerdctl coverage without creating separate durable identities. Cover broad prune operations, forced/resource removal, ordinary and privileged execution, and relevant lifecycle operations with Docker-compatible semantics.

### `command.kubernetes-operations`

Add OpenShift `oc` coverage for deletion, drains, execution, tunnels, file transfer, apply/patch/scale/rollout mutations, and documented dry-run safe forms. Retain one Kubernetes capability boundary.

### `command.infrastructure-as-code`

Add AWS CDK, AWS SAM, and Serverless Framework teardown operations, including common Node runner aliases such as `npx cdk destroy`, `npm exec ... cdk destroy`, `npx serverless remove`, and `npx sls remove`.

### Existing database Extensions

Expand direct client coverage for destructive one-shot commands:

- PostgreSQL `psql -c/--command` destructive SQL.
- MySQL `mysql -e/--execute` destructive SQL.
- MongoDB `mongosh --eval` destructive collection/database operations.
- SQLite `sqlite3` destructive positional SQL and destructive restore/import commands.

## Package runner contract

Node-distributed CLIs must support the documented direct binary plus applicable `npx`, `bunx`, `npm exec`, `pnpm exec`, `pnpm dlx`, and Yarn dlx forms. Package-name and binary-name differences must not create bypasses, including `firebase-tools`/`firebase`, `@railway/cli`/`railway`, and `aws-cdk`/`cdk`.

## Safety contract

Every rule must:

- operate on the canonical parsed command model;
- emit evidence only and never grant authority;
- preserve the strongest matching policy floor;
- avoid scanning unrelated free-form shell text;
- keep help/version/read-only and documented preview forms non-reviewable where side-effect freedom is guaranteed;
- fail conservatively when option interpretation is ambiguous;
- publish stable rule IDs, action classes, risk classes, safer alternatives, and primary references.

Ansible `--check` is not treated as globally safe because individual tasks can opt out of check mode. Read-only modes such as `--version`, `--list-hosts`, `--syntax-check`, `--list-tasks`, and `--list-tags` must remain safe.

OpenShift dry-run exemptions must be command-specific and value-bounded. Do not globally exempt arbitrary `--dry-run` usage.

## Acceptance criteria

- All new identities appear in the built-in registry with non-empty references and rule ownership.
- Existing identities retain stable IDs while gaining additive rule coverage.
- Direct and Windows launcher forms are covered where applicable.
- Node runner wrapper regressions cover package-name/binary-name mismatches.
- Destructive and secret-bearing commands reach both side-effect-free inspection and runtime review.
- Help, version, observer, syntax-only, and documented dry-run commands remain `no_match` where safe.
- Mixed/compound commands retain all independent evidence.
- No new file exceeds repository size limits.
- Generated extension directory/catalog artifacts are synchronized.
- Focused tests, registry tests, full CI, security gates, Sonar/quality gates, and review checks pass on the exact PR head.

## Non-goals

- Creating separate durable IDs for Podman, nerdctl, OpenShift, CDK, SAM, or Serverless Framework where an existing capability already owns the policy boundary.
- Replacing the canonical command parser with regex scanning or a second parser.
- Treating every common utility as a first-class Extension merely because it is popular.
- Weakening existing required-core floors or managed controls.
