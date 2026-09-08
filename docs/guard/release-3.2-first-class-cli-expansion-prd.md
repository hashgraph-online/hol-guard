# PRD: Release 3.2 First-Class CLI Expansion

Status: implementation
Base branch: `release/3.2`

## Problem

HOL Guard has strong command coverage for Git, Docker, Kubernetes/Helm, Terraform/OpenTofu/Pulumi, the three major cloud CLIs, common databases, storage tools, hosting CLIs, CI/CD CLIs, and package installation. Important production control planes still fall back to generic or unlisted-CLI handling, which loses typed destructive-operation semantics, safe counterparts, stable Extension IDs, and wrapper-aware policy evidence.

Release 3.2 should close the highest-value gaps without turning every popular executable into a permanent security boundary.

## Goals

1. Add first-class reviewed Extensions for high-blast-radius production, GitOps, secret, data, and deployment CLIs.
2. Expand existing capability boundaries where a new stable ID would fragment one security domain.
3. Preserve parse-once semantics and structured matcher evidence.
4. Keep help, preview, dry-run, status, list, and other documented side-effect-free forms non-reviewable where the CLI provides them.
5. Support native executable suffixes and common launcher forms where the existing matcher framework already does so.
6. Keep package installation delegated to Package Firewall and add the missing .NET/NuGet ecosystem.
7. Add regression coverage for destructive forms, safe counterparts, reordered global flags/options, Windows launchers, compound commands, and wrapper forms.

## New first-class Extension boundaries

### `command.platform.cloudflare`
Executables/launchers: `wrangler` and supported Node one-shot launchers.

Protect:
- Worker deploy/delete
- Pages deploy/project deletion
- D1 database deletion and destructive execution surfaces
- KV namespace/key deletion
- R2 bucket/object deletion
- Queue deletion
- secret put/delete and bulk secret mutation
- workflow destructive mutations where exposed by the CLI

### `command.gitlab`
Executable: `glab`.

Protect:
- project deletion
- merge request merge/rebase and other remote publication/state changes
- release/tag deletion
- CI/CD variable mutation and value retrieval
- other high-impact repository administration commands

Keep `command.cicd.gitlab` for the existing pipeline-specific compatibility boundary; overlapping evidence is acceptable and strongest policy wins.

### `command.secrets.vault`
Executable: `vault`.

Protect:
- KV secret read/write/delete/destroy/undelete
- token revoke and high-impact auth administration
- policy write/delete
- secret-engine disable and other destructive control-plane operations

### `command.database.prisma`
Executables/launchers: `prisma`, `npx prisma`, `pnpm prisma`, `pnpm dlx prisma`, `yarn prisma`, `bunx prisma`.

Protect:
- migrate deploy/reset/resolve operations that mutate production state
- `db push --accept-data-loss`
- explicit destructive/reset operations available in supported Prisma generations

### `command.platform.firebase`
Executable: `firebase` and common Node launchers.

Protect:
- production deploys
- hosting/site deletion or disablement
- functions deletion
- database/firestore destructive operations exposed by the CLI
- secret/config mutation

### `command.gitops.argocd`
Executable: `argocd`.

Protect:
- app sync with prune
- application deletion
- resource deletion
- rollback
- patch/update operations
- ApplicationSet deletion
- operation termination where it changes remote reconciliation state

### `command.gitops.flux`
Executable: `flux`.

Protect:
- reconcile operations that apply remote state
- delete operations
- suspend/resume
- uninstall

### `command.database.bigquery`
Executable: `bq`.

Protect:
- dataset/table/model/routine/reservation/transfer deletion
- recursive/forced removal
- load/query operations that replace or truncate destination data when structurally detectable

### `command.platform.fly`
Executables: `fly`, `flyctl`.

Protect:
- app destruction
- machine destruction
- deploy/release changes
- secret set/unset
- volume deletion

### `command.platform.railway`
Executable: `railway`.

Protect:
- project/service/environment deletion
- volume deletion
- production deploy/redeploy/restart where it changes remote state
- variable mutation and secret-bearing shell execution surfaces

### `command.configuration-management.ansible`
Executables: `ansible`, `ansible-playbook`, `ansible-pull`, `ansible-vault`.

Protect:
- remote execution/playbook application
- `ansible-pull` execution
- vault decrypt/view operations as secret access
- destructive inventory-wide operations when structurally identifiable

Do not globally treat `--check` as safe because tasks can override check mode.

### `command.cloud.digitalocean`
Executable: `doctl`.

Protect:
- Droplet, Kubernetes, database, load balancer, firewall, domain, volume, snapshot, app, registry, and other documented delete/destroy operations
- high-impact production mutations where a safe inspection counterpart exists

### `command.secrets.1password`
Executable: `op`.

Protect:
- `op read`
- item/document retrieval of secret material
- secret injection/execution surfaces such as `op run` and `op inject`
- destructive item/vault mutations where available

## Existing boundaries to expand

### `command.container-runtime`
Add Podman and nerdctl equivalents for destructive container/image/volume/network/system operations plus exec/run secret-bearing surfaces. Do not create separate product IDs when the capability is container-runtime administration.

### `command.kubernetes-operations`
Add OpenShift `oc` coverage for kubectl-compatible destructive, exec, copy, port-forward, rollout, scale, patch, apply/delete and OpenShift-specific administration operations.

### `command.infrastructure-as-code`
Add AWS CDK, SAM, and Serverless Framework destructive/deployment commands where they represent infrastructure or production control-plane mutation.

### Existing database Extensions
Add direct client mutation coverage where structurally safe to recognize:
- PostgreSQL `psql`
- MySQL `mysql`
- MongoDB `mongosh`
- SQLite one-shot SQL/meta-command mutation

### Cloud Extensions
Expand beyond deletion-only matrices for high-risk secret access and credential creation/rotation where the provider CLI has a distinct structured command path.

### Package supply chain
Add `command.package.dotnet` for NuGet/.NET installation through `dotnet` and `nuget`.

Add a distinct package-publication capability in a later slice if publication/yank/unpublish operations cannot cleanly share Package Firewall's install-only contract.

## Non-goals

- No permanent Extensions for ordinary text-processing/build utilities solely because they are popular.
- No raw-shell regex parser parallel to the canonical command model.
- No Extension may grant authority or bypass Guard policy.
- No broad allowlist for help/dry-run flags without command-specific semantics.
- No weakening of existing required-core floors.

## Acceptance criteria

- Every new stable Extension ID appears in the canonical registry and generated directory.
- Every dangerous operation family has at least one destructive regression and one documented safe/read-only counterpart where available.
- Windows `.cmd`/`.exe` launcher forms inherit portable executable matching.
- Node one-shot wrappers are covered for CLIs commonly distributed through npm.
- Compound commands retain evidence from every matching segment.
- Existing Extension IDs and rule IDs remain stable.
- Focused extension tests, registry tests, directory generation checks, Ruff, type checks, unit CI, security gates, and Sonar quality gate pass.
- No new-code duplication or coverage regressions violate repository quality gates.
