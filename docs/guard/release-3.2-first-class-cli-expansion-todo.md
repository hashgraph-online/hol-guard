# TODO: Release 3.2 First-Class CLI Expansion

Base branch: `release/3.2`

## Architecture and docs

- [x] Add PRD.
- [x] Add implementation TODO.
- [ ] Add takeaway prompt for continuation/handoff.
- [ ] Add new Extension catalog assembly module(s) without a second parser.
- [ ] Regenerate Extension directory.
- [ ] Keep stable IDs/action classes/risk classes covered by registry contracts.

## P0 first-class CLIs

- [ ] Cloudflare Wrangler: deploy/delete, Pages, D1, KV, R2, queues, secrets.
- [ ] GitLab glab: project/admin/merge/release/variable capability coverage beyond pipeline cancellation.
- [ ] HashiCorp Vault: KV secret read/write/delete/destroy, token revoke, policy mutation.
- [ ] Prisma: migrate/reset/deploy and `db push --accept-data-loss` across supported launchers.
- [ ] Firebase: deploy, hosting/site/function deletion, secret/config mutation.
- [ ] Argo CD: sync/prune, delete, rollback, resource deletion, patch/update.
- [ ] Flux: reconcile, delete, suspend/resume, uninstall.
- [ ] BigQuery bq: dataset/table/model/routine/reservation/transfer deletion and destructive replacement forms.
- [ ] Fly.io fly/flyctl: app/machine/volume destruction, deploy/release, secret mutation.
- [ ] Railway: project/service/environment/volume deletion, deploy/redeploy, variable mutation.

## P1 first-class CLIs

- [ ] Ansible: remote execution/playbooks/pull and ansible-vault secret access; do not trust `--check` globally.
- [ ] DigitalOcean doctl: destructive resource administration across major service families.
- [ ] 1Password op: secret reads/injection/execution and destructive secret-store mutation.

## Existing-boundary expansions

- [ ] `command.container-runtime`: Podman equivalents.
- [ ] `command.container-runtime`: nerdctl equivalents where grammar matches Docker/containerd semantics.
- [ ] `command.kubernetes-operations`: OpenShift `oc` kubectl-compatible and OpenShift-specific high-impact operations.
- [ ] `command.infrastructure-as-code`: AWS CDK destroy/deploy.
- [ ] `command.infrastructure-as-code`: AWS SAM deploy/delete where remote infrastructure state changes.
- [ ] `command.infrastructure-as-code`: Serverless Framework deploy/remove.
- [ ] PostgreSQL: direct `psql` destructive one-shot SQL where deterministic.
- [ ] MySQL: direct `mysql` destructive one-shot SQL where deterministic.
- [ ] MongoDB: `mongosh` destructive eval/file forms where deterministic.
- [ ] SQLite: broader destructive one-shot SQL/meta commands where deterministic.
- [ ] Cloud providers: first-class high-risk secret reads and credential creation/rotation.
- [ ] Package Firewall: add .NET/NuGet install ecosystem.

## Required test matrix

For every added operation family:

- [ ] destructive command reaches inspection evidence and runtime review;
- [ ] help/status/list/preview/dry-run remains safe when the upstream contract guarantees no mutation;
- [ ] global options before/after subcommands are handled;
- [ ] `.cmd` and `.exe` launchers behave the same as native names;
- [ ] Node-distributed CLIs support the launchers Guard already recognizes (`npx`, `bunx`, `pnpm`, `yarn`, npm exec/dlx variants as applicable);
- [ ] quoting and paths with spaces preserve structured matching;
- [ ] chained/compound commands do not erase evidence;
- [ ] malformed or unknown options never imply safety;
- [ ] extension/rule ownership remains stable;
- [ ] persisted evidence contains no raw secrets/paths/environment payloads.

## Validation and merge

- [ ] Focused extension tests pass.
- [ ] `tests/test_guard_command_extension_registry.py` passes.
- [ ] `tests/test_guard_command_extension_directory.py` passes.
- [ ] generated extension directory check passes.
- [ ] Ruff check/format pass.
- [ ] full unit CI passes.
- [ ] security gates pass.
- [ ] native/runtime compatibility gates pass where touched.
- [ ] Sonar quality gate passes without exclusions.
- [ ] all actionable review comments resolved.
- [ ] merge to `release/3.2` only after exact-head CI is green.
