# TODO: Release 3.2 common CLI first-class Extensions

Target branch: `release/3.2`

Completion requires code, tests, catalog metadata, generated documentation, review threads, and exact-head CI to agree on the same protection boundaries.

## Planning and contracts

- [x] Define stable new Extension identities and existing-boundary expansions in the PRD.
- [x] Keep Podman/nerdctl under `command.container-runtime`.
- [x] Keep OpenShift under `command.kubernetes-operations`.
- [x] Keep CDK/SAM/Serverless under `command.infrastructure-as-code`.
- [x] Keep direct database clients under their existing database Extension IDs.
- [x] Preserve canonical parse-once matcher architecture.

## New first-class Extensions

- [x] Cloudflare Wrangler.
- [x] GitLab `glab`.
- [x] HashiCorp Vault.
- [x] Prisma.
- [x] Firebase.
- [x] Argo CD.
- [x] Flux.
- [x] .NET/NuGet.
- [x] BigQuery `bq`.
- [x] Fly.io.
- [x] Railway.
- [x] Ansible and ansible-vault.
- [x] DigitalOcean `doctl`.
- [x] 1Password `op`.
- [x] Cross-ecosystem package publication.
- [x] Cloud secret and credential lifecycle operations.

## Existing-boundary expansions

- [x] Podman and nerdctl broad prune coverage.
- [ ] Podman and nerdctl resource removal parity (`rm`, `container rm`, `image rm`, `volume rm`, `network rm`).
- [ ] Podman and nerdctl ordinary `run`/`exec` first-class execution coverage.
- [x] Podman and nerdctl privileged run coverage.
- [x] OpenShift delete, drain, exec/rsh, port-forward, and rsync.
- [ ] OpenShift apply/patch/scale/rollout mutation coverage with bounded dry-run safe forms.
- [x] CDK/SAM/Serverless direct teardown coverage.
- [ ] CDK package/binary runner aliases (`aws-cdk` and `cdk`) across supported Node runners.
- [ ] Serverless `sls` aliases across supported Node runners.
- [x] PostgreSQL split `-c` direct DROP coverage.
- [x] MySQL split `-e` direct DROP coverage.
- [ ] PostgreSQL/MySQL equals-attached and short-attached one-shot SQL coverage.
- [ ] Broaden direct SQL destructive verbs beyond DROP where structurally safe to do so.
- [ ] Add MongoDB `mongosh --eval` destructive coverage.
- [ ] Add SQLite destructive one-shot SQL/restore/import coverage.

## Wrapper and grammar regressions

- [x] Wrangler Node runners.
- [x] Prisma Node runners.
- [x] Firebase package/binary aliases.
- [ ] Railway package/binary aliases (`@railway/cli` and `railway`).
- [ ] `npx cdk destroy`.
- [ ] `npm exec -- cdk destroy`.
- [ ] `npm exec --package=aws-cdk -- cdk destroy`.
- [ ] `npx sls remove`, `bunx sls remove`, and `pnpm dlx sls remove`.
- [ ] `dotnet add <PROJECT> package <PKG>` positional project form.
- [ ] `yarn publish`.
- [ ] `pnpm unpublish`.

## Safe variants and false positives

- [x] Help variants for new rules.
- [ ] Ensure `ansible --version` is safe.
- [ ] Ensure `ansible --list-hosts` is safe.
- [ ] Ensure `ansible-playbook --syntax-check` is safe.
- [ ] Ensure `ansible-playbook --list-tasks` and `--list-tags` are safe.
- [x] Do not globally mark Ansible `--check` as safe.
- [ ] Ensure `oc delete/apply/patch --dry-run=client|server` is safe only where documented.
- [ ] Add safe SELECT counterparts for all direct SQL matchers.
- [ ] Verify help flags cannot be forged through option values.

## Catalog and documentation

- [x] Split implementation modules below repository file-size limits.
- [x] Add PRD.
- [x] Add TODO.
- [x] Add takeaway prompt.
- [ ] Regenerate the built-in extension directory.
- [ ] Regenerate/export catalog artifacts if required by release/3.2 checks.
- [ ] Update test-suite ratchet only to observed exact-head values.
- [ ] Remove obsolete PR description language claiming planning documents are excluded.

## Review closure

- [ ] Resolve every non-outdated actionable review thread after the corresponding fix is on the branch.
- [ ] Resolve outdated threads whose findings are demonstrably fixed by current code.
- [ ] Re-run Greptile and reach 5/5 with zero unresolved actionable comments.
- [ ] Confirm Capy/Kilo/other configured review checks have no remaining actionable findings.
- [ ] Do not dismiss valid review findings merely to make the PR green.

## CI and merge

- [ ] Focused common CLI tests pass.
- [ ] Existing command-extension contract tests pass.
- [ ] Registry and directory tests pass.
- [ ] Ruff/format/quality gates pass.
- [ ] Sonar quality gate passes.
- [ ] CodeQL and security gates pass.
- [ ] Native/release/installed verification gates triggered by this PR pass.
- [ ] Every required exact-head check is success or an expected skip.
- [ ] Reconcile with the latest `release/3.2` head before merge if the base moves.
- [ ] Squash merge the canonical PR into `release/3.2`.
- [ ] Verify the resulting `release/3.2` commit and post-merge workflows are healthy.
