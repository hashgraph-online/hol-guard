# TODO: Common CLI First-Class Extensions for HOL Guard 3.2

Base branch: `release/3.2`

## Architecture

- [x] Define stable IDs and capability boundaries in the PRD.
- [x] Keep Podman/nerdctl under `command.container-runtime`.
- [x] Keep OpenShift `oc` under `command.kubernetes-operations`.
- [x] Keep CDK/SAM/Serverless teardown under `command.infrastructure-as-code`.
- [x] Keep direct PostgreSQL/MySQL DROP under existing database IDs.
- [x] Add shared rule assembly so existing direct Extensions can receive augmentation rules without duplicate Extension IDs.
- [x] Allow later release-specific specs to override metadata for an existing direct ID while retaining one registry identity.
- [x] Feed common CLI augmentation rules into core Extension assembly for container-runtime expansion.

## New first-class Extensions

- [x] Cloudflare Wrangler: deploy, deletion, secret mutation.
- [x] GitLab glab: destructive admin, MR merge/rebase, variable access.
- [x] HashiCorp Vault: secret reads, secret mutation, token/policy/mount administration.
- [x] Prisma: migrate reset, direct SQL execution, `db push --accept-data-loss`, migrate deploy.
- [x] Firebase: production deploy plus destructive Functions/Firestore/RTDB/Hosting operations.
- [x] Argo CD: delete plus sync/rollback/patch/terminate-op.
- [x] Flux: delete/uninstall plus reconcile/suspend/resume.
- [x] .NET/NuGet: package add/install/restore plus NuGet push/delete.
- [x] BigQuery `bq`: remove and replace-load.
- [x] Fly.io: deploy, app/Machine/volume/IP destruction, secret mutation.
- [x] Railway: deploy/redeploy, delete, volume delete, variables, secret-populated shell.
- [x] Ansible: ad-hoc/playbook/pull execution and Ansible Vault access.
- [x] DigitalOcean doctl: destructive compute/Kubernetes/database/network/storage/app operations.
- [x] 1Password op: secret read/injection and destructive deletion.
- [x] Cross-ecosystem package publication: npm/pnpm/yarn/cargo/gem/twine/poetry.
- [x] Cross-cloud secret/credential authority: AWS/GCP/Azure secret reads and credential mutations.

## Existing coverage expansion

- [x] Podman prune and privileged run.
- [x] nerdctl prune and privileged run.
- [x] `oc delete` and `oc adm drain`.
- [x] `oc exec` / `oc rsh`.
- [x] `oc port-forward`.
- [x] `oc rsync`.
- [x] `cdk destroy`, including Node launcher forms.
- [x] `sam delete`.
- [x] `serverless remove` / `sls remove`, including Node launcher forms.
- [x] direct `psql` DROP.
- [x] direct `mysql` DROP.

## Wrapper and portability coverage

- [x] `.cmd` / `.exe` portable executable aliases through shared matcher helpers.
- [x] `npx` launcher support for Node CLIs.
- [x] `bunx` launcher support for Node CLIs.
- [x] `npm exec` launcher support for Node CLIs.
- [x] `pnpm exec` and `pnpm dlx` launcher support for Node CLIs.
- [x] `yarn dlx` launcher support for Node CLIs.
- [x] conservative global-option handling for cloud/control-plane CLIs.

## Safety regressions

- [x] Reviewed cases for every new Extension.
- [x] Reviewed cases for every existing-ID expansion.
- [x] Help variants remain safe.
- [x] Representative list/status/read-only commands remain safe.
- [x] Ansible `--version` remains safe.
- [x] Ansible `--check` is not globally whitelisted.
- [x] Direct SQL SELECT examples remain safe.
- [x] Registry metadata and references are asserted.

## Release gates

- [ ] Run focused common-CLI tests on the PR head.
- [ ] Run command Extension registry and permission catalog suites.
- [ ] Run the full release/3.2 CI matrix.
- [ ] Resolve all review comments with code or explicit evidence.
- [ ] Keep Sonar quality gate green without exclusions.
- [ ] Merge only when exact-head required CI is green.
