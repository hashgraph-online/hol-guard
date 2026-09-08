# Takeaway prompt: Release 3.2 common CLI first-class Extensions

Use this prompt to resume the release/3.2 common CLI work without losing architectural or acceptance-test context.

```text
Work in hashgraph-online/hol-guard on the existing canonical PR for release/3.2 common CLI first-class Extensions. Do not open a duplicate PR and do not retarget to main.

Goal: finish the release/3.2 common CLI coverage end to end, resolve every valid review and CI blocker, and merge only when the exact PR head is clean.

Read first:
- docs/guard/release-3-2-common-cli-extensions-prd.md
- docs/guard/release-3-2-common-cli-extensions-todo.md
- docs/guard/extensions/contributing.md
- the current PR review threads and exact-head CI/check runs

Architecture rules:
- Preserve the canonical parse-once command model. Do not add raw-shell regex parsing as a parallel authority path.
- Match structured executable/subcommand/option semantics and emit evidence only. Guard policy remains authoritative.
- Use new stable Extension IDs only for distinct durable capabilities. Keep Podman/nerdctl under command.container-runtime, OpenShift under command.kubernetes-operations, CDK/SAM/Serverless under command.infrastructure-as-code, and direct database clients under existing database IDs.
- Preserve required-core and managed-control floors.
- Keep each source file within repository size limits.
- Add Windows launcher and supported Node-runner coverage when the CLI is commonly distributed through Node package runners.

New first-class identities to retain:
command.platform.cloudflare
command.gitlab
command.secrets.vault
command.database.prisma
command.platform.firebase
command.gitops.argocd
command.gitops.flux
command.package.dotnet
command.database.bigquery
command.platform.fly
command.platform.railway
command.configuration-management.ansible
command.cloud.digitalocean
command.secrets.1password
command.package-publication
command.cloud-secrets

Required existing-boundary expansions:
- Podman/nerdctl: prune, resource removal, run/exec, privileged execution.
- OpenShift oc: delete/drain, exec/rsh, port-forward, rsync, apply/patch/scale/rollout mutations with command-specific bounded dry-run safety.
- IaC: cdk, sam, serverless/sls teardown including npx/bunx/npm exec/pnpm/yarn runner forms and package-name/binary-name differences.
- Direct DB clients: psql -c/--command, mysql -e/--execute, mongosh --eval, sqlite3 positional destructive SQL/restore/import.
- Package publication: npm/pnpm/Yarn/Cargo/RubyGems/Twine/Poetry publish/unpublish/yank/upload forms.
- Cloud secrets/credentials: AWS, Google Cloud, and Azure secret retrieval plus access-key/service-account/app-credential lifecycle operations.

Known regressions that must be explicitly covered:
- npx cdk destroy
- npm exec -- cdk destroy
- npm exec --package=aws-cdk -- cdk destroy
- npx sls remove / bunx sls remove / pnpm dlx sls remove
- npx railway up and other railway-bin forms when package is @railway/cli
- dotnet add MyApp.csproj package Newtonsoft.Json
- yarn publish
- pnpm unpublish
- psql --command="DROP DATABASE production" and -cDROP variants
- mysql --execute="DROP DATABASE production" and -eDROP variants
- safe SELECT equivalents
- ansible --version / --list-hosts
- ansible-playbook --syntax-check / --list-tasks / --list-tags
- oc delete/apply/patch --dry-run=client or server only where documented safe

Do not globally treat ansible --check as safe because tasks may disable check mode.
Do not globally suppress any arbitrary --dry-run flag.

Review workflow:
1. Read all current unresolved review threads before commenting.
2. Fix valid findings in one coherent pass and add focused regressions.
3. Resolve only threads whose findings are actually addressed.
4. Re-run/reconcile automated review until Greptile is 5/5 with zero unresolved actionable comments if that check is configured for the PR.
5. Avoid repetitive status comments.

Merge gates:
- focused command tests green
- registry/directory/catalog contracts green
- generated extension docs/catalog synchronized
- ruff/format/quality and Sonar green
- CodeQL/security/release/installed verification green
- no unresolved actionable review comments
- branch reconciled with latest release/3.2 if base moved
- squash merge into release/3.2
- verify post-merge release/3.2 workflows

Do not return early merely because one check is pending or one reviewer is unavailable. Continue fixing everything that can be fixed in the current run and merge only when GitHub shows a genuinely safe merge state.
```
