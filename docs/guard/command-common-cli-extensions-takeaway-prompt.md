# Takeaway Prompt: Finish HOL Guard 3.2 Common CLI Extensions

Continue the HOL Guard common-CLI first-class Extension work end to end.

Repository: `hashgraph-online/hol-guard`
Base branch: `release/3.2`
Feature branch: `feat/3.2-common-cli-extensions`

Read these files first:

- `docs/guard/command-common-cli-extensions-prd.md`
- `docs/guard/command-common-cli-extensions-todo.md`
- `src/codex_plugin_scanner/guard/runtime/command_common_cli_extensions.py`
- `tests/test_guard_command_common_cli_extensions.py`

The implementation must add first-class built-in coverage for Cloudflare Wrangler, full GitLab `glab` authority beyond CI cancellation, HashiCorp Vault, Prisma, Firebase, Argo CD, Flux, .NET/NuGet, BigQuery `bq`, Fly.io, Railway, Ansible, DigitalOcean `doctl`, 1Password `op`, package publication, and cross-cloud secret/credential operations.

Existing capability boundaries must be expanded rather than duplicated:

- Podman and nerdctl belong to `command.container-runtime`.
- OpenShift `oc` belongs to `command.kubernetes-operations`.
- AWS CDK, AWS SAM, and Serverless Framework teardown belongs to `command.infrastructure-as-code`.
- direct `psql` and `mysql` DROP operations belong to their existing database Extensions.

Preserve HOL Guard Extension invariants:

- parse once; do not scan raw shell text with a second parser;
- structured matcher evidence only;
- no Extension may grant authority or weaken another match;
- stable IDs and action/risk ownership must validate;
- safe variants must be explicit and side-effect-free;
- do not globally whitelist Ansible `--check`;
- handle wrappers, reordered options, Windows aliases, compound commands, and safe help forms;
- keep secret values, command text, local paths, and environment values out of persisted Extension metadata.

Use the GitHub connector for every repository read/write/review/CI action. Do not create GitHub issues. Before commenting on the PR, read existing maintainer comments/reviews and current contributor commits. Keep GitHub comments short, direct, and specific. Do not post repeated status comments.

Drive the PR through all review and CI failures. Fix root causes rather than weakening tests, lint, security, performance, coverage, Sonar, or native-runtime thresholds. Reconcile the feature branch with the latest `release/3.2` head before final certification if the base moves. Merge with the repository's normal merge style only after the exact PR head is green and actionable review threads are resolved.

When finished, update the TODO release-gate checkboxes to reflect the evidence that actually passed.
