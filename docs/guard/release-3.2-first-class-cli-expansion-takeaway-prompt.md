# Takeaway prompt: Release 3.2 first-class CLI expansion

Use this prompt to resume or independently audit the work:

> Continue the HOL Guard release/3.2 first-class CLI expansion from the current implementation branch. Treat `release/3.2` as the only valid base. Read `docs/guard/release-3.2-first-class-cli-expansion-prd.md` and `docs/guard/release-3.2-first-class-cli-expansion-todo.md`, then inspect the current branch diff and every existing review comment before changing code.
>
> Finish first-class typed command coverage for Cloudflare Wrangler, full GitLab glab administration, HashiCorp Vault, Prisma, Firebase, Argo CD, Flux, BigQuery bq, Fly.io, Railway, Ansible, DigitalOcean doctl, and 1Password op. Expand existing boundaries rather than inventing duplicate IDs for Podman/nerdctl under `command.container-runtime`, OpenShift `oc` under `command.kubernetes-operations`, AWS CDK/SAM/Serverless Framework under `command.infrastructure-as-code`, direct database clients under their existing database Extensions, high-risk cloud secret/credential operations under their provider boundaries, and .NET/NuGet under Package Firewall.
>
> Preserve Guard's parse-once architecture. Do not add raw-shell regex parsing inside matchers, do not let an Extension grant authority, and do not weaken required floors. For every destructive or secret-bearing operation, add a structured matcher and a safe/read-only counterpart where the upstream CLI guarantees one. Support reordered global options, Windows launcher suffixes, compound commands, quoting, and supported Node one-shot launchers. Malformed or unknown syntax must never imply safety.
>
> Keep stable Extension IDs, risk/action classes, permissions, generated directory metadata, and tests in sync. Run focused extension tests first, then registry/directory generation checks, Ruff/format/type checks, full CI, security gates, native/runtime compatibility checks if touched, and Sonar. Fix every actionable review comment rather than waiving it. Do not create GitHub issues. Do not merge to main. Merge only into `release/3.2`, only after exact-head CI is green and review is clean.
