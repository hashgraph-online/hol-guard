# HOL Guard extension directory

HOL Guard 3 groups command protection into inspectable Extensions. Each Extension owns a stable capability boundary,
its rule metadata, safer alternatives, and the evidence it contributes to Guard's policy decision. Extensions detect
and explain command facts; they do not grant authority, execute commands, or replace Guard policy.

Use this directory to discover coverage shipped by the current source tree.
The tables are generated from the catalog compiled by Rust from canonical JSON
sources. `command explain`, the local dashboard, and catalog APIs read the same
generated metadata; the native program owns command matching. Directory checks
verify that the tables match that catalog.

To add or update coverage, start with the [contribution guide](contributing.md)
and [native source workflow](../extension-contributions.md). Edit
`contributions/command-sources/command.<name>.json`, add portable fixtures, and
regenerate the projections. New Python detector modules are not the contribution
path. The [Extension Builder](../extension-builder/README.md) can create a review
kit from an exported CLI inventory or MCP tool list.

```bash
# List every Extension.
hol-guard command extensions

# Inspect one Extension and its stable rules.
hol-guard command extensions command.git --json

# Test a command without executing it or creating an approval.
hol-guard command explain 'git reset --hard HEAD~1'
```

Protection model meanings:

- **Required core**: an immutable minimum protection floor shipped by HOL Guard.
- **Built in**: reviewed native coverage in the compiled catalog.
- **Package Firewall**: package operations delegated to Guard's supply-chain enforcement surface.
- **External opt-in**: a contributed extension that remains off until enabled through Guard's controls.

<!-- BEGIN GENERATED EXTENSION DIRECTORY -->

### Core safety

| Extension | What it protects | Rules | Protection model |
| :--- | :--- | ---: | :--- |
| `command.container-runtime` | Reviews container lifecycle, cleanup, execution, network, and persistent-data operations that can expose credentials or mutate host state. | 21 | Built in |
| `command.data-protection` | Detects shell flows that can send credentials or local file contents to a network destination. | 2 | Built in |
| `command.encoded-execution` | Reviews decode-and-execute flows whose effective program is hidden from normal command inspection. | 1 | Built in |
| `command.filesystem` | Reviews recursive deletion and access-control changes across filesystem trees. | 2 | Required core |
| `command.git` | Reviews everyday Git porcelain plus local and remote operations that can discard work, replace history, refresh a remote Guard cannot verify, or read a staged index Guard cannot bound. | 39 | Required core |
| `command.guard-self-protection` | Prevents commands from authorizing their own Guard approval or weakening protected Guard state. | 1 | Required core |
| `command.kubernetes-secrets` | Reviews Kubernetes CLI operations that can reveal cluster or application secrets. | 1 | Built in |
| `command.shell-mutations` | Reviews destructive shell, Git, filesystem, redirection, and protected configuration mutations. | 5 | Built in |
| `command.system` | Reviews storage formatting and operating-system power-state mutations. | 1 | Required core |
| `command.windows` | Reviews destructive Windows storage and operating-system commands. | 1 | Required core |

### Cloud and infrastructure

| Extension | What it protects | Rules | Protection model |
| :--- | :--- | ---: | :--- |
| `command.api-gateway` | Reviews API and gateway deletion through supported cloud CLIs. | 1 | Built in |
| `command.cdn` | Reviews distribution, VPC origin, key-value-store, profile, and endpoint deletion through supported cloud CLIs. | 1 | Built in |
| `command.cloud.aws` | Reviews a validated AWS CLI operation matrix for permanent resource deletion and service termination across identity, compute, data, delivery, and control-plane services. | 1 | Built in |
| `command.cloud.azure` | Reviews a validated Azure CLI operation matrix for permanent resource deletion across subscription, identity, network, compute, application, data, messaging, and AI services. | 1 | Built in |
| `command.cloud.gcp` | Reviews a validated gcloud operation matrix for permanent resource deletion across stable and supported release tracks. | 1 | Built in |
| `command.dns.aws` | Reviews AWS Route 53 hosted-zone, record, health-check, traffic-policy, DNSSEC, and Resolver deletions. | 6 | Built in |
| `command.dns.azure` | Reviews Azure public DNS, private DNS, virtual-network link, and DNS resolver deletion through Azure CLI. | 6 | Built in |
| `command.dns.gcp` | Reviews gcloud Cloud DNS managed-zone, record-set, policy, and response-policy deletions and updates. | 6 | Built in |
| `command.infrastructure-as-code` | Reviews infrastructure teardown through Terraform, OpenTofu, and Pulumi. | 1 | Built in |
| `command.kubernetes-operations` | Reviews cluster mutations, remote execution, file transfer, tunnels, certificate decisions, and Helm lifecycle operations. | 28 | Built in |
| `command.load-balancer` | Reviews load-balancer, target-group, listener, and forwarding-rule deletion through supported cloud CLIs. | 1 | Built in |

### Data and resilience

| Extension | What it protects | Rules | Protection model |
| :--- | :--- | ---: | :--- |
| `command.backup.borg` | Reviews Borg operations that delete, prune, or recreate archives. | 1 | Built in |
| `command.backup.rclone` | Reviews rclone operations that delete, move, purge, or synchronize data. | 1 | Built in |
| `command.backup.restic` | Reviews restic operations that remove snapshots or repository data. | 1 | Built in |
| `command.backup.velero` | Reviews Velero operations that delete backup data or recovery records. | 1 | Built in |
| `command.database.mongodb` | Reviews restore operations that drop and replace collections. | 1 | Built in |
| `command.database.mysql` | Reviews mysqladmin database removal operations. | 1 | Built in |
| `command.database.postgresql` | Reviews explicit PostgreSQL database removal commands. | 1 | Built in |
| `command.database.redis` | Reviews Redis key deletion and database flush commands. | 1 | Built in |
| `command.database.sqlite` | Reviews SQLite restore operations that replace database content. | 1 | Built in |
| `command.database.supabase` | Reviews database reset and migration rollback commands. | 1 | Built in |
| `command.storage.aws-s3` | Reviews AWS CLI high-level S3 commands and S3 API object, bucket, access-control, and configuration operations including copy, list, sync, website, and deletion. | 14 | Built in |
| `command.storage.azure-blob` | Reviews Azure CLI storage commands including upload, list, copy, and deletion. | 6 | Built in |
| `command.storage.google-cloud` | Reviews Google CLI storage commands including copy, list, sync, and deletion. | 7 | Built in |
| `command.storage.minio` | Reviews MinIO Client commands including copy, list, mirror, and deletion. | 7 | Built in |

### Delivery and remote operations

| Extension | What it protects | Rules | Protection model |
| :--- | :--- | ---: | :--- |
| `command.cicd.circleci` | Reviews remote pipeline execution through CircleCI CLI. | 1 | Built in |
| `command.cicd.github` | Reviews workflow-run cancellation, deletion, and workflow disabling through GitHub CLI. | 2 | Built in |
| `command.cicd.gitlab` | Reviews remote pipeline cancellation through GitLab CLI. | 1 | Built in |
| `command.github` | Reviews distinct GitHub maintenance, content, merge, publication, workflow, and control effects. | 15 | Built in |
| `command.platform.heroku` | Reviews app destruction, pipeline promotion, and release rollback. | 2 | Built in |
| `command.platform.netlify` | Reviews site deletion and production deployments. | 2 | Built in |
| `command.platform.vercel` | Reviews deployment and project deletion plus production deployment, promotion, and rollback. | 2 | Built in |
| `command.remote.essh` | Reviews essh invocations that execute commands across a host group or delete cached hosts, keys, and workspaces. | 2 | External opt-in |
| `command.remote.rsync` | Reviews rsync options that delete destination data or remove synchronized source files. | 2 | Built in |
| `command.remote.scp` | Reviews SCP transfers that can overwrite local or remote destination files. | 1 | Built in |
| `command.remote.ssh` | Reviews SSH invocations that explicitly execute a remote command. | 2 | Built in |

### Managed services

| Extension | What it protects | Rules | Protection model |
| :--- | :--- | ---: | :--- |
| `command.email` | Reviews email identity, template, configuration-set, and contact-list deletion through AWS CLI. | 1 | Built in |
| `command.feature-flags` | Reviews permanent feature-flag deletion through LaunchDarkly CLI. | 1 | Built in |
| `command.messaging.kafka` | Reviews Kafka topic, group, offset, and record deletion operations. | 1 | Built in |
| `command.messaging.nats` | Reviews NATS stream, consumer, key-value, and object-store removal operations. | 1 | Built in |
| `command.messaging.rabbitmq` | Reviews RabbitMQ deletion and broker reset operations. | 1 | Built in |
| `command.monitoring` | Reviews alarm, dashboard, metric-stream, and alert deletion through supported cloud CLIs. | 1 | Built in |
| `command.payment` | Reviews product, coupon, customer, and webhook endpoint deletion through Stripe CLI. | 1 | Built in |
| `command.search.elasticsearch` | Reviews explicit DELETE requests to recognizable Elasticsearch API targets. | 1 | Built in |

### Package supply chain

| Extension | What it protects | Rules | Protection model |
| :--- | :--- | ---: | :--- |
| `command.package.go` | Routes Go module and tool installation requests through Guard's package firewall. | 0 | Package Firewall |
| `command.package.jvm` | Routes Maven and Gradle dependency operations through Guard's package firewall. | 0 | Package Firewall |
| `command.package.node` | Routes Node package installs and one-shot execution through Guard's package firewall. | 0 | Package Firewall |
| `command.package.php` | Routes Composer dependency operations through Guard's package firewall. | 0 | Package Firewall |
| `command.package.python` | Routes Python dependency installs and isolated package execution through Guard's package firewall. | 0 | Package Firewall |
| `command.package.ruby` | Routes RubyGem and Bundler dependency operations through Guard's package firewall. | 0 | Package Firewall |
| `command.package.rust` | Routes Cargo dependency and binary installation requests through Guard's package firewall. | 0 | Package Firewall |
| `command.package.system` | Routes operating-system package installation requests through Guard's package firewall. | 0 | Package Firewall |

### Specialized tools

| Extension | What it protects | Rules | Protection model |
| :--- | :--- | ---: | :--- |
| `command.mcp-agenthub` | Reviews AgentHub tools that run other coding agents (Codex, Claude Code, Antigravity, Aider, Goose), change or discard their work, apply it to the working tree, or send code to those agents' providers. Tools not listed are reviewed. Off until you turn it on. | 0 | External opt-in |
| `command.mcp-asdecided` | Read-only repository requirements, decisions, designs, roadmaps, and prompts for coding agents. Off until you turn it on. | 0 | External opt-in |
| `command.mcp-authyouragent` | Reviews the tools that drive a signed-in browser vault: navigate, click, type_text, press_key, select_option, go_back, fill_secret (types a saved password or TOTP code the agent never sees) and request_approval. Reads, status checks, take over and sign-out follow your normal Guard policy. The server also holds committing clicks for phone approval. Off until you turn it on. | 0 | External opt-in |
| `command.mcp-clipugc` | Reviews ClipUGC hosted MCP tools that spend the user's credits, permanently delete influencers, looks, clips or videos, or publish an influencer to the shared public cast. Read-only and free tools keep Guard's usual handling. Off until you turn it on. | 0 | External opt-in |
| `command.mcp-contribos` | Reviews open-source contribution tools: policy radar, issue briefs, pre-submit checks, review coaching, and contribution records. Off until you turn it on. | 0 | External opt-in |
| `command.mcp-enola` | Allows enola's read-only architecture query tools. Snapshot generation, baseline pinning, and snapshot diffing write enola's own .enola state and stay on Guard's usual handling. Matches uvx and pipx launches of the enola-cli package. Off until you turn it on. | 0 | External opt-in |
| `command.mcp-evernode-mcp` | Reviews Evernode MCP tools that look up live hosts on api.onledger.net or generate contract files, deploy commands, and an unsigned Hook install command. Offline linting, pattern advice, and lease math are allowed. The server never signs, submits, or holds keys. Off until you turn it on. | 0 | External opt-in |
| `command.mcp-filesystem` | Reviews official filesystem MCP tools. Off until you turn it on. | 0 | External opt-in |
| `command.mcp-instapods` | Reviews sensitive InstaPods pod, billing, command execution, and file-write tools for the official hosted MCP server. | 0 | External opt-in |
| `command.mcp-insumer` | Reviews the InsumerAPI tools that can spend money or credits or change merchant state: verification and trust calls that use credits or pay per call in USDC, payment registrations, API key and merchant creation, merchant configuration, domain verification and the public listing. Read-only lookups keep Guard's usual handling. Off until you turn it on. | 0 | External opt-in |
| `command.mcp-lattice-talk` | Cross-harness agent message bus over Redis — shared sessions, rooms, direct messages, and memory for AI coding agents. Messaging, session and room membership changes, cursor updates, and memory writes default to review; read-only discovery tools inherit. Off until you turn it on. | 0 | External opt-in |
| `command.mcp-loomdesk` | Reviews LoomDesk's planning tools, which return unsigned Robinhood Chain transactions (open, add to, change or close a liquidity position, a limit order, a swap, a new pool) for the caller's own wallet to sign. LoomDesk holds no keys and signs nothing. Read tools keep Guard's usual handling. Off until you turn it on. | 0 | External opt-in |
| `command.mcp-pr-ui-compare` | Reviews PR UI Compare tools that run project install and start commands, write artifacts outside the repository, and download Chromium or FFmpeg. Off until you turn it on. | 0 | External opt-in |
| `command.mcp-reaper` | Reviews destructive REAPER project-editing tools: batch track deletion, track template deletion, clearing every tempo marker, and multi-step undo. Off until you turn it on. | 0 | External opt-in |
| `command.mcp-vome-home-assistant` | Reviews Home Assistant, ESPHome and Node-RED tools that control devices, change configuration, install third-party code, manage users, read cameras, flash firmware or switch a hosted home's failover. Off until you turn it on. | 0 | External opt-in |
| `command.mcp-x-reader` | Reviews x-reader external/local content reads. Off until enabled. | 0 | External opt-in |
| `command.mcp-xahau-mcp` | Reviews Xahau MCP tools that read public Xahau JSON-RPC endpoints or emit unsigned transactions and Hook source a user could sign or deploy. Offline codec, Hook WASM analysis, and local VM tools are allowed. The server never signs, submits, or holds keys. Off until you turn it on. | 0 | External opt-in |
| `command.skill-sunset` | Reviews the canonical Skill Sunset audit surface and its local report and viewer side effects. Experiment execution and npm launcher policy remain outside this extension. | 1 | External opt-in |
| `command.tui-runner` | Reviews TUI Runner --reconfigure invocations, which overwrite a project's saved process configuration. Port cleanup, process spawning, and project scaffolding happen through TUI Runner's interactive menu after launch and are not observable command-line events, so this extension does not cover them. | 1 | External opt-in |

### Other extensions

| Extension | What it protects | Rules | Protection model |
| :--- | :--- | ---: | :--- |
| `command.agentbridge` | Reviews AgentBridge CLI commands that can overwrite generated plugin files or execute with an attached app tool registry. | 2 | External opt-in |
| `command.answerloops` | Reviews answerLoops CLI commands that start a self-hosted instance with Docker Compose or download agent skill files into ./.claude/skills/. Help and usage output are not reviewed. | 2 | External opt-in |
| `command.appimg` | Conservative operation knowledge compiled from a contributor inventory. | 17 | External opt-in |
| `command.blitcp` | Reviews blitcp copies that leave the host, elevate privileges, or skip verification. | 4 | External opt-in |
| `command.blkcp` | Reviews blkcp commands that write directly to raw block devices or bypass safety guards with --force. | 2 | External opt-in |
| `command.cloudg` | Reviews cloud credential use, security scanner execution, and Terraform file generation through the CloudG CLI. | 3 | External opt-in |
| `command.cogext` | Reviews the cogext CLI's mutating commitment operations (add, fulfill, fail). Read-only commands (extract, list, get, stats) are not matched and remain automatic. Note: `cogext add` may initialize ~/.cogext on a fresh machine; that side effect is covered structurally because `add` is in the reviewed set. | 3 | External opt-in |
| `command.cs` | Reviews cs (Claude Sessions) commands that launch Claude Code in another folder, write pin or archive files, or send session text to a model for a recap. Read-only commands (ls, show) are not matched. | 4 | External opt-in |
| `command.ctty` | Reviews ctty remote execution (batch exec and bare-host SSH), file transfers (put/get/scp), SFTP/FTP/WebDAV mutations, and local inventory writes (add/edit/move/import), while leaving read-only inspection unmatched. | 7 | External opt-in |
| `command.digline` | Reviews digline commands that spend model calls, write under .digline/, or expose a way to change the approved baseline. digline is a regression gate for LLM applications, the approved reference lives in your repo. | 6 | External opt-in |
| `command.errand` | Requires Errand 0.4.2 or later. Reviews job execution (any operand-bearing invocation) and `fetch --apply`; flag-only and help invocations remain automatic. Conservative port of the v1 detector: declarative matchers cannot exclude known read-only subcommands, so operand-bearing calls like `errand ps` also review. | 2 | External opt-in |
| `command.faf-cli` | Reviews faf-cli commands that write agent instruction files (AGENTS.md, CLAUDE.md, .cursorrules, GEMINI.md, Copilot instructions), add an MCP server to an agent's config, install git hooks, git drivers or CI workflows, send project context off the machine, or rewrite faf's own project files (project.faf, .fafb, soul.fafm, cards). Read-only commands (score, check, dna, context, drift, log, diff, convert, search, share, wjttc, info, formats, demo) are not matched by this extension; Guard's default handling for commands no rule matches still applies to them. Covers the `faf` and `faf-cli` executables; npx, bunx, pnpx, pnpm, yarn, npm exec, yarn exec, npm x, bun x, pnpm dlx and yarn dlx launches of either bin name; and versioned launches (`pkg@tag`) of the `faf-cli` npm package. | 5 | External opt-in |
| `command.framework.laravel` | Reviews destructive Artisan database wipes, migration resets, and queue purges. | 5 | Built in |
| `command.genclave` | Reviews gEnclave (ge) security enclave operations that mutate credentials, modify access policies, or unlock persistent sessions. | 3 | External opt-in |
| `command.gitsync` | Reviews gitsync's live mirror sync, server-side webhook rewrites, and service install/uninstall. `check`, `status`, and plain `hooks` do not match any rule here; Guard's default floor still applies to them since gitsync is not on the built-in safe-command list and no rule in this extension matches those subcommands. Every mutating subcommand covered here always requires review, even with --help, -h or --dry-run present, because gitsync's flag parser can silently drop those flags depending on argument order and this matcher engine cannot detect when that happened. | 2 | External opt-in |
| `command.google-workspace.gog` | Opt-in review of finite pinned gog CLI delivery, sharing, event, export, generic API and identity-override routes. This does not authenticate accounts or mediate provider execution. | 6 | External opt-in |
| `command.keibidrop` | Reviews kd commands that share a local file with a peer, write a peer's file to local disk, or set which peer identity the session accepts. | 3 | External opt-in |
| `command.kim` | Reviews kim commands that mutate the local reminder config, daemon state, or notification settings; read-only inspection stays automatic. | 16 | External opt-in |
| `command.kranz` | Reviews Kranz action execution, runtime lifecycle changes, configuration replacement, and retained evidence deletion. | 10 | External opt-in |
| `command.noodle` | Reviews request and collection execution through the Noodle terminal REST client. | 1 | External opt-in |
| `command.ollama` | Reviews Ollama commands that publish models to a registry or remove local model data. | 2 | External opt-in |
| `command.probe` | Reviews HTTP execution and OpenCollection workspace mutations through the Probe CLI. | 8 | External opt-in |
| `command.repo2nb` | Reviews repo2nb commands that can overwrite an existing destination directory or silently drop untracked notebook cells. | 2 | External opt-in |
| `command.repopy` | Reviews repopy CLI operations across repository cloning, dependency installation, remote Git linkage, and non-interactive workspace cleanup. | 3 | External opt-in |
| `command.routed` | Reviews host adapter changes, environment reconciliation, and updates through the Routed CLI. | 5 | External opt-in |
| `command.skill-base` | Reviews authenticated Skill Base CLI publications before local Skill files are uploaded as a new version. | 1 | External opt-in |
| `command.snoboard` | Reviews snoboard commands that write initiative.md or fetch from origin. validate, status, and next-number without --fetch only read and are not matched. fix --dry-run, --help, and --version exit without writing. Upstream CLI 0.1.0. | 3 | External opt-in |
| `command.syngraphe` | Reviews shared repository context initialization, document creation, state archiving, and agent policy creation through syngraphe or syg. | 4 | External opt-in |
| `command.theourgia` | Reviews Theourgia commands that run code through an external interpreter, delete blocks, install log segments, or change the committed store or a writer's drafts, while leaving the read-only verbs (outline, search, refs, read, grep, log, diff, check and the exports) unmatched. | 5 | External opt-in |
| `command.uivoid` | Reviews uivoid commands that create or reconfigure a live MCP server mapped from an existing API, rotate the credential it calls that API with, or write local session and skill files a later command or agent session will trust. | 5 | External opt-in |
| `command.vttforge` | Reviews VTTForge CLI commands that write a project: the scaffold, lint fixes, and the v14 migration written in place. The audit, the lint report and the migration preview stay unreviewed. | 3 | External opt-in |
| `command.xencode` | Reviews Xencode state-changing CLI operations that can mutate Git worktrees or the local Xencode plugin environment. This community coverage does not certify Xencode or every future CLI feature. | 4 | External opt-in |
| `command.xrpl-muse-skill` | Guards the xrpl-muse-skill ceremony: xrpl-trade builds unsigned transaction proposals and never signs; xrpl-sign --approve is the sole hash-bound, policy-gated signer; fresh installs stay read-only until the typed xrpl-trade live ceremony. Proposal, signing, and gate-transition commands review; read-only queries stay inert. | 7 | External opt-in |

<!-- END GENERATED EXTENSION DIRECTORY -->

## Contribute

Start with the [Extension contribution guide](contributing.md). It covers proposal quality, stable identity design,
matcher constraints, safe-counterpart tests, privacy, validation, and the review rubric. New command coverage enters
the vetted built-in registry; Guard does not import executable detector code from workspaces or downloaded bundles.

For a large implementation, open a draft pull request with the **Command extension** template early so
maintainers can confirm scope and avoid overlapping IDs before the implementation is complete.

## Architecture and authority

- [Command Extension architecture](../command-extension-architecture.md)
- [Extension precedence and minimum actions](../command-extension-precedence.md)
- [Command Extension threat model](../command-extension-threat-model.md)
- [Local Extensions and protection settings](../managed-controls-local-extensions.md)
