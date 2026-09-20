# HOL Guard extension directory

HOL Guard 3 groups command protection into inspectable Extensions. Each Extension owns a stable capability boundary,
its rule metadata, safer alternatives, and the evidence it contributes to Guard's policy decision. Extensions detect
and explain command facts; they do not grant authority, execute commands, or replace Guard policy.

Use this directory to discover the built-in coverage shipped by the current source tree. The tables are generated
from the same validated registry used by runtime hooks, `command explain`, the local dashboard, and catalog APIs, so
the documentation cannot silently drift from the product.

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
- **Built in**: a reviewed detector in the canonical local registry.
- **Package Firewall**: package operations delegated to Guard's supply-chain enforcement surface.

<!-- BEGIN GENERATED EXTENSION DIRECTORY -->

### Core safety

| Extension | What it protects | Rules | Protection model |
| :--- | :--- | ---: | :--- |
| `command.container-runtime` | Reviews container lifecycle, cleanup, execution, network, and persistent-data operations that can expose credentials or mutate host state. | 25 | Built in |
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
| `command.cloud.digitalocean` | Reviews destructive DigitalOcean control-plane operations through doctl. | 1 | Built in |
| `command.cloud.gcp` | Reviews a validated gcloud operation matrix for permanent resource deletion across stable and supported release tracks. | 1 | Built in |
| `command.dns.aws` | Reviews AWS Route 53 hosted-zone, record, health-check, traffic-policy, DNSSEC, and Resolver deletions. | 6 | Built in |
| `command.dns.azure` | Reviews Azure public DNS, private DNS, virtual-network link, and DNS resolver deletion through Azure CLI. | 6 | Built in |
| `command.dns.gcp` | Reviews gcloud Cloud DNS managed-zone, record-set, policy, and response-policy deletions and updates. | 6 | Built in |
| `command.infrastructure-as-code` | Reviews teardown through Terraform, OpenTofu, Pulumi, AWS CDK, AWS SAM, and Serverless Framework. | 3 | Built in |
| `command.kubernetes-operations` | Reviews Kubernetes/OpenShift mutations, remote execution, tunnels, file transfer, and security changes. | 33 | Built in |
| `command.load-balancer` | Reviews load-balancer, target-group, listener, and forwarding-rule deletion through supported cloud CLIs. | 1 | Built in |

### Data and resilience

| Extension | What it protects | Rules | Protection model |
| :--- | :--- | ---: | :--- |
| `command.backup.borg` | Reviews Borg operations that delete, prune, or recreate archives. | 1 | Built in |
| `command.backup.rclone` | Reviews rclone operations that delete, move, purge, or synchronize data. | 1 | Built in |
| `command.backup.restic` | Reviews restic operations that remove snapshots or repository data. | 1 | Built in |
| `command.backup.velero` | Reviews Velero operations that delete backup data or recovery records. | 1 | Built in |
| `command.database.bigquery` | Reviews bq operations that remove resources or replace destination data. | 1 | Built in |
| `command.database.mongodb` | Reviews restore operations that drop and replace collections. | 2 | Built in |
| `command.database.mysql` | Reviews mysqladmin database removal operations. | 2 | Built in |
| `command.database.postgresql` | Reviews explicit PostgreSQL database removal commands. | 2 | Built in |
| `command.database.prisma` | Reviews destructive resets, direct SQL, data-loss pushes, and production migrations. | 2 | Built in |
| `command.database.redis` | Reviews Redis key deletion and database flush commands. | 1 | Built in |
| `command.database.sqlite` | Reviews SQLite restore operations that replace database content. | 2 | Built in |
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
| `command.platform.cloudflare` | Reviews Cloudflare deployment, resource deletion, and secret mutation through Wrangler. | 2 | Built in |
| `command.platform.firebase` | Reviews production deployment and destructive Firebase application and data operations. | 3 | Built in |
| `command.platform.fly` | Reviews Fly.io production deploys, destructive resource operations, and secret mutation. | 4 | Built in |
| `command.platform.heroku` | Reviews app destruction, pipeline promotion, and release rollback. | 2 | Built in |
| `command.platform.netlify` | Reviews site deletion and production deployments. | 2 | Built in |
| `command.platform.railway` | Reviews Railway deployment, deletion, variable mutation, and secret-populated shell access. | 4 | Built in |
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
| `command.package.dotnet` | Reviews package dependency ingress plus NuGet publication and deletion. | 3 | Built in |
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
| `command.mcp-filesystem` | Reviews official filesystem MCP tools. Off until you turn it on. | 0 | External opt-in |
| `command.skill-sunset` | Reviews the canonical Skill Sunset audit surface and its local report and viewer side effects. Experiment execution and npm launcher policy remain outside this extension. | 1 | External opt-in |

### Other extensions

| Extension | What it protects | Rules | Protection model |
| :--- | :--- | ---: | :--- |
| `command.blitcp` | Reviews blitcp copies that leave the host, elevate privileges, or skip verification. | 4 | External opt-in |
| `command.cloud-secrets` | Reviews secret retrieval and credential lifecycle mutations across AWS, Google Cloud, and Azure CLIs. | 2 | Built in |
| `command.configuration-management.ansible` | Reviews remote Ansible execution and access to encrypted Ansible Vault material. | 2 | Built in |
| `command.framework.laravel` | Reviews destructive Artisan database wipes, migration resets, and queue purges. | 5 | Built in |
| `command.gitlab` | Reviews GitLab deletion, merge/rebase, and CI/CD variable access through glab. | 4 | Built in |
| `command.gitops.argocd` | Reviews destructive GitOps administration and live reconciliation mutations through argocd. | 3 | Built in |
| `command.gitops.flux` | Reviews destructive Flux administration and forced reconciliation state changes. | 2 | Built in |
| `command.noodle` | Reviews request and collection execution through the Noodle terminal REST client. | 1 | External opt-in |
| `command.ollama` | Reviews Ollama commands that publish models to a registry or remove local model data. | 2 | External opt-in |
| `command.package-publication` | Reviews publish, upload, unpublish, and yank operations across common package ecosystems. | 2 | Built in |
| `command.probe` | Reviews HTTP execution and OpenCollection workspace mutations through the Probe CLI. | 8 | External opt-in |
| `command.repo2nb` | Reviews repo2nb commands that can overwrite an existing destination directory or silently drop untracked notebook cells. | 2 | External opt-in |
| `command.secrets.1password` | Reviews secret reads, secret injection, and destructive object deletion through op. | 3 | Built in |
| `command.secrets.vault` | Reviews Vault secret reads, destructive secret mutation, and security administration. | 4 | Built in |

<!-- END GENERATED EXTENSION DIRECTORY -->

## Contribute

Start with the [Extension contribution guide](contributing.md). It covers proposal quality, stable identity design,
matcher constraints, safe-counterpart tests, privacy, validation, and the review rubric. New command coverage enters
the vetted built-in registry; Guard does not import executable detector code from workspaces or downloaded bundles.

Use the [Extension proposal issue form](../../../.github/ISSUE_TEMPLATE/command-extension-proposal.yml) before a
large implementation so maintainers can confirm scope and avoid overlapping IDs.

## Architecture and authority

- [Command Extension architecture](../command-extension-architecture.md)
- [Extension precedence and minimum actions](../command-extension-precedence.md)
- [Command Extension threat model](../command-extension-threat-model.md)
- [Local Extensions and protection settings](../managed-controls-local-extensions.md)
