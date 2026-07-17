# HOL Guard Enterprise Packet

This packet explains what Guard controls, where customers see those controls in
the product, and which exports security and GRC teams can request without
engineering narration.

Guard Cloud is optional. Local Guard continues to enforce policy, write
receipts, and operate without sign-in. Cloud adds synced memory, team RBAC,
integrations, exports, and admin workflows on top of the same local runtime.

Related docs:

- [Local Guard vs Guard Cloud](./local-vs-cloud.md)
- [Harness support matrix](./harness-support.md)
- [Enterprise event taxonomy](./enterprise-event-taxonomy.md)
- [Enterprise export examples](./enterprise-export-examples.md)
- [MDM compatibility PRD](./mdm-compatibility-prd.md)
- [MDM compatibility implementation TODO](./mdm-compatibility-todo.md)
- [MDM deployment and Intune contract](./mdm-deployment.md)
- [MDM proxy, private CA, and endpoint contract](./mdm-networking.md)
- [MDM release evidence template](./mdm-release-evidence-template.md)
- [Self-protection and deletion detection PRD](./self-protection-prd.md)
- [Self-protection implementation TODO](./self-protection-todo.md)

## Control maps

Each map lists the control, the enforcement layer, and where the customer can
review it in Guard Cloud or local runtime output.

### AI agent risk

| Control | Local Guard | Guard Cloud | Customer view |
| --- | --- | --- | --- |
| Harness discovery and attach | Detects configured harnesses and records runtime sessions | Syncs session health and stale coverage | **Agents**, **Home** |
| Tool-call interception | Evaluates shell, MCP, skill, and file actions before side effects | Stores searchable receipts and decision history | **Evidence**, **Inbox** |
| Approval paths | Native harness approval, local approval center, terminal resolution | Delegated approvals and team routing | **Inbox**, **Controls** |
| Agent identity and tokens | Local daemon identity and scoped tokens | Workspace-scoped agent registry and RBAC | **Agents**, **Team** |
| Trust and drift signals | Local policy and inventory diff detection | Trust score, incidents, intelligence findings | **Intelligence**, **Incidents** |

### MCP and skill risk

| Control | Local Guard | Guard Cloud | Customer view |
| --- | --- | --- | --- |
| MCP server inventory | Parses descriptors, commands, transports, and dependencies | Syncs inventory snapshots over time | **Agents**, **Evidence** |
| Skill inventory | Parses `SKILL.md`, install intent, and declared tools | Syncs skill drift and review history | **Agents**, **Evidence** |
| Descriptor and schema drift | Detects hash changes and material risk deltas | Requires reapproval when drift is high-risk | **Inbox**, **Controls** |
| Tool poisoning and shadowing checks | Local evaluators flag hidden instructions and collisions | Incident routing for high-confidence drift | **Incidents**, **Intelligence** |
| Package intent inside skills | Blocks risky install instructions before execution | Receipts and firewall linkage | **Firewall**, **Evidence** |

### Supply-chain risk

| Control | Local Guard | Guard Cloud | Customer view |
| --- | --- | --- | --- |
| Package manager shims | Intercepts npm, pnpm, pip, and other supported managers | Firewall UI and synced evaluations | **Firewall** |
| Feed freshness and source health | Local feed checks and stale warnings | Feed health indicators in Cloud | **Firewall**, **Controls** |
| Policy evaluation | Local block, warn, monitor, and exception paths | Shared policy memory and simulator | **Controls**, **Firewall** |
| Audit export | Local receipts include package intent metadata | Workspace audit export API | **Firewall**, API export |

### Local enforcement

| Control | Local Guard | Guard Cloud | Customer view |
| --- | --- | --- | --- |
| Launch interception | Blocks or warns before risky commands run | Mirrors decisions after sync | Local daemon, **Evidence** |
| Policy version pinning | Local policy files and presets | Team policy packs and workspace scope | **Controls** |
| Receipts and explain output | Signed local receipts with redacted summaries | Searchable history and exports | **Evidence** |
| Cloud outage independence | Enforcement continues without Cloud sign-in | Sync catches up when Cloud returns | **Home**, **Protect** |

### Evidence and export

| Control | Local Guard | Guard Cloud | Customer view |
| --- | --- | --- | --- |
| Receipt manifest export | Redacted local summaries | `/api/guard/receipts/export` | **Evidence** export |
| AI-BOM export | Inventory redaction in export builder | Workspace-scoped AI-BOM bundle | **Evidence**, API |
| Action explanation fields | Shared explanation contract in receipts | Inspector and export surfaces | **Evidence**, **Incidents** |
| Integrity manifest | Local export checksum metadata | Enterprise manifest helper in portal | Export bundle header |
| SIEM forwarding | Not required for local protection | Generic **Webhook** integration (available) | **Settings** → Integrations |

### Notification and incident response

| Control | Local Guard | Guard Cloud | Customer view |
| --- | --- | --- | --- |
| High-severity routing | Local alerts and approval center | Slack, email, PagerDuty, Jira, GitHub, webhook | **Settings**, **Incidents** |
| Incident timeline | Local receipt linkage | Attack-path header, owner, remediation checklist | **Incidents** |
| External work linkage | N/A locally | Jira, GitHub, PagerDuty, Slack refs on incidents | **Incidents** |
| Delivery records | Local notification attempts when configured | Integration health and retry status | **Settings** → Integrations |

Catalog-only observability providers (Datadog, Splunk, Sentinel) are labeled
**Planned** in Guard Cloud. Customers can still forward the canonical
`guard.siem.v1` payload through the available **Webhook** integration today.

## Workspace controls

| Control | Where enforced | Customer view |
| --- | --- | --- |
| Personal vs team workspace scope | Cloud auth and workspace queries | **Settings**, workspace switcher |
| Viewer / member / admin / owner RBAC | API route guards | **Team**, **Settings** |
| Service principal ownership | Token and principal registry | **Agents** |
| Billing entitlements | Plan config and checkout | **Billing** |
| Audit read/export permissions | Supply-chain and evidence routes | API + **Evidence** |

## Buyer FAQ

**Does Guard require Cloud sign-in for local protection?**  
No. Local interception, policy, receipts, and approval paths work without Cloud.

**What does a paid Cloud plan add?**  
Synced history, searchable activity, team RBAC, integrations, exports, longer
retention, and admin workflows.

**Where do we see a blocked package install?**  
**Firewall** for evaluation details, **Evidence** for receipts, **Incidents**
when severity warrants routing, and export APIs for GRC archives.

**Can we send events to Splunk or Datadog today?**  
Use the available **Webhook** integration with the canonical event schema in
[Enterprise event taxonomy](./enterprise-event-taxonomy.md). Native Splunk,
Datadog, and Sentinel connectors remain catalog **Planned** until setup,
delivery, retry, and tests ship for each provider.

## Source references

- Guard architecture: [architecture.md](./architecture.md)
- Incident response: [incident-response.md](./incident-response.md)
- Remediation patterns: [remediation.md](./remediation.md)
- Cloud API inventory: `hol-points-portal/docs/guard-cloud-api-inventory.generated.md`
