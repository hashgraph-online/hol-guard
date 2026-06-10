# Guard Enterprise Event Taxonomy

Guard Cloud emits a normalized, redacted event shape for exports, webhook
delivery, and SIEM forwarding. The canonical schema version is `guard.siem.v1`.

## Required fields

| Field | Type | Description |
| --- | --- | --- |
| `eventVersion` | string | Always `guard.siem.v1` |
| `eventType` | enum | See event types below |
| `occurredAt` | ISO-8601 UTC | Event timestamp |
| `severity` | enum | `info`, `medium`, `high`, `critical` |
| `workspaceId` | string | Workspace scope for the event |
| `receiptId` | string | Linked receipt or audit record id |
| `actor.actorType` | enum | `human`, `agent`, `system` |
| `actor.actorHash` | string | Stable hashed actor identifier |
| `subject.artifactType` | enum | `receipt`, `approval`, `policy`, `incident`, `feed`, `package` |
| `subject.artifactId` | string | Stable artifact identifier |
| `subject.ecosystem` | string \| null | Package ecosystem when relevant |
| `redaction.rawCommandIncluded` | false | Raw shell commands are never exported |
| `redaction.rawPromptIncluded` | false | Raw prompts are never exported |
| `redaction.secretMaterialIncluded` | false | Secrets and tokens are never exported |
| `routing.suggestedSink` | enum | `siem`, `ticketing`, `case-management` |
| `routing.enterpriseTrigger` | string \| null | Sales-assist trigger when applicable |

## Event types

| `eventType` | Typical severity | Meaning |
| --- | --- | --- |
| `receipt.created` | info | Guard recorded a decision receipt |
| `approval.resolved` | medium | Human or delegated approval resolved |
| `policy.mutation` | medium | Workspace policy changed |
| `incident.created` | high | Guard opened an incident |
| `feed.degraded` | medium | Supply-chain feed stale or degraded |
| `package.blocked` | critical | Package install blocked by policy |

## Confidence and severity guidance

- **Severity** describes customer impact if the event is ignored.
- **Confidence** for incident and firewall events is stored on incident and
  evaluation records in Guard Cloud, not in raw command text.
- Export and webhook payloads use redacted summaries only. Confidence scores
  appear as numeric fields on incident exports, not as free-text model output.

## Identity fields

| ID | Scope | Notes |
| --- | --- | --- |
| `workspaceId` | Cloud workspace | Required on signed-in exports |
| `actor.actorHash` | Actor | Hashed; no email or display name in SIEM payload |
| `receiptId` | Audit trail | Join key across receipt, incident, and export manifests |
| Agent / device ids | Runtime | Available on receipt exports and incident timelines; omitted from default SIEM samples |

## Generic webhook schema versioning

Webhook deliveries SHOULD include:

```json
{
  "schemaVersion": "guard.webhook.v1",
  "event": { "... guard.siem.v1 fields ..." },
  "delivery": {
    "provider": "webhook",
    "sentAt": "2026-06-10T18:00:00.000Z",
    "idempotencyKey": "delivery_01jz_example"
  }
}
```

Breaking changes increment `guard.webhook.vN`. Non-breaking field additions stay
on the same major version.

## Vendor mapping

Guard ships sample mappings for common SIEM sinks in
`hol-points-portal/src/lib/guard/siem/guard-siem-vendor-formats.ts`. These are
schema examples for webhook forwarding; native Splunk, Elastic, Sentinel, and
Datadog integrations remain **Planned** in the integration catalog until each
provider has setup, delivery, retry, and test coverage.

See [Enterprise export examples](./enterprise-export-examples.md) for JSON
samples.
