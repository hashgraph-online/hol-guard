# Guard Enterprise Export Examples

This page lists export surfaces security and GRC teams can reference during
reviews. All examples are redacted by default.

## Export surfaces

| Export | API / surface | Contents |
| --- | --- | --- |
| Policy version | **Controls** UI + policy receipts | Active rules, owners, scopes, receipt links |
| Firewall evaluation | **Firewall** UI + `/api/guard/supply-chain/*` | Package, version, harness, policy version, decision |
| Receipt / evidence manifest | `/api/guard/receipts/export` | Redacted receipt summaries and filters |
| Incident timeline | **Incidents** UI + incident export | Attack-path header, owner, evidence refs, remediation |
| Trust score snapshot | **Intelligence** UI | Workspace risk posture summary |
| Notification delivery record | **Settings** → Integrations | Provider health, last delivery, retry state |
| Workspace audit events | `/api/guard/supply-chain/audit/export` | Supply-chain audit log (CSV/JSON) |
| AI-BOM bundle | Inventory export builder | MCP, skills, packages, policies with redaction metadata |
| Integrity manifest | Enterprise export manifest helper | SHA-256 checksums per export artifact |

## Integrity manifest (example)

```json
{
  "schemaVersion": "guard.enterprise-export.v1",
  "generatedAt": "2026-06-10T18:00:00.000Z",
  "workspaceId": "workspace_9d21",
  "artifacts": [
    {
      "exportType": "receipt-manifest",
      "contentSha256": "b3a8f2…",
      "recordCount": 128,
      "redaction": {
        "rawSecretsIncluded": false,
        "rawCommandsIncluded": false,
        "rawPromptsIncluded": false
      }
    }
  ]
}
```

## Canonical SIEM event (guard.siem.v1)

```json
{
  "eventVersion": "guard.siem.v1",
  "eventType": "package.blocked",
  "occurredAt": "2026-06-08T18:10:00.000Z",
  "severity": "critical",
  "workspaceId": "workspace_9d21",
  "receiptId": "package_receipt_01jz",
  "actor": { "actorType": "agent", "actorHash": "actor_agent_7f3a" },
  "subject": {
    "artifactType": "package",
    "artifactId": "package:npm/acme-risky-install",
    "ecosystem": "npm"
  },
  "redaction": {
    "rawCommandIncluded": false,
    "rawPromptIncluded": false,
    "secretMaterialIncluded": false
  },
  "routing": {
    "enterpriseTrigger": "siem_export_schema_request",
    "suggestedSink": "siem"
  }
}
```

## Webhook envelope (available today)

Use the **Webhook** integration in Guard Cloud to POST the canonical event to
your HTTPS endpoint:

```json
{
  "schemaVersion": "guard.webhook.v1",
  "event": { "... guard.siem.v1 object ..." },
  "delivery": {
    "provider": "webhook",
    "sentAt": "2026-06-10T18:00:00.000Z",
    "idempotencyKey": "delivery_01jz_example"
  }
}
```

## Vendor sink examples (schema mapping)

These examples show how to map `guard.siem.v1` into common SIEM shapes when
forwarding through your webhook receiver. Native connectors remain **Planned**
until provider setup and delivery tests ship.

### Splunk HEC-style

```json
{
  "time": 1717867800,
  "host": "guard-cloud",
  "source": "hol-guard",
  "sourcetype": "guard:siem:v1",
  "event": { "... guard.siem.v1 object ..." }
}
```

### Elastic ECS-style

```json
{
  "@timestamp": "2026-06-08T18:10:00.000Z",
  "event.kind": "event",
  "event.category": ["security"],
  "event.type": ["info"],
  "event.action": "package.blocked",
  "guard.event_version": "guard.siem.v1",
  "guard.workspace_id": "workspace_9d21",
  "guard.receipt_id": "package_receipt_01jz",
  "guard.redaction": {
    "raw_command_included": false,
    "raw_prompt_included": false,
    "secret_material_included": false
  }
}
```

### Microsoft Sentinel-style

```json
{
  "TimeGenerated": "2026-06-08T18:10:00.000Z",
  "AlertName": "Guard package blocked",
  "Severity": "High",
  "ExtendedProperties": {
    "guardEventVersion": "guard.siem.v1",
    "guardEventType": "package.blocked",
    "guardWorkspaceId": "workspace_9d21",
    "guardReceiptId": "package_receipt_01jz"
  }
}
```

### Datadog log-style

```json
{
  "ddsource": "hol-guard",
  "service": "guard-cloud",
  "message": "Guard package blocked",
  "guard": { "... guard.siem.v1 object ..." }
}
```

## Redaction rules (all exports)

Exports MUST NOT include:

- Raw shell commands or prompt bodies
- Bearer tokens, API keys, or `.env` contents
- Local filesystem paths under user home directories
- Raw email addresses in SIEM samples

Portal export builders attach explicit `redaction` metadata when fields are
removed or summarized.
