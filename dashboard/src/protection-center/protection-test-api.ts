import { fetchExtensionControlApi } from "../guard-api";

export type ProtectionTestMatch = {
  permission_id: string | null;
  extension_id: string;
  extension_name: string;
  rule_id: string;
  rule_title: string;
  description: string;
  severity: "low" | "medium" | "high" | "critical";
  risk_classes: string[];
};

export type ProtectionTestResult = {
  schema_version: "guard.daemon.extension-control-test.v1";
  decision: "allowed" | "ask-first" | "blocked";
  minimum_action: "allow" | "monitor" | "review" | "block";
  matched: boolean;
  module_matched: boolean;
  other_protection_matched: boolean;
  explanation: string;
  matches: ProtectionTestMatch[];
  safer_alternatives: string[];
  authority_health: string;
  revision: number;
  catalog_digest: string;
};

const DECISIONS = new Set(["allowed", "ask-first", "blocked"]);
const MINIMUM_ACTIONS = new Set(["allow", "monitor", "review", "block"]);
const SEVERITIES = new Set(["low", "medium", "high", "critical"]);

function record(value: unknown): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) throw new Error("Guard returned an invalid Test Lab response");
  return value as Record<string, unknown>;
}

function boundedString(value: unknown, field: string, limit = 512): string {
  if (typeof value !== "string" || !value.trim() || value.length > limit) throw new Error(`Guard returned an invalid ${field}`);
  return value;
}

function stringList(value: unknown, field: string, limit: number): string[] {
  if (!Array.isArray(value) || value.length > limit || !value.every((item) => typeof item === "string" && item.length <= 320)) {
    throw new Error(`Guard returned an invalid ${field}`);
  }
  return [...value] as string[];
}

function normalizeProtectionTestResult(value: unknown): ProtectionTestResult {
  const raw = record(value);
  if (raw.schema_version !== "guard.daemon.extension-control-test.v1") throw new Error("Guard returned an unsupported Test Lab response");
  if (typeof raw.decision !== "string" || !DECISIONS.has(raw.decision)) throw new Error("Guard returned an invalid Test Lab decision");
  if (typeof raw.minimum_action !== "string" || !MINIMUM_ACTIONS.has(raw.minimum_action)) throw new Error("Guard returned an invalid Test Lab action");
  if (typeof raw.matched !== "boolean" || typeof raw.module_matched !== "boolean" || typeof raw.other_protection_matched !== "boolean") {
    throw new Error("Guard returned invalid Test Lab match state");
  }
  if (!Array.isArray(raw.matches) || raw.matches.length > 32) throw new Error("Guard returned too many Test Lab matches");
  const matches = raw.matches.map((item) => {
    const match = record(item);
    if (typeof match.severity !== "string" || !SEVERITIES.has(match.severity)) throw new Error("Guard returned an invalid Test Lab severity");
    return {
      extension_id: boundedString(match.extension_id, "extension ID", 256),
      extension_name: boundedString(match.extension_name, "extension name", 120),
      rule_id: boundedString(match.rule_id, "rule ID", 256),
      permission_id: typeof match.permission_id === "string" && match.permission_id.trim() ? match.permission_id : null,
      rule_title: boundedString(match.rule_title, "rule title", 160),
      description: boundedString(match.description, "rule description", 320),
      severity: match.severity as ProtectionTestMatch["severity"],
      risk_classes: stringList(match.risk_classes, "risk classes", 16),
    };
  });
  if (typeof raw.revision !== "number" || !Number.isSafeInteger(raw.revision) || raw.revision < 0) throw new Error("Guard returned an invalid Test Lab revision");
  return {
    schema_version: "guard.daemon.extension-control-test.v1",
    decision: raw.decision as ProtectionTestResult["decision"],
    minimum_action: raw.minimum_action as ProtectionTestResult["minimum_action"],
    matched: raw.matched,
    module_matched: raw.module_matched,
    other_protection_matched: raw.other_protection_matched,
    explanation: boundedString(raw.explanation, "Test Lab explanation", 320),
    matches,
    safer_alternatives: stringList(raw.safer_alternatives, "safer alternatives", 8),
    authority_health: boundedString(raw.authority_health, "authority health", 64),
    revision: raw.revision,
    catalog_digest: boundedString(raw.catalog_digest, "catalog digest", 128),
  };
}

export async function testProtectionCommand(extensionId: string, command: string): Promise<ProtectionTestResult> {
  const response = await fetchExtensionControlApi("/v1/extension-controls/test", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ extension_id: extensionId, command }),
  });
  let payload: unknown;
  try {
    payload = await response.json();
  } catch {
    throw new Error(`Guard returned invalid JSON (${response.status})`);
  }
  if (!response.ok) {
    const raw = typeof payload === "object" && payload !== null && !Array.isArray(payload) ? payload as Record<string, unknown> : {};
    throw new Error(typeof raw.error === "string" ? raw.error.replaceAll("_", " ") : `Test Lab request failed (${response.status})`);
  }
  return normalizeProtectionTestResult(payload);
}

export { normalizeProtectionTestResult };