import { fetchExtensionControlApi } from "./guard-api";
import {
  normalizeEffectiveExtensionControls,
  normalizeExtensionCatalog,
  normalizeExtensionControlLayer,
} from "./extension-controls-normalize";
import {
  normalizeExtensionMutationApply,
  normalizeExtensionMutationPreview,
} from "./extension-control-preview-normalize";
import { normalizeEffectiveExtensionControlProjection } from "./extension-control-projection-normalize";

export type ExtensionControlState = "enabled" | "disabled";
export type GuardTreatment = "allow" | "warn" | "review" | "require-reapproval" | "sandbox-required" | "block";
export type ExtensionRiskTier = "low" | "medium" | "high" | "critical";
export type ExtensionRuleMode = "required" | "enforce" | "review" | "monitor" | "disabled";
export type EffectiveControlState = "allowed" | "blocked";
export type ExplicitControlState = "inherited" | "enabled" | "disabled";

export type ExtensionRuleSafeVariant = {
  variant_id: string;
  title: string;
  matcher_kind: string;
};

export type ExtensionRule = {
  rule_id: string;
  rule_version: number | string;
  title: string;
  description: string;
  severity: ExtensionRiskTier;
  risk_classes: string[];
  action_classes: string[];
  safer_alternatives: string[];
  default_mode: ExtensionRuleMode;
  matcher_kind: string;
  safe_variants: ExtensionRuleSafeVariant[];
  compatibility_fallback: boolean;
};

export type ExtensionPermission = {
  permission_id: string;
  schema_version: number;
  extension_id: string;
  implementation_version: string;
  label: string;
  description: string;
  risk_tier: ExtensionRiskTier;
  baseline_floor: GuardTreatment;
  default_enabled: boolean;
  configurable: boolean;
  fixed_reason: string | null;
  typed_capabilities: string[];
  action_classes: string[];
  rule_ids: string[];
  dependencies: string[];
  conflicts: string[];
  implied_permissions: string[];
  introduced_version: string;
  deprecated: boolean;
  replacement_permission_id: string | null;
  safer_guidance: string[];
  example_command: string | null;
  family: string | null;
};

export type ExtensionCatalogItem = {
  schema_version: number;
  extension_id: string;
  name: string;
  description: string;
  enabled: boolean;
  required: boolean;
  source: "built-in" | "local-admin" | "signed-cloud";
  version: string;
  aliases: string[];
  dependencies: string[];
  conflicts: string[];
  delegated_protection: string | null;
  ecosystem_ids: string[];
  executables: string[];
  project_markers: string[];
  reference_urls: string[];
  action_classes: string[];
  risk_classes: string[];
  safer_alternatives: string[];
  rule_count: number;
  rules: ExtensionRule[];
  permission_count: number;
  permissions: ExtensionPermission[];
};

export type ExtensionControlLayer = {
  schema_version: string;
  kind: "local-admin" | "signed-cloud";
  catalog_digest: string;
  global_lockdown: boolean;
  controls: Array<{
    target_kind: "extension" | "permission";
    target_id: string;
    state: ExtensionControlState;
  }>;
};

export type ExtensionCatalogResponse = {
  schema_version: string;
  control_schema_version?: string;
  catalog_digest: string;
  extensions: ExtensionCatalogItem[];
  limits?: {
    max_body_bytes?: number;
    max_controls?: number;
    max_observations?: number;
  };
};

export type EffectiveExtensionProjectionItem = {
  extension_id: string;
  effective_state: EffectiveControlState;
  local_state: ExplicitControlState;
  managed_state: ExplicitControlState;
  required: boolean;
  reason_codes: string[];
};

export type EffectivePermissionProjectionItem = {
  permission_id: string;
  extension_id: string;
  effective_state: EffectiveControlState;
  local_state: ExplicitControlState;
  managed_state: ExplicitControlState;
  configurable: boolean;
  fixed_reason: string | null;
  reason_codes: string[];
};

export type EffectiveExtensionControlProjection = {
  schema_version: "guard.daemon.extension-control-projection.v1";
  revision: number;
  catalog_digest: string;
  health: "unenrolled" | "protected" | "tampered" | "degraded-unacknowledged" | "degraded-acknowledged" | "recovery-required";
  extensions: EffectiveExtensionProjectionItem[];
  permissions: EffectivePermissionProjectionItem[];
};

export type EffectiveExtensionControls = {
  schema_version: string;
  health: EffectiveExtensionControlProjection["health"];
  revision: number;
  catalog_digest: string;
  global_lockdown: boolean;
  controls: Array<{
    target: { kind: "extension" | "permission"; target_id: string };
    state: ExtensionControlState;
  }>;
  layers: ExtensionControlLayer[];
  failures: Array<{ code: string; detail?: string; layer_kind?: string }>;
  projection?: EffectiveExtensionControlProjection;
};

export type ExtensionControlHistoryItem = {
  revision: number;
  previous_revision: number;
  occurred_at: string;
  catalog_digest: string;
  layers: ExtensionControlLayer[];
};

export type ExtensionControlHistoryResponse = {
  schema_version: "guard.daemon.extension-control-history.v1";
  revision: number;
  catalog_digest: string;
  items: ExtensionControlHistoryItem[];
};

export type ExtensionMutationPayload = {
  previous_revision: number;
  catalog_digest: string;
  layers: ExtensionControlLayer[];
  actor_id: string;
  idempotency_key: string;
  nonce: string;
  approval_password?: string;
  approval_totp_code?: string;
  session_nonce?: string;
  proof_id?: string;
};

export type ExtensionSemanticPreviewWarning = {
  code: string;
  message: string;
  target_id?: string;
  count?: number;
};

export type ExtensionSemanticPreviewTarget = {
  target: { kind: "extension" | "permission"; target_id: string };
  extension_id: string;
  extension_name?: string;
  label: string;
  before_explicit: ExplicitControlState;
  after_explicit: ExplicitControlState;
  before_effective: EffectiveControlState;
  after_effective: EffectiveControlState;
  baseline_risk?: string;
  baseline_floor?: string;
  affected_permission_ids: string[];
  affected_rule_ids: string[];
  affected_extension_ids?: string[];
  dependency_permission_ids?: string[];
  implied_permission_ids?: string[];
  conflict_permission_ids?: string[];
  provenance?: string[];
  warnings: ExtensionSemanticPreviewWarning[];
};

export type ExtensionSemanticPreview = {
  schema_version: "guard.daemon.extension-control-semantic-preview.v1";
  global_lockdown: { before: boolean; after: boolean; changed: boolean };
  changed_target_count: number;
  affected_permission_count: number;
  affected_rule_count: number;
  changed_targets: ExtensionSemanticPreviewTarget[];
  approval_required?: boolean;
  summary: {
    newly_blocked_permissions: number;
    newly_allowed_permissions: number;
    effective_change_count: number;
  };
};

export type ExtensionMutationPreview = {
  schema_version: string;
  previous_revision: number;
  next_revision: number;
  catalog_digest: string;
  canonical_diff_digest: string;
  global_lockdown: boolean;
  controls: number;
  semantic_preview: ExtensionSemanticPreview;
  proof_id?: string;
};

export type ExtensionMutationApplyResponse = {
  schema_version: string;
  status: "applied";
  revision: number;
  catalog_digest: string;
};

export class ExtensionControlApiError extends Error {
  constructor(
    message: string,
    readonly status: number,
    readonly code?: string,
    readonly recoveryAction?: string,
  ) {
    super(message);
  }
}

async function request(path: string, init?: RequestInit): Promise<unknown> {
  const response = await fetchExtensionControlApi(path, init);
  let payload: unknown;
  try {
    payload = await response.json();
  } catch {
    throw new ExtensionControlApiError(`Guard returned invalid JSON (${response.status})`, response.status);
  }
  if (!response.ok) {
    const error = typeof payload === "object" && payload !== null ? payload as Record<string, unknown> : {};
    throw new ExtensionControlApiError(
      typeof error.error === "string" ? error.error : `Request failed (${response.status})`,
      response.status,
      typeof error.error === "string" ? error.error : undefined,
      typeof error.recovery === "object" &&
        error.recovery !== null &&
        typeof (error.recovery as Record<string, unknown>).action === "string"
        ? (error.recovery as Record<string, unknown>).action as string
        : undefined,
    );
  }
  return payload;
}

export async function fetchExtensionCatalog(): Promise<ExtensionCatalogResponse> {
  return normalizeExtensionCatalog(await request("/v1/extension-controls/catalog"));
}

export async function fetchEffectiveExtensionControls(): Promise<EffectiveExtensionControls> {
  const raw = await request("/v1/extension-controls/effective");
  const normalized = normalizeEffectiveExtensionControls(raw);
  if (typeof raw !== "object" || raw === null || Array.isArray(raw)) return normalized;
  const projectionValue = (raw as Record<string, unknown>).projection;
  if (projectionValue === undefined) return normalized;
  const projection = normalizeEffectiveExtensionControlProjection(projectionValue);
  if (
    projection.revision !== normalized.revision ||
    projection.catalog_digest !== normalized.catalog_digest ||
    projection.health !== normalized.health
  ) {
    throw new ExtensionControlApiError("Guard returned an inconsistent extension-control projection", 502);
  }
  return { ...normalized, projection };
}

export async function fetchExtensionControlHistory(): Promise<ExtensionControlHistoryResponse> {
  const raw = await request("/v1/extension-controls/history");
  if (typeof raw !== "object" || raw === null || Array.isArray(raw)) throw new ExtensionControlApiError("Guard returned invalid settings history", 502);
  const root = raw as Record<string, unknown>;
  if (root.schema_version !== "guard.daemon.extension-control-history.v1") throw new ExtensionControlApiError("Guard returned unsupported settings history", 502);
  if (!Number.isSafeInteger(root.revision) || (root.revision as number) < 0 || typeof root.catalog_digest !== "string") throw new ExtensionControlApiError("Guard returned invalid settings history metadata", 502);
  if (!Array.isArray(root.items) || root.items.length > 50) throw new ExtensionControlApiError("Guard returned too much settings history", 502);
  const items = root.items.map((value, index) => {
    if (typeof value !== "object" || value === null || Array.isArray(value)) throw new ExtensionControlApiError("Guard returned invalid settings history item", 502);
    const item = value as Record<string, unknown>;
    if (!Number.isSafeInteger(item.revision) || !Number.isSafeInteger(item.previous_revision) || typeof item.occurred_at !== "string" || typeof item.catalog_digest !== "string" || !Array.isArray(item.layers)) throw new ExtensionControlApiError("Guard returned invalid settings history item", 502);
    const layers = item.layers.map((layer, layerIndex) => normalizeExtensionControlLayer(layer, `history.items[${index}].layers[${layerIndex}]`));
    return {
      revision: item.revision as number,
      previous_revision: item.previous_revision as number,
      occurred_at: item.occurred_at,
      catalog_digest: item.catalog_digest,
      layers,
    };
  });
  return {
    schema_version: "guard.daemon.extension-control-history.v1",
    revision: root.revision as number,
    catalog_digest: root.catalog_digest,
    items,
  };
}

export async function recoverExtensionControlAuthority(credentials?: {
  approval_password?: string;
  approval_totp_code?: string;
}): Promise<EffectiveExtensionControls> {
  const raw = await request("/v1/extension-controls/recover-authority", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      session_nonce: crypto.randomUUID().replaceAll("-", ""),
      ...credentials,
    }),
  });
  const normalized = normalizeEffectiveExtensionControls(raw);
  if (typeof raw === "object" && raw !== null && !Array.isArray(raw) && (raw as Record<string, unknown>).projection !== undefined) {
    return { ...normalized, projection: normalizeEffectiveExtensionControlProjection((raw as Record<string, unknown>).projection) };
  }
  return normalized;
}

export async function acknowledgeDegradedExtensionControlAuthority(credentials?: {
  approval_password?: string;
  approval_totp_code?: string;
}): Promise<EffectiveExtensionControls> {
  const raw = await request("/v1/extension-controls/acknowledge-degraded", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      session_nonce: crypto.randomUUID().replaceAll("-", ""),
      ...credentials,
    }),
  });
  const normalized = normalizeEffectiveExtensionControls(raw);
  if (typeof raw === "object" && raw !== null && !Array.isArray(raw) && (raw as Record<string, unknown>).projection !== undefined) {
    return { ...normalized, projection: normalizeEffectiveExtensionControlProjection((raw as Record<string, unknown>).projection) };
  }
  return normalized;
}

export async function previewExtensionMutation(payload: ExtensionMutationPayload): Promise<ExtensionMutationPreview> {
  try {
    return normalizeExtensionMutationPreview(await request("/v1/extension-controls/preview", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    }));
  } catch (error) {
    if (error instanceof ExtensionControlApiError) throw error;
    throw new ExtensionControlApiError(error instanceof Error ? error.message : "Guard returned an invalid preview response", 502);
  }
}

export async function applyExtensionMutation(payload: ExtensionMutationPayload): Promise<ExtensionMutationApplyResponse> {
  try {
    return normalizeExtensionMutationApply(await request("/v1/extension-controls/apply", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    }));
  } catch (error) {
    if (error instanceof ExtensionControlApiError) throw error;
    throw new ExtensionControlApiError(error instanceof Error ? error.message : "Guard returned an invalid apply response", 502);
  }
}
