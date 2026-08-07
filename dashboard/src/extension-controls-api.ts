import { fetchExtensionControlApi } from "./guard-api";

export type ExtensionControlState = "enabled" | "disabled";

export type ExtensionCatalogItem = {
  extension_id: string;
  name: string;
  description: string;
  required: boolean;
  source: string;
  version: string;
  action_classes: string[];
  risk_classes: string[];
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
  catalog_digest: string;
  extensions: ExtensionCatalogItem[];
};

export type EffectiveExtensionControls = {
  schema_version: string;
  health: "unenrolled" | "protected" | "tampered";
  revision: number;
  catalog_digest: string;
  global_lockdown: boolean;
  controls: Array<{
    target: { kind: "extension" | "permission"; target_id: string };
    state: ExtensionControlState;
  }>;
  layers: ExtensionControlLayer[];
  failures: Array<{ code: string; detail: string }>;
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

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetchExtensionControlApi(path, init);
  const payload: unknown = await response.json();
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
  return payload as T;
}

export function fetchExtensionCatalog(): Promise<ExtensionCatalogResponse> {
  return request("/v1/extension-controls/catalog");
}

export function fetchEffectiveExtensionControls(): Promise<EffectiveExtensionControls> {
  return request("/v1/extension-controls/effective");
}

export function previewExtensionMutation(payload: ExtensionMutationPayload): Promise<Record<string, unknown>> {
  return request("/v1/extension-controls/preview", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
}

export function applyExtensionMutation(payload: ExtensionMutationPayload): Promise<Record<string, unknown>> {
  return request("/v1/extension-controls/apply", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
}
