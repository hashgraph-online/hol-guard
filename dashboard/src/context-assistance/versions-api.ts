import { fetchWithGuardAuth } from "../guard-api";
import { isGuardDemoMode } from "../guard-demo";
import { ContextAssistanceApiError } from "./api";
import { parseContextAssistanceStatus } from "./status";
import type { ContextAssistanceStatus } from "./types";
import type { ContextProof } from "./workspaces-api";

export type CigarUpdatePreferences = {
  mode: "manual" | "notify" | "prepare";
  allow_preview: boolean;
  retain_last_good: boolean;
  pinned_build?: string;
};
export type CigarVersionsRequest =
  | { action: "releases" | "catalog" | "interpreters" | "jobs" | "preferences" }
  | { action: "job" | "cancel"; job_id: string }
  | { action: "refresh_catalog"; job_id: string }
  | { action: "import_catalog"; signed_catalog: string }
  | { action: "setup_interpreter"; job_id: string; build_id: string }
  | { action: "install"; job_id: string; build_id: string; interpreter_id: string }
  | { action: "prepare_switch"; job_id: string; target_runtime_id: string; expected_generation: string }
  | { action: "prepare_rollback"; job_id: string; expected_generation: string }
  | { action: "commit"; job_id: string; expected_generation: string; reconnect: boolean }
  | { action: "recover"; job_id: string; expected_generation?: string }
  | { action: "set_preferences"; expected_revision: string; preferences: CigarUpdatePreferences };

export type CigarVersionsReply = {
  state: ContextAssistanceStatus;
  result: Record<string, unknown>;
};
const object = (value: unknown): value is Record<string, unknown> =>
  value !== null && typeof value === "object" && !Array.isArray(value);
const readRoutes = {
  releases: "/v1/context-assistance/versions", catalog: "/v1/context-assistance/catalog",
  interpreters: "/v1/context-assistance/interpreters", jobs: "/v1/context-assistance/jobs",
} as const;
const noProof = new Set(["releases", "catalog", "interpreters", "jobs", "job", "cancel", "preferences"]);

export function parseCigarVersionsReply(value: unknown): CigarVersionsReply {
  if (!object(value) || value.schema !== "guard-cigar-versions-result.v1" || !object(value.result)) {
    throw new ContextAssistanceApiError("versions_payload_invalid", "Guard returned incompatible CIGAR update data. Refresh status.");
  }
  return { state: parseContextAssistanceStatus(value.state), result: value.result };
}

function errorMessage(code: string, status: number): string {
  if (status === 404) return "Update Guard to use CIGAR version controls.";
  if (status === 401) return "Reconnect to the local Guard session, then refresh CIGAR updates.";
  if (status === 403) return "Guard needs your approval before this change.";
  if (code.endsWith("outcome_unknown")) return "Guard may have accepted this operation. Refresh jobs before retrying.";
  if (code.endsWith("preferences_conflict") || code.endsWith("selection_conflict") || code.endsWith("context_stale")) {
    return "CIGAR settings changed. Refresh the current selection and jobs before trying again.";
  }
  if (code.endsWith("_busy") || code.endsWith("cleanup_pending")) return "Another CIGAR operation is finishing. Refresh jobs after it completes.";
  if (code.endsWith("recovery_required")) return "This CIGAR operation needs recovery. Refresh its job before choosing the next action.";
  if (code.endsWith("data_choice_required")) return "Saved CIGAR data needs an explicit choice before this selection can proceed.";
  return "CIGAR did not return a confirmed result. Refresh status and jobs before trying again.";
}

/** Opening metadata never starts SDK work. Mutations are explicit and never retried here. */
export async function requestCigarVersions(
  input: CigarVersionsRequest, proof?: ContextProof, signal?: AbortSignal,
): Promise<CigarVersionsReply> {
  if (isGuardDemoMode()) throw new ContextAssistanceApiError("demo_unavailable", "CIGAR updates require a local Guard installation.");
  const route = Object.hasOwn(readRoutes, input.action) ? readRoutes[input.action as keyof typeof readRoutes] : undefined;
  const timeout = AbortSignal.timeout(12_000);
  const credentials = noProof.has(input.action) ? undefined : proof;
  const response = await fetchWithGuardAuth(route ?? "/v1/context-assistance/versions", {
    cache: "no-store", signal: signal ? AbortSignal.any([signal, timeout]) : timeout,
    ...(route ? {} : { method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ input,
        ...(credentials?.currentPassword ? { approval_password: credentials.currentPassword } : {}),
        ...(credentials?.totpCode ? { approval_totp_code: credentials.totpCode } : {}),
      }),
    }),
  });
  const body: unknown = await response.json().catch(() => null);
  if (!response.ok) {
    const code = object(body) && typeof body.code === "string" && /^[a-z0-9_]{1,160}$/.test(body.code) ? body.code
      : object(body) && typeof body.error === "string" && /^approval_gate_[a-z0-9_]{1,140}$/.test(body.error) ? body.error
      : "context_assistance_unavailable";
    throw new ContextAssistanceApiError(code, errorMessage(code, response.status));
  }
  return parseCigarVersionsReply(body);
}
