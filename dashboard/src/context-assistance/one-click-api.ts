import { fetchWithGuardAuth } from "../guard-api";
import { isGuardDemoMode } from "../guard-demo";
import type { GuardContextAssistanceConfig } from "../guard-types";
import { ContextAssistanceApiError } from "./api";
import type { ContextProof } from "./workspaces-api";

const object = (v: unknown): v is Record<string, unknown> => v !== null && typeof v === "object" && !Array.isArray(v);

/** Save only the CIGAR preference through the ordinary settings route and its existing proof. */
export async function saveCigarPreference(
  config: GuardContextAssistanceConfig, proof?: ContextProof, signal?: AbortSignal,
): Promise<GuardContextAssistanceConfig> {
  if (isGuardDemoMode()) throw new ContextAssistanceApiError("demo_unavailable", "Turning on CIGAR requires a local Guard installation.");
  const timeout = AbortSignal.timeout(12_000);
  const response = await fetchWithGuardAuth("/v1/settings", {
    method: "POST", cache: "no-store", headers: { "Content-Type": "application/json" },
    signal: signal ? AbortSignal.any([signal, timeout]) : timeout,
    body: JSON.stringify({ settings: { context_assistance: config },
      ...(proof?.currentPassword ? { approval_password: proof.currentPassword } : {}),
      ...(proof?.totpCode ? { approval_totp_code: proof.totpCode } : {}) }),
  });
  const body: unknown = await response.json().catch(() => null);
  if (!response.ok) {
    const code = object(body) && typeof body.error === "string" && /^[a-z0-9_]{1,160}$/.test(body.error) ? body.error : "settings_unavailable";
    throw new ContextAssistanceApiError(code, response.status === 400 && object(body) && typeof body.message === "string"
      ? "Guard could not save this setting: " + body.message.slice(0, 200)
      : response.status === 403 ? "Guard needs your approval before this change."
      : "Guard did not confirm the saved setting. Refresh status before trying again.");
  }
  const saved = object(body) && object(body.settings) ? body.settings.context_assistance : null;
  if (!object(saved) || saved.schema_version !== 1 || typeof saved.enabled !== "boolean" || typeof saved.runtime_id !== "string") {
    throw new ContextAssistanceApiError("settings_payload_invalid", "Guard returned settings this page does not understand. Refresh status.");
  }
  return saved as GuardContextAssistanceConfig;
}
