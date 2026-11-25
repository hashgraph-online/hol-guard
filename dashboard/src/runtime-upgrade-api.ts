import { fetchWithGuardAuth } from "./guard-api";
import { type GuardRuntimeUpgradeAdvice, normalizeRuntimeUpgradeAdvice } from "./runtime-upgrade-advice";

export class RuntimeUpgradeError extends Error {
  constructor(
    readonly status: number,
    readonly code: string | null,
  ) {
    super(runtimeUpgradeErrorMessage(code, status));
    this.name = "RuntimeUpgradeError";
  }
}

function runtimeUpgradeErrorMessage(code: string | null, status: number): string {
  switch (code) {
    case "runtime_upgrade_unavailable":
      return "Guard no longer offers this switch. Reload the review to see the current advice.";
    case "runtime_upgrade_version_mismatch":
      return "The advice changed since this page loaded. Reload the review and try again.";
    case "runtime_upgrade_failed":
      return "Guard could not update nvm's default version. Run the command below in a terminal instead.";
    default:
      if (status === 401 || status === 403) {
        return "This review link cannot change nvm's default. Open the review from Guard, or run the command below in a terminal.";
      }
      return `Guard could not switch the Node.js version (${status}).`;
  }
}

/** Asks Guard to make `version` nvm's default for the runtime behind this
 * review. Guard recomputes the advice first and refuses any other version. */
export async function switchRuntimeDefault(requestId: string, version: string): Promise<GuardRuntimeUpgradeAdvice | null> {
  const response = await fetchWithGuardAuth(`/v1/requests/${encodeURIComponent(requestId)}/runtime-upgrade`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ version }),
  });
  const payload = (await response.json().catch(() => null)) as unknown;
  const record = typeof payload === "object" && payload !== null ? (payload as Record<string, unknown>) : null;
  if (!response.ok) {
    throw new RuntimeUpgradeError(response.status, typeof record?.error === "string" ? record.error : null);
  }
  return normalizeRuntimeUpgradeAdvice(record?.runtime_upgrade);
}
