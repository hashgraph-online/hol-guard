import { fetchWithGuardAuth } from "../guard-api";
import { isRecord } from "../supply-chain-audit-result";

/**
 * Calls behind the Cloud actions settings page. The model in
 * cloud-actions-model.ts checks the shape of each answer.
 */

export type CloudActionsCheckOutcome =
  | { kind: "checked"; payload: unknown }
  | { kind: "wait"; retryAfterSeconds: number; message: string };

const STATUS_PATH = "/v1/cloud-actions/status";

async function failureMessage(response: Response, fallback: string): Promise<string> {
  const payload = (await response.json().catch(() => null)) as unknown;
  const message = isRecord(payload) ? payload["message"] : null;
  return typeof message === "string" && message.trim() ? message : fallback;
}

/** This computer's Cloud actions connection and the last check. The daemon answers without calling Guard Cloud. */
export async function fetchCloudActionsStatus(): Promise<unknown> {
  const response = await fetchWithGuardAuth(STATUS_PATH, { cache: "no-store" });
  if (!response.ok) {
    throw new Error(await failureMessage(response, `Request failed with ${response.status}`));
  }
  return (await response.json()) as unknown;
}

/** Ask Guard Cloud whether it offers Cloud actions. The daemon allows one check a minute. */
export async function checkCloudActionsNow(): Promise<CloudActionsCheckOutcome> {
  const response = await fetchWithGuardAuth(STATUS_PATH, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: "{}",
    cache: "no-store",
  });
  if (response.status === 429 || response.status === 409) {
    const payload = (await response.json().catch(() => null)) as unknown;
    const retry = isRecord(payload) ? payload["retry_after_seconds"] : null;
    const message = isRecord(payload) && typeof payload["message"] === "string" ? payload["message"] : null;
    // Waiting does not help a computer that is not connected; say so instead of counting down.
    if (isRecord(payload) && payload["error"] === "not_paired") {
      throw new Error(message ?? "This computer is not connected to Guard Cloud. Run hol-guard connect.");
    }
    return {
      kind: "wait",
      retryAfterSeconds: typeof retry === "number" && Number.isFinite(retry) && retry > 0 ? Math.min(retry, 60) : 10,
      message: message ?? "Guard is already checking. Try again shortly.",
    };
  }
  if (!response.ok) {
    throw new Error(await failureMessage(response, "Guard could not check Cloud actions. Try again."));
  }
  return { kind: "checked", payload: (await response.json()) as unknown };
}
