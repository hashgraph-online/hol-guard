import {
  ProviderIntegrationApiError,
  safeHttpsUrl,
  type ProviderConnectPreview,
  type ProviderDetail,
} from "./provider-integrations-api";

/** What the dialog shows after a connect attempt (PRD 6.8). State only, never provider text. */
export type ConnectOutcome = "connected" | "key_invalid" | "unreachable" | "rate_limited" | "disabled" | "start_again";

/** A preview older than this is replaced before the key is sent, so its proof is never stale. */
const PROOF_MARGIN_MS = 10_000;

export function connectOutcome(code: string): ConnectOutcome {
  switch (code) {
    case "provider_key_invalid":
      return "key_invalid";
    case "provider_rate_limited":
      return "rate_limited";
    case "provider_capability_unavailable":
    case "provider_managed_policy_unavailable":
      return "disabled";
    case "provider_proof_invalid":
    case "provider_connect_superseded":
      return "start_again";
    default:
      return "unreachable";
  }
}

export const OUTCOME_TEXT: Record<ConnectOutcome, string> = {
  connected: "Connected. Guard checked the key with the provider.",
  key_invalid: "The provider rejected this key. Check it and paste it again.",
  unreachable: "Guard could not reach the provider. Nothing was saved. Try again later.",
  rate_limited: "The provider is limiting requests right now. Nothing was saved. Try again in a minute.",
  disabled: "Provider integrations are turned off on this device, so nothing was saved.",
  start_again: "This connect request is no longer valid. Review what is shared and connect again.",
};

/** The "Get a key" link: the manifest's https URL plus one static referral parameter. */
export function getKeyHref(obtainUrl: string | null): string | null {
  const safe = safeHttpsUrl(obtainUrl);
  if (!safe) return null;
  const url = new URL(safe);
  url.searchParams.set("referrer_id", "holguard");
  return url.toString();
}

function sameSet(left: readonly string[], right: readonly string[]): boolean {
  return left.length === right.length && [...left].sort().join("\n") === [...right].sort().join("\n");
}

/** Whether two previews would send the same facts to the same hosts. */
export function sameDisclosure(left: ProviderConnectPreview, right: ProviderConnectPreview): boolean {
  return sameSet(left.shares, right.shares) && sameSet(left.optInFacts, right.optInFacts) && sameSet(left.hosts, right.hosts);
}

export type ConnectSteps = {
  now: () => number;
  preview: () => Promise<ProviderConnectPreview>;
  connect: (proof: string) => Promise<ProviderDetail>;
};

export type ConnectResult =
  | { kind: "done"; outcome: ConnectOutcome; detail?: ProviderDetail }
  | { kind: "changed"; preview: ProviderConnectPreview };

/**
 * Send the key with a live proof. A preview near expiry is replaced first; when the replacement
 * would share different facts or call different hosts, nothing is sent and the person reviews it.
 */
export async function runProviderConnect(shown: ProviderConnectPreview, steps: ConnectSteps): Promise<ConnectResult> {
  try {
    let proof = shown.challenge;
    if (steps.now() > shown.expiresAtMs - PROOF_MARGIN_MS) {
      const fresh = await steps.preview();
      if (!sameDisclosure(shown, fresh)) return { kind: "changed", preview: fresh };
      proof = fresh.challenge;
    }
    const detail = await steps.connect(proof);
    return { kind: "done", outcome: detail.summary.state === "connected" ? "connected" : "disabled", detail };
  } catch (error) {
    const code = error instanceof ProviderIntegrationApiError ? error.code : "provider_request_failed";
    return { kind: "done", outcome: connectOutcome(code) };
  }
}
