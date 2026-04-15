import type {
  GuardApprovalRequest,
  GuardArtifactDiff,
  GuardPolicyDecision,
  GuardReceipt,
  GuardRuntimeSnapshot
} from "./guard-types";
import {
  getDemoDiff,
  getDemoPolicy,
  getDemoReceipts,
  getDemoRequest,
  getDemoRequests,
  isGuardDemoMode
} from "./guard-demo";

async function readJson<T>(input: RequestInfo, init?: RequestInit): Promise<T> {
  const response = await fetch(input, init);
  if (!response.ok) {
    throw new Error(`Request failed with ${response.status}`);
  }
  return (await response.json()) as T;
}

export async function fetchRequests(): Promise<GuardApprovalRequest[]> {
  if (isGuardDemoMode()) {
    return getDemoRequests();
  }
  const payload = await readJson<{ items: GuardApprovalRequest[] }>("/v1/requests");
  return payload.items;
}

export async function fetchRuntimeSnapshot(): Promise<GuardRuntimeSnapshot> {
  if (isGuardDemoMode()) {
    const demoRequests = getDemoRequests();
    const demoReceipts = getDemoReceipts();
    return {
      generated_at: new Date().toISOString(),
      approval_center_url: "http://127.0.0.1:4455",
      runtime_state: {
        session_id: "demo-runtime",
        daemon_host: "127.0.0.1",
        daemon_port: 4455,
        started_at: new Date().toISOString(),
        last_heartbeat_at: new Date().toISOString(),
        approval_center_url: "http://127.0.0.1:4455"
      },
      pending_count: demoRequests.length,
      receipt_count: demoReceipts.length,
      items: demoRequests,
      latest_receipts: demoReceipts.slice(0, 10)
    };
  }
  return readJson<GuardRuntimeSnapshot>("/v1/runtime");
}

export async function fetchRequest(requestId: string): Promise<GuardApprovalRequest> {
  if (isGuardDemoMode()) {
    return getDemoRequest(requestId);
  }
  return readJson<GuardApprovalRequest>(`/v1/requests/${requestId}`);
}

export async function fetchReceipts(): Promise<GuardReceipt[]> {
  if (isGuardDemoMode()) {
    return getDemoReceipts();
  }
  const payload = await readJson<{ items: GuardReceipt[] }>("/v1/receipts");
  return payload.items;
}

export async function fetchLatestReceipt(
  artifactId: string,
  harness: string
): Promise<GuardReceipt | null> {
  if (isGuardDemoMode()) {
    return getDemoReceipts().find((entry) => entry.artifact_id === artifactId) ?? null;
  }
  const response = await fetch(
    `/v1/receipts/latest?harness=${encodeURIComponent(harness)}&artifact_id=${encodeURIComponent(artifactId)}`
  );
  if (response.status === 404) {
    return null;
  }
  if (!response.ok) {
    throw new Error(`Receipt request failed with ${response.status}`);
  }
  return (await response.json()) as GuardReceipt;
}

export async function fetchPolicy(harness: string): Promise<GuardPolicyDecision[]> {
  if (isGuardDemoMode()) {
    return getDemoPolicy(harness);
  }
  const payload = await readJson<{ items: GuardPolicyDecision[] }>(
    `/v1/policy?harness=${encodeURIComponent(harness)}`
  );
  return payload.items;
}

export async function fetchDiff(
  artifactId: string,
  harness: string
): Promise<GuardArtifactDiff | null> {
  if (isGuardDemoMode()) {
    return getDemoDiff(artifactId, harness);
  }
  const response = await fetch(
    `/v1/artifacts/${encodeURIComponent(artifactId)}/diff?harness=${encodeURIComponent(harness)}`
  );
  if (response.status === 404) {
    return null;
  }
  if (!response.ok) {
    throw new Error(`Diff request failed with ${response.status}`);
  }
  return (await response.json()) as GuardArtifactDiff;
}

export async function resolveRequest(input: {
  requestId: string;
  action: "allow" | "block";
  scope: string;
  workspace?: string;
  reason: string;
}): Promise<void> {
  if (isGuardDemoMode()) {
    return;
  }
  const actionPath = input.action === "allow" ? "approve" : "block";
  await readJson(`/v1/requests/${encodeURIComponent(input.requestId)}/${actionPath}`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json"
    },
    body: JSON.stringify({
      action: input.action,
      scope: input.scope,
      workspace: input.workspace || undefined,
      reason: input.reason || undefined
    })
  });
}
