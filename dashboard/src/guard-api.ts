import type {
  GuardApprovalRequest,
  GuardArtifactDiff,
  GuardLocalStateSummary,
  GuardPolicyDecision,
  GuardReceipt,
  GuardRuntimeSummary,
  GuardSession,
  GuardSessionResume,
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

export async function fetchSessions(): Promise<GuardSession[]> {
  if (isGuardDemoMode()) {
    return [];
  }
  const payload = await readJson<{ items: GuardSession[] }>("/v1/sessions");
  return payload.items;
}

export async function fetchSessionResume(sessionId: string): Promise<GuardSessionResume> {
  if (isGuardDemoMode()) {
    throw new Error("Guard demo mode does not expose runtime sessions.");
  }
  return readJson<GuardSessionResume>(`/v1/sessions/${encodeURIComponent(sessionId)}/resume`);
}

export async function fetchRuntimeSummary(): Promise<GuardRuntimeSummary> {
  if (isGuardDemoMode()) {
    return {
      session: null,
      attachments: [],
      operations: [],
      activeOperation: null,
    };
  }
  const sessions = await fetchSessions();
  const activeSession = sessions[0] ?? null;
  if (activeSession === null) {
    return {
      session: null,
      attachments: [],
      operations: [],
      activeOperation: null,
    };
  }
  const resume = await fetchSessionResume(activeSession.session_id);
  return {
    session: resume.session,
    attachments: resume.attachments,
    operations: resume.operations,
    activeOperation: resume.operations[0] ?? null,
  };
}

export async function fetchLocalStateSummary(): Promise<GuardLocalStateSummary> {
  if (isGuardDemoMode()) {
    return {
      headline_state: "local_only",
      pending_approvals: 0,
      receipt_count: getDemoReceipts().length,
      sync_configured: false,
      latest_sync: null,
      latest_connect_state: null,
      runtime: {
        sessions: 0,
        operations: 0,
        latest_session: null,
        latest_operation: null,
      },
      portal_links: {},
      guidance: {
        title: "Local protection is active",
        body: "Guard is saving local evidence and will pause the next changed tool on this machine.",
        command: "hol-guard connect",
        primary_link: null,
      },
      updated_at: new Date().toISOString(),
    };
  }
  return readJson<GuardLocalStateSummary>("/v1/local-state");
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
