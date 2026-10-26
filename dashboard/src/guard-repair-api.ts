import { fetchWithGuardAuth } from "./guard-api";
import { isGuardDemoMode } from "./guard-demo";
import { isRecord } from "./supply-chain-audit-result";

export type GuardRepairCredentials = {
  approval_password?: string;
  approval_totp_code?: string;
};

export type GuardRepairStepStatus = "ok" | "changed" | "planned" | "skipped" | "error";

export type GuardRepairStep = {
  step: string;
  title: string;
  status: GuardRepairStepStatus;
  summary: string;
};

export type GuardRepairReport = {
  dry_run: boolean;
  status: "healthy" | "repaired" | "needs_repair" | "partial";
  summary: string;
  steps: GuardRepairStep[];
};

export type GuardHookRemovalHarness = {
  harness: string;
  hook_count?: number;
  files_with_hooks?: string[];
  adapter_uninstall?: string;
  swept_hook_count?: number;
};

export type GuardHookRemovalReport = {
  dry_run: boolean;
  status: "planned" | "nothing_to_remove" | "removed" | "partial";
  harnesses: GuardHookRemovalHarness[];
  removed_hook_count: number;
  backup_dir?: string | null;
  reinstall_command: string;
  post_state?: { clean: boolean; remaining_harnesses: GuardHookRemovalHarness[] };
};

export const HOOK_REMOVAL_CONFIRMATION = "remove-guard-hooks";

export class GuardRepairRequestError extends Error {
  readonly status: number;
  readonly code: string | null;

  constructor(status: number, code: string | null, message: string) {
    super(message);
    this.name = "GuardRepairRequestError";
    this.status = status;
    this.code = code;
  }
}

const STEP_STATUSES = new Set(["ok", "changed", "planned", "skipped", "error"]);

export function normalizeRepairReport(payload: unknown): GuardRepairReport {
  if (!isRecord(payload) || !Array.isArray(payload.steps) || typeof payload.status !== "string") {
    throw new GuardRepairRequestError(502, "invalid_response", "Guard returned an invalid repair result.");
  }
  const steps: GuardRepairStep[] = [];
  for (const item of payload.steps) {
    if (!isRecord(item) || typeof item.step !== "string") continue;
    steps.push({
      step: item.step,
      title: typeof item.title === "string" ? item.title : item.step,
      status: STEP_STATUSES.has(String(item.status)) ? (item.status as GuardRepairStepStatus) : "error",
      summary: typeof item.summary === "string" ? item.summary : "",
    });
  }
  return {
    dry_run: payload.dry_run === true,
    status: payload.status as GuardRepairReport["status"],
    summary: typeof payload.summary === "string" ? payload.summary : "",
    steps,
  };
}

function normalizeHarnessRows(value: unknown): GuardHookRemovalHarness[] {
  if (!Array.isArray(value)) return [];
  return value.flatMap((item) => {
    if (!isRecord(item) || typeof item.harness !== "string") return [];
    return [
      {
        harness: item.harness,
        hook_count: typeof item.hook_count === "number" ? item.hook_count : undefined,
        files_with_hooks: Array.isArray(item.files_with_hooks)
          ? item.files_with_hooks.filter((entry): entry is string => typeof entry === "string")
          : undefined,
        adapter_uninstall: typeof item.adapter_uninstall === "string" ? item.adapter_uninstall : undefined,
        swept_hook_count: typeof item.swept_hook_count === "number" ? item.swept_hook_count : undefined,
      },
    ];
  });
}

export function normalizeHookRemovalReport(payload: unknown): GuardHookRemovalReport {
  if (!isRecord(payload) || typeof payload.status !== "string") {
    throw new GuardRepairRequestError(502, "invalid_response", "Guard returned an invalid removal result.");
  }
  const postState = isRecord(payload.post_state)
    ? {
        clean: payload.post_state.clean === true,
        remaining_harnesses: normalizeHarnessRows(payload.post_state.remaining_harnesses),
      }
    : undefined;
  return {
    dry_run: payload.dry_run === true,
    status: payload.status as GuardHookRemovalReport["status"],
    harnesses: normalizeHarnessRows(payload.harnesses),
    removed_hook_count: typeof payload.removed_hook_count === "number" ? payload.removed_hook_count : 0,
    backup_dir: typeof payload.backup_dir === "string" ? payload.backup_dir : null,
    reinstall_command:
      typeof payload.reinstall_command === "string" ? payload.reinstall_command : "hol-guard install --all",
    post_state: postState,
  };
}

async function postJson(path: string, body: Record<string, unknown>): Promise<unknown> {
  const response = await fetchWithGuardAuth(path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  const payload = (await response.json().catch(() => null)) as unknown;
  if (!response.ok) {
    const code = isRecord(payload) && typeof payload.error === "string" ? payload.error : null;
    const message =
      isRecord(payload) && typeof payload.message === "string"
        ? payload.message
        : `Guard request failed with ${response.status}.`;
    throw new GuardRepairRequestError(response.status, code, message);
  }
  return payload;
}

function credentialFields(credentials?: GuardRepairCredentials): Record<string, string> {
  const fields: Record<string, string> = {};
  if (credentials?.approval_password !== undefined) fields.approval_password = credentials.approval_password;
  if (credentials?.approval_totp_code !== undefined) fields.approval_totp_code = credentials.approval_totp_code;
  return fields;
}

export async function runGuardRepair(options: {
  dryRun?: boolean;
  credentials?: GuardRepairCredentials;
} = {}): Promise<GuardRepairReport> {
  if (isGuardDemoMode()) {
    return {
      dry_run: options.dryRun === true,
      status: "healthy",
      summary: "Nothing needed repair.",
      steps: [{ step: "hooks", title: "Harness hooks", status: "ok", summary: "All managed hooks verified." }],
    };
  }
  return normalizeRepairReport(
    await postJson("/v1/repair", {
      dry_run: options.dryRun === true,
      ...credentialFields(options.credentials),
    }),
  );
}

export async function planGuardHookRemoval(): Promise<GuardHookRemovalReport> {
  if (isGuardDemoMode()) {
    return {
      dry_run: true,
      status: "planned",
      harnesses: [{ harness: "codex", hook_count: 3 }],
      removed_hook_count: 0,
      reinstall_command: "hol-guard install --all",
    };
  }
  return normalizeHookRemovalReport(await postJson("/v1/protection/remove-hooks", { dry_run: true }));
}

export async function removeAllGuardHooks(credentials?: GuardRepairCredentials): Promise<GuardHookRemovalReport> {
  if (isGuardDemoMode()) {
    return {
      dry_run: false,
      status: "removed",
      harnesses: [{ harness: "codex", hook_count: 3 }],
      removed_hook_count: 3,
      reinstall_command: "hol-guard install --all",
      post_state: { clean: true, remaining_harnesses: [] },
    };
  }
  return normalizeHookRemovalReport(
    await postJson("/v1/protection/remove-hooks", {
      confirm: HOOK_REMOVAL_CONFIRMATION,
      ...credentialFields(credentials),
    }),
  );
}
