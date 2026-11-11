import type { CigarSetupPlan } from "./one-click";
import type { ContextAssistanceStatus } from "./types";

/**
 * Turning CIGAR on is driven from this page. When someone clicks Turn on CIGAR
 * and then opens another page, the click is remembered for this browser tab so
 * setup picks up where it stopped when they come back, instead of showing Off.
 */
const KEY = "hol-guard.cigar.turn-on-requested";
/** The safety check this click started, so coming back can finish it instead of waiting for it to expire. */
const JOB_KEY = "hol-guard.cigar.turn-on-job";
/** An old click is not a reason to start CIGAR. */
const RESUME_WINDOW_MS = 30 * 60_000;

type Store = Pick<Storage, "getItem" | "setItem" | "removeItem">;

function store(): Store | null {
  try { return typeof window === "undefined" ? null : window.sessionStorage; } catch { return null; }
}

export function rememberTurnOn(now: number, storage: Store | null = store()) {
  try { storage?.setItem(KEY, String(now)); } catch { /* Setup still works; it just will not resume. */ }
}

export function rememberTurnOnJob(jobId: string, storage: Store | null = store()) {
  try { storage?.setItem(JOB_KEY, jobId); } catch { /* Setup still works; it just will not resume. */ }
}

/** Drop the click but keep a prepared safety check, so approving later commits it instead of waiting for it to expire. */
export function forgetTurnOnClick(storage: Store | null = store()) {
  try { storage?.removeItem(KEY); } catch { /* Nothing to forget without storage. */ }
}

export function forgetTurnOn(storage: Store | null = store()) {
  try { storage?.removeItem(KEY); storage?.removeItem(JOB_KEY); } catch { /* Nothing to forget without storage. */ }
}

export function turnOnJob(storage: Store | null = store()): string | null {
  try { return storage?.getItem(JOB_KEY) || null; } catch { return null; }
}

export function turnOnRequestedAt(storage: Store | null = store()): number | null {
  try {
    const value = Number(storage?.getItem(KEY) ?? NaN);
    return Number.isFinite(value) ? value : null;
  } catch { return null; }
}

/** Resume only an unfinished click that needs no new approval and is still possible. */
export function shouldResumeTurnOn(
  requestedAt: number | null, now: number, status: ContextAssistanceStatus | null, plan: CigarSetupPlan | null,
  approvalRequired: boolean,
): boolean {
  if (requestedAt === null || now - requestedAt > RESUME_WINDOW_MS || now < requestedAt) return false;
  if (!status || status.effective_enabled || plan?.kind !== "run") return false;
  return !(approvalRequired && plan.approval);
}
