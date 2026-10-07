import { useSyncExternalStore } from "react";

// Presentation state only. Never used to decide, approve or execute requests.
let readFailed = false;
const listeners = new Set<() => void>();
export function recordBusinessQueueReadFailure(failed: boolean): void {
  if (failed === readFailed) return;
  readFailed = failed;
  for (const listener of listeners) listener();
}
export function businessQueueReadFailed(): boolean {
  return readFailed;
}
export function recordBusinessQueueReadResult(payload: {
  native_business_queue_error?: unknown;
  native_business_queue_checked?: unknown;
}): void {
  if (payload.native_business_queue_error !== undefined) recordBusinessQueueReadFailure(true);
  else if (payload.native_business_queue_checked === true) recordBusinessQueueReadFailure(false);
}
export function useBusinessQueueReadFailure(): boolean {
  return useSyncExternalStore((listener) => {
    listeners.add(listener);
    return () => listeners.delete(listener);
  }, businessQueueReadFailed, () => false);
}
export function BusinessQueueReadNotice() {
  return <div role="alert" className="rounded-xl border border-brand-attention/30 bg-brand-attention/[0.06] p-4">
    <p className="text-sm font-semibold text-brand-attention">Saved business requests could not be loaded.</p>
    <p className="mt-1 text-sm text-brand-dark">Other Guard requests remain available. The saved business queue is incomplete; refresh to try again.</p>
    <button type="button" onClick={() => window.location.reload()}
      className="mt-3 min-h-11 rounded-lg border border-brand-attention/30 px-3 text-sm font-semibold text-brand-dark focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2">
      Refresh queue
    </button>
  </div>;
}
