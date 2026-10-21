import { fetchLocalCliApi } from "./guard-api";

/** A known ID lets Cancel reach the daemon even before the start response arrives. */
export async function startCancelableDiscoveryJob<T>(
  signal: AbortSignal,
  start: (clientJobId: string) => Promise<T>,
): Promise<T | null> {
  if (signal.aborted) return null;
  const clientJobId = globalThis.crypto.randomUUID().replaceAll("-", "");
  let cancelSent = false;
  const cancel = () => {
    if (cancelSent) return;
    cancelSent = true;
    void fetchLocalCliApi("/v1/local-clis/refresh-job", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ job_id: clientJobId, cancel: true }),
    }).catch(() => undefined);
  };
  signal.addEventListener("abort", cancel, { once: true });
  try {
    const result = await start(clientJobId);
    return signal.aborted ? null : result;
  } catch (error) {
    if (signal.aborted) return null;
    throw error;
  } finally {
    signal.removeEventListener("abort", cancel);
    if (signal.aborted) cancel();
  }
}
