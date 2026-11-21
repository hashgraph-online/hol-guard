/**
 * Builds a refresh function whose overlapping calls resolve in order: only the
 * most recently started call applies its data or its error, so an older poll
 * that finishes last never replaces a newer snapshot.
 */
export function createLatestRefresh<T>(
  load: () => Promise<T>,
  apply: { onData: (value: T) => void; onError: (error: unknown) => void },
): () => Promise<void> {
  let latest = 0;
  return async () => {
    latest += 1;
    const request = latest;
    try {
      const value = await load();
      if (request === latest) apply.onData(value);
    } catch (error) {
      if (request === latest) apply.onError(error);
    }
  };
}
