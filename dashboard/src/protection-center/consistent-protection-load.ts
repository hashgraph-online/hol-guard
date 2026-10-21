export const PROTECTION_DATA_CHANGED_MESSAGE =
  "Protection data changed while Guard was loading. Check again before making changes.";

// The catalog read model and the effective controls describe one catalog only
// once Guard has bound both to it. A pack activation or an upgrade settling its
// transition moves them one at a time, and the daemon converges on its next
// control refresh (every 5 s). Retry across that window instead of showing an
// error the user can only clear by restarting Guard.
export const CONSISTENT_LOAD_RETRY_DELAYS_MS: readonly number[] = [250, 1000, 2000, 4000];

type Digested = { readonly catalog_digest: string };

const defaultSleep = (ms: number): Promise<void> => new Promise((resolve) => setTimeout(resolve, ms));

export async function loadConsistentProtectionData<C extends Digested, E extends Digested>(
  loadCatalog: () => Promise<C>,
  loadEffective: () => Promise<E>,
  options: { readonly delays?: readonly number[]; readonly sleep?: (ms: number) => Promise<void> } = {},
): Promise<{ catalog: C; effective: E }> {
  const delays = options.delays ?? CONSISTENT_LOAD_RETRY_DELAYS_MS;
  const sleep = options.sleep ?? defaultSleep;
  for (let attempt = 0; ; attempt += 1) {
    const [catalog, effective] = await Promise.all([loadCatalog(), loadEffective()]);
    if (catalog.catalog_digest === effective.catalog_digest) return { catalog, effective };
    const delay = delays[attempt];
    // A pair that never agrees is still refused: edits drafted against one
    // catalog must not be applied against another.
    if (delay === undefined) throw new Error(PROTECTION_DATA_CHANGED_MESSAGE);
    await sleep(delay);
  }
}
