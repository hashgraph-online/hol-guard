import { refreshEffectiveExtensionControls } from "../extension-controls-api";

// Shown beside the extension list, never in place of it. The daemon refuses a
// mutation whose catalog digest is not its own (409 `catalog_conflict`), and a
// split pair always carries one digest it does not hold, so the page reads
// fine but cannot save until a reload lands a pair that agrees.
export const PROTECTION_DATA_UNSETTLED_MESSAGE =
  "Guard is still settling a protection update, so a few extensions may read as out of date and changes cannot be saved yet. Reload this page in a few seconds.";

// Shown beside the extension list, never in place of it. The daemon failed to
// prepare its verified catalog, so the page reads the catalog the daemon
// already holds. That list is whatever registry the daemon bound at startup,
// which a failed installed-authority migration can leave short of a rebuilt
// one, and the preview a save depends on prepares from the same installed
// bundle, so it can still be refused. The notice therefore says what is
// reduced and promises neither completeness nor a successful save; it keeps
// the page in reach instead of taking it away.
export const CATALOG_PREPARATION_DEGRADED_MESSAGE =
  "Guard could not rebuild its extension list, so this page is showing the list Guard already had. It may not have every extension, and a policy change can still be refused until Guard rebuilds. Updating HOL Guard restores the rebuilt list; Guard writes the reason to its log at ~/.hol-guard/logs/daemon.log.";

export const PROTECTION_SAVE_UNSETTLED_MESSAGE =
  "Guard could not save this protection change, so your current protection is unchanged. Guard is still settling a protection update; reload this page in a few seconds, then make the change again.";

// The catalog read model and the effective controls describe one catalog only
// once Guard has bound both to it. A pack activation or an upgrade settling its
// transition moves them one at a time, and the daemon converges on its next
// control refresh (every 5 s). Retry across that window before showing the
// list as unsettled.
// A refresh keeps the model it already rendered only when the fresh read
// describes the same catalog in the same way: same digest, same protocol, and
// the same degraded mode. Recovery from a degraded read can land the identical
// digest and protocol, so leaving `degraded` out of this comparison keeps the
// earlier model and with it a notice that no longer describes the page.
export function reusableCatalogModel<
  C extends { readonly catalog_digest: string; readonly protocol: string; readonly degraded?: string },
>(previous: C | null | undefined, fresh: C): C {
  if (
    previous &&
    previous.catalog_digest === fresh.catalog_digest &&
    previous.protocol === fresh.protocol &&
    previous.degraded === fresh.degraded
  ) {
    return previous;
  }
  return fresh;
}

export const CONSISTENT_LOAD_RETRY_DELAYS_MS: readonly number[] = [250, 1000, 2000, 4000];

type Digested = { readonly catalog_digest: string };

export type ProtectionLoad<C, E> = {
  readonly catalog: C;
  readonly effective: E;
  /** Whether both sides named one catalog. False still carries a usable pair. */
  readonly consistent: boolean;
};

const defaultSleep = (ms: number): Promise<void> => new Promise((resolve) => setTimeout(resolve, ms));

export async function loadConsistentProtectionData<C extends Digested, E extends Digested>(
  loadCatalog: () => Promise<C>,
  loadEffective: () => Promise<E>,
  options: {
    readonly delays?: readonly number[];
    readonly sleep?: (ms: number) => Promise<void>;
    readonly repair?: () => Promise<unknown>;
  } = {},
): Promise<ProtectionLoad<C, E>> {
  const delays = options.delays ?? CONSISTENT_LOAD_RETRY_DELAYS_MS;
  const sleep = options.sleep ?? defaultSleep;
  const repair = options.repair ?? refreshEffectiveExtensionControls;
  for (let attempt = 0; ; attempt += 1) {
    const [catalog, effective] = await Promise.all([loadCatalog(), loadEffective()]);
    if (catalog.catalog_digest === effective.catalog_digest) {
      return { catalog, effective, consistent: true };
    }
    const delay = delays[attempt];
    // A pair that never agrees still loads. Refusing the read was the one
    // outcome the user could not clear: the list, the policies and the editor
    // all disappeared behind a retry button that ran the same read again. The
    // mutation route carries the real guarantee, so the page shows what it has
    // and says it is unsettled.
    if (delay === undefined) return { catalog, effective, consistent: false };
    // Waiting alone only settles a transition that is still moving. A daemon
    // whose catalog binding and whose control snapshot settled on different
    // catalogs stays split until it reads the authority again, so ask it to:
    // the request is a read on the daemon side and commits nothing. A repair
    // that fails is not fatal, because the retry is still worth taking.
    await repair().catch(() => undefined);
    await sleep(delay);
  }
}
