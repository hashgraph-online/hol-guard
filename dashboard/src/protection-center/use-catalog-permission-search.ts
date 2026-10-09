import { useEffect, useMemo, useState } from "react";

import type { CatalogPermissionHit, CatalogReadModel } from "../extension-catalog-v2";
import { useDebounce } from "../use-debounce";
import { commandPatternQuery } from "./model/protection-landing";

const SEARCH_DEBOUNCE_MS = 150;

type SearchState = { query: string; hits: readonly CatalogPermissionHit[]; error: string | null };

/**
 * Candidate permissions for a pattern query, read from the catalog's
 * permission search. While a newer query is in flight the previous candidates
 * stay visible; the caller's ranking re-applies the current terms to them.
 */
export function useCatalogPermissionSearch(catalog: CatalogReadModel, rawQuery: string): SearchState & { pending: boolean } {
  const current = commandPatternQuery(rawQuery);
  const query = useDebounce(current, SEARCH_DEBOUNCE_MS);
  const [state, setState] = useState<SearchState>({ query: "", hits: [], error: null });
  const local = useMemo(
    () => (catalog.localSearch ? { query: current, hits: catalog.localSearch(current), error: null } : null),
    [catalog, current],
  );
  useEffect(() => {
    if (local) return;
    if (!query) {
      setState({ query, hits: [], error: null });
      return;
    }
    let cancelled = false;
    catalog.searchPermissions(query).then(
      (hits) => { if (!cancelled) setState({ query, hits, error: null }); },
      (error: unknown) => {
        if (!cancelled) setState({ query, hits: [], error: error instanceof Error ? error.message : "Guard could not search command patterns." });
      },
    );
    return () => { cancelled = true; };
  }, [catalog, local, query]);
  if (local) return { ...local, pending: false };
  return { ...state, pending: current !== "" && state.query !== current };
}
