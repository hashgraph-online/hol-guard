import { useCallback, useEffect, useRef, useState } from "react";

import { fetchLocalCliApi } from "../guard-api";
import {
  fetchLocalCliList,
  LocalCliApiError,
  normalizeLocalCliList,
  type LocalCliListResponse,
} from "../local-cli-api";

async function fetchLocalCliDiscover(): Promise<LocalCliListResponse> {
  const response = await fetchLocalCliApi("/v1/local-clis/discover", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: "{}",
  });
  const payload: unknown = await response.json().catch(() => null);
  if (!response.ok) {
    throw new LocalCliApiError("local_cli_request_failed", "Guard could not refresh custom extensions.");
  }
  return normalizeLocalCliList(payload);
}

export function useLocalCliCatalog() {
  const [data, setData] = useState<LocalCliListResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [discovering, setDiscovering] = useState(false);
  const [catalogReady, setCatalogReady] = useState(false);
  const loadGeneration = useRef(0);
  const load = useCallback(async () => {
    const generation = loadGeneration.current + 1;
    loadGeneration.current = generation;
    try {
      const next = await fetchLocalCliList();
      if (loadGeneration.current !== generation) return;
      setData(next);
      setError(null);
    } catch (caught) {
      if (loadGeneration.current !== generation) return;
      setError(caught instanceof Error ? caught.message : "Guard could not load custom extensions.");
    }
  }, []);
  const discover = useCallback(async () => {
    const generation = loadGeneration.current + 1;
    loadGeneration.current = generation;
    setDiscovering(true);
    setCatalogReady(false);
    try {
      const next = await fetchLocalCliDiscover();
      if (loadGeneration.current !== generation) return;
      setData(next);
      setError(null);
    } catch {
      try {
        const next = await fetchLocalCliList();
        if (loadGeneration.current !== generation) return;
        setData(next);
        setError(null);
      } catch (caught) {
        if (loadGeneration.current !== generation) return;
        setError(caught instanceof Error ? caught.message : "Guard could not load custom extensions.");
      }
    } finally {
      if (loadGeneration.current === generation) {
        setDiscovering(false);
        setCatalogReady(true);
      }
    }
  }, []);
  useEffect(() => {
    void load();
  }, [load]);
  return { data, error, load, discover, discovering, catalogReady };
}
