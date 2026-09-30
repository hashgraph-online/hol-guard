import { useCallback, useEffect, useRef, useState } from "react";

import { fetchLocalCliApi } from "../guard-api";
import {
  fetchLocalCliList,
  LocalCliApiError,
  normalizeLocalCliList,
  type LocalCliListResponse,
} from "../local-cli-api";

export type LocalCliDiscoveryOutcome = "refreshed" | "partial" | "superseded";

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

function discoveryIssueMessage(issue: LocalCliListResponse["discovery_issue"]): string | null {
  switch (issue) {
    case "catalog_limit_reached":
      return "Some connectors have more tools than Guard can catalog safely. Existing choices were kept.";
    case "configured_host_scan_failed":
      return "Guard could not read configured host connections. Check the host app and retry.";
    case "observed_provider_scan_failed":
      return "Guard could not merge observed provider tools. Existing choices were kept; retry discovery.";
    case "package_catalog_refresh_failed":
      return "Guard could not refresh project scripts. Existing custom extensions were kept; retry discovery.";
    default:
      return null;
  }
}

export function useLocalCliCatalog() {
  const [data, setData] = useState<LocalCliListResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [discoveryNotice, setDiscoveryNotice] = useState<string | null>(null);
  const [discovering, setDiscovering] = useState(false);
  const [catalogReady, setCatalogReady] = useState(false);
  const loadGeneration = useRef(0);
  const publicationPoll = useRef({ revision: -1, attempts: 0 });
  const load = useCallback(async (preserveDiscoveryNotice = false) => {
    const generation = loadGeneration.current + 1;
    loadGeneration.current = generation;
    try {
      const next = await fetchLocalCliList();
      if (loadGeneration.current !== generation) return;
      setData(next);
      setError(null);
      if (!preserveDiscoveryNotice) setDiscoveryNotice(null);
    } catch (caught) {
      if (loadGeneration.current !== generation) return;
      setError(caught instanceof Error ? caught.message : "Guard could not load custom extensions.");
    }
  }, []);
  const discover = useCallback(async (): Promise<LocalCliDiscoveryOutcome> => {
    const generation = loadGeneration.current + 1;
    loadGeneration.current = generation;
    setDiscovering(true);
    setCatalogReady(false);
    try {
      const next = await fetchLocalCliDiscover();
      if (loadGeneration.current !== generation) return "superseded";
      setData(next);
      setError(null);
      setDiscoveryNotice(discoveryIssueMessage(next.discovery_issue));
      return next.discovery_issue ? "partial" : "refreshed";
    } catch (error) {
      try {
        const next = await fetchLocalCliList();
        if (loadGeneration.current !== generation) return "superseded";
        setData(next);
        setError(null);
        setDiscoveryNotice(error instanceof Error ? error.message : "Guard could not refresh custom extensions.");
        return "partial";
      } catch (caught) {
        if (loadGeneration.current !== generation) return "superseded";
        setError(caught instanceof Error ? caught.message : "Guard could not load custom extensions.");
        return "partial";
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
  useEffect(() => {
    if (discovering || data?.native_publication?.state !== "pending") return;
    if (publicationPoll.current.revision !== data.revision) {
      publicationPoll.current = { revision: data.revision, attempts: 0 };
    }
    if (publicationPoll.current.attempts >= 20) return;
    const timer = window.setTimeout(() => {
      publicationPoll.current.attempts += 1;
      void load(true);
    }, 1500);
    return () => window.clearTimeout(timer);
  }, [data, discovering, load]);
  return { data, error, discoveryNotice, load, discover, discovering, catalogReady };
}
