import { useCallback, useEffect, useRef, useState } from "react";

import { fetchLocalCliApi } from "../guard-api";
import {
  fetchLocalCliList,
  LocalCliApiError,
  normalizeLocalCliList,
  type LocalCliListResponse,
} from "../local-cli-api";
import { createListingSequence } from "./listing-sequence";

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
    case "configured_host_persist_failed":
      return "Guard read your host connections but could not save them. Existing choices were kept; retry discovery, and restart Guard if it keeps failing.";
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
  const sequence = useRef(createListingSequence());
  const publicationPoll = useRef({ revision: -1, attempts: 0 });
  // Resolves false when the listing on screen does not include this load: its
  // own fetch failed, or a newer load replaced it and that one failed. A newer
  // load is waited for, so a caller never describes the listing it had before.
  const load = useCallback((preserveDiscoveryNotice = false): Promise<boolean> => {
    const { listed } = sequence.current.start(async (isCurrent) => {
      try {
        const next = await fetchLocalCliList();
        if (!isCurrent()) return false;
        setData(next);
        setError(null);
        if (!preserveDiscoveryNotice) setDiscoveryNotice(null);
        return true;
      } catch (caught) {
        if (!isCurrent()) return false;
        setError(caught instanceof Error ? caught.message : "Guard could not load custom extensions.");
        return false;
      }
    }, (applied) => applied);
    return listed;
  }, []);
  const discover = useCallback(async (): Promise<LocalCliDiscoveryOutcome> => {
    setDiscovering(true);
    setCatalogReady(false);
    const { result, isCurrent } = sequence.current.start(async (isCurrent) => {
      try {
        const next = await fetchLocalCliDiscover();
        if (!isCurrent()) return { outcome: "superseded" as const, applied: false };
        setData(next);
        setError(null);
        setDiscoveryNotice(discoveryIssueMessage(next.discovery_issue));
        return { outcome: next.discovery_issue ? "partial" as const : "refreshed" as const, applied: true };
      } catch (error) {
        try {
          const next = await fetchLocalCliList();
          if (!isCurrent()) return { outcome: "superseded" as const, applied: false };
          setData(next);
          setError(null);
          setDiscoveryNotice(error instanceof Error ? error.message : "Guard could not refresh custom extensions.");
          return { outcome: "partial" as const, applied: true };
        } catch (caught) {
          if (!isCurrent()) return { outcome: "superseded" as const, applied: false };
          setError(caught instanceof Error ? caught.message : "Guard could not load custom extensions.");
          return { outcome: "partial" as const, applied: false };
        }
      }
    }, ({ applied }) => applied);
    try {
      return (await result).outcome;
    } finally {
      if (isCurrent()) {
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
