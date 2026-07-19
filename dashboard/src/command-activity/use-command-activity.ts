import { useCallback, useEffect, useMemo, useRef, useState } from "react";

import { fetchCommandActivityApi } from "../guard-api";
import { createCommandActivityClient } from "./command-activity-api";
import {
  advanceCommandActivityCursor,
  commandActivityAnalyticsQueryForFilters,
  completeCommandFeedback,
  commandActivityLoadFailed,
  commandActivityLoadStarted,
  commandActivityLoadSucceeded,
  DEFAULT_COMMAND_ACTIVITY_FILTERS,
  INITIAL_COMMAND_ACTIVITY_CURSOR_STATE,
  parseCommandActivityFilters,
  retreatCommandActivityCursor,
  serializeCommandActivityFilters,
  updateCommandActivityFilters,
  type CommandActivityCursorState,
  type CommandFeedbackState,
  type CommandActivityFilters,
  type CommandActivityLoadState,
} from "./command-activity-state";
import type {
  CommandActivityAnalytics,
  CommandActivityPage,
  CommandExtensionsPage,
  CommandFeedbackLabel,
} from "./command-activity-types";

const client = createCommandActivityClient(fetchCommandActivityApi);
const COMMAND_SELECTED_PARAM = "command_selected";

function initialFilters(harness: string | null): CommandActivityFilters {
  if (typeof window === "undefined") return { ...DEFAULT_COMMAND_ACTIVITY_FILTERS, harness };
  const parsed = parseCommandActivityFilters(new URLSearchParams(window.location.search));
  return { ...parsed, harness: harness ?? parsed.harness };
}

function initialSelectedId(): string | null {
  if (typeof window === "undefined") return null;
  const value = new URLSearchParams(window.location.search).get(COMMAND_SELECTED_PARAM);
  return value !== null && value.length <= 256 && /^[a-z][a-z0-9]*(?:[._:-][a-z0-9]+)*$/.test(value) ? value : null;
}

function writeCommandUrl(filters: CommandActivityFilters, selectedId: string | null, globalView: boolean): void {
  const url = new URL(window.location.href);
  for (const key of [...url.searchParams.keys()]) {
    if (key.startsWith("command_")) url.searchParams.delete(key);
  }
  const urlFilters = globalView ? filters : { ...filters, harness: null };
  for (const [key, value] of serializeCommandActivityFilters(urlFilters)) url.searchParams.set(key, value);
  if (selectedId) url.searchParams.set(COMMAND_SELECTED_PARAM, selectedId);
  if (globalView) url.searchParams.set("view", "commands");
  else url.searchParams.set("activity", "commands");
  window.history.replaceState({}, "", url.toString());
}

function previousPage(state: CommandActivityLoadState<CommandActivityPage>): CommandActivityPage | null {
  if (state.kind === "ready") return state.data;
  if (state.kind === "loading" || state.kind === "error") return state.previous;
  return null;
}

function previousData<T>(state: CommandActivityLoadState<T>): T | null {
  if (state.kind === "ready") return state.data;
  if (state.kind === "loading" || state.kind === "error") return state.previous;
  return null;
}

export type { CommandFeedbackState } from "./command-activity-state";

export function useCommandActivity(harness: string | null = null) {
  const [filters, setFilters] = useState<CommandActivityFilters>(() => initialFilters(harness));
  const [cursor, setCursor] = useState<CommandActivityCursorState>(INITIAL_COMMAND_ACTIVITY_CURSOR_STATE);
  const [selectedId, setSelectedId] = useState<string | null>(initialSelectedId);
  const [page, setPage] = useState<CommandActivityLoadState<CommandActivityPage>>({ kind: "idle" });
  const [analytics, setAnalytics] = useState<CommandActivityLoadState<CommandActivityAnalytics>>({ kind: "idle" });
  const [extensions, setExtensions] = useState<CommandActivityLoadState<CommandExtensionsPage>>({ kind: "idle" });
  const [feedback, setFeedback] = useState<CommandFeedbackState>({ kind: "idle" });
  const [refreshKey, setRefreshKey] = useState(0);
  const requestIdRef = useRef(0);
  const previousHarnessRef = useRef(harness);
  const effectiveFilters = useMemo(
    () => ({ ...filters, harness: harness ?? filters.harness }),
    [filters, harness],
  );

  useEffect(() => {
    if (previousHarnessRef.current === harness) return;
    previousHarnessRef.current = harness;
    setFilters((current) => ({ ...current, harness }));
    setCursor(INITIAL_COMMAND_ACTIVITY_CURSOR_STATE);
    setSelectedId(null);
    setFeedback({ kind: "idle" });
    setPage({ kind: "idle" });
    setAnalytics({ kind: "idle" });
  }, [harness]);

  useEffect(() => {
    writeCommandUrl(effectiveFilters, selectedId, harness === null);
  }, [effectiveFilters, harness, selectedId]);

  useEffect(() => {
    const controller = new AbortController();
    const requestId = ++requestIdRef.current;
    setPage((current) => commandActivityLoadStarted(requestId, previousPage(current)));
    setAnalytics((current) => commandActivityLoadStarted(requestId, previousData(current)));
    Promise.allSettled([
      client.fetchPage(effectiveFilters, cursor.current, controller.signal),
      client.fetchAnalytics(commandActivityAnalyticsQueryForFilters(effectiveFilters), controller.signal),
    ]).then(([pageResult, analyticsResult]) => {
      if (controller.signal.aborted) return;
      if (pageResult.status === "fulfilled") {
        setPage((current) => commandActivityLoadSucceeded(current, requestId, pageResult.value, (value) => value.items.length === 0));
      } else {
        setPage((current) => commandActivityLoadFailed(current, requestId, pageResult.reason));
      }
      if (analyticsResult.status === "fulfilled") {
        setAnalytics((current) => commandActivityLoadSucceeded(current, requestId, analyticsResult.value, () => false));
      } else {
        setAnalytics((current) => commandActivityLoadFailed(current, requestId, analyticsResult.reason));
      }
    });
    return () => controller.abort();
  }, [cursor.current, effectiveFilters, refreshKey]);

  useEffect(() => {
    const controller = new AbortController();
    const requestId = ++requestIdRef.current;
    setExtensions((current) => commandActivityLoadStarted(requestId, previousData(current)));
    client.fetchExtensions({ limit: 100 }, controller.signal).then(
      (data) => setExtensions((current) => commandActivityLoadSucceeded(current, requestId, data, (value) => value.items.length === 0)),
      (error) => setExtensions((current) => commandActivityLoadFailed(current, requestId, error)),
    );
    return () => controller.abort();
  }, []);

  useEffect(() => {
    const controller = new AbortController();
    let stopped = false;
    let eventCursor = 0;
    async function listen() {
      while (!stopped) {
        try {
          for await (const event of client.streamInvalidations(eventCursor, controller.signal)) {
            eventCursor = event.sequence;
            setRefreshKey((value) => value + 1);
          }
          if (!stopped) await new Promise<void>((resolve) => setTimeout(resolve, 1_000));
        } catch {
          if (!controller.signal.aborted) await new Promise<void>((resolve) => setTimeout(resolve, 1_000));
        }
      }
    }
    void listen();
    return () => {
      stopped = true;
      controller.abort();
    };
  }, []);

  const updateFilters = useCallback(
    (patch: Partial<CommandActivityFilters>) => {
      setFilters((current) => updateCommandActivityFilters(current, patch, harness));
      setCursor(INITIAL_COMMAND_ACTIVITY_CURSOR_STATE);
      setSelectedId(null);
      setFeedback({ kind: "idle" });
      setPage({ kind: "idle" });
      setAnalytics({ kind: "idle" });
    },
    [harness],
  );

  const selectActivity = useCallback((activityId: string | null) => {
    setSelectedId(activityId);
    setFeedback({ kind: "idle" });
  }, []);

  const nextPage = useCallback(() => {
    const data = previousPage(page);
    const nextCursor = data?.next_cursor;
    if (nextCursor) {
      setPage({ kind: "idle" });
      setCursor((current) => advanceCommandActivityCursor(current, nextCursor));
    }
  }, [page]);

  const previousPageAction = useCallback(() => {
    setPage({ kind: "idle" });
    setCursor((current) => retreatCommandActivityCursor(current));
  }, []);

  const recordFeedback = useCallback(
    async (label: CommandFeedbackLabel) => {
      if (!selectedId) return;
      const activityId = selectedId;
      setFeedback({ kind: "saving", activity_id: activityId, label });
      try {
        const result = await client.recordFeedback({ activity_id: activityId, label });
        setPage((current) => {
          if (current.kind !== "ready") return current;
          return {
            ...current,
            data: { ...current.data, items: current.data.items.map((item) => (item.activity_id === activityId ? { ...item, feedback_label: result.label } : item)) },
          };
        });
        setFeedback((current) => completeCommandFeedback(current, activityId, { kind: "saved", label: result.label }));
      } catch {
        setFeedback((current) => completeCommandFeedback(current, activityId, { kind: "error", message: "Unable to save feedback." }));
      }
    },
    [selectedId],
  );

  const pageData = previousPage(page);
  const selectedActivity = useMemo(
    () => pageData?.items.find((item) => item.activity_id === selectedId) ?? null,
    [pageData, selectedId],
  );

  const retry = useCallback(() => {
    setRefreshKey((value) => value + 1);
  }, []);

  return {
    filters: effectiveFilters,
    page,
    pageData,
    analytics,
    extensions,
    cursor,
    selectedActivity,
    selectedId,
    feedback,
    updateFilters,
    selectActivity,
    nextPage,
    previousPage: previousPageAction,
    recordFeedback,
    retry,
  };
}
