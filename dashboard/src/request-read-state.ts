import { useCallback, useEffect, useMemo, useState } from "react";

export const REQUEST_READ_STATE_KEY = "hol-guard:read-request-ids";
export const REQUEST_READ_STATE_LIMIT = 500;

export type RequestReadState = {
  isRead: (requestId: string) => boolean;
  markRead: (requestId: string) => void;
  markUnread: (requestId: string) => void;
  markAllRead: (requestIds: string[]) => void;
};

export type ReadStateShape = {
  ids: string[];
};

function safeReadStorage(storage: Storage | null | undefined): string[] {
  if (!storage) return [];
  try {
    const raw = storage.getItem(REQUEST_READ_STATE_KEY);
    if (!raw) return [];
    const parsed = JSON.parse(raw) as ReadStateShape;
    if (!parsed || !Array.isArray(parsed.ids)) return [];
    return parsed.ids.filter((id): id is string => typeof id === "string");
  } catch {
    return [];
  }
}

function safeWriteStorage(storage: Storage | null | undefined, ids: string[]): void {
  if (!storage) return;
  try {
    storage.setItem(REQUEST_READ_STATE_KEY, JSON.stringify({ ids }));
  } catch {
    // Ignore quota or disabled-storage errors.
  }
}

export function addReadIds(current: string[], requestIds: string[], limit = REQUEST_READ_STATE_LIMIT): string[] {
  const toAdd = new Set(requestIds);
  const next = current.filter((id) => !toAdd.has(id));
  next.unshift(...requestIds);
  if (next.length > limit) {
    next.length = limit;
  }
  return next;
}

export function removeReadId(current: string[], requestId: string): string[] {
  return current.filter((id) => id !== requestId);
}

export function createRequestReadState(
  storage: Storage | null | undefined = typeof window !== "undefined" ? window.localStorage : null
): RequestReadState {
  let ids = safeReadStorage(storage);

  const persist = (): void => {
    safeWriteStorage(storage, ids);
  };

  return {
    isRead: (requestId: string) => ids.includes(requestId),
    markRead: (requestId: string) => {
      ids = addReadIds(ids, [requestId]);
      persist();
    },
    markUnread: (requestId: string) => {
      ids = removeReadId(ids, requestId);
      persist();
    },
    markAllRead: (requestIds: string[]) => {
      if (requestIds.length === 0) return;
      ids = addReadIds(ids, requestIds);
      persist();
    },
  };
}

export function useRequestReadState(): RequestReadState {
  const [readIds, setReadIds] = useState<string[]>(() => safeReadStorage(window?.localStorage));

  useEffect(() => {
    setReadIds(safeReadStorage(window?.localStorage));
  }, []);

  useEffect(() => {
    safeWriteStorage(window?.localStorage, readIds);
  }, [readIds]);

  const isRead = useCallback((requestId: string) => readIds.includes(requestId), [readIds]);

  const markRead = useCallback((requestId: string) => {
    setReadIds((current) => addReadIds(current, [requestId]));
  }, []);

  const markUnread = useCallback((requestId: string) => {
    setReadIds((current) => removeReadId(current, requestId));
  }, []);

  const markAllRead = useCallback((requestIds: string[]) => {
    if (requestIds.length === 0) return;
    setReadIds((current) => addReadIds(current, requestIds));
  }, []);

  return useMemo(
    () => ({ isRead, markRead, markUnread, markAllRead }),
    [isRead, markRead, markUnread, markAllRead]
  );
}
