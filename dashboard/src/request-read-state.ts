import { useCallback, useEffect, useMemo, useState } from 'react';

import {
  fetchReadState,
  postReadStateMarkAllRead,
  postReadStateMarkRead,
  postReadStateMarkUnread,
} from './guard-api';

export type RequestReadState = {
  isRead: (requestId: string) => boolean;
  markRead: (requestId: string) => void;
  markUnread: (requestId: string) => void;
  markAllRead: (requestIds: string[]) => void;
  readCount: number;
};

const FETCH_DEBOUNCE_MS = 2_000;

export function useRequestReadState(): RequestReadState {
  const [readIds, setReadIds] = useState<Set<string>>(() => new Set());
  const [lastFetch, setLastFetch] = useState<number>(0);

  const refresh = useCallback(async () => {
    try {
      const response = await fetchReadState();
      if (response?.ids) {
        setReadIds(new Set(response.ids));
      }
    } catch {
      // Daemon may be unreachable during SSR or initial mount; stale state is acceptable.
    }
    setLastFetch(Date.now());
  }, []);

  useEffect(() => {
    if (Date.now() - lastFetch > FETCH_DEBOUNCE_MS) {
      void refresh();
    }
  }, [lastFetch, refresh]);

  const isRead = useCallback(
    (requestId: string) => readIds.has(requestId),
    [readIds],
  );

  const markRead = useCallback(
    (requestId: string) => {
      setReadIds((prev) => {
        if (prev.has(requestId)) return prev;
        const next = new Set(prev);
        next.add(requestId);
        return next;
      });
      void postReadStateMarkRead(requestId).catch(() => {});
    },
    [],
  );

  const markUnread = useCallback(
    (requestId: string) => {
      setReadIds((prev) => {
        if (!prev.has(requestId)) return prev;
        const next = new Set(prev);
        next.delete(requestId);
        return next;
      });
      void postReadStateMarkUnread(requestId).catch(() => {});
    },
    [],
  );

  const markAllRead = useCallback(
    (requestIds: string[]) => {
      if (requestIds.length === 0) return;
      setReadIds((prev) => {
        const next = new Set(prev);
        for (const id of requestIds) next.add(id);
        return next;
      });
      void postReadStateMarkAllRead(requestIds).catch(() => {});
    },
    [],
  );

  return useMemo(
    () => ({ isRead, markRead, markUnread, markAllRead, readCount: readIds.size }),
    [isRead, markRead, markUnread, markAllRead, readIds.size],
  );
}

export const REQUEST_READ_STATE_LIMIT = 50000;
