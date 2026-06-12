import { useCallback, useEffect, useRef, useState } from "react";

export function useCopyFeedbackTimeout(resetMs: number) {
  const [copied, setCopied] = useState(false);
  const resetTimeoutRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  const clearResetTimeout = useCallback(() => {
    if (resetTimeoutRef.current !== null) {
      clearTimeout(resetTimeoutRef.current);
      resetTimeoutRef.current = null;
    }
  }, []);

  useEffect(() => {
    return () => {
      clearResetTimeout();
    };
  }, [clearResetTimeout]);

  const flashCopied = useCallback(() => {
    clearResetTimeout();
    setCopied(true);
    resetTimeoutRef.current = setTimeout(() => {
      resetTimeoutRef.current = null;
      setCopied(false);
    }, resetMs);
  }, [clearResetTimeout, resetMs]);

  const resetCopied = useCallback(() => {
    clearResetTimeout();
    setCopied(false);
  }, [clearResetTimeout]);

  return { copied, flashCopied, resetCopied };
}
