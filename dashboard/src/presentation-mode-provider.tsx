import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { fetchSettings, updateSettings } from "./guard-api";
import type { GuardPresentationMode, GuardResolvedPresentation } from "./guard-types";
import { confirmsPresentationWrite, presentationWritePayload, readPresentationSettings, unavailablePresentation } from "./presentation-mode-state";

type PresentationContextValue = {
  mode: GuardPresentationMode;
  presentation: GuardResolvedPresentation;
  loading: boolean;
  saving: boolean;
  error: string | null;
  saved: boolean;
  setMode: (mode: GuardPresentationMode) => Promise<void>;
  refresh: () => Promise<void>;
};
const DEFAULT_PRESENTATION = unavailablePresentation();
const PresentationContext = createContext<PresentationContextValue>({
  mode: "everyday", presentation: DEFAULT_PRESENTATION, loading: true, saving: false,
  error: null, saved: false, setMode: async () => {}, refresh: async () => {},
});

export function PresentationModeProvider({ children }: { children: ReactNode }) {
  const [presentation, setPresentation] = useState(DEFAULT_PRESENTATION);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [saved, setSaved] = useState(false);
  const current = useRef(presentation);
  const mounted = useRef(false);
  const pending = useRef(false);
  const reading = useRef(false);
  const generation = useRef(0);

  const publish = useCallback((value: GuardResolvedPresentation) => {
    if (!mounted.current) return;
    current.current = value;
    setPresentation(value);
    setLoading(false);
  }, []);

  const refresh = useCallback(async () => {
    if (pending.current || reading.current) return;
    reading.current = true;
    const request = ++generation.current;
    try {
      const payload = await fetchSettings();
      if (request === generation.current && !pending.current) publish(readPresentationSettings(payload.settings));
    } catch {
      if (request === generation.current && !pending.current) {
        publish({ ...current.current, writable: false, diagnostic: "presentation_settings_unavailable" });
      }
    } finally {
      reading.current = false;
    }
  }, [publish]);

  const setMode = useCallback(async (mode: GuardPresentationMode) => {
    if (pending.current || !current.current.writable) return;
    const before = current.current;
    pending.current = true;
    generation.current += 1;
    setSaving(true);
    setSaved(false);
    setError(null);
    try {
      const response = await updateSettings(presentationWritePayload(before, mode));
      const acknowledged = readPresentationSettings(response.settings);
      if (!confirmsPresentationWrite(before, acknowledged, mode)) throw new Error("Unconfirmed save");
      const readback = readPresentationSettings((await fetchSettings()).settings);
      publish(readback);
      if (!confirmsPresentationWrite(before, readback, mode) || readback.revision < acknowledged.revision) {
        throw new Error("Preference changed before readback");
      }
      if (mounted.current) setSaved(true);
    } catch {
      // A lost response does not prove the write failed. Show the current Core
      // value when it can be read, rather than claiming the old mode was kept.
      try { publish(readPresentationSettings((await fetchSettings()).settings)); }
      catch { publish({ ...current.current, writable: false, diagnostic: "presentation_settings_unavailable" }); }
      if (mounted.current) setError("The saved preference could not be confirmed. Reload it and try again.");
    } finally {
      pending.current = false;
      if (mounted.current) setSaving(false);
    }
  }, [publish]);

  useEffect(() => {
    mounted.current = true;
    const refreshVisible = () => {
      if (document.visibilityState !== "hidden") void refresh();
    };
    refreshVisible();
    const timer = window.setInterval(refreshVisible, 3000);
    window.addEventListener("focus", refreshVisible);
    document.addEventListener("visibilitychange", refreshVisible);
    return () => {
      mounted.current = false;
      generation.current += 1;
      window.clearInterval(timer);
      window.removeEventListener("focus", refreshVisible);
      document.removeEventListener("visibilitychange", refreshVisible);
    };
  }, [refresh]);

  const value = useMemo(() => ({
    mode: presentation.value, presentation, loading, saving, error, saved, setMode, refresh,
  }), [presentation, loading, saving, error, saved, setMode, refresh]);
  return <PresentationContext.Provider value={value}>{children}</PresentationContext.Provider>;
}

export function usePresentationMode(): PresentationContextValue {
  return useContext(PresentationContext);
}
