import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from "react";

import { fetchSettings, updateSettings } from "./guard-api";
import {
  PRESENTATION_SCHEMA_VERSION,
  resolvePresentationMode,
  type GuardPresentationMode,
  type GuardPresentationSource,
  type ResolvedGuardPresentationMode,
} from "./presentation-mode";

type PresentationModeState =
  | { status: "loading"; resolved: ResolvedGuardPresentationMode }
  | { status: "ready"; resolved: ResolvedGuardPresentationMode }
  | { status: "error"; resolved: ResolvedGuardPresentationMode; error: string };

type PresentationModeContextValue = PresentationModeState & {
  setMode: (mode: GuardPresentationMode) => Promise<void>;
  refresh: () => Promise<void>;
  sessionPreview: GuardPresentationMode | null;
  setSessionPreview: (mode: GuardPresentationMode | null) => void;
};

const DEFAULT_RESOLVED = resolvePresentationMode({});
const PresentationModeContext = createContext<PresentationModeContextValue | null>(null);
const PRESENTATION_SOURCES = new Set<GuardPresentationSource>([
  "default",
  "local-explicit",
  "migrated",
  "session-preview",
  "cloud-profile",
  "read-error",
]);

type CorePresentationSettings = {
  presentation_mode?: unknown;
  presentation_mode_explicit?: unknown;
  presentation_schema_version?: unknown;
  presentation_revision?: unknown;
  presentation?: {
    value?: unknown;
    source?: unknown;
    explicit?: unknown;
    writable?: unknown;
    schema_version?: unknown;
    revision?: unknown;
    diagnostic?: unknown;
  } | null;
};

function resolvedFromSettings(
  settings: CorePresentationSettings,
  sessionPreview: GuardPresentationMode | null,
): ResolvedGuardPresentationMode {
  const source = settings.presentation;
  if (sessionPreview === null && source) {
    const value = source.value;
    const sourceName = source.source;
    const schemaVersion = source.schema_version;
    const revision = source.revision;
    if (
      (value === "everyday" || value === "technical") &&
      typeof sourceName === "string" &&
      PRESENTATION_SOURCES.has(sourceName as GuardPresentationSource) &&
      schemaVersion === PRESENTATION_SCHEMA_VERSION &&
      typeof revision === "number" &&
      Number.isSafeInteger(revision) &&
      revision >= 0
    ) {
      return {
        value,
        source: sourceName as GuardPresentationSource,
        explicit: source.explicit === true,
        writable: source.writable !== false,
        schemaVersion: PRESENTATION_SCHEMA_VERSION,
        revision,
        diagnostic: typeof source.diagnostic === "string" ? source.diagnostic : null,
      };
    }
  }
  return resolvePresentationMode({
    value: source?.value ?? settings.presentation_mode,
    explicit: source?.explicit ?? settings.presentation_mode_explicit,
    schemaVersion: source?.schema_version ?? settings.presentation_schema_version,
    revision: source?.revision ?? settings.presentation_revision,
    writable: typeof source?.writable === "boolean" ? source.writable : true,
    sessionPreview: sessionPreview ?? undefined,
  });
}

export function PresentationModeProvider({
  children,
  initialResolved,
  loadFromCore = true,
}: {
  children: ReactNode;
  initialResolved?: ResolvedGuardPresentationMode;
  loadFromCore?: boolean;
}) {
  const [sessionPreview, setSessionPreview] = useState<GuardPresentationMode | null>(null);
  const [state, setState] = useState<PresentationModeState>(() =>
    initialResolved
      ? { status: "ready", resolved: initialResolved }
      : { status: "loading", resolved: DEFAULT_RESOLVED },
  );

  const refresh = useCallback(async () => {
    if (!loadFromCore) return;
    try {
      const payload = await fetchSettings();
      setState({ status: "ready", resolved: resolvedFromSettings(payload.settings, sessionPreview) });
    } catch (error) {
      setState({
        status: "error",
        resolved: resolvePresentationMode({ readError: true, sessionPreview: sessionPreview ?? undefined }),
        error: error instanceof Error ? error.message : "Unable to load the local presentation preference.",
      });
    }
  }, [loadFromCore, sessionPreview]);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  const setMode = useCallback(
    async (mode: GuardPresentationMode) => {
      const current = state.resolved;
      if (!current.writable) {
        throw new Error("The local presentation preference is read-only on this surface.");
      }
      const payload = await updateSettings({
        presentation_mode: mode,
        presentation_revision: current.revision,
      });
      setSessionPreview(null);
      setState({ status: "ready", resolved: resolvedFromSettings(payload.settings, null) });
    },
    [state.resolved],
  );

  const value = useMemo<PresentationModeContextValue>(
    () => ({ ...state, setMode, refresh, sessionPreview, setSessionPreview }),
    [refresh, sessionPreview, setMode, state],
  );
  return <PresentationModeContext.Provider value={value}>{children}</PresentationModeContext.Provider>;
}

export function usePresentationMode(): PresentationModeContextValue {
  const value = useContext(PresentationModeContext);
  if (value === null) {
    throw new Error("usePresentationMode must be used inside PresentationModeProvider");
  }
  return value;
}
