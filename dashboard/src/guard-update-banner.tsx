import { useCallback, useEffect, useRef, useState } from "react";
import { HiMiniArrowPath } from "react-icons/hi2";

import { requestGuardDesktopHandoff } from "./guard-api";
import {
  DESKTOP_HANDOFF_FAILED,
  DESKTOP_HANDOFF_GUIDANCE,
  DESKTOP_HANDOFF_OPENING_LABEL,
  type DesktopUpdateBannerModel,
} from "./guard-update-copy";

const DISMISSED_KEY = "guard-desktop-update-dismissed";
/** How long the banner waits for the app window to take over before it
 * falls back to naming the menu-bar route. */
const HANDOFF_GUIDANCE_DELAY_MS = 6_000;

type HandoffPhase = "idle" | "requesting" | "opening" | "guidance" | "failed";

export function readDismissedDesktopUpdateVersion(): string | null {
  try {
    return window.sessionStorage.getItem(DISMISSED_KEY);
  } catch {
    // Session storage is optional in hardened browser contexts.
    return null;
  }
}

export function rememberDismissedDesktopUpdateVersion(version: string): void {
  try {
    window.sessionStorage.setItem(DISMISSED_KEY, version);
  } catch {
    // Session storage is optional in hardened browser contexts.
  }
}

/**
 * The update announcement shown at the top of the dashboard when it runs
 * inside the HOL Guard app. The primary action hands off to the app's own
 * updater (the dashboard cannot install against the runtime the app owns);
 * if the app window does not take over, the banner names the menu-bar
 * route instead of pretending the handoff worked.
 */
export function GuardUpdateBanner(props: {
  model: DesktopUpdateBannerModel;
  onDismiss: (version: string) => void;
}) {
  const { model, onDismiss } = props;
  const [phase, setPhase] = useState<HandoffPhase>("idle");
  const guidanceTimer = useRef<number | null>(null);
  // A handoff attempt belongs to one offered version: when a newer release
  // replaces the model, the old attempt's promise and timer must not move
  // the new banner's phase.
  const attemptRef = useRef(0);

  useEffect(() => {
    attemptRef.current += 1;
    if (guidanceTimer.current !== null) {
      window.clearTimeout(guidanceTimer.current);
      guidanceTimer.current = null;
    }
    setPhase("idle");
  }, [model.latestVersion]);

  useEffect(
    () => () => {
      if (guidanceTimer.current !== null) {
        window.clearTimeout(guidanceTimer.current);
      }
    },
    [],
  );

  const handleUpdate = useCallback(() => {
    if (phase === "requesting" || phase === "opening") {
      return;
    }
    const attempt = attemptRef.current + 1;
    attemptRef.current = attempt;
    setPhase("requesting");
    void requestGuardDesktopHandoff()
      .then((result) => {
        if (attemptRef.current !== attempt) {
          return;
        }
        if (!result.handoff_requested) {
          setPhase("failed");
          return;
        }
        setPhase("opening");
        guidanceTimer.current = window.setTimeout(() => {
          if (attemptRef.current === attempt) {
            setPhase("guidance");
          }
        }, HANDOFF_GUIDANCE_DELAY_MS);
      })
      .catch(() => {
        if (attemptRef.current === attempt) {
          setPhase("failed");
        }
      });
  }, [phase]);

  const handleDismiss = useCallback(() => {
    rememberDismissedDesktopUpdateVersion(model.latestVersion);
    onDismiss(model.latestVersion);
  }, [model.latestVersion, onDismiss]);

  const busy = phase === "requesting" || phase === "opening";

  return (
    <div
      className="flex flex-col gap-3 rounded-xl border border-brand-blue/30 bg-brand-blue/[0.06] px-4 py-3 sm:flex-row sm:items-center sm:justify-between"
      role="status"
    >
      <div className="flex items-start gap-3">
        <HiMiniArrowPath
          className={`mt-0.5 h-5 w-5 shrink-0 text-brand-blue ${busy ? "animate-spin" : ""}`}
          aria-hidden="true"
        />
        <div>
          <p className="text-sm font-semibold text-brand-dark">{model.title}</p>
          <p className="mt-1 text-sm text-brand-dark/75">{model.body}</p>
          {phase === "guidance" ? (
            <p className="mt-1 text-sm text-brand-dark/75">{DESKTOP_HANDOFF_GUIDANCE}</p>
          ) : null}
          {phase === "failed" ? (
            <p className="mt-1 text-sm text-brand-dark/75" role="alert">
              {DESKTOP_HANDOFF_FAILED}
            </p>
          ) : null}
        </div>
      </div>
      <div className="flex flex-wrap gap-2">
        <button
          type="button"
          onClick={handleUpdate}
          disabled={busy}
          aria-label="Update Guard in the HOL Guard app"
          className="inline-flex min-h-11 items-center justify-center rounded-lg bg-brand-blue px-4 text-sm font-semibold text-white disabled:cursor-not-allowed disabled:opacity-70"
        >
          {busy ? DESKTOP_HANDOFF_OPENING_LABEL : "Update in the app"}
        </button>
        <button
          type="button"
          onClick={handleDismiss}
          disabled={busy}
          className="inline-flex min-h-11 items-center justify-center rounded-lg border border-slate-200 bg-white px-4 text-sm font-medium text-brand-dark disabled:cursor-not-allowed disabled:opacity-70"
        >
          Not now
        </button>
      </div>
    </div>
  );
}
