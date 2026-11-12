import { useEffect, useRef, useState } from "react";

import {
  checkPluginUpdates,
  dismissPluginUpdate,
  type PluginUpdate,
  type PluginUpdatesResult,
} from "./plugin-updates-api";

const RUNTIME_LABELS: Record<string, string> = {
  "claude-code": "Claude Code",
  codex: "Codex",
  cursor: "Cursor",
  gemini: "Gemini CLI",
  "gemini-cli": "Gemini CLI",
  opencode: "OpenCode",
  vscode: "VS Code",
};

export function runtimeLabel(runtime: string): string {
  return RUNTIME_LABELS[runtime] ?? runtime;
}

export function urgentReasonCopy(update: PluginUpdate): string | null {
  if (update.reason === "security_fix") return "Urgent: a newer release fixes a high or critical finding.";
  if (update.reason === "installed_high_severity") return "Urgent: the installed release had a high or critical finding.";
  return update.urgent ? "Urgent update." : null;
}

function updateKey(update: PluginUpdate): string {
  return `${update.slug}\u0000${update.runtime}`;
}

function dismissalKey(update: Pick<PluginUpdate, "slug" | "latestVersion">): string {
  return `${update.slug}\u0000${update.latestVersion}`;
}

/** Drops prompts the reader dismissed while this answer was in flight. */
export function withoutDismissed(result: PluginUpdatesResult, dismissed: ReadonlySet<string>): PluginUpdatesResult {
  if (result.status !== "ok" || dismissed.size === 0) return result;
  const updates = result.updates.filter((update) => !dismissed.has(dismissalKey(update)));
  return { status: "ok", updates, dismissed: result.dismissed + result.updates.length - updates.length };
}

/**
 * "Update available" for installed plugins whose authors recorded a newer,
 * checked release on HOL. The check runs only when the reader asks, and a
 * dismissal holds until a newer release is checked.
 */
export function PluginUpdatesSection() {
  const [result, setResult] = useState<PluginUpdatesResult | null>(null);
  const [checking, setChecking] = useState(false);
  const [dismissing, setDismissing] = useState<string | null>(null);
  const [dismissError, setDismissError] = useState<string | null>(null);
  const controller = useRef<AbortController | null>(null);
  const dismissedDuringCheck = useRef(new Set<string>());
  useEffect(() => () => controller.current?.abort(), []);

  const check = async () => {
    controller.current?.abort();
    const next = new AbortController();
    controller.current = next;
    dismissedDuringCheck.current = new Set();
    setChecking(true);
    setDismissError(null);
    try {
      const answer = await checkPluginUpdates(next.signal);
      if (!next.signal.aborted) setResult(withoutDismissed(answer, dismissedDuringCheck.current));
    } catch {
      // Aborted because the reader left or checked again.
    } finally {
      if (controller.current === next) {
        controller.current = null;
        setChecking(false);
      }
    }
  };

  const dismiss = async (update: PluginUpdate) => {
    const key = updateKey(update);
    setDismissing(key);
    setDismissError(null);
    try {
      await dismissPluginUpdate(update);
      dismissedDuringCheck.current.add(dismissalKey(update));
      setResult((current) => (current ? withoutDismissed(current, new Set([dismissalKey(update)])) : current));
    } catch (caught) {
      setDismissError(caught instanceof Error ? caught.message : "Guard could not dismiss this update.");
    } finally {
      setDismissing(null);
    }
  };

  const updates = result?.status === "ok" ? result.updates : [];
  return (
    <section className="mt-8 border-b border-slate-200 pb-5" aria-labelledby="plugin-updates-heading" data-testid="plugin-updates">
      <h2 id="plugin-updates-heading" className="text-base font-semibold text-brand-dark">Plugin updates</h2>
      <p className="mt-1 max-w-2xl text-sm leading-6 text-brand-dark/75">
        Compare the plugins installed here with the releases their authors scanned and checked on HOL. Guard downloads
        the public release index and compares versions on this device; nothing about your plugins is sent.
      </p>
      <button
        type="button"
        onClick={() => void check()}
        disabled={checking}
        aria-busy={checking}
        className="mt-3 min-h-11 rounded-xl border border-slate-300 px-4 text-sm font-semibold text-brand-dark disabled:opacity-50"
      >
        {checking ? "Checking plugin updates…" : result ? "Check again" : "Check for plugin updates"}
      </button>
      {result?.status === "failed" ? (
        <p role="alert" className="mt-3 text-sm leading-6 text-red-700">{result.message}</p>
      ) : null}
      {dismissError ? <p role="alert" className="mt-3 text-sm leading-6 text-red-700">{dismissError}</p> : null}
      {result?.status === "ok" ? (
        <p role="status" className="mt-3 text-sm leading-6 text-brand-dark/75">
          {updates.length === 0
            ? "No newer checked releases for the plugins installed here."
            : `${updates.length} ${updates.length === 1 ? "update" : "updates"} available.`}
          {result.dismissed > 0 ? ` ${result.dismissed} dismissed until a newer release is checked.` : ""}
        </p>
      ) : null}
      {updates.length > 0 ? (
        <ul className="mt-3 divide-y divide-slate-200">
          {updates.map((update) => {
            const urgent = urgentReasonCopy(update);
            const key = updateKey(update);
            return (
              <li key={key} className="flex flex-wrap items-start justify-between gap-3 py-4">
                <div className="min-w-0">
                  <h3 className="break-all text-sm font-semibold text-brand-dark">{update.slug}</h3>
                  <p className="mt-1 text-sm leading-6 text-brand-dark/75">
                    {runtimeLabel(update.runtime)} · {update.installedVersion} → {update.latestVersion}
                  </p>
                  {urgent ? (
                    <p className="mt-1 text-sm font-semibold leading-6 text-red-700" data-testid="plugin-update-urgent">
                      {urgent}
                    </p>
                  ) : null}
                </div>
                <div className="flex flex-wrap gap-2">
                  {update.releasesUrl ? (
                    <a
                      href={update.releasesUrl}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="inline-flex min-h-11 items-center rounded-xl border border-brand-blue/30 px-4 text-sm font-semibold text-brand-blue no-underline"
                    >
                      View release
                    </a>
                  ) : null}
                  <button
                    type="button"
                    onClick={() => void dismiss(update)}
                    disabled={dismissing !== null}
                    className="min-h-11 rounded-xl border border-slate-300 px-4 text-sm font-semibold text-brand-dark disabled:opacity-50"
                  >
                    {dismissing === key ? "Dismissing…" : `Dismiss ${update.latestVersion}`}
                  </button>
                </div>
              </li>
            );
          })}
        </ul>
      ) : null}
    </section>
  );
}
