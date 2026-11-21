import { useCallback, useEffect, useRef, useState } from "react";
import { HiMiniArrowPath, HiMiniArrowTopRightOnSquare, HiMiniCloud, HiMiniShieldCheck } from "react-icons/hi2";

import { checkCloudActionsNow, fetchCloudActionsStatus } from "./cloud-actions-api";
import {
  CLOUD_ACTIONS_CONNECT_COMMAND,
  cloudActionsCheckedCopy,
  cloudActionsCurrentState,
  cloudActionsLinks,
  cloudActionsReconnectCommand,
  cloudActionsRetryAfterSeconds,
  cloudActionsSettingCopy,
  cloudActionsStateCopy,
  cloudActionsSummary,
  normalizeCloudActionsStatus,
  type CloudActionsConnection,
  type CloudActionsStatus,
  type CloudActionsTone,
} from "./cloud-actions-model";

const TONE_CLASS: Record<CloudActionsTone, string> = {
  good: "border-emerald-200 bg-emerald-50 text-emerald-800",
  neutral: "border-slate-200 bg-slate-50 text-slate-700",
  attention: "border-amber-200 bg-amber-50 text-amber-900",
};

const UNREADABLE = "Guard could not read the Cloud actions status on this computer. Update Guard, then reload this page.";
const HEADING_ID = "cloud-actions-connection";

function CommandLine({ label, command }: { label: string; command: string }) {
  return (
    <div className="mt-2">
      <p className="text-xs text-slate-600">{label}</p>
      {/* Long commands scroll sideways on a phone, so the box takes keyboard focus. */}
      <code
        tabIndex={0}
        className="mt-1 block overflow-x-auto whitespace-pre rounded-md bg-slate-50 px-3 py-2 font-mono text-xs text-brand-dark focus:outline-none focus-visible:ring-2 focus-visible:ring-brand-dark"
      >
        {command}
      </code>
    </div>
  );
}

function Reconnect({ connection }: { connection: CloudActionsConnection }) {
  const command = cloudActionsReconnectCommand(connection);
  if (command !== null) return <CommandLine label="To reconnect, run this in a terminal" command={command} />;
  return (
    <p className="mt-2 text-sm text-slate-700">
      To reconnect, run <code className="font-mono text-xs">hol-guard connect</code> with{" "}
      <code className="font-mono text-xs">--connect-url</code> set to the Guard Cloud connect page on {connection.site}.
    </p>
  );
}

function CloudPages({ connection }: { connection: CloudActionsConnection }) {
  const links = cloudActionsLinks(connection);
  if (links.length === 0) return null;
  const pagesId = `${HEADING_ID}-pages`;
  return (
    <nav aria-labelledby={pagesId} className="mt-3">
      <h5 id={pagesId} className="text-xs text-slate-600">
        Open in Guard Cloud
      </h5>
      <ul className="mt-1 grid grid-cols-1 gap-x-6 gap-y-1 sm:grid-cols-2">
        {links.map((link) => (
          <li key={link.label} className="min-w-0">
            <a
              href={link.href}
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex min-h-11 items-center gap-1.5 rounded-sm text-sm font-semibold text-brand-dark underline decoration-brand-blue underline-offset-2 hover:decoration-2 focus:outline-none focus-visible:ring-2 focus-visible:ring-brand-dark sm:min-h-0"
            >
              {link.label}
              <HiMiniArrowTopRightOnSquare aria-hidden="true" className="h-3.5 w-3.5 shrink-0" />
              <span className="sr-only">(opens in a new tab)</span>
            </a>
            <p className="text-xs text-slate-600">{link.description}</p>
          </li>
        ))}
      </ul>
    </nav>
  );
}

export function CloudActionsConnectionCard({
  connection,
  now,
  staleAfterSeconds,
}: {
  connection: CloudActionsConnection;
  now: Date;
  staleAfterSeconds: number;
}) {
  const state = cloudActionsCurrentState(connection);
  const copy = cloudActionsStateCopy(state);
  return (
    <div aria-labelledby={HEADING_ID} className="rounded-xl border border-slate-100 bg-white p-4">
      <div className="flex flex-wrap items-start justify-between gap-2">
        <div className="min-w-0">
          <h4 id={HEADING_ID} className="break-all text-sm font-semibold text-brand-dark">
            {connection.workspace ?? "Workspace not reported"}
          </h4>
          <p className="mt-0.5 break-all text-xs text-slate-600">{connection.site ?? "Guard Cloud site not recorded"}</p>
        </div>
        <span className={`inline-flex shrink-0 items-center rounded-full border px-2.5 py-0.5 text-xs font-semibold ${TONE_CLASS[copy.tone]}`}>
          {copy.label}
        </span>
      </div>
      <dl className="mt-3 grid grid-cols-1 gap-x-6 gap-y-2 text-sm sm:grid-cols-2">
        <div className="min-w-0">
          <dt className="text-xs text-slate-600">Cloud actions on this computer</dt>
          <dd className="mt-0.5 text-brand-dark">{cloudActionsSettingCopy(connection.setting)}</dd>
        </div>
        <div className="min-w-0">
          <dt className="text-xs text-slate-600">Guard Cloud's answer</dt>
          <dd className="mt-0.5 text-brand-dark">{cloudActionsCheckedCopy(connection.check, now, staleAfterSeconds)}</dd>
        </div>
      </dl>
      {connection.check.message !== null && state === connection.check.state ? (
        <p className="mt-2 text-sm text-slate-600">{connection.check.message}</p>
      ) : null}
      {copy.remedy !== null ? <p className="mt-2 text-sm text-slate-700">{copy.remedy}</p> : null}
      {copy.reconnect ? <Reconnect connection={connection} /> : null}
      <CloudPages connection={connection} />
    </div>
  );
}

export function CloudActionsSettingsView({
  status,
  error,
  loading,
  checking,
  notice,
  retryAfterSeconds,
  now,
  onCheck,
}: {
  status: CloudActionsStatus | null;
  error: string | null;
  loading: boolean;
  checking: boolean;
  notice: string | null;
  retryAfterSeconds: number;
  now: Date;
  onCheck: () => void;
}) {
  let summary = error ?? "Reading Cloud actions...";
  if (status !== null && !loading) summary = cloudActionsSummary(status);
  const connection = status?.connection ?? null;
  let checkLabel = "Check now";
  if (checking) checkLabel = "Checking...";
  else if (retryAfterSeconds > 0) checkLabel = `Check again in ${retryAfterSeconds}s`;
  return (
    <div className="flex min-h-0 flex-1 flex-col space-y-6">
      <div className="flex items-start gap-3 rounded-xl border border-emerald-100 bg-emerald-50/60 p-4">
        <HiMiniShieldCheck aria-hidden="true" className="mt-0.5 h-5 w-5 shrink-0 text-emerald-700" />
        <p className="text-sm text-slate-700">
          Protection on this computer does not depend on Cloud actions. It keeps working when Guard Cloud is offline,
          when this computer is disconnected, and when included actions run out.
        </p>
      </div>
      <section aria-labelledby="cloud-actions-heading" className="space-y-3">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div className="min-w-0">
            <h3 id="cloud-actions-heading" className="flex items-center gap-2 text-sm font-semibold text-brand-dark">
              <HiMiniCloud aria-hidden="true" className="h-5 w-5 shrink-0" /> Cloud actions
            </h3>
            <p className="mt-1 text-sm text-slate-600">
              Cloud actions let AI tools on this computer ask for actions in the Guard Cloud workspace this computer is
              connected to. Guard Cloud decides those actions; they never approve anything Guard pauses on this computer.
            </p>
          </div>
          {connection !== null ? (
            <button
              type="button"
              disabled={checking || loading || retryAfterSeconds > 0}
              onClick={onCheck}
              className="inline-flex min-h-11 shrink-0 items-center gap-2 rounded-md border border-slate-200 px-3 py-2 text-sm font-semibold text-brand-dark hover:bg-slate-50 disabled:opacity-60 sm:min-h-10"
            >
              <HiMiniArrowPath aria-hidden="true" className="h-4 w-4" />
              {checkLabel}
            </button>
          ) : null}
        </div>
        <p role="status" className="text-sm text-slate-700">
          {summary}
        </p>
        {notice !== null ? <p role="alert" className="text-sm text-amber-900">{notice}</p> : null}
        {connection !== null ? (
          <CloudActionsConnectionCard connection={connection} now={now} staleAfterSeconds={status?.staleAfterSeconds ?? 300} />
        ) : null}
        {status !== null && connection === null ? (
          <CommandLine label="To connect, run this in a terminal" command={CLOUD_ACTIONS_CONNECT_COMMAND} />
        ) : null}
        {status !== null ? (
          <p className="text-xs text-slate-600">
            Included actions and connected accounts are kept in Guard Cloud, not on this computer. Guard Cloud asks you to
            sign in to your account in the browser before it shows them.
          </p>
        ) : null}
      </section>
    </div>
  );
}

export function CloudActionsSettings() {
  const [status, setStatus] = useState<CloudActionsStatus | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [checking, setChecking] = useState(false);
  const [notice, setNotice] = useState<string | null>(null);
  const [now, setNow] = useState(() => new Date());
  const [waitUntil, setWaitUntil] = useState<number>(0);
  const revision = useRef(0);

  const apply = useCallback((payload: unknown) => {
    const next = normalizeCloudActionsStatus(payload);
    setStatus(next);
    setError(next === null ? UNREADABLE : null);
    const current = new Date();
    setNow(current);
    if (next !== null) {
      setWaitUntil(current.getTime() + cloudActionsRetryAfterSeconds(next.nextCheckAllowedAt, current) * 1000);
    }
  }, []);

  useEffect(() => {
    const current = ++revision.current;
    void (async () => {
      try {
        const payload = await fetchCloudActionsStatus();
        if (current === revision.current) apply(payload);
      } catch {
        if (current === revision.current) {
          setError("Guard on this computer did not answer. Protection status is on the Home page; reload to try again.");
        }
      } finally {
        if (current === revision.current) setLoading(false);
      }
    })();
    return () => {
      revision.current += 1;
    };
  }, [apply]);

  // Keeps "Checked ... ago" and the wait countdown current without asking Guard Cloud.
  useEffect(() => {
    const timer = window.setInterval(() => setNow(new Date()), 1000);
    return () => window.clearInterval(timer);
  }, []);

  const onCheck = useCallback(() => {
    const current = ++revision.current;
    setChecking(true);
    setNotice(null);
    void (async () => {
      try {
        const outcome = await checkCloudActionsNow();
        if (current !== revision.current) return;
        if (outcome.kind === "wait") {
          setNotice(outcome.message);
          setWaitUntil(Date.now() + outcome.retryAfterSeconds * 1000);
        } else {
          apply(outcome.payload);
        }
      } catch (cause) {
        if (current === revision.current) {
          setNotice(cause instanceof Error ? cause.message : "Guard could not check Cloud actions. Try again.");
        }
      } finally {
        if (current === revision.current) setChecking(false);
      }
    })();
  }, [apply]);

  const retryAfterSeconds = Math.max(0, Math.ceil((waitUntil - now.getTime()) / 1000));
  return (
    <CloudActionsSettingsView
      status={status}
      error={error}
      loading={loading}
      checking={checking}
      notice={notice}
      retryAfterSeconds={retryAfterSeconds}
      now={now}
      onCheck={onCheck}
    />
  );
}
