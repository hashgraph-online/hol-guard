import { useMemo, useState } from "react";
import { HiMiniCheckCircle, HiMiniExclamationTriangle } from "react-icons/hi2";

import type { ExtensionCatalogItem } from "../extension-controls-api";
import { ProtectionDecisionBadge } from "./components/protection-primitives";
import { testProtectionCommand, type ProtectionTestResult } from "./protection-test-api";
import { EXTENSION_CHIP_CLASS } from "./protection-surface";

function safeExamples(extension: ExtensionCatalogItem): string[] {
  const executable = extension.executables[0];
  const examples = extension.extension_id === "command.git"
    ? ["git status", "git reset --hard HEAD~1", "git push --force-with-lease"]
    : executable
      ? [`${executable} --help`]
      : [];
  return examples.slice(0, 3);
}

function resultTitle(result: ProtectionTestResult): string {
  if (result.decision === "blocked") return "Guard would block this";
  if (result.decision === "ask-first") return "Guard would ask first";
  return "Guard would allow this";
}

export function ProtectionTestLab({ extension }: { extension: ExtensionCatalogItem }) {
  const [command, setCommand] = useState("");
  const [result, setResult] = useState<ProtectionTestResult | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const examples = useMemo(() => safeExamples(extension), [extension]);

  const run = async () => {
    const candidate = command.trim();
    if (!candidate || busy) return;
    setBusy(true);
    setError(null);
    setResult(null);
    try {
      setResult(await testProtectionCommand(extension.extension_id, candidate));
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Test Lab could not evaluate this command.");
    } finally {
      setBusy(false);
    }
  };

  return <section aria-labelledby="protection-test-lab-heading" className="mt-10 rounded-2xl border border-slate-200 bg-white p-5 sm:p-6">
    <div className="flex flex-wrap items-baseline justify-between gap-2">
      <h2 id="protection-test-lab-heading" className="text-lg font-semibold tracking-tight text-brand-dark">Test Lab</h2>
      <p className="text-xs text-slate-500">Nothing is executed. The check runs locally and is not saved.</p>
    </div>
    <p className="mt-1 text-sm text-slate-500">See how Guard would handle a {extension.name} command without running it.</p>
    {examples.length ? <div className="mt-4 flex flex-wrap gap-2">{examples.map((example) => <button key={example} type="button" disabled={busy} onClick={() => { setCommand(example); setResult(null); setError(null); }} className={`${EXTENSION_CHIP_CLASS} disabled:cursor-not-allowed disabled:opacity-50`}>{example}</button>)}</div> : null}
    <div className="mt-3 flex flex-col gap-2 sm:flex-row">
      <input
        value={command}
        disabled={busy}
        onChange={(event) => { setCommand(event.target.value.slice(0, 4096)); setResult(null); setError(null); }}
        onKeyDown={(event) => { if (event.key === "Enter") { event.preventDefault(); void run(); } }}
        maxLength={4096}
        spellCheck={false}
        autoComplete="off"
        aria-label="Command to check"
        placeholder="Paste a command Guard stopped, like git reset --hard HEAD~1"
        className="min-h-11 w-full flex-1 rounded-xl border border-slate-200 bg-white px-3 font-mono text-sm text-brand-dark placeholder:font-sans placeholder:text-slate-400 focus:border-brand-blue focus:outline-none focus:ring-2 focus:ring-blue-100"
      />
      <button type="button" onClick={() => { void run(); }} disabled={busy || !command.trim()} className="min-h-11 shrink-0 rounded-xl bg-brand-blue px-4 text-sm font-semibold text-white disabled:cursor-not-allowed disabled:opacity-50">{busy ? "Checking…" : "Check safely"}</button>
    </div>
    {error ? <p role="alert" className="mt-4 rounded-xl border border-red-200 bg-red-50 p-3 text-sm text-red-800">{error}</p> : null}
    {result ? <div role="status" className="mt-5 rounded-xl bg-slate-50 p-4">
      <div className="flex flex-wrap items-center gap-3">
        <ProtectionDecisionBadge result={result.decision} />
        <strong className="text-sm text-brand-dark">{resultTitle(result)}</strong>
        {result.decision === "allowed" ? <HiMiniCheckCircle className="size-5 text-emerald-700" aria-hidden="true" /> : <HiMiniExclamationTriangle className="size-5 text-amber-700" aria-hidden="true" />}
      </div>
      <p className="mt-3 text-sm leading-6 text-brand-dark/80">{result.explanation}</p>
      {result.matches.length ? <div className="mt-4">
        <p className="text-xs font-semibold uppercase tracking-[0.14em] text-slate-400">Protection rules involved</p>
        <div className="mt-3 space-y-2">{result.matches.slice(0, 6).map((match) => <div key={`${match.extension_id}:${match.rule_id}`} className="rounded-xl bg-white p-3">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <strong className="text-sm text-brand-dark">{match.rule_title}</strong>
            <span className="text-xs font-semibold capitalize text-brand-dark/55">{match.severity} risk</span>
          </div>
          <p className="mt-1 text-xs leading-5 text-brand-dark/70">{match.description}</p>
        </div>)}</div>
      </div> : null}
      {result.safer_alternatives.length ? <div className="mt-4">
        <p className="text-xs font-semibold uppercase tracking-[0.14em] text-slate-400">Safer alternatives</p>
        <ul className="mt-2 list-disc space-y-1 pl-5 text-sm text-brand-dark/80">{result.safer_alternatives.map((alternative) => <li key={alternative}>{alternative}</li>)}</ul>
      </div> : null}
      <p className="mt-4 text-xs text-slate-500">This result uses the current local protection state. It is a read-only evaluation and does not create an approval or receipt.</p>
    </div> : null}
  </section>;
}
