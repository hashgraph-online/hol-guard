import { useMemo, useState } from "react";
import { HiMiniBeaker, HiMiniCheckCircle, HiMiniExclamationTriangle } from "react-icons/hi2";

import type { ExtensionCatalogItem } from "../extension-controls-api";
import { ProtectionDecisionBadge } from "./components/protection-primitives";
import { testProtectionCommand, type ProtectionTestResult } from "./protection-test-api";
import { EXTENSION_CHIP_CLASS, EXTENSION_KICKER_CLASS, EXTENSION_PANEL_CLASS } from "./protection-surface";

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

  return <section aria-labelledby="protection-test-lab-heading" className={EXTENSION_PANEL_CLASS}>
    <div className="flex items-start gap-3">
      <span className="grid size-10 shrink-0 place-items-center rounded-xl bg-[rgba(85,153,254,0.1)] text-brand-blue" aria-hidden="true"><HiMiniBeaker className="size-5" /></span>
      <div className="min-w-0">
        <p className={EXTENSION_KICKER_CLASS}>Paste the command Guard stopped</p>
        <h2 id="protection-test-lab-heading" className="mt-2 text-lg font-semibold text-brand-dark">Test Lab</h2>
        <p className="mt-1 text-sm leading-6 text-brand-dark/80">See how Guard would handle a command without running it, then adjust the exact pattern it matched.</p>
      </div>
    </div>
    <p className="mt-5 max-w-2xl text-sm leading-6 text-brand-dark/80">
      <strong className="font-semibold text-brand-dark">Nothing is executed.</strong> The command is evaluated locally in memory and is not saved to Activity or sent to Guard Cloud.
    </p>
    {examples.length ? <div className="mt-5">
      <div className={EXTENSION_KICKER_CLASS}>Try an example</div>
      <div className="mt-3 flex flex-wrap gap-2">{examples.map((example) => <button key={example} type="button" disabled={busy} onClick={() => { setCommand(example); setResult(null); setError(null); }} className={`${EXTENSION_CHIP_CLASS} disabled:cursor-not-allowed disabled:opacity-50`}>{example}</button>)}</div>
    </div> : null}
    <label className="mt-6 block">
      <span className="text-sm font-semibold text-brand-dark">Command to check</span>
      <textarea value={command} disabled={busy} onChange={(event) => { setCommand(event.target.value.slice(0, 4096)); setResult(null); setError(null); }} maxLength={4096} rows={3} spellCheck={false} autoComplete="off" placeholder="Paste a command here. Guard will not run it." className="mt-2 w-full resize-y rounded-2xl border border-[rgba(63,65,116,0.14)] bg-white/80 px-4 py-3 font-mono text-sm text-brand-dark outline-none focus:border-brand-blue focus:ring-2 focus:ring-blue-100" />
    </label>
    <div className="mt-3 flex flex-wrap items-center gap-2">
      <button type="button" onClick={() => { void run(); }} disabled={busy || !command.trim()} className="min-h-11 rounded-xl bg-brand-blue px-4 text-sm font-semibold text-white disabled:cursor-not-allowed disabled:opacity-50">{busy ? "Checking…" : "Check safely"}</button>
      {command ? <button type="button" disabled={busy} onClick={() => { setCommand(""); setResult(null); setError(null); }} className="min-h-11 rounded-xl border border-[rgba(63,65,116,0.16)] bg-white/80 px-4 text-sm font-semibold text-brand-dark disabled:cursor-not-allowed disabled:opacity-50">Clear</button> : null}
      <span className="text-xs text-brand-dark/55">{command.length}/4096</span>
    </div>
    {error ? <p role="alert" className="mt-4 rounded-xl border border-red-200 bg-red-50 p-3 text-sm text-red-800">{error}</p> : null}
    {result ? <div role="status" className="mt-5 rounded-2xl bg-white/55 p-4">
      <div className="flex flex-wrap items-center gap-3">
        <ProtectionDecisionBadge result={result.decision} />
        <strong className="text-sm text-brand-dark">{resultTitle(result)}</strong>
        {result.decision === "allowed" ? <HiMiniCheckCircle className="size-5 text-emerald-700" aria-hidden="true" /> : <HiMiniExclamationTriangle className="size-5 text-amber-700" aria-hidden="true" />}
      </div>
      <p className="mt-3 text-sm leading-6 text-brand-dark/80">{result.explanation}</p>
      {result.matches.length ? <div className="mt-4">
        <div className={EXTENSION_KICKER_CLASS}>Protection rules involved</div>
        <div className="mt-3 space-y-2">{result.matches.slice(0, 6).map((match) => <div key={`${match.extension_id}:${match.rule_id}`} className="rounded-xl bg-white/70 p-3">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <strong className="text-sm text-brand-dark">{match.rule_title}</strong>
            <span className="text-xs font-semibold capitalize text-brand-dark/55">{match.severity} risk</span>
          </div>
          <p className="mt-1 text-xs leading-5 text-brand-dark/70">{match.description}</p>
          {match.permission_id ? (
            <a
              href={`#pattern-${match.permission_id}`}
              onClick={(event) => {
                event.preventDefault();
                document.getElementById(`pattern-${match.permission_id}`)?.scrollIntoView({ behavior: "smooth", block: "center" });
                window.history.replaceState(null, "", `#pattern-${match.permission_id}`);
                window.dispatchEvent(new HashChangeEvent("hashchange"));
              }}
              className="mt-2 inline-flex min-h-9 items-center rounded-lg px-1 text-xs font-semibold text-brand-blue hover:underline"
            >Adjust this pattern</a>
          ) : null}
        </div>)}</div>
      </div> : null}
      {result.safer_alternatives.length ? <div className="mt-4">
        <div className={EXTENSION_KICKER_CLASS}>Safer alternatives</div>
        <ul className="mt-2 list-disc space-y-1 pl-5 text-sm text-brand-dark/80">{result.safer_alternatives.map((alternative) => <li key={alternative}>{alternative}</li>)}</ul>
      </div> : null}
      <p className="mt-4 text-xs text-brand-dark/55">This result uses the current local protection state. It is a read-only evaluation and does not create an approval or receipt.</p>
    </div> : null}
  </section>;
}