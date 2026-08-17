import { useCallback, useEffect, useState } from "react";
import type { ChangeEvent, FormEvent } from "react";

import {
  ApprovalProofFieldInputs,
  buildApprovalProofCredentials,
  isApprovalProofSubmitDisabled,
} from "../approval-proof-inline";
import {
  applyLocalCliMutation,
  LocalCliApiError,
  previewLocalCliMutation,
  recognizeLocalCli,
  suggestedCustomExtensions,
  type LocalCliItem,
  type LocalCliState,
} from "../local-cli-api";
import { useModalDialog } from "../use-modal-dialog";
import { useResolvedApprovalGate } from "../use-resolved-approval-gate";
import { InlineError } from "./components/protection-primitives";

function randomToken(): string {
  return crypto.randomUUID().replaceAll("-", "");
}

export function AddCustomExtensionDialog(props: {
  items: LocalCliItem[];
  revision: number;
  onClose: () => void;
  onAdded: (cliId: string) => void;
}) {
  const { resolvedApprovalGate, resolveApprovalGate } = useResolvedApprovalGate(null);
  const [command, setCommand] = useState("");
  const [recognized, setRecognized] = useState<LocalCliItem | null>(null);
  const [summary, setSummary] = useState<string | null>(null);
  const [pending, setPending] = useState<LocalCliState | null>(null);
  const [password, setPassword] = useState("");
  const [totp, setTotp] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const dialogRef = useModalDialog<HTMLFormElement>(props.onClose, !busy);
  const suggestions = suggestedCustomExtensions(props.items).slice(0, 6);

  useEffect(() => {
    void resolveApprovalGate({ failClosed: true }).catch(() => {
      setError("Guard could not load local approval settings yet.");
    });
  }, [resolveApprovalGate]);

  const handleCommand = useCallback((event: ChangeEvent<HTMLInputElement>) => {
    setCommand(event.target.value);
    setRecognized(null);
    setSummary(null);
    setPending(null);
    setError(null);
  }, []);
  const handlePassword = useCallback((event: ChangeEvent<HTMLInputElement>) => {
    setPassword(event.target.value);
  }, []);
  const handleTotp = useCallback((event: ChangeEvent<HTMLInputElement>) => {
    setTotp(event.target.value);
  }, []);
  const selectSuggestion = useCallback((item: LocalCliItem) => {
    setCommand(item.example_label);
    setRecognized(item);
    setSummary(`Later commands from this same ${item.name} file are covered. Different flags are fine.`);
    setPending(null);
    setError(null);
  }, []);
  const findTool = useCallback(async () => {
    setBusy(true);
    setError(null);
    try {
      const result = await recognizeLocalCli(command);
      setRecognized(result.item);
      setSummary(result.summary);
      setPending(null);
    } catch (caught) {
      setRecognized(null);
      setSummary(null);
      setError(caught instanceof LocalCliApiError ? caught.message : "Guard could not identify that command.");
    } finally {
      setBusy(false);
    }
  }, [command]);
  const requestAllow = useCallback(() => setPending("allowed"), []);
  const requestBlock = useCallback(() => setPending("blocked"), []);
  const handleSubmit = useCallback(async (event: FormEvent) => {
    event.preventDefault();
    if (recognized === null) {
      await findTool();
      return;
    }
    if (pending === null) return;
    setBusy(true);
    setError(null);
    try {
      const payload = {
        cli_id: recognized.cli_id,
        identity_hash: recognized.identity_hash,
        name: recognized.name,
        kind: recognized.kind,
        example_label: recognized.example_label,
        interpreter_name: recognized.interpreter_name,
        state: pending,
        previous_revision: props.revision,
        session_nonce: randomToken(),
        ...buildApprovalProofCredentials(resolvedApprovalGate, {
          approvalPassword: password,
          approvalTotpCode: totp,
        }),
      };
      await previewLocalCliMutation(payload);
      await applyLocalCliMutation(payload);
      props.onAdded(recognized.cli_id);
    } catch (caught) {
      setError(caught instanceof LocalCliApiError ? caught.message : "Guard could not add this custom extension.");
    } finally {
      setBusy(false);
    }
  }, [findTool, password, pending, props, recognized, resolvedApprovalGate, totp]);

  const proofReady = pending !== null && recognized !== null;
  const submitDisabled = recognized === null
    ? command.trim() === "" || busy
    : !proofReady || isApprovalProofSubmitDisabled(
      resolvedApprovalGate,
      { approvalPassword: password, approvalTotpCode: totp },
      busy,
    );
  const submitLabel = recognized === null ? (busy ? "Looking…" : "Find this tool") : busy ? "Saving…" : pending === "blocked" ? "Block this tool" : "Allow this tool";

  return (
    <div className="fixed inset-0 z-50 grid place-items-center bg-slate-950/45 p-4 backdrop-blur-sm">
      <form
        ref={dialogRef}
        tabIndex={-1}
        role="dialog"
        aria-modal="true"
        aria-labelledby="add-custom-extension-title"
        onSubmit={handleSubmit}
        className="w-full max-w-lg rounded-3xl bg-white p-6 shadow-2xl focus:outline-none"
      >
        <h2 id="add-custom-extension-title" className="text-xl font-semibold text-brand-dark">Add a custom extension</h2>
        <p className="mt-2 text-sm leading-6 text-brand-dark/80">
          Paste the command for your tool. Guard binds to that file, then you can allow or block later commands from it.
        </p>
        <label htmlFor="custom-extension-command" className="mt-5 block text-sm font-semibold text-brand-dark">Command</label>
        <input
          id="custom-extension-command"
          value={command}
          onChange={handleCommand}
          spellCheck={false}
          autoComplete="off"
          placeholder="python3 scripts/cwv.py --by url"
          className="mt-2 min-h-11 w-full rounded-xl border border-slate-300 px-3 text-sm text-brand-dark placeholder:text-brand-dark/40 focus:border-brand-blue focus:outline-none focus:ring-2 focus:ring-brand-blue/30"
        />
        <p className="mt-2 text-sm leading-6 text-brand-dark/70">
          One command. Include the script or binary. Not <span className="font-medium">ls</span>, <span className="font-medium">grep</span>, or a pipeline.
        </p>
        {recognized ? (
          <div className="mt-5 rounded-2xl border border-slate-200 bg-slate-50 px-4 py-3">
            <p className="text-sm font-semibold text-brand-dark">{recognized.name}</p>
            <p className="mt-1 font-mono text-xs text-brand-dark/70">{recognized.example_label}</p>
            {summary ? <p className="mt-2 text-sm leading-6 text-brand-dark/80">{summary}</p> : null}
            <div className="mt-4 flex flex-wrap gap-2">
              <button type="button" onClick={requestAllow} className={`min-h-11 rounded-xl px-4 text-sm font-semibold ${pending === "allowed" ? "bg-brand-blue text-white" : "border border-slate-300 text-brand-dark"}`}>
                Allow this tool
              </button>
              <button type="button" onClick={requestBlock} className={`min-h-11 rounded-xl px-4 text-sm font-semibold ${pending === "blocked" ? "bg-brand-dark text-white" : "border border-slate-300 text-brand-dark"}`}>
                Block this tool
              </button>
            </div>
          </div>
        ) : null}
        {proofReady ? (
          <div className="mt-5">
            <ApprovalProofFieldInputs
              approvalGate={resolvedApprovalGate}
              approvalPassword={password}
              approvalTotpCode={totp}
              onApprovalPasswordChange={handlePassword}
              onApprovalTotpCodeChange={handleTotp}
            />
          </div>
        ) : null}
        {suggestions.length > 0 && recognized === null ? (
          <div className="mt-5">
            <p className="text-sm font-semibold text-brand-dark">Seen on this device</p>
            <ul className="mt-2 divide-y divide-slate-200">
              {suggestions.map((item) => (
                <li key={item.cli_id}>
                  <SuggestionButton item={item} onSelect={selectSuggestion} />
                </li>
              ))}
            </ul>
          </div>
        ) : null}
        {error ? <div className="mt-4"><InlineError message={error} /></div> : null}
        <div className="mt-6 flex justify-end gap-3">
          <button type="button" disabled={busy} onClick={props.onClose} className="min-h-11 rounded-xl px-4 text-sm font-semibold text-brand-dark">Cancel</button>
          <button type="submit" disabled={submitDisabled} className="min-h-11 rounded-xl bg-brand-blue px-5 text-sm font-semibold text-white disabled:opacity-60">
            {submitLabel}
          </button>
        </div>
      </form>
    </div>
  );
}

function SuggestionButton(props: { item: LocalCliItem; onSelect: (item: LocalCliItem) => void }) {
  const handleSelect = useCallback(() => {
    props.onSelect(props.item);
  }, [props]);
  return (
    <button type="button" onClick={handleSelect} className="flex min-h-11 w-full items-baseline justify-between gap-3 py-2 text-left">
      <span className="truncate text-sm font-semibold text-brand-dark">{props.item.name}</span>
      <span className="truncate font-mono text-xs text-brand-dark/60">{props.item.example_label}</span>
    </button>
  );
}
