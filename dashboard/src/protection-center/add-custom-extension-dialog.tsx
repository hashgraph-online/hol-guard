import { useCallback, useEffect, useRef, useState } from "react";
import type { ChangeEvent, FormEvent } from "react";

import {
  ApprovalProofFieldInputs,
  buildApprovalProofCredentials,
  isApprovalProofSubmitDisabled,
} from "../approval-proof-inline";
import {
  applyLocalCliMutation,
  filterExtensionSuggestions,
  filterPackageScriptCommands,
  LocalCliApiError,
  previewLocalCliMutation,
  looksLikePackageScriptPaste,
  keepsPackageScriptCatalog,
  preferredPackageScriptExtension,
  recognizeLocalCli,
  suggestedHarnessExtensions,
  suggestedPackageScriptExtensions,
  suggestedSeenExtensions,
  type LocalCliCommandState,
  type LocalCliItem,
  type LocalCliState,
} from "../local-cli-api";
import {
  addDialogSubmitLabel,
  allowActionLabel,
  blockActionLabel,
  dialogIntro,
  filterCountCopy,
  ProjectSwitcher,
  SuggestionPanel,
  suggestionSummary,
  surfaceBadge,
} from "./add-custom-extension-support";
import { CustomExtensionCommandList, commandStatesPayload, withCommandState } from "./custom-extension-commands";
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
  const [commands, setCommands] = useState<LocalCliItem["commands"]>([]);
  const [summary, setSummary] = useState<string | null>(null);
  const [pending, setPending] = useState<LocalCliState | null>(null);
  const [password, setPassword] = useState("");
  const [totp, setTotp] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const dialogRef = useModalDialog<HTMLFormElement>(props.onClose, !busy);
  const recognizeGeneration = useRef(0);
  const autoRecognizedCommand = useRef("");
  const didAutoSelect = useRef(false);
  const rememberedProjects = suggestedPackageScriptExtensions(props.items);
  const packageScriptSuggestions = filterExtensionSuggestions(
    rememberedProjects,
    command,
  ).slice(0, 6);
  const harnessSuggestions = filterExtensionSuggestions(
    suggestedHarnessExtensions(props.items),
    command,
  ).slice(0, 8);
  const seenSuggestions = filterExtensionSuggestions(
    suggestedSeenExtensions(props.items),
    command,
  ).slice(0, 6);
  const hasSuggestions = packageScriptSuggestions.length > 0
    || harnessSuggestions.length > 0
    || seenSuggestions.length > 0;

  useEffect(() => {
    void resolveApprovalGate({ failClosed: true }).catch(() => {
      setError("Guard could not load local approval settings yet.");
    });
  }, [resolveApprovalGate]);

  const handleCommand = useCallback((event: ChangeEvent<HTMLInputElement>) => {
    const value = event.target.value;
    const keepCatalog = recognized?.surface === "package-scripts" && keepsPackageScriptCatalog(value, commands);
    setCommand(value);
    setError(null);
    if (keepCatalog) return;
    recognizeGeneration.current += 1;
    autoRecognizedCommand.current = "";
    setBusy(false);
    setRecognized(null);
    setCommands([]);
    setSummary(null);
    setPending(null);
  }, [commands, recognized]);
  const handlePassword = useCallback((event: ChangeEvent<HTMLInputElement>) => {
    setPassword(event.target.value);
  }, []);
  const handleTotp = useCallback((event: ChangeEvent<HTMLInputElement>) => {
    setTotp(event.target.value);
  }, []);
  const runRecognize = useCallback(async (commandText: string, cliId?: string, silent = false) => {
    const generation = recognizeGeneration.current + 1;
    recognizeGeneration.current = generation;
    setBusy(true);
    if (!silent) setError(null);
    try {
      const result = await recognizeLocalCli(commandText, cliId ? { cliId } : undefined);
      if (recognizeGeneration.current !== generation) return;
      setRecognized(result.item);
      setCommands(result.item.commands);
      setSummary(result.summary);
      setPending(result.item.surface === "package-scripts" ? "allowed" : null);
      setError(null);
    } catch (caught) {
      if (recognizeGeneration.current !== generation) return;
      setRecognized(null);
      setSummary(null);
      if (!silent) {
        setError(caught instanceof LocalCliApiError ? caught.message : "Guard could not identify that command.");
      }
    } finally {
      if (recognizeGeneration.current === generation) setBusy(false);
    }
  }, []);
  const selectSuggestion = useCallback((item: LocalCliItem) => {
    if (item.surface !== "package-scripts") setCommand(item.example_label);
    setError(null);
    if (item.surface === "mcp" && item.commands.length === 0) {
      setRecognized(null);
      setCommands([]);
      setSummary(null);
      setPending(null);
      void runRecognize(item.example_label, item.cli_id);
      return;
    }
    setRecognized(item);
    setCommands(item.commands);
    setSummary(suggestionSummary(item));
    setPending(item.surface === "package-scripts" && item.commands.length > 0 ? "allowed" : null);
  }, [runRecognize]);
  const findTool = useCallback(async () => {
    await runRecognize(command);
  }, [command, runRecognize]);
  useEffect(() => {
    if (didAutoSelect.current || recognized !== null || command.trim() !== "") return;
    const preferred = preferredPackageScriptExtension(props.items);
    if (preferred === null) return;
    didAutoSelect.current = true;
    selectSuggestion(preferred);
  }, [command, props.items, recognized, selectSuggestion]);
  useEffect(() => {
    const trimmed = command.trim();
    if (recognized !== null || !looksLikePackageScriptPaste(trimmed)) return;
    if (autoRecognizedCommand.current === trimmed) return;
    const handle = window.setTimeout(() => {
      autoRecognizedCommand.current = trimmed;
      void runRecognize(trimmed, undefined, true);
    }, 280);
    return () => window.clearTimeout(handle);
  }, [busy, command, recognized, runRecognize]);
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
        commands: commandStatesPayload(commands),
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
  }, [commands, findTool, password, pending, props, recognized, resolvedApprovalGate, totp]);
  const handleCommandState = useCallback((commandId: string, state: LocalCliCommandState) => {
    setCommands((current) => withCommandState(current, commandId, state));
  }, []);

  const proofReady = pending !== null && recognized !== null;
  const submitDisabled = recognized === null
    ? command.trim() === "" || busy
    : !proofReady || isApprovalProofSubmitDisabled(
      resolvedApprovalGate,
      { approvalPassword: password, approvalTotpCode: totp },
      busy,
    );
  const submitLabel = addDialogSubmitLabel({
    recognized,
    busy,
    pending,
  });
  const showingPackageCatalog = recognized?.surface === "package-scripts";
  const visibleCommands = showingPackageCatalog
    ? filterPackageScriptCommands(commands, command)
    : commands;
  const commandLabel = showingPackageCatalog ? "Filter scripts" : "Command";
  const commandPlaceholder = showingPackageCatalog
    ? "guard:audit"
    : "npm run guard:audit";

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
          {dialogIntro(rememberedProjects.length > 0, showingPackageCatalog === true)}
        </p>
        <label htmlFor="custom-extension-command" className="mt-5 block text-sm font-semibold text-brand-dark">{commandLabel}</label>
        <input
          id="custom-extension-command"
          value={command}
          onChange={handleCommand}
          spellCheck={false}
          autoComplete="off"
          placeholder={commandPlaceholder}
          className="mt-2 min-h-11 w-full rounded-xl border border-slate-300 px-3 text-sm text-brand-dark placeholder:text-brand-dark/40 focus:border-brand-blue focus:outline-none focus:ring-2 focus:ring-brand-blue/30"
        />
        <p className="mt-2 text-sm leading-6 text-brand-dark/70">
          {showingPackageCatalog
            ? "Typing filters nested names. Allow still enrolls every script in this project."
            : <>One command. A script, a binary, <span className="font-medium">npm run</span>, a project folder, or an MCP launch. Not a pipeline.</>}
        </p>
        {recognized !== null && showingPackageCatalog ? (
          <ProjectSwitcher
            items={rememberedProjects}
            currentId={recognized.cli_id}
            onSelect={selectSuggestion}
          />
        ) : null}
        {recognized ? (
          <div className="mt-5 rounded-2xl border border-slate-200 bg-slate-50 px-4 py-3">
            <div className="flex flex-wrap items-center gap-2">
              <p className="text-sm font-semibold text-brand-dark">{recognized.name}</p>
              {surfaceBadge(recognized.surface) ? (
                <span className="rounded-full bg-white px-2 py-0.5 text-[11px] font-semibold tracking-wide text-brand-dark/70 ring-1 ring-slate-200">
                  {surfaceBadge(recognized.surface)}
                </span>
              ) : null}
            </div>
            <p className="mt-1 font-mono text-xs text-brand-dark/70">
              {recognized.source_label ? `${recognized.source_label} · ${recognized.example_label}` : recognized.example_label}
            </p>
            {summary ? <p className="mt-2 text-sm leading-6 text-brand-dark/80">{summary}</p> : null}
            {showingPackageCatalog && command.trim() !== "" ? (
              <p className="mt-2 text-xs leading-5 text-brand-dark/60">
                {filterCountCopy(visibleCommands.length, commands.length)}
              </p>
            ) : null}
            {visibleCommands.length > 0 ? (
              <div className={`mt-4 overflow-auto rounded-2xl bg-white ${showingPackageCatalog ? "max-h-96" : "max-h-72"}`}>
                <CustomExtensionCommandList
                  commands={visibleCommands}
                  disabled={busy}
                  surface={recognized.surface}
                  onChange={handleCommandState}
                />
              </div>
            ) : null}
            <div className="mt-4 flex flex-wrap gap-2">
              <button type="button" onClick={requestAllow} className={`min-h-11 rounded-xl px-4 text-sm font-semibold ${pending === "allowed" ? "bg-brand-blue text-white" : "border border-slate-300 text-brand-dark"}`}>
                {allowActionLabel(recognized.surface)}
              </button>
              <button type="button" onClick={requestBlock} className={`min-h-11 rounded-xl px-4 text-sm font-semibold ${pending === "blocked" ? "bg-brand-dark text-white" : "border border-slate-300 text-brand-dark"}`}>
                {blockActionLabel(recognized.surface)}
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
        {recognized === null ? (
          <SuggestionPanel
            query={command}
            hasSuggestions={hasSuggestions}
            packageScriptSuggestions={packageScriptSuggestions}
            harnessSuggestions={harnessSuggestions}
            seenSuggestions={seenSuggestions}
            onSelect={selectSuggestion}
          />
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
