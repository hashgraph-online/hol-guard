import { useCallback, useEffect, useRef, useState } from "react";
import type { ChangeEvent, FormEvent } from "react";
import { HiMiniArrowLeft } from "react-icons/hi2";

import {
  ApprovalProofFieldInputs,
  approvalGateProofReady,
  approvalProofRecentlySatisfied,
  buildApprovalProofCredentials,
  isApprovalProofSubmitDisabled,
} from "../approval-proof-inline";
import {
  applyLocalCliMutation,
  enrollablePackageScriptCommands,
  enrollmentCommandStates,
  filterExtensionSuggestions,
  LocalCliApiError,
  previewLocalCliMutation,
  looksLikePackageScriptPaste,
  keepsPackageScriptCatalog,
  preferredPackageScriptExtension,
  recognizeLocalCli,
  suggestedHarnessExtensions,
  suggestedPackageScriptExtensions,
  suggestedSeenExtensions,
  type LocalCliCommand,
  type LocalCliCommandState,
  type LocalCliItem,
  type LocalCliState,
} from "../local-cli-api";
import {
  addDialogSubmitLabel,
  allowActionLabel,
  blockActionLabel,
  commandFieldLabel,
  dialogIntro,
  enrollConfirmCopy,
  enrollSubmitDisabled,
  mcpCatalogHasTools,
  isObservedMcpItem,
  mcpListingRetryError,
  McpListingStatus,
  SuggestionPanel,
  suggestionSummary,
  type EnrollStep,
} from "./add-custom-extension-support";
import { CustomExtensionCommandBrowser } from "./custom-extension-command-browser";
import { packageScriptQueryFrom, SelectedProject } from "./add-custom-extension-project";
import { groupStateSummary } from "./custom-extension-command-view";
import { withCommandState } from "./custom-extension-commands";
import { bulkPolicyCopy, commandBrowserCopy } from "./local-cli-panel-copy";
import { mcpToolCanReceiveDirectAllow } from "./mcp-catalog-state";
import { useResolvedApprovalGate } from "../use-resolved-approval-gate";
import { InlineError } from "./components/protection-primitives";
import { McpRegistrySearch } from "./mcp-registry-search";
import { initialAddCommand, prefillSuggestedStates } from "./custom-extension-profile";
import type { LocalCliDiscoveryOutcome } from "./use-local-cli-catalog";

function randomToken(): string {
  return crypto.randomUUID().replaceAll("-", "");
}

export function AddCustomExtensionWorkspace(props: {
  items: LocalCliItem[];
  revision: number;
  discovering?: boolean;
  onBack: () => void;
  onAdded: (cliId: string) => void;
  onConfigured: () => Promise<LocalCliDiscoveryOutcome>;
}) {
  const { resolvedApprovalGate, resolveApprovalGate, refreshApprovalGate } = useResolvedApprovalGate(null);
  const [command, setCommand] = useState(() => initialAddCommand(window.location.search));
  const [recognized, setRecognized] = useState<LocalCliItem | null>(null);
  const [commands, setCommands] = useState<LocalCliItem["commands"]>([]);
  // The suggested settings Guard opened with, so edits can be marked as changed.
  const [baseline, setBaseline] = useState<LocalCliItem["commands"]>([]);
  const [summary, setSummary] = useState<string | null>(null);
  const [pending, setPending] = useState<LocalCliState | null>(null);
  const [step, setStep] = useState<EnrollStep>("pick");
  const [password, setPassword] = useState("");
  const [totp, setTotp] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [registryOpen, setRegistryOpen] = useState(false);
  const recognizeGeneration = useRef(0);
  const autoRecognizedCommand = useRef("");
  const didAutoSelect = useRef(false);
  const sawDiscovering = useRef(false);
  const rememberedProjects = suggestedPackageScriptExtensions(props.items);
  const packageScriptSuggestions = filterExtensionSuggestions(rememberedProjects, command).slice(0, 8);
  const harnessSuggestions = filterExtensionSuggestions(suggestedHarnessExtensions(props.items), command).slice(0, 8);
  const seenSuggestions = filterExtensionSuggestions(suggestedSeenExtensions(props.items), command).slice(0, 6);
  const hasSuggestions = packageScriptSuggestions.length > 0
    || harnessSuggestions.length > 0
    || seenSuggestions.length > 0;
  useEffect(() => {
    void resolveApprovalGate({ failClosed: true }).catch(() => {
      setError("Guard could not load local approval settings yet.");
    });
  }, [resolveApprovalGate]);

  const resetRecognition = useCallback(() => {
    recognizeGeneration.current += 1;
    autoRecognizedCommand.current = "";
    setBusy(false);
    setRecognized(null);
    setCommands([]);
    setBaseline([]);
    setSummary(null);
    setPending(null);
    setStep("pick");
  }, []);
  const handleCommand = useCallback((event: ChangeEvent<HTMLInputElement>) => {
    const value = event.target.value;
    const keepCatalog = recognized?.surface === "package-scripts" && keepsPackageScriptCatalog(value, commands);
    setCommand(value);
    setError(null);
    if (keepCatalog) return;
    resetRecognition();
  }, [commands, recognized, resetRecognition]);
  const handlePassword = useCallback((event: ChangeEvent<HTMLInputElement>) => {
    setPassword(event.target.value);
  }, []);
  const handleTotp = useCallback((event: ChangeEvent<HTMLInputElement>) => {
    const digits = event.target.value.replace(/\D/g, "").slice(0, 6);
    event.target.value = digits;
    setTotp(digits);
  }, []);
  const markRecognized = useCallback((item: LocalCliItem, nextSummary: string | null) => {
    const prefilled = prefillSuggestedStates(item);
    setRecognized(item);
    setCommands(prefilled);
    setBaseline(prefilled);
    setSummary(nextSummary);
    setPending("allowed");
    setStep("review");
  }, []);
  const runRecognize = useCallback(async (
    commandText: string,
    cliId?: string,
    silent = false,
    keepOnError = false,
  ) => {
    const generation = recognizeGeneration.current + 1;
    recognizeGeneration.current = generation;
    setBusy(true);
    if (!silent) setError(null);
    try {
      const result = await recognizeLocalCli(commandText, cliId ? { cliId } : undefined);
      if (recognizeGeneration.current !== generation) return;
      markRecognized(result.item, result.summary);
      if (keepOnError) {
        setError(mcpListingRetryError(result.help_status, result.item.commands));
      } else {
        setError(null);
      }
    } catch (caught) {
      if (recognizeGeneration.current !== generation) return;
      if (!keepOnError) {
        setRecognized(null);
        setSummary(null);
        setStep("pick");
      }
      if (!silent) {
        setError(caught instanceof LocalCliApiError ? caught.message : "Guard could not identify that command.");
      }
    } finally {
      if (recognizeGeneration.current === generation) setBusy(false);
    }
  }, [markRecognized]);
  const selectSuggestion = useCallback((item: LocalCliItem) => {
    if (item.surface !== "package-scripts") setCommand(item.example_label);
    setError(null);
    if (item.surface === "mcp" && item.commands.length === 0) {
      setRecognized(null);
      setCommands([]);
      setSummary(null);
      setPending(null);
      setStep("pick");
      void runRecognize(item.example_label, item.cli_id);
      return;
    }
    markRecognized(item, suggestionSummary(item));
  }, [markRecognized, runRecognize]);
  const findTool = useCallback(async () => {
    await runRecognize(command);
  }, [command, runRecognize]);
  const retryMcpListing = useCallback(() => {
    if (recognized === null) return;
    void runRecognize(command.trim() || recognized.example_label, recognized.cli_id, false, true);
  }, [command, recognized, runRecognize]);
  useEffect(() => {
    if (props.discovering === true) sawDiscovering.current = true;
    if (!sawDiscovering.current || props.discovering === true || command.trim() !== "") return;
    const preferred = preferredPackageScriptExtension(props.items);
    if (preferred === null) return;
    if (recognized !== null) {
      if (recognized.cli_id !== preferred.cli_id) return;
      if (
        recognized.identity_hash === preferred.identity_hash
        && recognized.commands.length === preferred.commands.length
      ) {
        return;
      }
      markRecognized(preferred, suggestionSummary(preferred));
      return;
    }
    if (didAutoSelect.current) return;
    didAutoSelect.current = true;
    selectSuggestion(preferred);
  }, [command, markRecognized, props.discovering, props.items, recognized, selectSuggestion]);
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
  const findAnotherProject = useCallback(() => {
    resetRecognition();
    setCommand("");
    setError(null);
    window.requestAnimationFrame(() => document.getElementById("custom-extension-command")?.focus());
  }, [resetRecognition]);
  const backToReview = useCallback(() => {
    setStep("review");
    setError(null);
  }, []);
  const showingPackageCatalog = recognized?.surface === "package-scripts";
  const enrollable = showingPackageCatalog ? enrollablePackageScriptCommands(commands) : commands;
  const bulkEligible = useCallback((entry: LocalCliCommand) => (
    recognized?.surface === "mcp" ? mcpToolCanReceiveDirectAllow(entry) : true
  ), [recognized]);
  const applyBulk = useCallback((commandIds: ReadonlySet<string>, state: LocalCliCommandState) => {
    setCommands((current) => current.map((entry) => (
      commandIds.has(entry.command_id) && bulkEligible(entry) ? { ...entry, state } : entry
    )));
    // Blocking every script blocks the project. On a server the bulk choice only covers the
    // listed tools, so the server stays enrolled and a server-wide block is chosen at confirm.
    const blocksAll = showingPackageCatalog && state === "block"
      && enrollable.every((entry) => commandIds.has(entry.command_id));
    setPending(blocksAll ? "blocked" : "allowed");
  }, [bulkEligible, enrollable, showingPackageCatalog]);
  const switchProject = useCallback((item: LocalCliItem) => {
    setCommand("");
    selectSuggestion(item);
  }, [selectSuggestion]);
  // The footer describes what saving submits, which can differ from the draft rows.
  const savedStates = recognized === null || pending === null
    ? null
    : new Map(enrollmentCommandStates(enrollable, pending, recognized.surface).map((entry) => [entry.command_id, entry.state]));
  const savedPreview = enrollable.map((entry) => ({ ...entry, state: savedStates?.get(entry.command_id) ?? entry.state }));
  const handleSubmit = useCallback(async (event: FormEvent) => {
    event.preventDefault();
    if (recognized === null) {
      await findTool();
      return;
    }
    if (step !== "confirm") {
      setStep("confirm");
      setError(null);
      setBusy(true);
      try {
        await refreshApprovalGate({ failClosed: true });
      } catch {
        setError("Guard could not load local approval settings yet.");
      } finally {
        setBusy(false);
      }
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
        commands: enrollmentCommandStates(commands, pending, recognized.surface),
        ...buildApprovalProofCredentials(resolvedApprovalGate, {
          approvalPassword: password,
          approvalTotpCode: totp,
        }),
      };
      await previewLocalCliMutation(payload);
      await applyLocalCliMutation(payload);
      await refreshApprovalGate();
      props.onAdded(recognized.cli_id);
    } catch (caught) {
      setError(caught instanceof LocalCliApiError ? caught.message : "Guard could not add this custom extension.");
    } finally {
      setBusy(false);
    }
  }, [commands, findTool, password, pending, props, recognized, refreshApprovalGate, resolvedApprovalGate, step, totp]);
  const handleCommandState = useCallback((commandId: string, state: LocalCliCommandState) => {
    setCommands((current) => withCommandState(current, commandId, state));
    // An individual choice turns a server-wide block into a custom mix.
    setPending("allowed");
  }, []);

  const proofReady = pending !== null && recognized !== null;
  const confirming = step === "confirm" && recognized !== null;
  const submitDisabled = enrollSubmitDisabled({
    recognized,
    command,
    confirming,
    proofReady,
    proofBlocked: isApprovalProofSubmitDisabled(
      resolvedApprovalGate,
      { approvalPassword: password, approvalTotpCode: totp },
      busy,
      false,
      true,
    ),
    busy,
  });
  const showingMcpCatalog = recognized?.surface === "mcp";
  const observedMcp = isObservedMcpItem(recognized);
  const mcpHasTools = mcpCatalogHasTools(enrollable);
  const showMcpRetry = showingMcpCatalog && !mcpHasTools;
  let confirmTitle = allowActionLabel(recognized?.surface ?? "cli");
  if (pending === "blocked") {
    confirmTitle = blockActionLabel(recognized?.surface ?? "cli");
  } else if (observedMcp) {
    confirmTitle = "Save tool permissions";
  }
  const browserCopy = commandBrowserCopy(recognized?.surface);
  const bulkCopy = bulkPolicyCopy(recognized?.surface ?? "cli");
  const blockedSummary = observedMcp && pending === "blocked"
    ? "This connector will be blocked, including tools that have not been listed yet."
    : summary;
  const recentlySatisfied = approvalProofRecentlySatisfied(resolvedApprovalGate);
  const gateReady = resolvedApprovalGate === null ? null : approvalGateProofReady(resolvedApprovalGate);

  return (
    <form
      data-testid="add-custom-extension"
      onSubmit={handleSubmit}
      className="flex min-h-[70vh] w-full flex-col"
    >
      <button
        type="button"
        onClick={confirming ? backToReview : props.onBack}
        className="inline-flex min-h-11 w-fit items-center gap-2 rounded-lg px-1 text-sm font-semibold text-brand-dark/80 hover:text-brand-dark"
      >
        <HiMiniArrowLeft className="size-4" aria-hidden="true" />
        {confirming ? "Back to settings" : "Extensions"}
      </button>
      {confirming && recognized ? (
        <section className="mt-6 max-w-xl" aria-labelledby="custom-extension-confirm-title">
          <h1 id="custom-extension-confirm-title" className="text-2xl font-semibold tracking-tight text-brand-dark">
            {confirmTitle}
          </h1>
          <p className="mt-2 text-sm leading-6 text-slate-500">
            {recognized.source_label ? `${recognized.name} · ${recognized.source_label}` : recognized.name}
          </p>
          {summary ? <p className="mt-2 text-sm leading-6 text-brand-dark/70">{observedMcp && pending === "blocked" ? "This connector will be blocked, including tools that have not been listed yet." : summary}</p> : null}
          <p className="mt-5 text-sm leading-6 text-brand-dark/80">
            {enrollConfirmCopy(recognized.surface, recentlySatisfied, resolvedApprovalGate?.totp_enabled === true, gateReady)}
          </p>
          <div className="mt-5 max-w-sm">
            <ApprovalProofFieldInputs
              approvalGate={resolvedApprovalGate}
              approvalPassword={password}
              approvalTotpCode={totp}
              requireGate={true}
              onApprovalPasswordChange={handlePassword}
              onApprovalTotpCodeChange={handleTotp}
            />
          </div>
        </section>
      ) : (
        <>
          <header className="mt-3 max-w-2xl pb-4">
            <h1 id="add-custom-extension-title" className="text-2xl font-semibold tracking-tight text-brand-dark">Add a custom extension</h1>
            <p className="mt-2 text-sm leading-6 text-slate-500">
              {dialogIntro(
                rememberedProjects.length > 0,
                recognized?.surface ?? null,
                props.discovering === true && recognized === null,
                !showMcpRetry,
                observedMcp,
              )}
            </p>
          </header>
          {!observedMcp && !showingPackageCatalog ? <>
            <label htmlFor="custom-extension-command" className="mt-4 block text-sm font-semibold text-brand-dark">
              {recognized === null ? "Find an extension" : commandFieldLabel(recognized.surface)}
            </label>
            <input
            id="custom-extension-command"
            value={command}
            onChange={handleCommand}
            spellCheck={false}
            autoComplete="off"
            placeholder="Project folder, npm run, server name, or launch command"
            className="mt-2 min-h-11 w-full max-w-xl rounded-xl border border-slate-300 bg-white px-3 text-sm text-brand-dark placeholder:text-brand-dark/70 focus:border-brand-blue focus:outline-none focus:ring-2 focus:ring-brand-blue/30"
            />
          </> : null}
          {recognized ? (
            <>
              {showingPackageCatalog ? (
                <SelectedProject
                  item={recognized}
                  projects={rememberedProjects}
                  disabled={busy}
                  onSelect={switchProject}
                  onFindAnother={findAnotherProject}
                />
              ) : (
                <section className="mt-5 max-w-3xl" aria-labelledby="custom-extension-selected">
                  <h2 id="custom-extension-selected" className="text-xl font-semibold tracking-tight text-brand-dark">
                    {recognized.name}
                  </h2>
                  <p className={`mt-1 text-xs text-brand-dark/70${observedMcp ? "" : " font-mono"}`}>
                    {observedMcp ? recognized.source_label : recognized.source_label ? `${recognized.source_label} · ${recognized.example_label}` : recognized.example_label}
                  </p>
                  {blockedSummary ? <p className="mt-2 max-w-2xl text-sm leading-6 text-brand-dark/70">{blockedSummary}</p> : null}
                  {showMcpRetry ? (
                    <McpListingStatus name={recognized.name} busy={busy} onRetry={retryMcpListing} />
                  ) : null}
                </section>
              )}
              {!showMcpRetry ? (
                <section className="mt-2 max-w-4xl" aria-label={`${recognized.name} ${browserCopy.units}`}>
                  <CustomExtensionCommandBrowser
                    key={recognized.cli_id}
                    commands={enrollable}
                    savedCommands={baseline}
                    surface={recognized.surface}
                    disabled={busy}
                    bulkEligible={bulkEligible}
                    bulkGroupLabel={bulkCopy.groupLabel}
                    bulkMixedCopy={bulkCopy.mixedCopy}
                    initialQuery={showingPackageCatalog ? packageScriptQueryFrom(command, enrollable) : undefined}
                    changedLabel="Changed"
                    onChange={handleCommandState}
                    onBulkChange={applyBulk}
                  />
                  {observedMcp ? (
                    <p className="mt-3 text-xs leading-5 text-brand-dark/70">Only tools your app has used are listed. More appear as it uses them.</p>
                  ) : null}
                </section>
              ) : null}
            </>
          ) : (
            <>
            <SuggestionPanel
              query={command}
              discovering={props.discovering === true}
              hasSuggestions={hasSuggestions}
              packageScriptSuggestions={packageScriptSuggestions}
              harnessSuggestions={harnessSuggestions}
              seenSuggestions={seenSuggestions}
              onSelect={selectSuggestion}
            />
            <McpRegistrySearch items={props.items} approvalGate={resolvedApprovalGate}
              onOpenChange={setRegistryOpen} onConfigured={props.onConfigured} />
            </>
          )}
        </>
      )}
      {error ? <div className="mt-4 max-w-xl"><InlineError message={error} /></div> : null}
      <div className={`${registryOpen && !recognized ? "relative" : "sticky bottom-[calc(var(--guard-shell-mobile-nav-height,0px)+env(safe-area-inset-bottom))] z-20 md:bottom-0"} mt-auto border-t border-slate-200 bg-white py-4`}>
        <div className="flex flex-wrap items-center gap-3">
          {recognized && !confirming && enrollable.length > 0 && !showMcpRetry ? (
            <p className="mr-auto text-sm text-brand-dark/75" data-testid="custom-extension-add-summary">
              <span className="font-semibold text-brand-dark">{enrollable.length} {browserCopy.unit(enrollable.length)}</span>
              {" · "}{groupStateSummary(savedPreview)}
            </p>
          ) : null}
          <button type="submit" disabled={submitDisabled} className="min-h-11 rounded-xl bg-brand-blue px-5 text-sm font-semibold text-white disabled:opacity-60">
            {addDialogSubmitLabel({ recognized, busy, pending, step: recognized ? step : "pick" })}
          </button>
          {recognized && confirming && pending === "allowed" ? (
            <button type="button" onClick={requestBlock} className="min-h-11 rounded-xl px-4 text-sm font-semibold text-brand-dark">
              {blockActionLabel(recognized.surface)}
            </button>
          ) : null}
          {recognized && confirming && pending === "blocked" ? (
            <button type="button" onClick={requestAllow} className="min-h-11 rounded-xl px-4 text-sm font-semibold text-brand-dark">
              {allowActionLabel(recognized.surface)}
            </button>
          ) : null}
        </div>
      </div>
    </form>
  );
}
