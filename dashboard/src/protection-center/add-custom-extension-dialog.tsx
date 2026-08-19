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
  LocalCliApiError,
  previewLocalCliMutation,
  recognizeLocalCli,
  seenSuggestionMeta,
  suggestedHarnessExtensions,
  suggestedSeenExtensions,
  type LocalCliCommandState,
  type LocalCliItem,
  type LocalCliState,
} from "../local-cli-api";
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
  const harnessSuggestions = filterExtensionSuggestions(
    suggestedHarnessExtensions(props.items),
    command,
  ).slice(0, 8);
  const seenSuggestions = filterExtensionSuggestions(
    suggestedSeenExtensions(props.items),
    command,
  ).slice(0, 6);
  const hasSuggestions = harnessSuggestions.length > 0 || seenSuggestions.length > 0;

  useEffect(() => {
    void resolveApprovalGate({ failClosed: true }).catch(() => {
      setError("Guard could not load local approval settings yet.");
    });
  }, [resolveApprovalGate]);

  const handleCommand = useCallback((event: ChangeEvent<HTMLInputElement>) => {
    recognizeGeneration.current += 1;
    setCommand(event.target.value);
    setRecognized(null);
    setCommands([]);
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
  const runRecognize = useCallback(async (commandText: string, cliId?: string) => {
    const generation = recognizeGeneration.current + 1;
    recognizeGeneration.current = generation;
    setBusy(true);
    setError(null);
    try {
      const result = await recognizeLocalCli(commandText, cliId ? { cliId } : undefined);
      if (recognizeGeneration.current !== generation) return;
      setRecognized(result.item);
      setCommands(result.item.commands);
      setSummary(result.summary);
      setPending(null);
    } catch (caught) {
      if (recognizeGeneration.current !== generation) return;
      setRecognized(null);
      setSummary(null);
      setError(caught instanceof LocalCliApiError ? caught.message : "Guard could not identify that command.");
    } finally {
      if (recognizeGeneration.current === generation) setBusy(false);
    }
  }, []);
  const selectSuggestion = useCallback((item: LocalCliItem) => {
    setCommand(item.example_label);
    setPending(null);
    setError(null);
    if (item.surface === "mcp" && item.commands.length === 0) {
      setRecognized(null);
      setCommands([]);
      setSummary(null);
      void runRecognize(item.example_label, item.cli_id);
      return;
    }
    setRecognized(item);
    setCommands(item.commands);
    setSummary(suggestionSummary(item));
  }, [runRecognize]);
  const findTool = useCallback(async () => {
    await runRecognize(command);
  }, [command, runRecognize]);
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
          Paste a script, binary, or MCP launch command, or pick something Guard already found. Everyday commands such as rg, grep, and whoami are not custom extensions.
        </p>
        <label htmlFor="custom-extension-command" className="mt-5 block text-sm font-semibold text-brand-dark">Command</label>
        <input
          id="custom-extension-command"
          value={command}
          onChange={handleCommand}
          spellCheck={false}
          autoComplete="off"
          placeholder="npx -y @modelcontextprotocol/server-github"
          className="mt-2 min-h-11 w-full rounded-xl border border-slate-300 px-3 text-sm text-brand-dark placeholder:text-brand-dark/40 focus:border-brand-blue focus:outline-none focus:ring-2 focus:ring-brand-blue/30"
        />
        <p className="mt-2 text-sm leading-6 text-brand-dark/70">
          One command. A script, a binary, or an MCP launch such as <span className="font-medium">npx</span> or <span className="font-medium">uvx</span>. Not a pipeline.
        </p>
        {recognized ? (
          <div className="mt-5 rounded-2xl border border-slate-200 bg-slate-50 px-4 py-3">
            <div className="flex flex-wrap items-center gap-2">
              <p className="text-sm font-semibold text-brand-dark">{recognized.name}</p>
              {recognized.surface === "mcp" ? (
                <span className="rounded-full bg-white px-2 py-0.5 text-[11px] font-semibold tracking-wide text-brand-dark/70 ring-1 ring-slate-200">
                  MCP server
                </span>
              ) : null}
            </div>
            <p className="mt-1 font-mono text-xs text-brand-dark/70">{recognized.example_label}</p>
            {summary ? <p className="mt-2 text-sm leading-6 text-brand-dark/80">{summary}</p> : null}
            {commands.length > 0 ? (
              <div className="mt-4 max-h-72 overflow-auto rounded-2xl bg-white">
                <CustomExtensionCommandList
                  commands={commands}
                  disabled={busy}
                  surface={recognized.surface}
                  onChange={handleCommandState}
                />
              </div>
            ) : null}
            <div className="mt-4 flex flex-wrap gap-2">
              <button type="button" onClick={requestAllow} className={`min-h-11 rounded-xl px-4 text-sm font-semibold ${pending === "allowed" ? "bg-brand-blue text-white" : "border border-slate-300 text-brand-dark"}`}>
                {recognized.surface === "mcp" ? "Allow this server" : "Allow this tool"}
              </button>
              <button type="button" onClick={requestBlock} className={`min-h-11 rounded-xl px-4 text-sm font-semibold ${pending === "blocked" ? "bg-brand-dark text-white" : "border border-slate-300 text-brand-dark"}`}>
                {recognized.surface === "mcp" ? "Block this server" : "Block this tool"}
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

function addDialogSubmitLabel(input: {
  recognized: LocalCliItem | null;
  busy: boolean;
  pending: LocalCliState | null;
}): string {
  if (input.recognized === null) {
    return input.busy ? "Looking…" : "Find this tool";
  }
  if (input.busy) {
    return "Saving…";
  }
  const mcp = input.recognized.surface === "mcp";
  if (input.pending === "blocked") {
    return mcp ? "Block this server" : "Block this tool";
  }
  return mcp ? "Allow this server" : "Allow this tool";
}

function suggestionEmptyCopy(query: string): string {
  if (query.trim() !== "") {
    return "No matching tools. Everyday commands such as rg, whoami, and script stay hidden.";
  }
  return "No extra tools yet. Paste a command above. Guard hides everyday shell, search, and test-runner commands.";
}

function suggestionSummary(item: LocalCliItem): string {
  if (item.surface === "mcp" && item.commands.length > 0) {
    return `Guard listed ${item.commands.length} tools from this MCP server. Recommended keeps the usual review. Allow or block each one.`;
  }
  if (item.surface === "mcp") {
    return `Find this tool to list MCP tools from ${item.name}.`;
  }
  if (item.commands.length > 0) {
    return `Guard loaded ${item.commands.length} commands. Recommended keeps the usual review. Allow or block each one.`;
  }
  return `Find this tool to read ${item.name} --help and load its commands.`;
}

function SuggestionPanel(props: {
  query: string;
  hasSuggestions: boolean;
  harnessSuggestions: LocalCliItem[];
  seenSuggestions: LocalCliItem[];
  onSelect: (item: LocalCliItem) => void;
}) {
  if (!props.hasSuggestions) {
    return (
      <p className="mt-5 text-sm leading-6 text-brand-dark/70">
        {suggestionEmptyCopy(props.query)}
      </p>
    );
  }
  return (
    <>
      <SuggestionGroup
        heading="From your apps"
        helper="MCP servers already configured in apps on this device."
        items={props.harnessSuggestions}
        onSelect={props.onSelect}
      />
      <SuggestionGroup
        heading="Seen on this device"
        helper="Your own tools that agents have run. Common commands stay hidden."
        items={props.seenSuggestions}
        onSelect={props.onSelect}
      />
    </>
  );
}

function SuggestionGroup(props: {
  heading: string;
  helper: string;
  items: LocalCliItem[];
  onSelect: (item: LocalCliItem) => void;
}) {
  if (props.items.length === 0) return null;
  return (
    <div className="mt-5">
      <p className="text-sm font-semibold text-brand-dark">{props.heading}</p>
      <p className="mt-1 text-xs leading-5 text-brand-dark/60">{props.helper}</p>
      <ul className="mt-2 divide-y divide-slate-200">
        {props.items.map((item) => (
          <li key={item.cli_id}>
            <SuggestionButton item={item} onSelect={props.onSelect} />
          </li>
        ))}
      </ul>
    </div>
  );
}

function SuggestionButton(props: { item: LocalCliItem; onSelect: (item: LocalCliItem) => void }) {
  const handleSelect = useCallback(() => {
    props.onSelect(props.item);
  }, [props]);
  return (
    <button type="button" onClick={handleSelect} className="flex min-h-11 w-full items-baseline justify-between gap-3 py-2 text-left">
      <span className="min-w-0">
        <span className="block truncate text-sm font-semibold text-brand-dark">{props.item.name}</span>
        <span className="block truncate text-xs text-brand-dark/60">
          {props.item.source_label ?? seenSuggestionMeta(props.item)}
        </span>
      </span>
      <span className="truncate font-mono text-xs text-brand-dark/60">{props.item.example_label}</span>
    </button>
  );
}
