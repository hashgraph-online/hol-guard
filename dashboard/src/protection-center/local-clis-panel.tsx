import { useCallback, useEffect, useState } from "react";
import type { ChangeEvent, FormEvent } from "react";
import { HiMiniArrowLeft, HiMiniPlus } from "react-icons/hi2";

import {
  ApprovalProofFieldInputs,
  buildApprovalProofCredentials,
  isApprovalProofSubmitDisabled,
} from "../approval-proof-inline";
import type { GuardApprovalGatePublicConfig } from "../guard-types";
import {
  addedCustomExtensions,
  applyLocalCliMutation,
  fetchLocalCliList,
  LocalCliApiError,
  previewLocalCliMutation,
  type LocalCliCommandState,
  type LocalCliItem,
  type LocalCliListResponse,
  type LocalCliState,
} from "../local-cli-api";
import { CustomExtensionCommandList, commandStatesPayload, withCommandState } from "./custom-extension-commands";
import { useModalDialog } from "../use-modal-dialog";
import { useResolvedApprovalGate } from "../use-resolved-approval-gate";
import { InlineError, ProtectionModuleRow } from "./components/protection-primitives";

export { AddCustomExtensionDialog } from "./add-custom-extension-dialog";

function randomToken(): string {
  return crypto.randomUUID().replaceAll("-", "");
}

function reviewTitle(name: string, state: LocalCliState): string {
  if (state === "allowed") return `Save ${name} command settings`;
  if (state === "blocked") return `Block ${name}`;
  return `Remove ${name}`;
}

export function customExtensionStateLabel(item: LocalCliItem): string {
  if (item.stale) return "This file changed. Review the extension again.";
  if (item.state === "blocked") return "Every command from this file is blocked.";
  if (item.state === "allowed") {
    if (item.commands.length === 0) {
      return "Matching commands from this file are allowed.";
    }
    const allowed = item.commands.filter((command) => command.state === "allow").length;
    if (allowed > 0) return `${allowed} command${allowed === 1 ? "" : "s"} allowed. The rest follow Recommended.`;
    return "Commands follow Recommended until you allow or block them.";
  }
  return item.example_label;
}

export function CustomExtensionsSection(props: {
  items: LocalCliItem[];
  onOpen: (cliId: string) => void;
  onAdd: () => void;
}) {
  const added = addedCustomExtensions(props.items);
  return (
    <section className="mt-10" aria-labelledby="custom-extensions-heading">
      <div className="flex flex-col gap-1 sm:flex-row sm:items-end sm:justify-between">
        <div>
          <h2 id="custom-extensions-heading" className="text-xl font-semibold tracking-tight text-brand-dark">Custom extensions</h2>
          <p className="mt-1 text-sm text-slate-500">Your own scripts and binaries, not Guard's built-in catalog.</p>
        </div>
        <button type="button" onClick={props.onAdd} className="inline-flex min-h-11 items-center gap-2 rounded-xl px-3 text-sm font-semibold text-brand-blue">
          <HiMiniPlus className="size-4" aria-hidden="true" />
          Add custom extension
        </button>
      </div>
      {added.length === 0 ? (
        <p className="mt-4 text-sm leading-6 text-brand-dark/75">None yet. Add one by pasting the command you want Guard to watch.</p>
      ) : (
        <div className="mt-4">
          {added.map((item) => (
            <CustomExtensionRow key={item.cli_id} item={item} onOpen={props.onOpen} />
          ))}
        </div>
      )}
    </section>
  );
}

export function AddCustomExtensionButton(props: { onClick: () => void }) {
  return (
    <button type="button" onClick={props.onClick} className="inline-flex min-h-11 items-center gap-2 rounded-xl border border-slate-300 px-4 text-sm font-semibold text-brand-dark">
      <HiMiniPlus className="size-4" aria-hidden="true" />
      Add custom extension
    </button>
  );
}

function CustomExtensionRow(props: { item: LocalCliItem; onOpen: (cliId: string) => void }) {
  const handleOpen = useCallback(() => {
    props.onOpen(props.item.cli_id);
  }, [props]);
  return (
    <ProtectionModuleRow
      extensionId={props.item.cli_id}
      name={props.item.name}
      description={props.item.example_label}
      behavior={customExtensionStateLabel(props.item)}
      custom
      executables={[props.item.name]}
      onOpen={handleOpen}
    />
  );
}

export function LocalCliDetail(props: {
  item: LocalCliItem;
  revision: number;
  onBack: () => void;
  onRefresh: () => Promise<void>;
}) {
  const { resolvedApprovalGate, resolveApprovalGate } = useResolvedApprovalGate(null);
  const [pending, setPending] = useState<LocalCliState | null>(null);
  const [commands, setCommands] = useState(props.item.commands);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const added = props.item.state !== "unset";
  const commandsDirty = commands.some((command, index) => command.state !== props.item.commands[index]?.state);
  useEffect(() => {
    setCommands(props.item.commands);
  }, [props.item.cli_id, props.item.grant_revision]);
  const requestAdd = useCallback(() => setPending("allowed"), []);
  const requestAllow = useCallback(() => setPending("allowed"), []);
  const requestBlock = useCallback(() => setPending("blocked"), []);
  const requestRemove = useCallback(() => setPending("unset"), []);
  const requestSaveCommands = useCallback(() => setPending(props.item.state === "blocked" ? "blocked" : "allowed"), [props.item.state]);
  const handleCommandState = useCallback((commandId: string, state: LocalCliCommandState) => {
    setCommands((current) => withCommandState(current, commandId, state));
  }, []);
  const clearPending = useCallback(() => {
    if (!busy) setPending(null);
  }, [busy]);
  const confirmChange = useCallback(async (credentials: { approval_password?: string; approval_totp_code?: string }) => {
    if (pending === null) return;
    setBusy(true);
    setError(null);
    try {
      const payload = {
        cli_id: props.item.cli_id,
        identity_hash: props.item.identity_hash,
        name: props.item.name,
        kind: props.item.kind,
        example_label: props.item.example_label,
        interpreter_name: props.item.interpreter_name,
        state: pending,
        previous_revision: props.revision,
        session_nonce: randomToken(),
        commands: commandStatesPayload(commands),
        ...credentials,
      };
      await previewLocalCliMutation(payload);
      await applyLocalCliMutation(payload);
      await props.onRefresh();
      setPending(null);
    } catch (caught) {
      setError(caught instanceof LocalCliApiError ? caught.message : "Guard could not update this custom extension.");
    } finally {
      setBusy(false);
    }
  }, [commands, pending, props]);

  useEffect(() => {
    void resolveApprovalGate({ failClosed: true }).catch(() => {
      setError("Guard could not load the local approval settings yet.");
    });
  }, [resolveApprovalGate]);

  return (
    <div data-testid="local-cli-detail" className="w-full">
      <button type="button" onClick={props.onBack} className="inline-flex min-h-11 items-center gap-2 rounded-lg px-1 text-sm font-semibold text-brand-dark/80 hover:text-brand-dark">
        <HiMiniArrowLeft className="size-4" aria-hidden="true" />
        Extensions
      </button>
      <header className="mt-4 border-b border-slate-200 pb-6">
        <p className="font-mono text-xs font-semibold tracking-[0.14em] text-slate-400">{props.item.example_label}</p>
        <h1 className="mt-2 text-2xl font-semibold tracking-tight text-brand-dark">{props.item.name}</h1>
        <p className="mt-2 max-w-2xl text-sm leading-6 text-slate-500">{customExtensionStateLabel(props.item)}</p>
        <p className="mt-3 max-w-2xl text-sm leading-6 text-brand-dark/75">
          Recommended keeps Guard's usual review. Allow or block applies to that command from this file. Pipes, wrappers, and destructive commands stay under Guard's usual rules.
        </p>
        <div className="mt-5 flex flex-wrap gap-3">
          {added ? (
            <>
              <button type="button" className="min-h-11 rounded-xl bg-brand-blue px-4 text-sm font-semibold text-white" onClick={requestAllow}>
                Allow this extension's commands
              </button>
              <button type="button" className="min-h-11 rounded-xl border border-slate-300 px-4 text-sm font-semibold text-brand-dark" onClick={requestBlock}>
                Block this extension
              </button>
              <button type="button" className="min-h-11 rounded-xl px-4 text-sm font-semibold text-brand-dark/80" onClick={requestRemove}>
                Remove custom extension
              </button>
            </>
          ) : (
            <button type="button" className="min-h-11 rounded-xl bg-brand-blue px-4 text-sm font-semibold text-white" onClick={requestAdd}>
              Add custom extension
            </button>
          )}
        </div>
      </header>
      {added ? (
        <section className="mt-8" aria-labelledby="custom-extension-commands-heading">
          <h2 id="custom-extension-commands-heading" className="text-lg font-semibold text-brand-dark">Command patterns</h2>
          <p className="mt-1 max-w-2xl text-sm leading-6 text-slate-500">
            Same settings as built-in tools. Recommended is the safe default.
          </p>
          <div className="mt-4">
            <CustomExtensionCommandList
              commands={commands}
              disabled={busy}
              onChange={handleCommandState}
            />
          </div>
          {commandsDirty ? (
            <button type="button" className="mt-4 min-h-11 rounded-xl bg-brand-blue px-4 text-sm font-semibold text-white" onClick={requestSaveCommands}>
              Review command changes
            </button>
          ) : null}
        </section>
      ) : null}
      {error && !pending ? <div className="mt-4"><InlineError message={error} /></div> : null}
      {pending ? (
        <CustomExtensionReviewModal
          item={props.item}
          nextState={pending}
          busy={busy}
          error={error}
          approvalGate={resolvedApprovalGate}
          onCancel={clearPending}
          onConfirm={confirmChange}
        />
      ) : null}
    </div>
  );
}

function CustomExtensionReviewModal(props: {
  item: LocalCliItem;
  nextState: LocalCliState;
  busy: boolean;
  error: string | null;
  approvalGate: GuardApprovalGatePublicConfig | null;
  onCancel: () => void;
  onConfirm: (credentials: { approval_password?: string; approval_totp_code?: string }) => void;
}) {
  const [password, setPassword] = useState("");
  const [totp, setTotp] = useState("");
  const dialogRef = useModalDialog<HTMLFormElement>(props.onCancel, !props.busy);
  const title = reviewTitle(props.item.name, props.nextState);
  const handlePassword = useCallback((event: ChangeEvent<HTMLInputElement>) => {
    setPassword(event.target.value);
  }, []);
  const handleTotp = useCallback((event: ChangeEvent<HTMLInputElement>) => {
    setTotp(event.target.value);
  }, []);
  const handleSubmit = useCallback((event: FormEvent) => {
    event.preventDefault();
    props.onConfirm(buildApprovalProofCredentials(props.approvalGate, {
      approvalPassword: password,
      approvalTotpCode: totp,
    }));
  }, [password, props, totp]);
  const submitDisabled = isApprovalProofSubmitDisabled(
    props.approvalGate,
    { approvalPassword: password, approvalTotpCode: totp },
    props.busy,
  );
  return (
    <div className="fixed inset-0 z-50 grid place-items-center bg-slate-950/45 p-4 backdrop-blur-sm">
      <form ref={dialogRef} tabIndex={-1} role="dialog" aria-modal="true" aria-labelledby="custom-extension-review-title" onSubmit={handleSubmit} className="w-full max-w-lg rounded-3xl bg-white p-6 shadow-2xl focus:outline-none">
        <h2 id="custom-extension-review-title" className="text-xl font-semibold text-brand-dark">{title}</h2>
        <p className="mt-2 text-sm leading-6 text-brand-dark/80">
          This stays on this device. Guard Cloud can keep the same custom extension on your other machines.
        </p>
        <div className="mt-5">
          <ApprovalProofFieldInputs
            approvalGate={props.approvalGate}
            approvalPassword={password}
            approvalTotpCode={totp}
            onApprovalPasswordChange={handlePassword}
            onApprovalTotpCodeChange={handleTotp}
          />
        </div>
        {props.error ? <div className="mt-4"><InlineError message={props.error} /></div> : null}
        <div className="mt-6 flex justify-end gap-3">
          <button type="button" disabled={props.busy} onClick={props.onCancel} className="min-h-11 rounded-xl px-4 text-sm font-semibold text-brand-dark">Cancel</button>
          <button type="submit" disabled={submitDisabled} className="min-h-11 rounded-xl bg-brand-blue px-5 text-sm font-semibold text-white disabled:opacity-60">
            {props.busy ? "Saving…" : "Confirm"}
          </button>
        </div>
      </form>
    </div>
  );
}

export function useLocalCliCatalog() {
  const [data, setData] = useState<LocalCliListResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const load = useCallback(async () => {
    try {
      setData(await fetchLocalCliList());
      setError(null);
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Guard could not load custom extensions.");
    }
  }, []);
  useEffect(() => {
    void load();
  }, [load]);
  return { data, error, load };
}
