import { useCallback, useEffect, useRef, useState } from "react";
import { HiMiniArrowLeft, HiMiniPlus } from "react-icons/hi2";

import {
  applyBulkCommandState,
  applyLocalCliMutation,
  bulkCommandState,
  enrollablePackageScriptCommands,
  LocalCliApiError,
  previewLocalCliMutation,
  recognizeLocalCli,
  refreshMcpInventory,
  type LocalCliCommandState,
  type LocalCliItem,
  type LocalCliListResponse,
  type LocalCliState,
} from "../local-cli-api";
import { BulkPolicyPicker } from "./add-custom-extension-catalog";
import { CustomExtensionCommandList, commandStatesPayload, withCommandState } from "./custom-extension-commands";
import { McpDeclaredSkills } from "./mcp-declared-skills";
import { useResolvedApprovalGate } from "../use-resolved-approval-gate";
import { InlineError } from "./components/protection-primitives";
import { customExtensionContinuityView } from "../managed-controls/custom-extension-continuity";
import { commandPermissionChanges, mcpCatalogCopy, mcpToolCanReceiveDirectAllow, rebaseCommandDraft } from "./mcp-catalog-state";
import { McpProviderActions, type ProviderActionDraft } from "./mcp-provider-actions";
import { ProviderWorkflows } from "./provider-workflows";
import { bulkPolicyCopy, continuityCopy, customExtensionStateLabel, detailCatalogHeading, detailCatalogHelper, detailPolicyCopy, mcpPermissionStatusLabel, nativePublicationMessage, randomToken, SUGGESTED_RULES_NOTICE } from "./local-cli-panel-copy";
import { customExtensionDisplayName, hasSuggestedRules, prefillSuggestedStates } from "./custom-extension-profile";
import { CustomExtensionReviewModal } from "./local-cli-review-modal";

export { customExtensionStateLabel } from "./local-cli-panel-copy";

export { AddCustomExtensionWorkspace } from "./add-custom-extension-dialog";
export { useLocalCliCatalog } from "./use-local-cli-catalog";

export function AddCustomExtensionButton(props: { onClick: () => void }) {
  return (
    <button type="button" onClick={props.onClick} className="inline-flex min-h-11 items-center gap-2 rounded-xl border border-slate-300 px-4 text-sm font-semibold text-brand-dark">
      <HiMiniPlus className="size-4" aria-hidden="true" />
      Add custom extension
    </button>
  );
}

export function LocalCliDetail(props: {
  item: LocalCliItem;
  revision: number;
  continuity: LocalCliListResponse["cloud"];
  nativePublication?: LocalCliListResponse["native_publication"];
  onBack: () => void;
  onRefresh: () => Promise<void>;
}) {
  const { resolvedApprovalGate, resolveApprovalGate, refreshApprovalGate } = useResolvedApprovalGate(null);
  const [pending, setPending] = useState<LocalCliState | null>(null);
  const [commands, setCommands] = useState(() => prefillSuggestedStates(props.item));
  const [providerDrafts, setProviderDrafts] = useState<Record<string, ProviderActionDraft>>({});
  const previousItem = useRef(props.item);
  const [busy, setBusy] = useState(false);
  const [catalogBusy, setCatalogBusy] = useState(false);
  const [catalogError, setCatalogError] = useState<string | null>(null);
  const catalogController = useRef<AbortController | null>(null);
  useEffect(() => () => catalogController.current?.abort(), []);
  const [error, setError] = useState<string | null>(null);
  const added = props.item.state !== "unset";
  const commandChanges = commandPermissionChanges(props.item.commands, commands);
  const commandsDirty = commandChanges.length > 0;
  useEffect(() => {
    const previous = previousItem.current;
    if (previous.cli_id !== props.item.cli_id || previous.identity_hash !== props.item.identity_hash) {
      setPending(null);
      setProviderDrafts({});
      setCatalogError(null);
      setError(previous.cli_id === props.item.cli_id ? "This extension changed. Review its permissions again." : null);
    }
    setCommands((current) => {
      if (previous.cli_id !== props.item.cli_id || previous.identity_hash !== props.item.identity_hash) {
        return prefillSuggestedStates(props.item);
      }
      const changed = previous.mcp_catalog?.revision !== props.item.mcp_catalog?.revision
        ? props.item.mcp_catalog?.changes?.changed : [];
      return rebaseCommandDraft(current, previous.commands, props.item.commands, changed);
    });
    previousItem.current = props.item;
  }, [props.item]);
  const openPending = useCallback(async (state: LocalCliState) => {
    await refreshApprovalGate();
    setPending(state);
  }, [refreshApprovalGate]);
  const requestAdd = useCallback(() => openPending("allowed"), [openPending]);
  const requestAllow = useCallback(() => openPending("allowed"), [openPending]);
  const requestBlock = useCallback(() => openPending("blocked"), [openPending]);
  const requestRemove = useCallback(() => openPending("unset"), [openPending]);
  const requestSaveCommands = useCallback(() => {
    openPending(props.item.state === "blocked" ? "blocked" : "allowed");
  }, [openPending, props.item.state]);
  const handleCommandState = useCallback((commandId: string, state: LocalCliCommandState) => {
    setCommands((current) => withCommandState(current, commandId, state));
  }, []);
  const applyBulk = useCallback((state: LocalCliCommandState) => {
    setCommands((current) => {
      let excluded = new Set<string>();
      if (props.item.surface === "package-scripts") excluded = new Set(["root", "other"]);
      if (props.item.surface === "mcp") {
        excluded = new Set(current.filter((command) => !mcpToolCanReceiveDirectAllow(command)).map((command) => command.command_id));
      }
      return applyBulkCommandState(current, state, excluded);
    });
  }, [props.item.surface]);
  let bulkTargets = commands;
  if (props.item.surface === "package-scripts") bulkTargets = enrollablePackageScriptCommands(commands);
  if (props.item.surface === "mcp") bulkTargets = commands.filter(mcpToolCanReceiveDirectAllow);
  const bulkState = bulkCommandState(bulkTargets);
  const bulkCopy = bulkPolicyCopy(props.item.surface);
  const continuity = customExtensionContinuityView("local-only");
  const catalog = mcpCatalogCopy(props.item);
  const refreshCatalog = useCallback(async () => {
    const controller = new AbortController();
    catalogController.current = controller;
    setCatalogBusy(true);
    setCatalogError(null);
    try {
      await refreshMcpInventory(props.item.cli_id, controller.signal);
      if (!controller.signal.aborted) await props.onRefresh();
    } catch (caught) {
      if (!controller.signal.aborted) setCatalogError(caught instanceof Error ? caught.message : "Guard could not refresh this connector. Try again.");
    } finally {
      setCatalogBusy(false);
      if (catalogController.current === controller) catalogController.current = null;
    }
  }, [props.item.cli_id, props.onRefresh]);
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
        ...(pending !== "unset" && Object.keys(providerDrafts).length > 0
          ? { provider_actions: Object.values(providerDrafts) } : {}),
        ...credentials,
      };
      await previewLocalCliMutation(payload);
      await applyLocalCliMutation(payload);
      setProviderDrafts({});
      await props.onRefresh();
      await refreshApprovalGate();
      setPending(null);
    } catch (caught) {
      setError(caught instanceof LocalCliApiError ? caught.message : "Guard could not update this custom extension.");
    } finally {
      setBusy(false);
    }
  }, [commands, providerDrafts, pending, props, refreshApprovalGate]);

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
        {props.item.surface !== "mcp" ? (
          <p className="font-mono text-xs font-semibold tracking-[0.14em] text-slate-400">{props.item.example_label}</p>
        ) : null}
        <h1 className="mt-2 text-2xl font-semibold tracking-tight text-brand-dark">{customExtensionDisplayName(props.item)}</h1>
        {props.item.surface === "mcp" && props.item.source_label ? (
          <p className="mt-2 text-sm text-slate-600">{props.item.source_label}</p>
        ) : null}
        <p className="mt-2 max-w-2xl text-sm leading-6 text-slate-500">{customExtensionStateLabel(props.item)}</p>
        {continuityCopy(props.item) ? (
          <div className="mt-3 max-w-2xl rounded-xl border border-slate-200 bg-slate-50 p-3" data-testid="custom-extension-continuity">
            <p className="text-sm font-semibold text-brand-dark">{continuityCopy(props.item)?.title}</p>
            <p className="mt-1 text-sm leading-6 text-slate-600">{continuityCopy(props.item)?.description}</p>
          </div>
        ) : null}
        <p className="mt-3 max-w-2xl text-sm leading-6 text-brand-dark/75">
          {detailPolicyCopy(props.item.surface)}
        </p>
        <div className="mt-5 flex flex-wrap gap-3">
          {added ? (
            <>
              {props.item.state === "allowed" ? (
                <p className="inline-flex min-h-11 items-center rounded-xl bg-slate-100 px-4 text-sm font-semibold text-brand-dark">
                  {props.item.surface === "mcp"
                    ? mcpPermissionStatusLabel(props.nativePublication, props.item.permission_scope)
                    : "Allowed on this device"}
                </p>
              ) : (
                <button type="button" className="min-h-11 rounded-xl bg-brand-blue px-4 text-sm font-semibold text-white" onClick={requestAllow}>
                  {props.item.surface === "mcp" ? "Enable tool permissions" : "Allow this extension's commands"}
                </button>
              )}
              {props.item.state === "blocked" ? (
                <p className="inline-flex min-h-11 items-center rounded-xl bg-slate-100 px-4 text-sm font-semibold text-brand-dark">
                  Blocked
                </p>
              ) : (
                <button type="button" className="min-h-11 rounded-xl border border-slate-300 px-4 text-sm font-semibold text-brand-dark" onClick={requestBlock}>
                  Block this extension
                </button>
              )}
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
      {props.item.surface === "mcp" && added ? (
        <section className="mt-5 rounded-xl border border-slate-200 p-4" aria-labelledby="mcp-publication-heading">
          <h2 id="mcp-publication-heading" className="text-sm font-semibold text-brand-dark">{props.item.permission_scope === "configured-connection" ? "Policy status" : "Enforcement status"}</h2>
          <p role="status" className="mt-2 text-sm leading-6 text-brand-dark/75">
            {nativePublicationMessage(props.nativePublication, props.item.permission_scope)}
          </p>
          {props.nativePublication?.state !== "acknowledged" ? (
            <button type="button" className="mt-3 min-h-11 rounded-xl border border-slate-300 px-4 text-sm font-semibold text-brand-dark"
              disabled={busy || catalogBusy} onClick={() => void props.onRefresh()}>
              Check enforcement status
            </button>
          ) : null}
        </section>
      ) : null}
      {catalog ? (
        <section className="mt-6 border-b border-slate-200 pb-5" aria-labelledby="mcp-inventory-heading" aria-busy={catalogBusy}>
          <h2 id="mcp-inventory-heading" className="text-sm font-semibold text-brand-dark">{catalog.title}</h2>
          <p className="mt-2 max-w-2xl text-sm leading-6 text-brand-dark/75">{catalog.description}</p>
          <p className="mt-2 text-xs leading-5 text-brand-dark/75">Refresh starts this connection’s configured server to list tools. It does not grant execution permission.</p>
          <button
            type="button"
            onClick={refreshCatalog}
            disabled={busy || catalogBusy || pending !== null}
            className="mt-3 inline-flex min-h-11 items-center rounded-xl border border-slate-300 px-4 text-sm font-semibold text-brand-dark disabled:cursor-wait disabled:opacity-50"
          >
            {catalogBusy ? "Refreshing inventory…" : "Refresh inventory"}
          </button>
          {catalogBusy ? <button type="button" onClick={() => catalogController.current?.abort()}
            className="ml-3 min-h-11 rounded-xl border border-slate-300 px-4 text-sm font-semibold text-brand-dark">Cancel refresh</button> : null}
          {catalogError ? <p role="alert" className="mt-3 max-w-2xl text-sm leading-6 text-red-700">{catalogError}</p> : null}
          {props.item.mcp_catalog ? (
            <p className="mt-2 text-xs leading-5 text-brand-dark/75">
              Last discovery attempt: <time dateTime={props.item.mcp_catalog.updated_at}>
                {new Date(props.item.mcp_catalog.updated_at).toLocaleString()}
              </time>
            </p>
          ) : null}
          {props.item.mcp_catalog?.changes && Object.values(props.item.mcp_catalog.changes).some((names) => names.length > 0) ? (
            <details className="mt-3 text-sm text-brand-dark/75" open>
              <summary className="min-h-11 cursor-pointer py-3 font-semibold">Changes from the last inventory</summary>
              <p className="max-w-2xl leading-6">
                New and changed tools need review. Removed tools lose Allow; their Deny choices remain.
                Stale tools have not been confirmed by this discovery attempt.
              </p>
              <dl className="mt-3 grid gap-3 sm:grid-cols-2">
                {([
                  ["added", "New tools"], ["changed", "Changed authority"],
                  ["removed", "Removed tools"], ["stale", "Not confirmed"],
                ] as const).map(([key, label]) => {
                  const names = props.item.mcp_catalog?.changes?.[key] ?? [];
                  return names.length > 0 ? (
                    <div key={key}>
                      <dt className="font-semibold">{label} · {names.length}</dt>
                      <dd className="mt-1 break-words leading-6">
                        {names.slice(0, 10).join(", ")}{names.length > 10 ? ` and ${names.length - 10} more` : ""}
                      </dd>
                    </div>
                  ) : null;
                })}
              </dl>
            </details>
          ) : null}
          <details className="mt-3 text-sm text-brand-dark/75">
            <summary className="min-h-11 cursor-pointer py-3 font-semibold">Connection details</summary>
            <p className="break-all font-mono text-xs leading-6">{props.item.example_label}</p>
            <p className="mt-2">Protocol: {props.item.mcp_catalog?.protocol_version ?? "Not verified"}</p>
            <p className="mt-2">Permission scope: {props.item.permission_scope === "configured-connection"
              ? "This configured host connection. Provider account and native host-hook binding are not verified."
              : props.item.permission_scope === "host-namespace"
                ? "This connector namespace in its host. Account changes cannot currently be verified."
                : props.item.permission_scope === "legacy-device"
                  ? "This server identity across this device. This is a legacy setting."
                  : "Not verified. Prefer Ask while the connection is unresolved."}</p>
          </details>
        </section>
      ) : null}
      {props.item.mcp_catalog?.skills_catalog?.declared ? <McpDeclaredSkills
        cliId={props.item.cli_id} identityHash={props.item.identity_hash} revision={props.item.mcp_catalog.revision}
        knownCount={props.item.mcp_catalog.skills_catalog.known_count} complete={props.item.mcp_catalog.skills_catalog.complete}
      /> : null}
      {props.item.provider_catalog ? (
        <>
          <McpProviderActions key={props.item.cli_id + props.item.identity_hash}
            cliId={props.item.cli_id} knownCount={props.item.provider_catalog.known_count}
            disabled={busy} authorityRevision={props.revision} drafts={providerDrafts}
            onChange={(action, state) => {
              if (!(action.tool_slug in providerDrafts) && Object.keys(providerDrafts).length >= 100) {
                setError("Review and save these 100 action changes before changing more.");
                return;
              }
              setProviderDrafts((current) => ({
                ...current, [action.tool_slug]: { tool_slug: action.tool_slug, state, revision: action.revision },
              }));
            }} />
          <ProviderWorkflows key={`workflow-${props.item.cli_id}-${props.item.identity_hash}`}
            cliId={props.item.cli_id} />
          {Object.keys(providerDrafts).length > 0 ? (
            <button type="button" disabled={busy}
              className="mt-4 min-h-11 rounded-xl bg-brand-blue px-4 text-sm font-semibold text-white"
              onClick={requestSaveCommands}>Review {Object.keys(providerDrafts).length} action changes</button>
          ) : null}
        </>
      ) : null}
      <section className="mt-6 rounded-2xl border border-slate-200 bg-slate-50 p-4" aria-labelledby="custom-extension-continuity-heading">
        <h2 id="custom-extension-continuity-heading" className="text-sm font-semibold text-brand-dark">{continuity.title}</h2>
        <p className="mt-2 text-sm leading-6 text-brand-dark/75">{props.continuity.summary || continuity.description}</p>
        <p className="mt-2 text-xs leading-5 text-brand-dark/60">{continuity.privacyDisclosure}</p>
      </section>
      {added || hasSuggestedRules(props.item) ? (
        <section className="mt-8" aria-labelledby="custom-extension-commands-heading">
          <h2 id="custom-extension-commands-heading" className="text-lg font-semibold text-brand-dark">
            {detailCatalogHeading(props.item.surface)}
          </h2>
          <p className="mt-1 max-w-2xl text-sm leading-6 text-slate-500">
            {detailCatalogHelper(props.item.surface)}
          </p>
          {commandsDirty && hasSuggestedRules(props.item) && !added ? (
            <p role="note" className="mt-2 max-w-2xl text-sm leading-6 text-brand-dark/75">{SUGGESTED_RULES_NOTICE}</p>
          ) : null}
          {bulkTargets.length > 0 ? (
            <BulkPolicyPicker
              value={bulkState}
              disabled={busy}
              onChange={applyBulk}
              groupLabel={bulkCopy.groupLabel}
              allowLabel={props.item.surface === "mcp" ? "Allow listed" : undefined}
              blockLabel={props.item.surface === "mcp" ? "Deny listed" : undefined}
              mcpPolicy={props.item.surface === "mcp"}
              mixedCopy={bulkCopy.mixedCopy}
            />
          ) : null}
          {props.item.surface === "mcp" && bulkTargets.length > 0 ? (
            <p className="mt-2 text-xs leading-5 text-brand-dark/75">
              Bulk choices apply to {bulkTargets.length} listed {bulkTargets.length === 1 ? "tool" : "tools"} with direct permissions.
              Execution wrappers and unlisted tools keep their separate review settings.
            </p>
          ) : null}
          <div className="mt-4">
            <CustomExtensionCommandList
              commands={commands}
              disabled={busy}
              surface={props.item.surface}
              onChange={handleCommandState}
            />
          </div>
          {commandsDirty ? (
            <button type="button" className="mt-4 min-h-11 rounded-xl bg-brand-blue px-4 text-sm font-semibold text-white" onClick={requestSaveCommands}>
              Review {commandChanges.length} {props.item.surface === "mcp" ? "tool" : "command"} changes
            </button>
          ) : null}
        </section>
      ) : null}
      {error && !pending ? <div className="mt-4"><InlineError message={error} /></div> : null}
      {pending ? (
        <CustomExtensionReviewModal
          item={props.item}
          nextState={pending}
          commandChanges={pending === "unset" ? [] : commandChanges}
          providerUpdates={pending === "unset" ? [] : Object.values(providerDrafts)}
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
