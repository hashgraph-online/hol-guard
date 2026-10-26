import { useCallback, useState } from "react";

import {
  applyLocalCliMutation,
  LocalCliApiError,
  previewLocalCliMutation,
  type LocalCliItem,
} from "../local-cli-api";
import { LOCAL_CLI_CAPABILITIES, type LocalCliCapability, type LocalCliCapabilityState } from "../local-cli-capability";
import { useResolvedApprovalGate } from "../use-resolved-approval-gate";
import { InlineError } from "./components/protection-primitives";
import { commandStatesPayload } from "./custom-extension-commands";
import { customExtensionDisplayName } from "./custom-extension-profile";
import { FRESH_TOTP_REQUIRED_MESSAGE, isFreshTotpRequired, randomToken } from "./local-cli-panel-copy";
import { CustomExtensionReviewModal } from "./local-cli-review-modal";

export const CAPABILITY_COPY: Record<LocalCliCapability, { label: string; description: string; blocked: string; need: string }> = {
  "loopback-network": {
    label: "Local network access",
    description: "Connect to services running on this computer, such as a local server.",
    blocked: "A run was stopped from connecting to this computer",
    need: "Turn this on if it needs a service running on this computer.",
  },
  "state-dir-read": {
    label: "Read its settings",
    description: "Read its own configuration and saved state in your home folder.",
    blocked: "A run was stopped from reading its settings",
    need: "Turn this on if it needs its saved configuration to work.",
  },
  "state-dir-write": {
    label: "Save its settings",
    description: "Write its own configuration and saved state in your home folder.",
    blocked: "A run was stopped from saving its settings",
    need: "Turn this on if it needs to keep its configuration between runs.",
  },
};

type CapabilityChange = { capability: LocalCliCapability; next: LocalCliCapabilityState };

/** This-device access for an allowed CLI, with the access its last denied run pointed at first. */
export function LocalCliCapabilities(props: {
  item: LocalCliItem;
  revision: number;
  onRefresh: () => Promise<void>;
}) {
  const { resolvedApprovalGate, refreshApprovalGate } = useResolvedApprovalGate(null);
  const [pending, setPending] = useState<CapabilityChange | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [freshTotpRequired, setFreshTotpRequired] = useState(false);
  const name = customExtensionDisplayName(props.item);
  const states = props.item.capabilities;
  const suggested = props.item.suggested_capability;

  const request = useCallback(async (change: CapabilityChange) => {
    setError(null);
    setFreshTotpRequired(false);
    try {
      await refreshApprovalGate({ failClosed: true });
    } catch {
      setError("Guard could not load your approval settings. Try again.");
      return;
    }
    setPending(change);
  }, [refreshApprovalGate]);
  const cancel = useCallback(() => {
    if (!busy) setPending(null);
  }, [busy]);
  const confirm = useCallback(async (credentials: { approval_password?: string; approval_totp_code?: string }) => {
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
        state: "allowed" as const,
        previous_revision: props.revision,
        session_nonce: randomToken(),
        // The saved command states, so this change carries no unsaved draft.
        commands: commandStatesPayload(props.item.commands),
        capabilities: { [pending.capability]: pending.next },
        ...credentials,
      };
      await previewLocalCliMutation(payload);
      await applyLocalCliMutation(payload);
      await props.onRefresh();
      await refreshApprovalGate();
      setPending(null);
    } catch (caught) {
      if (isFreshTotpRequired(caught)) {
        setFreshTotpRequired(true);
        await refreshApprovalGate().catch(() => undefined);
        setError(FRESH_TOTP_REQUIRED_MESSAGE);
      } else {
        setError(caught instanceof LocalCliApiError ? caught.message : "Guard could not change this access.");
      }
    } finally {
      setBusy(false);
    }
  }, [pending, props, refreshApprovalGate]);

  if (states === undefined) return null;
  return (
    <section className="mt-8 max-w-2xl" aria-labelledby="local-cli-capabilities-heading">
      <h2 id="local-cli-capabilities-heading" className="text-lg font-semibold text-brand-dark">Access on this device</h2>
      <p className="mt-1 text-sm leading-6 text-slate-600">
        Contained runs of {name} stay inside the workspace. Each access below widens that on this device only.
      </p>
      {suggested ? (
        <div role="status" data-testid="local-cli-capability-suggestion"
          className="mt-4 rounded-2xl border border-brand-blue/20 bg-blue-50/70 p-4">
          <p className="text-sm font-semibold text-brand-dark">{CAPABILITY_COPY[suggested].blocked}</p>
          <p className="mt-1 text-sm leading-6 text-brand-dark/80">
            {CAPABILITY_COPY[suggested].need} Everything else outside the workspace stays blocked.
          </p>
          <button type="button" disabled={busy} onClick={() => void request({ capability: suggested, next: "on" })}
            className="mt-3 min-h-11 rounded-xl bg-brand-blue px-4 text-sm font-semibold text-white disabled:opacity-60">
            Turn on {CAPABILITY_COPY[suggested].label.toLowerCase()}
          </button>
        </div>
      ) : null}
      <ul className="mt-4 divide-y divide-slate-200 border-y border-slate-200">
        {LOCAL_CLI_CAPABILITIES.map((capability) => {
          const on = states[capability] === "on";
          const copy = CAPABILITY_COPY[capability];
          return (
            <li key={capability} className="flex flex-col gap-3 py-4 sm:flex-row sm:items-center sm:justify-between">
              <div className="min-w-0">
                <p className="text-sm font-semibold text-brand-dark">
                  {copy.label}
                  <span className="ml-2 font-normal text-slate-600">{on ? "On" : "Off"}</span>
                </p>
                <p className="mt-0.5 text-sm leading-6 text-slate-600">{copy.description}</p>
              </div>
              <button type="button" disabled={busy}
                aria-label={`${on ? "Turn off" : "Turn on"} ${copy.label.toLowerCase()}`}
                onClick={() => void request({ capability, next: on ? "off" : "on" })}
                className="min-h-11 shrink-0 rounded-xl border border-slate-300 px-4 text-sm font-semibold text-brand-dark hover:bg-slate-50 disabled:opacity-60">
                {on ? "Turn off" : "Turn on"}
              </button>
            </li>
          );
        })}
      </ul>
      {error && !pending ? <div className="mt-4"><InlineError message={error} /></div> : null}
      {pending ? (
        <CustomExtensionReviewModal
          item={props.item}
          nextState="allowed"
          commandChanges={[]}
          providerUpdates={[]}
          capabilityChange={{ label: CAPABILITY_COPY[pending.capability].label, next: pending.next }}
          busy={busy}
          error={error}
          approvalGate={resolvedApprovalGate}
          requireFreshTotp={freshTotpRequired}
          onCancel={cancel}
          onConfirm={confirm}
        />
      ) : null}
    </section>
  );
}
