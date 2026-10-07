import { useCallback, useEffect, useState } from "react";

import { ApprovalProofModal } from "./approval-proof-modal";
import {
  ExtensionControlApiError,
  fetchEffectiveExtensionControls,
  recoverExtensionControlAuthority,
} from "./extension-controls-api";
import { fetchResolvedApprovalGate } from "./use-resolved-approval-gate";
import type { GuardApprovalGatePublicConfig } from "./guard-types";

export const PROTECTION_REPAIR_ROUTE = "/protection/repair";

export type ProtectionRepairAction = "repair" | "setup" | "home" | "extensions";

export type ProtectionRepairView = {
  title: string;
  body: string;
  action: ProtectionRepairAction;
  actionLabel: string;
};

const REPAIRABLE_HEALTH = new Set(["tampered", "recovery-required"]);

export function protectionRepairView(health: string, gateReady: boolean): ProtectionRepairView {
  if (health === "protected") {
    return {
      title: "Trusted settings are protected",
      body: "Trusted settings pass their integrity check. Retry the blocked action. If it still fails, open Home to check Guard.",
      action: "home",
      actionLabel: "Back to Home",
    };
  }
  if (REPAIRABLE_HEALTH.has(health)) {
    if (!gateReady) {
      return {
        title: "Trusted protection needs repair",
        body: "Trusted protection settings need repair, and local approval is not set up yet. Set up approval, then return here and press Repair protection.",
        action: "setup",
        actionLabel: "Set up approval",
      };
    }
    return {
      title: "Trusted protection needs repair",
      body: "Trusted protection settings need repair before this action can run. Press Repair protection, approve it, then retry the blocked action.",
      action: "repair",
      actionLabel: "Repair protection",
    };
  }
  return {
    title: "Protection does not need this repair",
    body: "This page rebuilds trusted protection settings after they fail a check. Open Extensions to see the current state.",
    action: "extensions",
    actionLabel: "Open Extensions",
  };
}

type ReadyState = {
  kind: "ready";
  health: string;
  gateReady: boolean;
  approvalGate: GuardApprovalGatePublicConfig | null;
};

type PageState =
  | { kind: "loading" }
  | { kind: "error" }
  | ReadyState;

function repairFailureMessage(error: unknown): string {
  if (error instanceof ExtensionControlApiError) {
    if (error.code === "authority_not_recoverable") {
      return "These protection settings do not need this repair. Retry the blocked action.";
    }
    if (error.status === 423 || (error.code ?? "").includes("approval")) {
      return "Approval did not succeed. Check the password and authenticator code, then press Repair protection again.";
    }
  }
  return "Repair did not complete. Press Repair protection and try again.";
}

export function ProtectionRepairPage(props: {
  onNavigate: (pathname: string) => void;
}) {
  const [page, setPage] = useState<PageState>({ kind: "loading" });
  const [proofOpen, setProofOpen] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    setPage({ kind: "loading" });
    setError(null);
    try {
      const [effective, gate] = await Promise.all([
        fetchEffectiveExtensionControls(),
        fetchResolvedApprovalGate(),
      ]);
      setPage({
        kind: "ready",
        health: effective.health,
        gateReady: Boolean(gate?.configured && gate.enabled),
        approvalGate: gate,
      });
    } catch {
      setPage({ kind: "error" });
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const confirmRepair = useCallback(async (credentials: {
    approval_password?: string;
    approval_totp_code?: string;
  }) => {
    setBusy(true);
    setError(null);
    try {
      const effective = await recoverExtensionControlAuthority(credentials);
      if (effective.health !== "protected") {
        setError("Guard could not verify repaired protection. Press Repair protection and try again.");
        return;
      }
      setProofOpen(false);
      setPage({
        kind: "ready",
        health: "protected",
        gateReady: true,
        approvalGate: page.kind === "ready" ? page.approvalGate : null,
      });
    } catch (caught) {
      setError(repairFailureMessage(caught));
    } finally {
      setBusy(false);
    }
  }, [page]);

  if (page.kind === "loading") {
    return (
      <section className="mx-auto w-full max-w-prose pt-6" aria-busy="true" aria-labelledby="protection-repair-heading">
        <h1 id="protection-repair-heading" className="text-2xl font-semibold text-brand-dark">Repair protection</h1>
        <p className="mt-3 text-base leading-7 text-brand-dark/80">Checking protection status.</p>
      </section>
    );
  }

  if (page.kind === "error") {
    return (
      <section className="mx-auto w-full max-w-prose pt-6" aria-labelledby="protection-repair-heading">
        <h1 id="protection-repair-heading" className="text-2xl font-semibold text-brand-dark">Repair protection</h1>
        <p className="mt-3 max-w-prose text-base leading-7 text-brand-dark/80">HOL Guard could not load protection status.</p>
        <button
          type="button"
          className="mt-6 inline-flex min-h-11 w-full items-center justify-center rounded-xl bg-brand-blue px-4 text-sm font-semibold text-white hover:bg-brand-dark focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-brand-blue sm:w-auto"
          onClick={() => { void load(); }}
        >Try again</button>
      </section>
    );
  }

  const view = protectionRepairView(page.health, page.gateReady);
  const buttonDisabled = busy;

  return (
    <section className="mx-auto w-full max-w-prose pt-6" aria-labelledby="protection-repair-heading">
      <h1 id="protection-repair-heading" className="text-2xl font-semibold text-balance text-brand-dark">{view.title}</h1>
      <p className="mt-3 max-w-prose text-base leading-7 text-brand-dark/80">{view.body}</p>
      <button
        type="button"
        className="mt-6 inline-flex min-h-11 w-full items-center justify-center rounded-xl bg-brand-blue px-4 text-sm font-semibold text-white hover:bg-brand-dark focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-brand-blue disabled:cursor-not-allowed disabled:opacity-60 sm:w-auto"
        disabled={buttonDisabled}
        aria-busy={busy}
        onClick={() => {
          if (view.action === "repair") {
            setProofOpen(true);
            return;
          }
          if (view.action === "setup") {
            props.onNavigate("/settings");
            return;
          }
          if (view.action === "extensions") {
            props.onNavigate("/extensions");
            return;
          }
          props.onNavigate("/");
        }}
      >{busy ? "Repairing…" : view.actionLabel}</button>
      {error ? <p role="alert" className="mt-4 rounded-xl border border-red-200 bg-red-50 px-3 py-2 text-sm leading-6 text-red-800">{error}</p> : null}
      {proofOpen && view.action === "repair" ? (
        <ApprovalProofModal
          title="Repair protection"
          detail="Rebuilding the trusted settings needs your approval password. Guard verifies the repair before protection changes unlock again."
          confirmLabel="Repair protection"
          approvalGate={page.approvalGate}
          requireFreshTotp={page.approvalGate?.totp_enabled === true}
          busy={busy}
          busyLabel="Repairing…"
          error={error}
          onCancel={() => { if (!busy) setProofOpen(false); }}
          onConfirm={(credentials) => { void confirmRepair(credentials); }}
        />
      ) : null}
    </section>
  );
}
