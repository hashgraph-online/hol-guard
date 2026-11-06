import { useCallback, useEffect, useState } from "react";
import type { ChangeEvent } from "react";
import {
  HiMiniArrowPath,
  HiMiniArrowTopRightOnSquare,
  HiMiniBugAnt,
  HiMiniCloudArrowDown,
  HiMiniShieldCheck,
} from "react-icons/hi2";
import { ApprovalProofInline, buildApprovalProofCredentials } from "./approval-proof-inline";
import { SUPPLY_CHAIN_SYNC_TIMEOUT_MS } from "./guard-api";
import { ActionButton, Tag } from "./approval-center-primitives";
import { GuardModalLayer } from "./guard-modal-layer";
import type { GuardApprovalGatePublicConfig, PackageFirewallStatusResponse } from "./guard-types";
import { SupplyChainAuditFailureNotice } from "./supply-chain-audit-failure-notice";
import { ConnectFlowCard } from "./supply-chain-firewall-views";
import { isStandaloneSyncRecoveryGate, type SupplyChainAuditRecoveryGate } from "./supply-chain-audit-recovery";
import type { SupplyChainRecoveryOperation } from "./supply-chain-audit-failure";

export type AuditRecoveryModalPhase =
  | "ready"
  | "syncing"
  | "connecting"
  | "auditing"
  | "approval"
  | "failed";

type AuditRecoveryModalProps = {
  gate: SupplyChainAuditRecoveryGate;
  phase: AuditRecoveryModalPhase;
  error: string | null;
  /** Which step produced `error`, so the notice names the right one. */
  errorOperation?: SupplyChainRecoveryOperation;
  connectError: string | null;
  connectStarting: boolean;
  connectFlow: PackageFirewallStatusResponse["connect_flow"];
  approvalGate: GuardApprovalGatePublicConfig | null;
  onClose: () => void;
  onPrimaryAction: () => void;
  onStartConnect: () => void;
  onApprovalSubmit: (credentials: {
    approval_password?: string;
    approval_totp_code?: string;
  }) => void;
  onApprovalBack: () => void;
};

function resolvePhaseLabel(phase: AuditRecoveryModalPhase): string {
  if (phase === "syncing") {
    return "Syncing intel";
  }
  if (phase === "connecting") {
    return "Waiting for Cloud";
  }
  if (phase === "auditing") {
    return "Running audit";
  }
  if (phase === "approval") {
    return "Approval required";
  }
  if (phase === "failed") {
    return "Needs attention";
  }
  return "Setup required";
}

function resolvePhaseTone(phase: AuditRecoveryModalPhase): "blue" | "attention" | "green" {
  if (phase === "failed") {
    return "attention";
  }
  if (phase === "auditing") {
    return "green";
  }
  return "blue";
}

function resolvePrimaryIcon(
  gate: SupplyChainAuditRecoveryGate,
  phase: AuditRecoveryModalPhase,
): typeof HiMiniCloudArrowDown {
  if (phase === "auditing") {
    return HiMiniBugAnt;
  }
  if (gate.primaryAction === "connect") {
    return HiMiniShieldCheck;
  }
  if (gate.primaryAction === "retry_audit") {
    return HiMiniBugAnt;
  }
  return HiMiniCloudArrowDown;
}

function resolvePrimaryLabel(
  gate: SupplyChainAuditRecoveryGate,
  phase: AuditRecoveryModalPhase,
): string {
  if (phase === "syncing") {
    return "Syncing supply-chain intel";
  }
  if (phase === "connecting") {
    return "Waiting for Guard Cloud";
  }
  if (phase === "auditing") {
    return "Running workspace audit";
  }
  return gate.primaryLabel;
}

/** Seconds a step must run before the dialog explains what Guard is waiting on. */
const BUSY_HINT_AFTER_SECONDS = 5;

export function resolveBusyHint(phase: AuditRecoveryModalPhase, elapsedSeconds: number): string | null {
  if (elapsedSeconds < BUSY_HINT_AFTER_SECONDS) {
    return null;
  }
  if (phase === "syncing") {
    const limitSeconds = Math.round(SUPPLY_CHAIN_SYNC_TIMEOUT_MS / 1000);
    return `Downloading the signed bundle from Guard Cloud (${elapsedSeconds}s). Guard stops waiting after ${limitSeconds}s and rechecks the feed.`;
  }
  if (phase === "connecting") {
    return `Waiting for you to approve Guard Cloud access in your browser (${elapsedSeconds}s).`;
  }
  if (phase === "auditing") {
    return `Scanning workspace manifests and lockfiles (${elapsedSeconds}s).`;
  }
  return null;
}

/** Seconds spent in the current busy phase; restarts when the dialog moves to another step. */
function useElapsedSeconds(busyPhase: AuditRecoveryModalPhase | null): number {
  const [elapsedSeconds, setElapsedSeconds] = useState(0);
  useEffect(() => {
    setElapsedSeconds(0);
    if (busyPhase === null) {
      return;
    }
    const startedAt = Date.now();
    const handle = window.setInterval(() => {
      setElapsedSeconds(Math.floor((Date.now() - startedAt) / 1000));
    }, 1000);
    return () => window.clearInterval(handle);
  }, [busyPhase]);
  return elapsedSeconds;
}

function resolveActiveStepIndex(
  gate: SupplyChainAuditRecoveryGate,
  phase: AuditRecoveryModalPhase,
): number {
  if (phase === "auditing") {
    return gate.steps.length;
  }
  if (phase === "syncing" || phase === "approval") {
    return gate.obstacle === "cloud_auth" ? 2 : 1;
  }
  if (phase === "connecting") {
    return 1;
  }
  return 0;
}

export function AuditRecoveryModal({
  gate,
  phase,
  error,
  errorOperation = "sync",
  connectError,
  connectStarting,
  connectFlow,
  approvalGate,
  onClose,
  onPrimaryAction,
  onStartConnect,
  onApprovalSubmit,
  onApprovalBack,
}: AuditRecoveryModalProps) {
  const [approvalPassword, setApprovalPassword] = useState("");
  const [approvalTotpCode, setApprovalTotpCode] = useState("");
  const [approvalSubmitting, setApprovalSubmitting] = useState(false);

  useEffect(() => {
    if (phase === "syncing" || phase === "connecting" || phase === "auditing") {
      return;
    }
    if (phase === "approval") {
      setApprovalSubmitting(false);
      return;
    }
    setApprovalPassword("");
    setApprovalTotpCode("");
    setApprovalSubmitting(false);
  }, [phase]);

  const activeStep = resolveActiveStepIndex(gate, phase);
  const standaloneSync = isStandaloneSyncRecoveryGate(gate);
  const primaryBusy = phase === "syncing" || phase === "connecting" || phase === "auditing";
  const PrimaryIcon = resolvePrimaryIcon(gate, phase);
  const elapsedSeconds = useElapsedSeconds(primaryBusy ? phase : null);
  const busyHint = primaryBusy ? resolveBusyHint(phase, elapsedSeconds) : null;
  const showConnectFlow =
    gate.primaryAction === "connect" && connectFlow !== null && phase !== "auditing";
  const showApprovalStep = phase === "approval";

  const handlePrimaryClick = useCallback(() => {
    if (primaryBusy) {
      return;
    }
    onPrimaryAction();
  }, [onPrimaryAction, primaryBusy]);

  const handleApprovalPasswordChange = useCallback((event: ChangeEvent<HTMLInputElement>) => {
    setApprovalPassword(event.target.value);
  }, []);

  const handleApprovalTotpCodeChange = useCallback((event: ChangeEvent<HTMLInputElement>) => {
    setApprovalTotpCode(event.target.value);
  }, []);

  const handleApprovalSubmit = useCallback(() => {
    setApprovalSubmitting(true);
    onApprovalSubmit(buildApprovalProofCredentials(approvalGate, { approvalPassword, approvalTotpCode }));
  }, [approvalGate, approvalPassword, approvalTotpCode, onApprovalSubmit]);

  return (
    <GuardModalLayer
      ariaLabel={standaloneSync ? "Approve supply-chain intel sync" : "Finish workspace audit setup"}
      onClose={onClose}
    >
      <div className="rounded-2xl border border-slate-200 bg-white shadow-xl">
        <div className="border-b border-slate-100 px-5 py-4">
          <div className="flex items-start justify-between gap-3">
            <div className="min-w-0 space-y-2">
              <div className="flex flex-wrap items-center gap-2">
                <p className="text-[10px] font-semibold uppercase tracking-[0.18em] text-brand-blue">
                  {standaloneSync ? "Supply-chain intel" : "Workspace audit"}
                </p>
                <Tag tone={resolvePhaseTone(phase)}>{resolvePhaseLabel(phase)}</Tag>
              </div>
              <h2 className="text-lg font-semibold tracking-[-0.02em] text-brand-dark">
                {gate.headline}
              </h2>
              <p className="max-w-xl text-sm leading-relaxed text-slate-600">{gate.detail}</p>
            </div>
            <button
              type="button"
              onClick={onClose}
              className="shrink-0 text-sm font-medium text-slate-500 hover:text-brand-dark"
            >
              Close
            </button>
          </div>
        </div>

        {showConnectFlow ? (
          <>
            <ConnectFlowCard
              minimal
              purpose="audit"
              mode="repair"
              connectFlow={connectFlow}
              connectStarting={connectStarting}
              connectError={connectError}
              headline={gate.headline}
              detail={gate.detail}
              onStartConnect={onStartConnect}
            />
            {busyHint !== null ? <p className="px-5 pb-4 text-xs leading-relaxed text-slate-500">{busyHint}</p> : null}
          </>
        ) : showApprovalStep ? (
          <div className="px-5 py-5">
            <ApprovalProofInline
              approvalGate={approvalGate}
              approvalPassword={approvalPassword}
              approvalTotpCode={approvalTotpCode}
              error={error !== null ? <SupplyChainAuditFailureNotice message={error} approvalStep operation={errorOperation} /> : null}
              submitLabel="Sync supply-chain intel"
              submitBusy={approvalSubmitting}
              onApprovalPasswordChange={handleApprovalPasswordChange}
              onApprovalTotpCodeChange={handleApprovalTotpCodeChange}
              onSubmit={handleApprovalSubmit}
              onBack={onApprovalBack}
            />
          </div>
        ) : (
          <div className="space-y-5 px-5 py-5">
            <ol className="grid gap-3 sm:grid-cols-2">
              {gate.steps.map((step, index) => {
                const stepNumber = index + 1;
                const isActive = stepNumber === activeStep;
                const isComplete = stepNumber < activeStep;
                return (
                  <li
                    key={step.title}
                    className={`rounded-xl border px-3 py-3 ${
                      isActive
                        ? "border-brand-blue/25 bg-brand-blue/[0.04]"
                        : isComplete
                          ? "border-slate-200 bg-slate-50/80"
                          : "border-slate-200 bg-white"
                    }`}
                  >
                    <p className="text-xs font-semibold uppercase tracking-[0.14em] text-slate-500">
                      Step {stepNumber}
                      {isComplete ? " · Done" : isActive ? " · In progress" : ""}
                    </p>
                    <p className="mt-1 text-sm font-semibold text-brand-dark">{step.title}</p>
                    <p className="mt-0.5 text-xs leading-relaxed text-slate-600">{step.body}</p>
                  </li>
                );
              })}
            </ol>

            {error !== null ? <SupplyChainAuditFailureNotice message={error} operation={errorOperation} /> : null}

            <div className="flex flex-wrap items-center gap-2">
              <ActionButton variant="primary" onClick={handlePrimaryClick} disabled={primaryBusy}>
                {primaryBusy ? (
                  <HiMiniArrowPath className="mr-1.5 h-4 w-4 animate-spin" aria-hidden="true" />
                ) : (
                  <PrimaryIcon className="mr-1.5 h-4 w-4" aria-hidden="true" />
                )}
                {resolvePrimaryLabel(gate, phase)}
              </ActionButton>
              {gate.primaryAction === "connect" && connectFlow?.authorize_url ? (
                <ActionButton href={connectFlow.authorize_url} variant="outline">
                  Open sign-in
                  <HiMiniArrowTopRightOnSquare className="ml-1.5 h-3.5 w-3.5" aria-hidden="true" />
                </ActionButton>
              ) : null}
            </div>
            {busyHint !== null ? <p className="text-xs leading-relaxed text-slate-500">{busyHint}</p> : null}
          </div>
        )}
      </div>
    </GuardModalLayer>
  );
}
