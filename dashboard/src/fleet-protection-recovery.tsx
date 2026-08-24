import { useCallback, useEffect, useRef, useState } from "react";
import {
  HiMiniCheckCircle,
  HiMiniChevronDown,
  HiMiniExclamationCircle,
  HiMiniWrenchScrewdriver,
} from "react-icons/hi2";
import { ActionButton } from "./approval-center-primitives";
import { harnessDisplayName } from "./approval-center-utils";
import {
  startOrRecoverCloudConnect,
  waitForAuthorizeUrl,
  waitForCloudConnection,
} from "./guard-cloud-connect-flow";
import { openPackageFirewallAuthorizeFallback } from "./package-firewall-connect-browser";
import type {
  GuardProtectionCheck,
  GuardProtectionHealth,
} from "./guard-types";
import { ProtectionRepairFlowError } from "./protection-repair-flow";

type GapAction = {
  label: string;
  detail: string;
};

type RepairState = {
  status: "working" | "success" | "error";
  message: string;
  failedHarnesses?: string[];
};

export type CloudPolicyRecoveryInput = {
  cloudState: "local_only" | "paired_waiting" | "paired_active";
  cloudSyncState: "healthy" | "pending" | "failed" | "degraded" | "disabled" | "stale";
  cloudPolicySyncError?: string | null;
  connectUrl: string;
};

type CloudPolicyRecoveryHint = {
  actionLabel: string;
  detail: string;
  href: string;
  startsOAuth: boolean;
  title: string;
};

type CloudConnectState = {
  authorizeUrl: string | null;
  message: string;
  status: "working" | "pending" | "success" | "error";
};

const PROTECTION_CHECK_ACTIONS: Record<string, GapAction> = {
  harness_hooks: {
    label: "App hooks",
    detail: "One or more app hooks need setup or repair.",
  },
  daemon: {
    label: "Local runtime",
    detail:
      "The local Guard runtime needs attention before protection can finish.",
  },
  policy_engine: {
    label: "Local policy engine",
    detail: "Guard could not confirm the local policy engine is ready.",
  },
  rule_packs: {
    label: "Local rule packs",
    detail: "Guard cannot confirm the active local rule-pack proof yet.",
  },
  decision_plane_compatibility: {
    label: "Decision plane",
    detail:
      "Guard reruns the decision-plane compatibility probe during repair. Retry here if it remains unproven.",
  },
  containment_compatibility: {
    label: "Containment",
    detail:
      "Guard reruns the containment compatibility probe during repair. Retry here if it remains unproven.",
  },
  sandbox: {
    label: "Sandbox",
    detail:
      "Guard reruns the sandbox enforcement probe during repair. Retry here if it remains unproven.",
  },
  decision_stream: {
    label: "Command evidence",
    detail:
      "Guard attempts evidence-store recovery during repair. Run a protected command only if fresh proof is still needed.",
  },
  tamper_checks: {
    label: "Local integrity checks",
    detail: "Managed Guard files or hooks did not pass integrity checks.",
  },
};

export function cloudPolicyRecoveryHint(input: CloudPolicyRecoveryInput): CloudPolicyRecoveryHint | null {
  const cloudProofUnavailable =
    input.cloudState !== "paired_active"
    || input.cloudSyncState !== "healthy"
    || Boolean(input.cloudPolicySyncError);
  if (!cloudProofUnavailable) return null;
  return {
    actionLabel: input.cloudState === "local_only" ? "Connect Guard Cloud" : "Open Guard Cloud",
    detail:
      "Local Guard remains active. Guard Cloud policy proof is separate from local repair and is not changed here.",
    href: input.connectUrl,
    startsOAuth: input.cloudState === "local_only",
    title: "Guard Cloud policy proof",
  };
}

function actionForCheck(
  check: GuardProtectionCheck,
  repairHarness?: string,
): GapAction {
  if (check.check_id === "harness_hooks" && repairHarness) {
    return {
      label: "App hooks",
      detail: `${harnessDisplayName(repairHarness)} hooks need setup or repair.`,
    };
  }
  const action = PROTECTION_CHECK_ACTIONS[check.check_id];
  return action
    ? action
    : {
        label: check.check_id.replace(/_/g, " "),
        detail: "Guard could not confirm this protection proof.",
      };
}

function ProtectionGapItem({
  action,
  check,
}: {
  action: GapAction;
  check: GuardProtectionCheck;
}) {
  return (
    <li className="flex items-start gap-2 border-t border-brand-attention/10 py-3 first:border-t-0">
      <div className="flex items-start gap-2 text-xs text-slate-600">
        <HiMiniExclamationCircle
          className={`mt-0.5 h-3.5 w-3.5 shrink-0 ${check.status === "fail" ? "text-brand-attention" : "text-slate-400"}`}
          aria-hidden="true"
        />
        <span>
          <strong className="font-semibold text-brand-dark">
            {action.label}
          </strong>
          <span className="ml-1 text-[10px] font-medium uppercase tracking-wide text-slate-400">
            {check.status === "fail" ? "Failed" : "Unproven"}
          </span>
          <span className="mt-0.5 block">{action.detail}</span>
        </span>
      </div>
    </li>
  );
}

type FleetProtectionRecoveryProps = {
  cloudPolicy: CloudPolicyRecoveryInput;
  health: GuardProtectionHealth;
  repairHarness?: string;
  repairHarnesses: string[];
  onRepairProtection: (harnesses: string[]) => Promise<string>;
  onRepairHarness?: (harness: string) => void;
};

function recoverySummary(failCount: number, unknownCount: number): string {
  if (failCount === 0) {
    return "Complete the remaining local proof here. Guard repairs and rechecks every local protection layer in one pass.";
  }
  const failedChecks = `${failCount} failed check${failCount === 1 ? "" : "s"}`;
  let remainingProofs = "";
  if (unknownCount > 0) {
    remainingProofs = `, then confirm the remaining ${unknownCount} proof${unknownCount === 1 ? "" : "s"}`;
  }
  return `Repair the ${failedChecks} here${remainingProofs}. Guard repairs and rechecks every local protection layer in one pass.`;
}

function repairButtonLabel(repairState: RepairState | null): string {
  if (repairState?.status === "working") return "Repairing…";
  if (repairState?.status === "error") return "Retry repair";
  return "Repair protection";
}

function cloudConnectPendingMessage(hasAuthorizeUrl: boolean, opened: boolean): string {
  if (!hasAuthorizeUrl) {
    return "Open the secure sign-in link below. This page will update automatically.";
  }
  if (opened) {
    return "Complete sign-in in the opened window. This page will update automatically.";
  }
  return "Your browser blocked the sign-in window. Open the secure sign-in link below.";
}

function cloudConnectButtonLabel(
  state: CloudConnectState | null,
  defaultLabel: string,
): string {
  if (state?.status === "working") return "Starting sign-in…";
  if (state?.status === "success") return "Guard Cloud connected";
  return defaultLabel;
}

function safeCloudConnectUrl(value: string | null | undefined): string | null {
  if (!value) return null;
  try {
    const url = new URL(value);
    if (!url.hostname || url.username || url.password) return null;
    const loopbackHosts = ["localhost", "127.0.0.1", "[::1]"];
    const secureRemote = url.protocol === "https:";
    const localHttp = url.protocol === "http:" && loopbackHosts.includes(url.hostname);
    if (!secureRemote && !localHttp) return null;
    return url.toString();
  } catch {
    return null;
  }
}

export function FleetProtectionRecovery(props: FleetProtectionRecoveryProps) {
  const [repairState, setRepairState] = useState<RepairState | null>(null);
  const [cloudConnectState, setCloudConnectState] = useState<CloudConnectState | null>(null);
  const [detailsOpen, setDetailsOpen] = useState(false);
  const cloudConnectControllerRef = useRef<AbortController | null>(null);
  const gaps = props.health.checks.filter((check) => check.status !== "pass");
  const failCount = gaps.filter((check) => check.status === "fail").length;
  const unknownCount = gaps.length - failCount;
  const cloudPolicyHint = cloudPolicyRecoveryHint(props.cloudPolicy);
  const isActiveCloudConnect = useCallback(
    (controller: AbortController) =>
      cloudConnectControllerRef.current === controller && !controller.signal.aborted,
    [],
  );

  const handleRepair = useCallback(async () => {
    setRepairState({
      status: "working",
      message: "Repairing app hooks, local runtime, local rule packs, and local integrity…",
    });
    try {
      const message = await props.onRepairProtection(props.repairHarnesses);
      setRepairState({ status: "success", message });
      setDetailsOpen(true);
    } catch (error: unknown) {
      const message =
        error instanceof Error
          ? error.message
          : "Repair paused before every protection step completed. Retry to continue safely.";
      setRepairState({
        status: "error",
        message,
        failedHarnesses:
          error instanceof ProtectionRepairFlowError ? error.failedHarnesses : undefined,
      });
      setDetailsOpen(true);
    }
  }, [props.onRepairProtection, props.repairHarnesses]);
  const handleRepairClick = useCallback(() => {
    void handleRepair();
  }, [handleRepair]);
  const handleDetailsToggle = useCallback(() => {
    setDetailsOpen((open) => !open);
  }, []);
  const handleTargetedRepair = useCallback(() => {
    const harness = repairState?.failedHarnesses?.[0];
    if (harness) props.onRepairHarness?.(harness);
  }, [props.onRepairHarness, repairState?.failedHarnesses]);
  const handleCloudConnect = useCallback(async () => {
    cloudConnectControllerRef.current?.abort();
    const controller = new AbortController();
    cloudConnectControllerRef.current = controller;
    setCloudConnectState({
      authorizeUrl: null,
      message: "Starting secure Guard Cloud sign-in…",
      status: "working",
    });
    try {
      const status = await waitForAuthorizeUrl(
        await startOrRecoverCloudConnect(controller.signal),
        controller.signal,
      );
      if (!isActiveCloudConnect(controller)) return;
      if (!status.connect_required) {
        setCloudConnectState({
          authorizeUrl: null,
          message: "Guard Cloud is connected.",
          status: "success",
        });
        return;
      }
      const flow = status.connect_flow;
      const authorizeUrl = safeCloudConnectUrl(flow?.authorize_url);
      const signInUrl = authorizeUrl ?? safeCloudConnectUrl(flow?.connect_url);
      if (!flow || !signInUrl) {
        throw new Error(
          flow?.detail || "Guard could not generate a secure sign-in link. Try again.",
        );
      }
      const opened = authorizeUrl
        ? openPackageFirewallAuthorizeFallback(authorizeUrl, flow.browser_opened)
        : false;
      if (!isActiveCloudConnect(controller)) return;
      setCloudConnectState({
        authorizeUrl: signInUrl,
        message: cloudConnectPendingMessage(Boolean(authorizeUrl), opened),
        status: "pending",
      });
      const connectedStatus = await waitForCloudConnection(status, {
        signal: controller.signal,
      });
      if (!isActiveCloudConnect(controller)) return;
      if (!connectedStatus.connect_required) {
        setCloudConnectState({
          authorizeUrl: null,
          message: "Guard Cloud is connected.",
          status: "success",
        });
        return;
      }
      const detail = connectedStatus.connect_flow?.detail;
      setCloudConnectState({
        authorizeUrl:
          safeCloudConnectUrl(connectedStatus.connect_flow?.authorize_url)
          ?? safeCloudConnectUrl(connectedStatus.connect_flow?.connect_url)
          ?? signInUrl,
        message:
          connectedStatus.connect_flow?.state === "failed"
            ? detail || "Guard Cloud sign-in could not finish. Try again."
            : "Automatic checking stopped before sign-in finished. Complete sign-in, then try again.",
        status: connectedStatus.connect_flow?.state === "failed" ? "error" : "pending",
      });
    } catch (error: unknown) {
      if (!isActiveCloudConnect(controller)) return;
      setCloudConnectState({
        authorizeUrl: null,
        message: error instanceof Error ? error.message : "Guard could not start sign-in. Try again.",
        status: "error",
      });
    }
  }, [isActiveCloudConnect]);
  const handleCloudConnectClick = useCallback(() => {
    void handleCloudConnect();
  }, [handleCloudConnect]);

  useEffect(() => {
    cloudConnectControllerRef.current?.abort();
    cloudConnectControllerRef.current = null;
    setCloudConnectState(null);
  }, [props.cloudPolicy.cloudState, props.cloudPolicy.connectUrl]);

  useEffect(() => () => cloudConnectControllerRef.current?.abort(), []);

  if (gaps.length === 0) return null;
  const working = repairState?.status === "working";
  const cloudConnectDisabled = ["working", "success"].includes(
    cloudConnectState?.status ?? "",
  );
  const cloudConnectMessageClassName =
    cloudConnectState?.status === "error" ? "text-sm text-red-600" : "text-sm text-slate-600";

  return (
    <section
      id="protection-recovery"
      className="border-y border-brand-attention/20 bg-brand-attention/[0.04] px-4 py-4 sm:px-5"
    >
      <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
        <div className="min-w-0">
          <div className="flex items-center gap-2">
            <HiMiniWrenchScrewdriver
              className="h-4 w-4 shrink-0 text-brand-attention"
              aria-hidden="true"
            />
            <h2 className="text-sm font-semibold text-brand-dark">
              Restore local protection
            </h2>
          </div>
          <p className="mt-1 text-sm text-slate-600">
            {recoverySummary(failCount, unknownCount)}
          </p>
        </div>
        <ActionButton onClick={handleRepairClick} disabled={working}>
          {repairButtonLabel(repairState)}
        </ActionButton>
      </div>
      {cloudPolicyHint ? (
        <div className="mt-3 border-t border-brand-attention/10 pt-3 text-sm text-slate-600">
          <p className="font-medium text-brand-dark">{cloudPolicyHint.title}</p>
          <p className="mt-1">{cloudPolicyHint.detail}</p>
          {cloudPolicyHint.startsOAuth ? (
            <div className="mt-2 flex flex-wrap items-center gap-3">
              <ActionButton
                onClick={handleCloudConnectClick}
                disabled={cloudConnectDisabled}
                variant="outline"
              >
                {cloudConnectButtonLabel(cloudConnectState, cloudPolicyHint.actionLabel)}
              </ActionButton>
              {cloudConnectState?.authorizeUrl ? (
                <ActionButton href={cloudConnectState.authorizeUrl} variant="quiet">
                  Open secure sign-in
                </ActionButton>
              ) : null}
              {cloudConnectState ? (
                <p className={cloudConnectMessageClassName} role="status">
                  {cloudConnectState.message}
                </p>
              ) : null}
            </div>
          ) : (
            <ActionButton href={cloudPolicyHint.href} variant="outline" className="mt-2">
              {cloudPolicyHint.actionLabel}
            </ActionButton>
          )}
        </div>
      ) : null}
      {repairState ? (
        <p
          className={`mt-3 flex items-start gap-2 text-sm ${repairState.status === "error" ? "text-red-600" : "text-slate-600"}`}
          aria-live="polite"
        >
          {repairState.status === "success" ? (
            <HiMiniCheckCircle
              className="mt-0.5 h-4 w-4 shrink-0 text-emerald-500"
              aria-hidden="true"
            />
          ) : null}
          {repairState.message}
        </p>
      ) : null}
      {repairState?.status === "error" && repairState.failedHarnesses?.[0] && props.onRepairHarness ? (
        <ActionButton onClick={handleTargetedRepair} variant="outline" className="mt-3">
          Open {harnessDisplayName(repairState.failedHarnesses[0])} repair
        </ActionButton>
      ) : null}
      <button
        type="button"
        onClick={handleDetailsToggle}
        aria-expanded={detailsOpen}
        className="mt-3 inline-flex items-center gap-1 text-xs font-medium text-brand-primary hover:underline focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2"
      >
        View repair details
        <HiMiniChevronDown
          className={`h-4 w-4 transition-transform ${detailsOpen ? "rotate-180" : ""}`}
          aria-hidden="true"
        />
      </button>
      {detailsOpen ? (
        <ul className="mt-2 border-t border-brand-attention/10">
          {gaps.map((check) => (
            <ProtectionGapItem
              key={check.check_id}
              action={actionForCheck(check, props.repairHarness)}
              check={check}
            />
          ))}
        </ul>
      ) : null}
    </section>
  );
}
