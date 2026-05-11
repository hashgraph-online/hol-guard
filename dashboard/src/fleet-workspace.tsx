import { useCallback } from "react";
import {
  HiMiniCheckCircle,
  HiMiniExclamationCircle,
  HiMiniWrenchScrewdriver,
  HiMiniXCircle,
  HiMiniChevronRight,
} from "react-icons/hi2";
import {
  ActionButton,
  EmptyState,
  SectionLabel,
  Tag,
  GuardHero,
  ProofStrip,
} from "./approval-center-primitives";
import { harnessDisplayName } from "./approval-center-utils";
import type { GuardInventoryItem, GuardPolicyDecision, GuardReceipt, GuardRuntimeSnapshot } from "./guard-types";

type FleetWorkspaceProps = {
  runtime: GuardRuntimeSnapshot;
  policies: GuardPolicyDecision[];
  inventory:
    | { kind: "idle" }
    | { kind: "loading" }
    | { kind: "error"; message: string }
    | { kind: "ready"; items: GuardInventoryItem[] };
  onConnectHarness?: (harness: string) => void;
  onTestHarness?: (harness: string) => void;
  onRepairHarness?: (harness: string) => void;
  onOpenAppDetail?: (harness: string) => void;
};

function collectHarnesses(snapshot: GuardRuntimeSnapshot): string[] {
  const harnesses = new Set<string>();
  for (const item of snapshot.items) harnesses.add(item.harness);
  for (const receipt of snapshot.latest_receipts) harnesses.add(receipt.harness);
  return Array.from(harnesses).sort((a, b) => a.localeCompare(b));
}

function renderReceiptContext(receipt: GuardReceipt): string {
  return `${harnessDisplayName(receipt.harness)} · ${receipt.policy_decision.replace(/-/g, " ")}`;
}

type AppStatus = "protected" | "found_unprotected" | "needs_repair" | "not_found";

function resolveAppStatus(
  install: { active?: boolean } | undefined,
  hasInventory: boolean,
  hasReceipts: boolean
): AppStatus {
  if (install !== undefined) {
    if (install.active) return "protected";
    return "needs_repair";
  }
  if (!hasInventory && !hasReceipts) return "not_found";
  return "found_unprotected";
}

function StatusIcon({ status }: { status: AppStatus }) {
  if (status === "protected") return <HiMiniCheckCircle className="h-4 w-4 text-emerald-500" aria-hidden="true" />;
  if (status === "found_unprotected") return <HiMiniExclamationCircle className="h-4 w-4 text-brand-attention" aria-hidden="true" />;
  if (status === "needs_repair") return <HiMiniWrenchScrewdriver className="h-4 w-4 text-brand-purple" aria-hidden="true" />;
  return <HiMiniXCircle className="h-4 w-4 text-slate-300" aria-hidden="true" />;
}

function StatusBadge({ status }: { status: AppStatus }) {
  if (status === "protected") return <span className="text-xs font-medium text-emerald-600">Protected</span>;
  if (status === "found_unprotected") return <span className="text-xs font-medium text-brand-attention">Found, not installed</span>;
  if (status === "needs_repair") return <span className="text-xs font-medium text-brand-purple">Repair needed</span>;
  return <span className="text-xs text-slate-400">Not found</span>;
}

export function FleetWorkspace(props: FleetWorkspaceProps) {
  const harnesses = collectHarnesses(props.runtime);
  const managedInstalls = props.runtime.managed_installs ?? [];
  const activeInstalls = managedInstalls.filter((i) => i.active);
  const inventory = props.inventory.kind === "ready" ? props.inventory.items : [];
  const visibleHarnesses = Array.from(
    new Set([
      ...managedInstalls.map((i) => i.harness),
      ...harnesses,
      ...inventory.map((i) => i.harness),
      ...props.policies.map((p) => p.harness),
    ])
  ).sort((a, b) => a.localeCompare(b));
  const runtimeState = props.runtime.runtime_state;
  const receiptHarnesses = new Set(props.runtime.latest_receipts.map((r) => r.harness));

  return (
    <div className="space-y-8">
      <GuardHero
        status={activeInstalls.length > 0 ? "clear" : "setup_gap"}
        headline={activeInstalls.length > 0 ? "Your apps are covered" : "Connect an app to start"}
        subheadline={
          activeInstalls.length > 0
            ? "Confirm that Guard is running and protecting your local AI apps."
            : "Guard works with Codex, Claude Code, Cursor, Hermes, OpenClaw, and more."
        }
        cta={<ActionButton href={props.runtime.fleet_url}>Open Cloud Devices</ActionButton>}
        secondaryCta={
          <ActionButton href={props.runtime.dashboard_url} variant="outline">
            Open Home
          </ActionButton>
        }
      />

      <ProofStrip
        items={[
          { label: "Needs review", value: `${props.runtime.pending_count}`, tone: props.runtime.pending_count > 0 ? "blue" : "slate" },
          { label: "History", value: `${props.runtime.receipt_count}`, tone: "purple" },
          { label: "Watched apps", value: `${activeInstalls.length > 0 ? activeInstalls.length : visibleHarnesses.length}`, tone: activeInstalls.length > 0 ? "green" : "slate" },
          { label: "Runtime", value: runtimeState ? "active" : "offline", tone: runtimeState ? "green" : "slate" },
        ]}
      />

      <div className="grid gap-8 lg:grid-cols-[minmax(0,1.4fr)_minmax(0,0.8fr)]">
        <section>
          <div className="mb-4">
            <SectionLabel>App coverage</SectionLabel>
            <p className="mt-1 text-sm text-slate-500">Which apps Guard is watching on this machine.</p>
          </div>

          {visibleHarnesses.length > 0 ? (
            <div className="divide-y divide-slate-100 border-t border-slate-100">
              {visibleHarnesses.map((harness) => {
                const install = managedInstalls.find((i) => i.harness === harness);
                const harnessInventory = inventory.filter((i) => i.harness === harness && i.present);
                const harnessPolicies = props.policies.filter((p) => p.harness === harness);
                const hasReceipts = receiptHarnesses.has(harness);
                const status = resolveAppStatus(install, harnessInventory.length > 0, hasReceipts);
                const isClickable = props.onOpenAppDetail !== undefined;

                return (
                  <div
                    key={harness}
                    className={`flex items-center justify-between gap-3 py-3 transition-colors ${
                      isClickable ? "cursor-pointer hover:bg-slate-50/60" : ""
                    }`}
                    onClick={isClickable ? () => props.onOpenAppDetail?.(harness) : undefined}
                    role={isClickable ? "button" : undefined}
                    tabIndex={isClickable ? 0 : undefined}
                    onKeyDown={
                      isClickable
                        ? (e) => {
                            if (e.key === "Enter" || e.key === " ") {
                              e.preventDefault();
                              props.onOpenAppDetail?.(harness);
                            }
                          }
                        : undefined
                    }
                  >
                    <div className="flex min-w-0 items-center gap-3">
                      <StatusIcon status={status} />
                      <div className="min-w-0">
                        <p className="text-sm font-medium text-brand-dark">{harnessDisplayName(harness)}</p>
                        <p className="text-xs text-slate-400">
                          {harnessInventory.length} actions · {harnessPolicies.length} decisions
                        </p>
                      </div>
                    </div>
                    <div className="flex items-center gap-2">
                      <StatusBadge status={status} />
                      {isClickable && <HiMiniChevronRight className="h-4 w-4 text-slate-300" aria-hidden="true" />}
                    </div>
                  </div>
                );
              })}
            </div>
          ) : (
            <EmptyState
              title="No watched apps yet"
              body="Run HOL Guard once with Codex, Claude Code, Cursor, Hermes, or another supported app and this machine will show coverage here."
              tone="teach"
            />
          )}

          {props.inventory.kind === "error" ? (
            <p className="mt-3 text-xs text-slate-500">{props.inventory.message}</p>
          ) : null}
        </section>

        <section>
          <div className="mb-4">
            <SectionLabel>Recent choices</SectionLabel>
            <p className="mt-1 text-sm text-slate-500">What Guard decided recently.</p>
          </div>
          {props.runtime.latest_receipts.length > 0 ? (
            <div className="space-y-0 divide-y divide-slate-100 border-t border-slate-100">
              {props.runtime.latest_receipts.slice(0, 6).map((receipt) => (
                <div key={receipt.receipt_id} className="py-2.5">
                  <p className="truncate text-sm font-medium text-brand-dark">
                    {receipt.artifact_name ?? receipt.artifact_id}
                  </p>
                  <p className="text-xs text-slate-400">{renderReceiptContext(receipt)}</p>
                </div>
              ))}
            </div>
          ) : (
            <EmptyState
              title="No choices yet"
              body="Allow or block an action once and HOL Guard will start building local history for this machine."
            />
          )}
        </section>
      </div>
    </div>
  );
}
