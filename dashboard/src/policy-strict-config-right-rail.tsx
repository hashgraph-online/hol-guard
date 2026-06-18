import type { ChangeEvent } from "react";
import {
  HiMiniArrowRight,
  HiMiniBeaker,
  HiMiniCheckCircle,
  HiMiniPlay,
} from "react-icons/hi2";
import { ActionButton, Badge, SectionLabel } from "./approval-center-primitives";
import { policyActionLabel } from "./approval-center-utils";
import { POLICY_PANEL_CARD_CLASS, STRICT_CONFIG_SCENARIOS, STRICT_CONFIG_WHAT_CHANGES } from "./policy-strict-config-surfaces";
import type { StrictPolicySimulationResult, StrictScenarioId } from "./policy-strict-config-utils";

function resolveExpectedActionTone(action: string): "success" | "destructive" | "warning" | "default" {
  if (action === "block") {
    return "destructive";
  }
  if (action === "allow") {
    return "success";
  }
  if (action === "warn" || action === "review" || action === "require-reapproval") {
    return "warning";
  }
  return "default";
}

type PolicyStrictConfigRightRailProps = {
  pendingInboxCount: number;
  cloudControlsUrl: string | null;
  scenarioId: StrictScenarioId;
  expectedAction: string;
  expectedReasoning: string;
  simulationVisible: boolean;
  simulation: StrictPolicySimulationResult | null;
  onOpenInbox?: () => void;
  onScenarioChange: (event: ChangeEvent<HTMLSelectElement>) => void;
  onRunSimulation: () => void;
};

export function PolicyStrictConfigRightRail({
  pendingInboxCount,
  cloudControlsUrl,
  scenarioId,
  expectedAction,
  expectedReasoning,
  simulationVisible,
  simulation,
  onOpenInbox,
  onScenarioChange,
  onRunSimulation,
}: PolicyStrictConfigRightRailProps) {
  return (
    <aside className="min-w-0 space-y-4 xl:sticky xl:top-6 xl:self-start">
      <div className={`${POLICY_PANEL_CARD_CLASS} p-4`}>
        <SectionLabel>What this changes</SectionLabel>
        <ul className="mt-3 space-y-2.5 text-sm leading-relaxed text-slate-600">
          {STRICT_CONFIG_WHAT_CHANGES.map((item) => (
            <li key={item} className="flex gap-2">
              <HiMiniCheckCircle className="mt-0.5 h-4 w-4 shrink-0 text-emerald-600" aria-hidden="true" />
              <span>{item}</span>
            </li>
          ))}
        </ul>
      </div>

      <div className={`${POLICY_PANEL_CARD_CLASS} p-4`}>
        <SectionLabel>Affected pending Inbox items</SectionLabel>
        <p className="mt-2 text-4xl font-semibold tabular-nums text-brand-blue">
          {pendingInboxCount}
          <span className="ml-1.5 text-lg font-medium text-brand-blue/75">Items</span>
        </p>
        <p className="mt-1 text-sm leading-relaxed text-slate-600">
          Pending review items may be affected by stricter fallback controls.
        </p>
        {onOpenInbox && pendingInboxCount > 0 ? (
          <div className="mt-3">
            <ActionButton variant="secondary" onClick={onOpenInbox}>
              Open Inbox
              <HiMiniArrowRight className="ml-1.5 h-4 w-4" aria-hidden="true" />
            </ActionButton>
          </div>
        ) : null}
      </div>

      <div className={`${POLICY_PANEL_CARD_CLASS} p-4 text-sm leading-relaxed text-slate-600`}>
        <p className="font-medium text-brand-dark">Cloud exceptions still apply</p>
        <p className="mt-2">
          Signed Cloud exceptions still require bundle acknowledgement before they apply locally.
        </p>
        {cloudControlsUrl ? (
          <a
            href={cloudControlsUrl}
            target="_blank"
            rel="noopener noreferrer"
            className="mt-3 inline-flex items-center gap-1 text-sm font-medium text-brand-blue hover:underline"
          >
            Learn more
            <HiMiniArrowRight className="h-3.5 w-3.5" aria-hidden="true" />
          </a>
        ) : null}
      </div>

      <div className={`${POLICY_PANEL_CARD_CLASS} border-brand-blue/15 bg-brand-blue/[0.03] p-4`}>
        <div className="flex items-start gap-2">
          <HiMiniBeaker className="mt-0.5 h-5 w-5 shrink-0 text-brand-blue" aria-hidden="true" />
          <div className="min-w-0 flex-1">
            <SectionLabel>Test policy</SectionLabel>
            <p className="mt-2 text-sm leading-relaxed text-slate-600">Simulate how Guard will respond.</p>
          </div>
        </div>
        <label className="mt-4 block space-y-1.5">
          <span className="text-sm font-medium text-brand-dark">Scenario</span>
          <select
            value={scenarioId}
            onChange={onScenarioChange}
            className="w-full rounded-xl border border-slate-200 bg-white px-3 py-2 text-sm text-brand-dark"
          >
            {STRICT_CONFIG_SCENARIOS.map((scenario) => (
              <option key={scenario.id} value={scenario.id}>
                {scenario.label}
              </option>
            ))}
          </select>
        </label>
        <div className="mt-4 space-y-2">
          <p className="text-xs font-medium uppercase tracking-wide text-slate-500">Expected action</p>
          <Badge tone={resolveExpectedActionTone(expectedAction)}>{policyActionLabel(expectedAction)}</Badge>
          {expectedReasoning ? <p className="text-sm leading-relaxed text-slate-600">{expectedReasoning}</p> : null}
        </div>
        <div className="mt-4">
          <ActionButton variant="secondary" onClick={onRunSimulation}>
            <HiMiniPlay className="mr-1.5 h-4 w-4" aria-hidden="true" />
            Run simulation
          </ActionButton>
        </div>
        {simulationVisible && simulation ? (
          <div className="mt-4 rounded-xl border border-slate-100 bg-white p-4">
            <p className="text-sm font-medium text-brand-dark">
              Policy simulator outcome: {policyActionLabel(simulation.outcome)} ({simulation.winningStep})
            </p>
            <ul className="mt-2 space-y-1 text-xs text-slate-600">
              {simulation.path.map((step) => (
                <li key={step}>{step}</li>
              ))}
            </ul>
          </div>
        ) : null}
      </div>
    </aside>
  );
}
