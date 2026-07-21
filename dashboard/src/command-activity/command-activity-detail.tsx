import { useCallback, type RefObject } from "react";
import { HiMiniXMark } from "react-icons/hi2";

import { Badge, SectionLabel } from "../approval-center-primitives";
import {
  commandDecisionLabel,
  commandEffectLabels,
  commandExecutionLabel,
  commandInteractionLabel,
  commandProofLabel,
  commandReasonLabel,
  FEEDBACK_LABELS,
  safeEvidenceId,
  safeVersion,
} from "./command-activity-presenters";
import type { CommandFeedbackState } from "./use-command-activity";
import type { CommandActivityItem, CommandFeedbackLabel } from "./command-activity-types";

function recordedTime(value: string): string {
  const date = new Date(value);
  return Number.isNaN(date.valueOf()) ? "Time unavailable" : date.toLocaleString();
}

function parseConfidenceLabel(value: CommandActivityItem["parse_confidence"]): string {
  if (value === "exact") return "Exact parse";
  if (value === "fallback") return "Compatibility fallback";
  if (value === "uncertain") return "Uncertain parse";
  return "Parse confidence unavailable";
}

function matchClassLabel(value: CommandActivityItem["matches"][number]["match_class"]): string {
  if (value === "unsafe") return "Unsafe evidence";
  if (value === "safe_variant") return "Safe variant evidence";
  return "Uncertainty evidence";
}

function approvalReuseLabel(value: CommandActivityItem["approval_reuse_status"]): string {
  if (value === "accepted") return "Existing authorization reused";
  if (value === "rejected") return "Existing authorization rejected";
  return "Not applicable";
}

function feedbackStatusMessage(feedback: CommandFeedbackState): string | null {
  if (feedback.kind === "saved") return "Feedback saved to local evidence.";
  if (feedback.kind === "error") return feedback.message;
  return null;
}

function EvidenceField(props: { label: string; value: string }) {
  return (
    <div>
      <dt className="text-xs font-medium text-slate-500">{props.label}</dt>
      <dd className="mt-0.5 text-sm font-medium text-brand-dark">{props.value}</dd>
    </div>
  );
}

function MatchEvidence(props: { match: CommandActivityItem["matches"][number]; controlling: boolean }) {
  const effects = commandEffectLabels(props.match);
  return (
    <li className="rounded-lg border border-slate-200 bg-slate-50/60 p-3">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <p className="text-sm font-medium text-brand-dark">{safeEvidenceId(props.match.rule_id)}</p>
        {props.controlling ? <Badge tone="info">Controlling rule</Badge> : null}
      </div>
      <p className="mt-1 text-xs text-slate-500">
        {safeEvidenceId(props.match.extension_id)} {safeVersion(props.match.extension_version)} · rule {safeVersion(props.match.rule_version)}
      </p>
      <dl className="mt-3 grid grid-cols-2 gap-3">
        <EvidenceField label="Evidence" value={matchClassLabel(props.match.match_class)} />
        <EvidenceField label="Policy floor" value={commandDecisionLabel(props.match.default_floor)} />
      </dl>
      <div className="mt-3 flex flex-wrap gap-1.5">
        {effects.length > 0 ? effects.map((effect) => <Badge key={effect}>{effect}</Badge>) : <span className="text-xs text-slate-500">Effect details unavailable</span>}
      </div>
    </li>
  );
}

export function CommandActivityDetail(props: {
  activity: CommandActivityItem;
  feedback: CommandFeedbackState;
  onFeedback: (label: CommandFeedbackLabel) => void;
  onClose: () => void;
  detailRef: RefObject<HTMLElement | null>;
}) {
  const handleShouldNotInterrupt = useCallback(
    () => props.onFeedback("should_not_have_interrupted"),
    [props.onFeedback],
  );
  const handleExpectedStop = useCallback(
    () => props.onFeedback("expected_guard_to_stop_this"),
    [props.onFeedback],
  );
  const saving = props.feedback.kind === "saving";
  const feedbackMessage = feedbackStatusMessage(props.feedback);
  const recordedFeedback = props.activity.feedback_label
    ? `Saved feedback: ${FEEDBACK_LABELS[props.activity.feedback_label]}`
    : null;

  return (
    <aside ref={props.detailRef} tabIndex={-1} aria-label="Command activity detail" className="space-y-5 p-4 outline-none sm:p-5">
      <div className="flex items-start justify-between gap-3">
        <div>
          <SectionLabel>Command activity</SectionLabel>
          <p className="mt-1 text-xs text-slate-500">{recordedTime(props.activity.occurred_at)}</p>
        </div>
        <button
          type="button"
          onClick={props.onClose}
          aria-label="Close command activity detail"
          className="inline-flex h-9 w-9 items-center justify-center rounded-lg text-slate-500 hover:bg-slate-100 hover:text-brand-dark"
        >
          <HiMiniXMark className="h-5 w-5" aria-hidden="true" />
        </button>
      </div>

      <dl className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-1">
        <EvidenceField label="Decision" value={commandDecisionLabel(props.activity.policy_action)} />
        <EvidenceField label="Execution proof" value={commandExecutionLabel(props.activity.execution_status)} />
        <EvidenceField label="Proof source" value={commandProofLabel(props.activity.proof_level)} />
        <EvidenceField label="Interaction" value={commandInteractionLabel(props.activity)} />
        <EvidenceField label="Decision reason" value={commandReasonLabel(props.activity.decision_reason_code)} />
        <EvidenceField label="Parse result" value={parseConfidenceLabel(props.activity.parse_confidence)} />
        <EvidenceField label="Authorization reuse" value={approvalReuseLabel(props.activity.approval_reuse_status)} />
        <EvidenceField
          label="Containment evidence"
          value={props.activity.decision_reason_code === "containment" ? "Recorded as controlling reason; details unavailable" : "Not recorded as controlling reason"}
        />
        <EvidenceField
          label="Workflow capability"
          value={props.activity.decision_reason_code === "capability" ? "Recorded as controlling reason; details unavailable" : "Not recorded as controlling reason"}
        />
      </dl>

      <div>
        <SectionLabel>Rule evidence</SectionLabel>
        {props.activity.matches.length > 0 ? (
          <ul className="mt-2 space-y-2">
            {props.activity.matches.map((match) => (
              <MatchEvidence
                key={`${match.ordinal}:${safeEvidenceId(match.rule_id)}`}
                match={match}
                controlling={match.rule_id === props.activity.controlling_rule_id}
              />
            ))}
          </ul>
        ) : (
          <p className="mt-2 text-sm text-slate-500">No rule match was recorded.</p>
        )}
      </div>

      <div className="border-t border-slate-100 pt-4">
        <SectionLabel>Was this interaction expected?</SectionLabel>
        <div className="mt-2 grid gap-2">
          <button
            type="button"
            disabled={saving}
            onClick={handleShouldNotInterrupt}
            className="min-h-10 rounded-lg border border-slate-200 px-3 text-left text-sm font-medium text-brand-dark hover:bg-slate-50 disabled:opacity-50"
          >
            {FEEDBACK_LABELS.should_not_have_interrupted}
          </button>
          <button
            type="button"
            disabled={saving}
            onClick={handleExpectedStop}
            className="min-h-10 rounded-lg border border-slate-200 px-3 text-left text-sm font-medium text-brand-dark hover:bg-slate-50 disabled:opacity-50"
          >
            {FEEDBACK_LABELS.expected_guard_to_stop_this}
          </button>
        </div>
        <p className="mt-2 min-h-5 text-xs text-slate-500" aria-live="polite">
          {saving ? "Saving feedback…" : feedbackMessage ?? recordedFeedback}
        </p>
      </div>
    </aside>
  );
}
