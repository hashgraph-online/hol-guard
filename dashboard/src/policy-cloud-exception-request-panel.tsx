import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import type { FormEvent } from "react";
import { HiMiniArrowRight } from "react-icons/hi2";
import { ActionButton } from "./approval-center-primitives";
import { createCloudExceptionRequest } from "./guard-api";
import type { GuardRuntimeSnapshot } from "./guard-types";
import {
  canAdvanceFromGuardrails,
  canAdvanceFromScope,
  canSubmitDraft,
  createDefaultDraft,
  hasValidSourceAnchor,
  loadDraftFromStorage,
  mergeDraft,
  resolvePublisherFromSource,
  saveDraftToStorage,
  buildSubmitPayload,
  WIZARD_STEPS,
  type CloudExceptionRequestDraft,
  type SubmittedRequestState,
  type WizardStep,
} from "./policy-cloud-exception-request-draft";
import {
  RequestModalShell,
  RequestStepper,
  RequestSummaryRail,
} from "./policy-cloud-exception-request-layout";
import {
  CloudExceptionGuardrailsStep,
  CloudExceptionReviewStep,
  CloudExceptionScopeStep,
  CloudExceptionSourceStep,
  CloudExceptionSubmittedStep,
} from "./policy-cloud-exception-request-steps";
import { resolveCloudPolicyControlsUrl } from "./policy-workspace-helpers";

type PolicyCloudExceptionRequestPanelProps = {
  snapshot: GuardRuntimeSnapshot;
  onSubmitted: (requestId?: string) => void;
  onCancel: () => void;
};

const STEP_SUBTITLES: Record<WizardStep | "Submitted", string> = {
  Source: "Start from a real approval or evidence record.",
  Scope: "Choose the narrowest scope that solves the problem.",
  Guardrails: "Set owner, reason, and expiry before Cloud reviews it.",
  Review: "Review before sending to Guard Cloud.",
  Submitted: "Guard Cloud will review it before local enforcement changes.",
};

export function PolicyCloudExceptionRequestPanel({
  snapshot,
  onSubmitted,
  onCancel,
}: PolicyCloudExceptionRequestPanelProps) {
  const openerRef = useRef<HTMLElement | null>(
    typeof document !== "undefined" ? (document.activeElement as HTMLElement | null) : null,
  );
  const receiptOptions = snapshot.latest_receipts ?? [];

  const harnessOptions = useMemo(() => {
    const fromReceipts = receiptOptions.map((receipt) => receipt.harness).filter(Boolean);
    const fromInstalls = (snapshot.managed_installs ?? []).map((entry) => entry.harness).filter(Boolean);
    return [...new Set([...fromReceipts, ...fromInstalls, "codex", "cursor"])].sort();
  }, [receiptOptions, snapshot.managed_installs]);

  const [draft, setDraft] = useState<CloudExceptionRequestDraft>(() =>
    mergeDraft(createDefaultDraft(snapshot), loadDraftFromStorage()),
  );
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [submitted, setSubmitted] = useState<SubmittedRequestState | null>(null);

  const activeStep: WizardStep | "Submitted" = submitted ? "Submitted" : WIZARD_STEPS[draft.stepIndex] ?? "Source";
  const cloudControlsUrl = resolveCloudPolicyControlsUrl(snapshot);

  const publisherFromSource = useMemo(
    () => resolvePublisherFromSource(snapshot, draft, receiptOptions),
    [draft, receiptOptions, snapshot],
  );

  const publisherAvailable = Boolean(publisherFromSource || draft.publisher.trim());

  useEffect(() => {
    if (publisherFromSource && draft.scope === "publisher" && !draft.publisher.trim()) {
      setDraft((current) => ({ ...current, publisher: publisherFromSource }));
    }
  }, [draft.scope, draft.publisher, publisherFromSource]);

  const expiryLabel = useMemo(() => {
    const date = new Date(draft.requestedExpiresAt);
    return Number.isNaN(date.getTime()) ? "Not set" : date.toLocaleString();
  }, [draft.requestedExpiresAt]);

  const actionLabel = useMemo(() => {
    const approval = snapshot.items?.find(
      (item) =>
        item.request_id === draft.sourceReviewItemId ||
        item.request_id === draft.pastedRequestId,
    );
    const receipt = receiptOptions.find((entry) => entry.receipt_id === draft.sourceReceiptId);
    return (
      approval?.artifact_name ||
      approval?.artifact_id ||
      receipt?.artifact_name ||
      receipt?.artifact_id ||
      "this action"
    );
  }, [draft.pastedRequestId, draft.sourceReceiptId, draft.sourceReviewItemId, receiptOptions, snapshot.items]);

  const patchDraft = useCallback((patch: Partial<CloudExceptionRequestDraft>) => {
    setDraft((current) => ({ ...current, ...patch }));
  }, []);

  const handleSaveDraft = useCallback(() => {
    saveDraftToStorage(draft);
  }, [draft]);

  const handleBack = useCallback(() => {
    setDraft((current) => ({ ...current, stepIndex: Math.max(0, current.stepIndex - 1) }));
    setError(null);
  }, []);

  const handleNext = useCallback(() => {
    setDraft((current) => ({
      ...current,
      stepIndex: Math.min(WIZARD_STEPS.length - 1, current.stepIndex + 1),
    }));
    setError(null);
  }, []);

  const handleEditStep = useCallback((stepIndex: number) => {
    setDraft((current) => ({ ...current, stepIndex }));
    setError(null);
  }, []);

  const handleSubmit = useCallback(
    async (event: FormEvent<HTMLFormElement>) => {
      event.preventDefault();
      if (!canSubmitDraft(draft)) {
        return;
      }
      setSubmitting(true);
      setError(null);
      try {
        const payload = buildSubmitPayload(draft);
        const response = await createCloudExceptionRequest(payload);
        const created = response.items.find((item) => item.status === "pending") ?? response.items[0];
        if (!created?.requestId) {
          throw new Error("Guard Cloud did not return a request id.");
        }
        setSubmitted({
          requestId: created.requestId,
          submittedAt: created.requestedAt || new Date().toISOString(),
          status: "pending",
        });
      } catch (submitError) {
        const message =
          submitError instanceof Error && submitError.message.trim()
            ? submitError.message
            : "Unable to submit the Cloud exception request.";
        setError(message);
      } finally {
        setSubmitting(false);
      }
    },
    [draft],
  );

  const handleDone = useCallback(() => {
    onSubmitted(submitted?.requestId);
  }, [onSubmitted, submitted?.requestId]);

  const handleViewPending = useCallback(() => {
    onSubmitted(submitted?.requestId);
  }, [onSubmitted, submitted?.requestId]);

  const handleCancel = useCallback(() => {
    onCancel();
  }, [onCancel]);

  useEffect(() => {
    return () => {
      openerRef.current?.focus?.();
    };
  }, []);

  useEffect(() => {
    const handleKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape" && !submitting) {
        event.preventDefault();
        handleCancel();
      }
    };
    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [handleCancel, submitting]);

  const sourceComplete = hasValidSourceAnchor(draft);
  const scopeComplete = canAdvanceFromScope(draft);
  const guardrailsComplete = canAdvanceFromGuardrails(draft);
  const showSaveDraft =
    activeStep !== "Source" &&
    activeStep !== "Submitted" &&
    (sourceComplete || scopeComplete || guardrailsComplete);

  const canContinue =
    (activeStep === "Source" && sourceComplete) ||
    (activeStep === "Scope" && scopeComplete) ||
    (activeStep === "Guardrails" && guardrailsComplete);

  if (receiptOptions.length === 0 && (snapshot.items ?? []).length === 0) {
    return (
      <RequestModalShell
        title="Request cloud exception"
        subtitle="Start from a real approval or evidence record."
        stepper={<RequestStepper activeStep="Source" />}
        onCancel={handleCancel}
        footer={
          <ActionButton variant="secondary" onClick={handleCancel}>
            Close
          </ActionButton>
        }
      >
        <p className="text-sm font-medium text-brand-dark">No source records yet</p>
        <p className="mt-2 text-sm text-brand-dark/75">
          Guard needs at least one Review approval or evidence receipt on this device to anchor a Cloud exception
          request. Run a protected action first, then return here from Evidence or Inbox.
        </p>
      </RequestModalShell>
    );
  }

  if (submitted) {
    return (
      <RequestModalShell
        title="Request cloud exception"
        subtitle={STEP_SUBTITLES.Submitted}
        onCancel={handleCancel}
        preventClose={submitting}
        footer={
          <ActionButton variant="secondary" onClick={handleCancel}>
            Close
          </ActionButton>
        }
      >
        <CloudExceptionSubmittedStep
          draft={draft}
          snapshot={snapshot}
          receipts={receiptOptions}
          submitted={submitted}
          expiryLabel={expiryLabel}
          cloudControlsUrl={cloudControlsUrl}
          onViewPending={handleViewPending}
          onDone={handleDone}
        />
      </RequestModalShell>
    );
  }

  return (
    <RequestModalShell
      title="Request cloud exception"
      subtitle={STEP_SUBTITLES[activeStep as WizardStep]}
      stepper={<RequestStepper activeStep={activeStep as WizardStep} />}
      summaryRail={
        <RequestSummaryRail
          activeStep={activeStep}
          sourceComplete={sourceComplete}
          scopeComplete={scopeComplete}
          guardrailsComplete={guardrailsComplete}
        />
      }
      onCancel={handleCancel}
      preventClose={submitting}
      footer={
        <div className="flex flex-col gap-3">
          <div className="rounded-xl border border-brand-blue/10 bg-brand-blue/[0.03] px-3 py-2 text-xs text-brand-dark/80">
            Exceptions are approved in Guard Cloud, then enforced locally as signed policy bundle entries.
          </div>
          <div className="flex flex-wrap items-center justify-between gap-2">
            <ActionButton variant="secondary" type="button" onClick={handleCancel} disabled={submitting}>
              Cancel
            </ActionButton>
            <div className="flex flex-wrap items-center gap-2">
              {showSaveDraft ? (
                <ActionButton variant="secondary" type="button" onClick={handleSaveDraft} disabled={submitting}>
                  Save draft locally
                </ActionButton>
              ) : null}
              {draft.stepIndex > 0 ? (
                <ActionButton variant="secondary" type="button" onClick={handleBack} disabled={submitting}>
                  Back
                </ActionButton>
              ) : null}
              {activeStep === "Review" ? (
                <form onSubmit={handleSubmit}>
                  <ActionButton variant="primary" type="submit" disabled={submitting || !canSubmitDraft(draft)}>
                    {submitting ? "Submitting…" : "Submit request"}
                  </ActionButton>
                </form>
              ) : (
                <ActionButton
                  variant="primary"
                  type="button"
                  onClick={handleNext}
                  disabled={submitting || !canContinue}
                >
                  Continue
                  <HiMiniArrowRight className="ml-1 inline h-4 w-4" aria-hidden="true" />
                </ActionButton>
              )}
            </div>
          </div>
          {activeStep === "Guardrails" && !canContinue ? (
            <p className="text-center text-xs text-slate-500 sm:text-right">Complete required fields to continue.</p>
          ) : null}
        </div>
      }
    >
      {activeStep === "Source" ? (
        <CloudExceptionSourceStep
          snapshot={snapshot}
          draft={draft}
          receipts={receiptOptions}
          onDraftChange={patchDraft}
        />
      ) : null}

      {activeStep === "Scope" ? (
        <CloudExceptionScopeStep
          snapshot={snapshot}
          draft={draft}
          receipts={receiptOptions}
          harnessOptions={harnessOptions}
          publisherAvailable={publisherAvailable}
          onDraftChange={patchDraft}
        />
      ) : null}

      {activeStep === "Guardrails" ? (
        <CloudExceptionGuardrailsStep
          draft={draft}
          snapshot={snapshot}
          receipts={receiptOptions}
          expiryLabel={expiryLabel}
          onDraftChange={patchDraft}
        />
      ) : null}

      {activeStep === "Review" ? (
        <CloudExceptionReviewStep
          draft={draft}
          snapshot={snapshot}
          receipts={receiptOptions}
          expiryLabel={expiryLabel}
          actionLabel={actionLabel}
          error={error}
          onEditStep={handleEditStep}
        />
      ) : null}
    </RequestModalShell>
  );
}
