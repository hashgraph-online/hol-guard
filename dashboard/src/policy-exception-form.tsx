import { useCallback, useMemo, useState } from "react";
import type { ChangeEvent, FormEvent } from "react";
import { HiMiniChevronLeft, HiMiniChevronRight } from "react-icons/hi2";
import { ActionButton, SectionLabel } from "./approval-center-primitives";
import { harnessDisplayName } from "./approval-center-utils";
import { savePolicyDecision } from "./guard-api";
import type { DecisionScope, GuardPolicyDecision } from "./guard-types";

const ACTION_FAMILIES = [
  { id: "package-request", label: "Package installs", example: "npm, pip, pnpm installs" },
  { id: "tool-action", label: "Shell and tool commands", example: "terminal commands agents run" },
  { id: "tool-output", label: "Command output", example: "reading prior command output" },
  { id: "prompt", label: "Prompt submissions", example: "prompts sent to the model" },
  { id: "file-read", label: "File reads", example: "reading local files" },
] as const;

const RESPONSE_OPTIONS = [
  { id: "warn", label: "Warn me", description: "Show a warning but still allow unless I block it." },
  { id: "require-reapproval", label: "Require review each time", description: "Never auto-allow; always ask in Inbox." },
  { id: "block", label: "Block", description: "Stop this action type in the chosen scope." },
  { id: "allow", label: "Allow", description: "Skip future prompts for this action in the chosen scope." },
] as const;

const SCOPE_OPTIONS: Array<{ value: DecisionScope; label: string; description: string }> = [
  { value: "workspace", label: "This project", description: "Same action in the current project folder." },
  { value: "harness", label: "This app", description: "Matching actions anywhere in the selected app." },
  { value: "artifact", label: "One specific action", description: "Only the exact fingerprint you provide." },
];

type PolicyExceptionFormProps = {
  policies: GuardPolicyDecision[];
  onSaved: () => void;
  onCancel: () => void;
};

type FormStep = "app" | "action" | "response" | "review";

export function PolicyExceptionForm({ policies, onSaved, onCancel }: PolicyExceptionFormProps) {
  const [step, setStep] = useState<FormStep>("app");
  const [harness, setHarness] = useState("");
  const [family, setFamily] = useState<string>(ACTION_FAMILIES[0].id);
  const [scope, setScope] = useState<DecisionScope>("workspace");
  const [response, setResponse] = useState<string>("warn");
  const [reason, setReason] = useState("");
  const [artifactId, setArtifactId] = useState("");
  const [workspace, setWorkspace] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const harnessOptions = useMemo(() => {
    const fromPolicies = policies.map((policy) => policy.harness).filter(Boolean);
    const defaults = ["codex", "cursor", "claude-code", "opencode", "copilot", "kimi"];
    return [...new Set([...fromPolicies, ...defaults])].sort();
  }, [policies]);

  const workspaceOptions = useMemo(() => {
    const fromPolicies = policies
      .map((policy) => policy.workspace)
      .filter((value): value is string => Boolean(value?.trim()));
    return [...new Set(fromPolicies)].sort();
  }, [policies]);

  const handleWorkspaceSelect = useCallback((event: ChangeEvent<HTMLSelectElement>) => {
    setWorkspace(event.target.value);
  }, []);

  const handleHarnessChange = useCallback((event: ChangeEvent<HTMLSelectElement>) => {
    setHarness(event.target.value);
  }, []);

  const handleReasonChange = useCallback((event: ChangeEvent<HTMLTextAreaElement>) => {
    setReason(event.target.value);
  }, []);

  const handleArtifactChange = useCallback((event: ChangeEvent<HTMLInputElement>) => {
    setArtifactId(event.target.value);
  }, []);

  const handleWorkspaceChange = useCallback((event: ChangeEvent<HTMLInputElement>) => {
    setWorkspace(event.target.value);
  }, []);

  const resolvedArtifactId = useMemo(() => {
    if (scope === "artifact") {
      return artifactId.trim() || null;
    }
    return `family:${family}`;
  }, [scope, artifactId, family]);

  const canContinue = useMemo(() => {
    if (step === "app") {
      return harness.trim().length > 0;
    }
    if (step === "action") {
      return family.trim().length > 0;
    }
    if (step === "response") {
      if (scope === "artifact" && !artifactId.trim()) {
        return false;
      }
      if (scope === "workspace" && !workspace.trim()) {
        return false;
      }
      return response.trim().length > 0 && reason.trim().length > 0;
    }
    return true;
  }, [step, harness, family, scope, artifactId, workspace, response, reason]);

  const handleBack = useCallback(() => {
    setError(null);
    if (step === "action") {
      setStep("app");
      return;
    }
    if (step === "response") {
      setStep("action");
      return;
    }
    if (step === "review") {
      setStep("response");
    }
  }, [step]);

  const handleNext = useCallback(() => {
    setError(null);
    if (step === "app") {
      setStep("action");
      return;
    }
    if (step === "action") {
      setStep("response");
      return;
    }
    if (step === "response") {
      setStep("review");
    }
  }, [step]);

  const handleSubmit = useCallback(
    async (event: FormEvent) => {
      event.preventDefault();
      if (!resolvedArtifactId) {
        setError("Choose what this exception should apply to.");
        return;
      }
      setSubmitting(true);
      setError(null);
      try {
        await savePolicyDecision({
          harness,
          scope,
          action: response,
          artifact_id: resolvedArtifactId,
          workspace: scope === "workspace" ? workspace.trim() : undefined,
          reason: reason.trim(),
        });
        onSaved();
      } catch (submitError) {
        const message = submitError instanceof Error ? submitError.message : "Could not save this exception.";
        setError(message);
      } finally {
        setSubmitting(false);
      }
    },
    [harness, scope, response, resolvedArtifactId, workspace, reason, onSaved],
  );

  const familyLabel = ACTION_FAMILIES.find((item) => item.id === family)?.label ?? family;
  const responseLabel = RESPONSE_OPTIONS.find((item) => item.id === response)?.label ?? response;
  const scopeLabelText = SCOPE_OPTIONS.find((item) => item.value === scope)?.label ?? scope;

  return (
    <form onSubmit={handleSubmit} className="rounded-2xl border border-brand-blue/15 bg-white p-5 shadow-sm space-y-5">
      <div>
        <SectionLabel>Create exception</SectionLabel>
        <p className="mt-1 text-sm text-slate-600">
          Tell Guard how to treat a class of actions before they run. You can change or remove exceptions later.
        </p>
      </div>

      {step === "app" ? (
        <div className="space-y-2">
          <label htmlFor="exception-harness" className="text-sm font-medium text-brand-dark">
            Which app should this apply to?
          </label>
          <select
            id="exception-harness"
            value={harness}
            onChange={handleHarnessChange}
            className="w-full rounded-xl border border-slate-200 bg-white px-3 py-2.5 text-sm text-brand-dark focus:border-brand-blue focus:outline-none focus:ring-2 focus:ring-brand-blue/20"
          >
            <option value="">Select an app</option>
            {harnessOptions.map((option) => (
              <option key={option} value={option}>
                {harnessDisplayName(option)}
              </option>
            ))}
          </select>
        </div>
      ) : null}

      {step === "action" ? (
        <div className="space-y-3">
          <p className="text-sm font-medium text-brand-dark">What kind of action?</p>
          <div className="grid gap-2 sm:grid-cols-2">
            {ACTION_FAMILIES.map((option) => (
              <button
                key={option.id}
                type="button"
                onClick={() => setFamily(option.id)}
                aria-pressed={family === option.id}
                className={`rounded-xl border px-3 py-3 text-left transition-colors ${
                  family === option.id
                    ? "border-brand-blue bg-brand-blue/[0.06]"
                    : "border-slate-200 hover:border-slate-300"
                }`}
              >
                <p className="text-sm font-semibold text-brand-dark">{option.label}</p>
                <p className="mt-0.5 text-xs text-slate-500">{option.example}</p>
              </button>
            ))}
          </div>
        </div>
      ) : null}

      {step === "response" ? (
        <div className="space-y-4">
          <div className="space-y-2">
            <p className="text-sm font-medium text-brand-dark">How far should this reach?</p>
            <div className="grid gap-2">
              {SCOPE_OPTIONS.map((option) => (
                <button
                  key={option.value}
                  type="button"
                  onClick={() => setScope(option.value)}
                  aria-pressed={scope === option.value}
                  className={`rounded-xl border px-3 py-2.5 text-left ${
                    scope === option.value ? "border-brand-blue bg-brand-blue/[0.06]" : "border-slate-200"
                  }`}
                >
                  <p className="text-sm font-semibold text-brand-dark">{option.label}</p>
                  <p className="text-xs text-slate-500">{option.description}</p>
                </button>
              ))}
            </div>
          </div>

          {scope === "workspace" ? (
            <div className="space-y-1.5">
              <label htmlFor="exception-workspace" className="text-sm font-medium text-brand-dark">
                Which project folder?
              </label>
              {workspaceOptions.length > 0 ? (
                <select
                  id="exception-workspace"
                  value={workspace}
                  onChange={handleWorkspaceSelect}
                  className="w-full rounded-xl border border-slate-200 bg-white px-3 py-2.5 text-sm text-brand-dark focus:border-brand-blue focus:outline-none focus:ring-2 focus:ring-brand-blue/20"
                >
                  <option value="">Select a remembered project</option>
                  {workspaceOptions.map((option) => (
                    <option key={option} value={option}>
                      {option.startsWith("workspace:") ? "This project (from a prior approval)" : option}
                    </option>
                  ))}
                </select>
              ) : (
                <input
                  id="exception-workspace"
                  type="text"
                  value={workspace}
                  onChange={handleWorkspaceChange}
                  placeholder="/path/to/your/project"
                  className="w-full rounded-xl border border-slate-200 px-3 py-2.5 text-sm focus:border-brand-blue focus:outline-none focus:ring-2 focus:ring-brand-blue/20"
                />
              )}
              <p className="text-xs text-slate-500">
                Guard matches the project folder where the agent runs. Pick one from your remembered rules, or paste a path.
              </p>
            </div>
          ) : null}

          {scope === "artifact" ? (
            <div className="space-y-1.5">
              <label htmlFor="exception-artifact" className="text-sm font-medium text-brand-dark">
                Exact artifact id (from Inbox or Evidence)
              </label>
              <input
                id="exception-artifact"
                type="text"
                value={artifactId}
                onChange={handleArtifactChange}
                placeholder="codex:project:tool-action:..."
                className="w-full rounded-xl border border-slate-200 px-3 py-2.5 font-mono text-xs focus:border-brand-blue focus:outline-none focus:ring-2 focus:ring-brand-blue/20"
              />
            </div>
          ) : null}

          <div className="space-y-2">
            <p className="text-sm font-medium text-brand-dark">What should Guard do?</p>
            <div className="grid gap-2 sm:grid-cols-2">
              {RESPONSE_OPTIONS.map((option) => (
                <button
                  key={option.id}
                  type="button"
                  onClick={() => setResponse(option.id)}
                  aria-pressed={response === option.id}
                  className={`rounded-xl border px-3 py-2.5 text-left ${
                    response === option.id ? "border-brand-blue bg-brand-blue/[0.06]" : "border-slate-200"
                  }`}
                >
                  <p className="text-sm font-semibold text-brand-dark">{option.label}</p>
                  <p className="text-xs text-slate-500">{option.description}</p>
                </button>
              ))}
            </div>
          </div>

          <div className="space-y-1.5">
            <label htmlFor="exception-reason" className="text-sm font-medium text-brand-dark">
              Why are you adding this?
            </label>
            <textarea
              id="exception-reason"
              value={reason}
              onChange={handleReasonChange}
              rows={3}
              placeholder="Example: Always warn before package installs in this repo."
              className="w-full rounded-xl border border-slate-200 px-3 py-2.5 text-sm focus:border-brand-blue focus:outline-none focus:ring-2 focus:ring-brand-blue/20"
            />
          </div>
        </div>
      ) : null}

      {step === "review" ? (
        <div className="rounded-xl border border-slate-100 bg-slate-50/80 px-4 py-3 text-sm text-brand-dark space-y-2">
          <p>
            <span className="font-semibold">{responseLabel}</span> {familyLabel.toLowerCase()} in{" "}
            <span className="font-semibold">{harnessDisplayName(harness)}</span> ({scopeLabelText.toLowerCase()}).
          </p>
          <p className="text-slate-600">{reason.trim()}</p>
        </div>
      ) : null}

      {error ? <p className="text-sm text-red-600">{error}</p> : null}

      <div className="flex flex-wrap items-center justify-between gap-2 pt-1">
        <ActionButton variant="secondary" type="button" onClick={step === "app" ? onCancel : handleBack}>
          {step === "app" ? "Cancel" : (
            <>
              <HiMiniChevronLeft className="mr-1 h-4 w-4" aria-hidden="true" />
              Back
            </>
          )}
        </ActionButton>
        {step === "review" ? (
          <ActionButton variant="primary" type="submit" disabled={submitting}>
            {submitting ? "Saving…" : "Save exception"}
          </ActionButton>
        ) : (
          <ActionButton variant="primary" type="button" onClick={handleNext} disabled={!canContinue}>
            Continue
            <HiMiniChevronRight className="ml-1 h-4 w-4" aria-hidden="true" />
          </ActionButton>
        )}
      </div>
    </form>
  );
}
