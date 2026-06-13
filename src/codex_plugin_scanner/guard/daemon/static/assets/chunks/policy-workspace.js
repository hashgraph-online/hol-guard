import { r as reactExports, b7 as savePolicyDecision, j as jsxRuntimeExports, S as SectionLabel, h as harnessDisplayName, A as ActionButton, b8 as HiMiniChevronLeft, y as HiMiniChevronRight, b9 as policyActionLabel, ba as scopeLabel, b as EmptyState, ac as Tag, p as HiMiniChevronUp, q as HiMiniChevronDown, B as Badge, m as formatRelativeTime, b5 as guardAwareHref, b0 as HiMiniCloudArrowUp, ax as HiMiniTrash, ad as HiMiniMagnifyingGlass, bb as HiMiniPlus } from "../guard-dashboard.js";
const ACTION_FAMILIES = [
  { id: "package-request", label: "Package installs", example: "npm, pip, pnpm installs" },
  { id: "tool-action", label: "Shell and tool commands", example: "terminal commands agents run" },
  {
    id: "tool-output",
    label: "Command output",
    example: "reading prior command output",
    artifactScopeOnly: true
  },
  { id: "prompt", label: "Prompt submissions", example: "prompts sent to the model" },
  { id: "file-read", label: "File reads", example: "reading local files" }
];
function familySupportsHarnessOrWorkspaceScope(familyId) {
  const family = ACTION_FAMILIES.find((entry) => entry.id === familyId);
  return family !== void 0 && !("artifactScopeOnly" in family && family.artifactScopeOnly);
}
const RESPONSE_OPTIONS = [
  { id: "warn", label: "Warn me", description: "Show a warning but still allow unless I block it." },
  { id: "require-reapproval", label: "Require review each time", description: "Never auto-allow; always ask in Inbox." },
  { id: "block", label: "Block", description: "Stop this action type in the chosen scope." },
  { id: "allow", label: "Allow", description: "Skip future prompts for this action in the chosen scope." }
];
const SCOPE_OPTIONS = [
  { value: "workspace", label: "This project", description: "Same action in the current project folder." },
  { value: "harness", label: "This app", description: "Matching actions anywhere in the selected app." },
  { value: "artifact", label: "One specific action", description: "Only the exact fingerprint you provide." }
];
function PolicyExceptionForm({ policies, onSaved, onCancel }) {
  const [step, setStep] = reactExports.useState("app");
  const [harness, setHarness] = reactExports.useState("");
  const [family, setFamily] = reactExports.useState(ACTION_FAMILIES[0].id);
  const [scope, setScope] = reactExports.useState("workspace");
  const [response, setResponse] = reactExports.useState("warn");
  const [reason, setReason] = reactExports.useState("");
  const [artifactId, setArtifactId] = reactExports.useState("");
  const [workspace, setWorkspace] = reactExports.useState("");
  const [submitting, setSubmitting] = reactExports.useState(false);
  const [error, setError] = reactExports.useState(null);
  const harnessOptions = reactExports.useMemo(() => {
    const fromPolicies = policies.map((policy) => policy.harness).filter(Boolean);
    const defaults = ["codex", "cursor", "claude-code", "opencode", "copilot", "kimi"];
    return [.../* @__PURE__ */ new Set([...fromPolicies, ...defaults])].sort();
  }, [policies]);
  const scopeOptions = reactExports.useMemo(() => {
    if (familySupportsHarnessOrWorkspaceScope(family)) {
      return SCOPE_OPTIONS;
    }
    return SCOPE_OPTIONS.filter((option) => option.value === "artifact");
  }, [family]);
  const handleFamilySelect = reactExports.useCallback((familyId) => {
    setFamily(familyId);
    if (!familySupportsHarnessOrWorkspaceScope(familyId)) {
      setScope("artifact");
    }
  }, []);
  const workspaceOptions = reactExports.useMemo(() => {
    const fromPolicies = policies.map((policy) => policy.workspace).filter((value) => Boolean(value?.trim()));
    return [...new Set(fromPolicies)].sort();
  }, [policies]);
  const handleWorkspaceSelect = reactExports.useCallback((event) => {
    setWorkspace(event.target.value);
  }, []);
  const handleHarnessChange = reactExports.useCallback((event) => {
    setHarness(event.target.value);
  }, []);
  const handleReasonChange = reactExports.useCallback((event) => {
    setReason(event.target.value);
  }, []);
  const handleArtifactChange = reactExports.useCallback((event) => {
    setArtifactId(event.target.value);
  }, []);
  const handleWorkspaceChange = reactExports.useCallback((event) => {
    setWorkspace(event.target.value);
  }, []);
  const resolvedArtifactId = reactExports.useMemo(() => {
    if (scope === "artifact") {
      return artifactId.trim() || null;
    }
    return `family:${family}`;
  }, [scope, artifactId, family]);
  const canContinue = reactExports.useMemo(() => {
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
  const handleBack = reactExports.useCallback(() => {
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
  const handleNext = reactExports.useCallback(() => {
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
  const handleSubmit = reactExports.useCallback(
    async (event) => {
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
          workspace: scope === "workspace" ? workspace.trim() : void 0,
          reason: reason.trim()
        });
        onSaved();
      } catch (submitError) {
        const message = submitError instanceof Error ? submitError.message : "Could not save this exception.";
        setError(message);
      } finally {
        setSubmitting(false);
      }
    },
    [harness, scope, response, resolvedArtifactId, workspace, reason, onSaved]
  );
  const familyLabel = ACTION_FAMILIES.find((item) => item.id === family)?.label ?? family;
  const responseLabel = RESPONSE_OPTIONS.find((item) => item.id === response)?.label ?? response;
  const scopeLabelText = SCOPE_OPTIONS.find((item) => item.value === scope)?.label ?? scope;
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("form", { onSubmit: handleSubmit, className: "rounded-2xl border border-brand-blue/15 bg-white p-5 shadow-sm space-y-5", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(SectionLabel, { children: "Create exception" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1 text-sm text-slate-600", children: "Tell Guard how to treat a class of actions before they run. You can change or remove exceptions later." })
    ] }),
    step === "app" ? /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "space-y-2", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("label", { htmlFor: "exception-harness", className: "text-sm font-medium text-brand-dark", children: "Which app should this apply to?" }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs(
        "select",
        {
          id: "exception-harness",
          value: harness,
          onChange: handleHarnessChange,
          className: "w-full rounded-xl border border-slate-200 bg-white px-3 py-2.5 text-sm text-brand-dark focus:border-brand-blue focus:outline-none focus:ring-2 focus:ring-brand-blue/20",
          children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("option", { value: "", children: "Select an app" }),
            harnessOptions.map((option) => /* @__PURE__ */ jsxRuntimeExports.jsx("option", { value: option, children: harnessDisplayName(option) }, option))
          ]
        }
      )
    ] }) : null,
    step === "action" ? /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "space-y-3", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm font-medium text-brand-dark", children: "What kind of action?" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "grid gap-2 sm:grid-cols-2", children: ACTION_FAMILIES.map((option) => /* @__PURE__ */ jsxRuntimeExports.jsxs(
        "button",
        {
          type: "button",
          onClick: () => handleFamilySelect(option.id),
          "aria-pressed": family === option.id,
          className: `rounded-xl border px-3 py-3 text-left transition-colors ${family === option.id ? "border-brand-blue bg-brand-blue/[0.06]" : "border-slate-200 hover:border-slate-300"}`,
          children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm font-semibold text-brand-dark", children: option.label }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-0.5 text-xs text-slate-500", children: option.example })
          ]
        },
        option.id
      )) })
    ] }) : null,
    step === "response" ? /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "space-y-4", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "space-y-2", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm font-medium text-brand-dark", children: "How far should this reach?" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "grid gap-2", children: scopeOptions.map((option) => /* @__PURE__ */ jsxRuntimeExports.jsxs(
          "button",
          {
            type: "button",
            onClick: () => setScope(option.value),
            "aria-pressed": scope === option.value,
            className: `rounded-xl border px-3 py-2.5 text-left ${scope === option.value ? "border-brand-blue bg-brand-blue/[0.06]" : "border-slate-200"}`,
            children: [
              /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm font-semibold text-brand-dark", children: option.label }),
              /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs text-slate-500", children: option.description })
            ]
          },
          option.value
        )) })
      ] }),
      scope === "workspace" ? /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "space-y-1.5", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("label", { htmlFor: "exception-workspace", className: "text-sm font-medium text-brand-dark", children: "Which project folder?" }),
        workspaceOptions.length > 0 ? /* @__PURE__ */ jsxRuntimeExports.jsxs(
          "select",
          {
            id: "exception-workspace",
            value: workspace,
            onChange: handleWorkspaceSelect,
            className: "w-full rounded-xl border border-slate-200 bg-white px-3 py-2.5 text-sm text-brand-dark focus:border-brand-blue focus:outline-none focus:ring-2 focus:ring-brand-blue/20",
            children: [
              /* @__PURE__ */ jsxRuntimeExports.jsx("option", { value: "", children: "Select a remembered project" }),
              workspaceOptions.map((option) => /* @__PURE__ */ jsxRuntimeExports.jsx("option", { value: option, children: option.startsWith("workspace:") ? "This project (from a prior approval)" : option }, option))
            ]
          }
        ) : /* @__PURE__ */ jsxRuntimeExports.jsx(
          "input",
          {
            id: "exception-workspace",
            type: "text",
            value: workspace,
            onChange: handleWorkspaceChange,
            placeholder: "/path/to/your/project",
            className: "w-full rounded-xl border border-slate-200 px-3 py-2.5 text-sm focus:border-brand-blue focus:outline-none focus:ring-2 focus:ring-brand-blue/20"
          }
        ),
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs text-slate-500", children: "Guard matches the project folder where the agent runs. Pick one from your remembered rules, or paste a path." })
      ] }) : null,
      scope === "artifact" ? /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "space-y-1.5", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("label", { htmlFor: "exception-artifact", className: "text-sm font-medium text-brand-dark", children: "Exact artifact id (from Inbox or Evidence)" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx(
          "input",
          {
            id: "exception-artifact",
            type: "text",
            value: artifactId,
            onChange: handleArtifactChange,
            placeholder: "codex:project:tool-action:...",
            className: "w-full rounded-xl border border-slate-200 px-3 py-2.5 font-mono text-xs focus:border-brand-blue focus:outline-none focus:ring-2 focus:ring-brand-blue/20"
          }
        )
      ] }) : null,
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "space-y-2", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm font-medium text-brand-dark", children: "What should Guard do?" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "grid gap-2 sm:grid-cols-2", children: RESPONSE_OPTIONS.map((option) => /* @__PURE__ */ jsxRuntimeExports.jsxs(
          "button",
          {
            type: "button",
            onClick: () => setResponse(option.id),
            "aria-pressed": response === option.id,
            className: `rounded-xl border px-3 py-2.5 text-left ${response === option.id ? "border-brand-blue bg-brand-blue/[0.06]" : "border-slate-200"}`,
            children: [
              /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm font-semibold text-brand-dark", children: option.label }),
              /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs text-slate-500", children: option.description })
            ]
          },
          option.id
        )) })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "space-y-1.5", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("label", { htmlFor: "exception-reason", className: "text-sm font-medium text-brand-dark", children: "Why are you adding this?" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx(
          "textarea",
          {
            id: "exception-reason",
            value: reason,
            onChange: handleReasonChange,
            rows: 3,
            placeholder: "Example: Always warn before package installs in this repo.",
            className: "w-full rounded-xl border border-slate-200 px-3 py-2.5 text-sm focus:border-brand-blue focus:outline-none focus:ring-2 focus:ring-brand-blue/20"
          }
        )
      ] })
    ] }) : null,
    step === "review" ? /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "rounded-xl border border-slate-100 bg-slate-50/80 px-4 py-3 text-sm text-brand-dark space-y-2", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "font-semibold", children: responseLabel }),
        " ",
        familyLabel.toLowerCase(),
        " in",
        " ",
        /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "font-semibold", children: harnessDisplayName(harness) }),
        " (",
        scopeLabelText.toLowerCase(),
        ")."
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-slate-600", children: reason.trim() })
    ] }) : null,
    error ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm text-red-600", children: error }) : null,
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap items-center justify-between gap-2 pt-1", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(ActionButton, { variant: "secondary", type: "button", onClick: step === "app" ? onCancel : handleBack, children: step === "app" ? "Cancel" : /* @__PURE__ */ jsxRuntimeExports.jsxs(jsxRuntimeExports.Fragment, { children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniChevronLeft, { className: "mr-1 h-4 w-4", "aria-hidden": "true" }),
        "Back"
      ] }) }),
      step === "review" ? /* @__PURE__ */ jsxRuntimeExports.jsx(ActionButton, { variant: "primary", type: "submit", disabled: submitting, children: submitting ? "Saving…" : "Save exception" }) : /* @__PURE__ */ jsxRuntimeExports.jsxs(ActionButton, { variant: "primary", type: "button", onClick: handleNext, disabled: !canContinue, children: [
        "Continue",
        /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniChevronRight, { className: "ml-1 h-4 w-4", "aria-hidden": "true" })
      ] })
    ] })
  ] });
}
const MATCHER_FAMILY_LABELS = {
  "package-request": "package install",
  "tool-action": "shell or tool command",
  "tool-output": "command output review",
  prompt: "prompt submission",
  "prompt-env-read": "environment variable read",
  mcp: "MCP server call",
  "file-read": "file read"
};
const GENERIC_REASONS = [
  "approved in review",
  "approved in local approval center",
  "local auto-resume proof",
  "local e2e approval proof"
];
function isCloudManagedPolicy(source) {
  return source === "cloud-sync" || source === "team-policy" || source === "policy-bundle";
}
function resolvePolicySourceLabel(source) {
  if (isCloudManagedPolicy(source)) {
    return "Guard Cloud";
  }
  if (source === "manual" || source === "local") {
    return "This device";
  }
  return source.replace(/_/g, " ");
}
function policyTargetLabel(policy) {
  return policy.artifact_id ?? policy.publisher ?? policy.workspace ?? "Global";
}
function isGenericReason(reason) {
  if (!reason?.trim()) {
    return true;
  }
  const normalized = reason.trim().toLowerCase();
  return GENERIC_REASONS.some((phrase) => normalized.includes(phrase));
}
function extractMatcherFamily(artifactId) {
  if (artifactId.startsWith("family:")) {
    return artifactId.slice("family:".length);
  }
  const parts = artifactId.split(":");
  for (const family of Object.keys(MATCHER_FAMILY_LABELS)) {
    if (parts.includes(family)) {
      return family;
    }
  }
  return null;
}
function resolveRuntimeActionLabel(artifactId) {
  const parts = artifactId.split(":");
  const runtimeIndex = parts.indexOf("runtime");
  if (runtimeIndex < 0) {
    return null;
  }
  const tail = parts.slice(runtimeIndex + 1);
  if (tail[0] === "global" && tail.length >= 3) {
    const tool = tail[1].replace(/-/g, " ");
    const action = tail.slice(2).join(" ").replace(/_/g, " ");
    return `${tool}: ${action}`;
  }
  return null;
}
function resolvePromptSubtypeLabel(artifactId) {
  const parts = artifactId.split(":");
  const promptIndex = parts.indexOf("prompt");
  if (promptIndex < 0) {
    return null;
  }
  const subtype = parts[promptIndex + 1];
  if (!subtype) {
    return "prompt review";
  }
  return subtype.replace(/_/g, " ");
}
function resolveWorkspaceLabel(workspace) {
  if (!workspace?.trim()) {
    return "this project";
  }
  const value = workspace.trim();
  if (value.startsWith("workspace:")) {
    return "this project";
  }
  if (value.startsWith("/")) {
    const segments = value.split("/").filter(Boolean);
    return segments[segments.length - 1] ?? "this project";
  }
  if (value.length > 32 && /^[a-f0-9]+$/i.test(value)) {
    return "this project";
  }
  return value;
}
function resolveActionVerb(action) {
  if (action === "allow") {
    return "Allow";
  }
  if (action === "block") {
    return "Block";
  }
  return policyActionLabel(action);
}
function resolveScopeSubtitle(policy) {
  const app = harnessDisplayName(policy.harness);
  if (policy.scope === "artifact") {
    return `Applies once in ${app}`;
  }
  if (policy.scope === "workspace") {
    return `Applies every time in ${resolveWorkspaceLabel(policy.workspace)} (${app})`;
  }
  if (policy.scope === "harness") {
    return `Applies every time in ${app}`;
  }
  if (policy.scope === "publisher") {
    const publisher = policy.publisher?.trim() || "this publisher";
    return `Applies to ${publisher} in ${app}`;
  }
  if (policy.scope === "global") {
    return "Applies on every project on this device";
  }
  return scopeLabel(policy.scope);
}
function resolveWhatPhrase(policy) {
  const artifactId = policy.artifact_id?.trim() ?? "";
  const publisher = policy.publisher?.trim();
  if (policy.scope === "global" && !artifactId && !publisher) {
    return "all guarded actions on this device";
  }
  const runtimeLabel = artifactId ? resolveRuntimeActionLabel(artifactId) : null;
  if (runtimeLabel) {
    return runtimeLabel;
  }
  const family = artifactId ? extractMatcherFamily(artifactId) : null;
  const familyPhrase = family ? MATCHER_FAMILY_LABELS[family] ?? family.replace(/-/g, " ") : null;
  if (familyPhrase) {
    if (artifactId.startsWith("family:") || policy.scope === "harness") {
      return `all ${familyPhrase}s`;
    }
    if (family === "prompt") {
      const subtype = resolvePromptSubtypeLabel(artifactId);
      return subtype ? `${familyPhrase} (${subtype})` : familyPhrase;
    }
    return familyPhrase;
  }
  if (publisher) {
    return `actions from ${publisher}`;
  }
  return "matching guarded actions";
}
function resolvePolicyDisplay(policy) {
  const reason = policy.reason?.trim() ?? null;
  const actionVerb = resolveActionVerb(policy.action);
  if (reason && !isGenericReason(reason)) {
    return {
      headline: `${actionVerb}: ${reason}`,
      subtitle: resolveScopeSubtitle(policy),
      technicalId: policy.artifact_id
    };
  }
  const what = resolveWhatPhrase(policy);
  return {
    headline: `${actionVerb} ${what}`,
    subtitle: resolveScopeSubtitle(policy),
    technicalId: policy.artifact_id
  };
}
function resolvePolicyEvidenceSearchTerm(policy) {
  const hash = policy.artifact_hash?.trim();
  if (hash) {
    const normalized = hash.replace(/^sha256:/i, "");
    return normalized.slice(0, 12);
  }
  const target = policyTargetLabel(policy);
  if (!target || target === "Global") {
    return null;
  }
  if (target.startsWith("family:")) {
    return target.slice("family:".length);
  }
  const parts = target.split(":");
  const last = parts[parts.length - 1];
  if (last && last.length >= 12 && /^[a-f0-9]+$/i.test(last)) {
    return last.slice(0, 12);
  }
  return null;
}
function resolvePolicyEvidenceHref(policy) {
  const params = new URLSearchParams();
  const searchTerm = resolvePolicyEvidenceSearchTerm(policy);
  if (searchTerm) {
    params.set("search", searchTerm);
  }
  const query = params.toString();
  return query ? `/evidence?${query}` : "/evidence";
}
function resolveCloudPolicyControlsUrl(snapshot) {
  const dashboardUrl = snapshot.dashboard_url?.trim();
  if (dashboardUrl) {
    return dashboardUrl;
  }
  const connectUrl = snapshot.connect_url?.trim();
  return connectUrl && connectUrl.length > 0 ? connectUrl : null;
}
function resolveCloudBundleSurfaceClass(tone) {
  if (tone === "attention") {
    return "rounded-2xl border border-amber-200/70 bg-amber-50/70 p-4 shadow-sm";
  }
  if (tone === "green") {
    return "rounded-2xl border border-emerald-200/70 bg-emerald-50/70 p-4 shadow-sm";
  }
  return "rounded-2xl border border-slate-200/70 bg-slate-50/70 p-4 shadow-sm";
}
function resolvePolicyMatcherFamily(policy) {
  const target = policy.artifact_id?.trim();
  if (!target) {
    return null;
  }
  return extractMatcherFamily(target);
}
function groupPoliciesByHarness(policies) {
  const map = /* @__PURE__ */ new Map();
  for (const policy of policies) {
    const key = policy.harness || "global";
    const existing = map.get(key) ?? [];
    map.set(key, [...existing, policy]);
  }
  return map;
}
function resolveSecurityModeCopy(level) {
  if (level === "strict") {
    return {
      label: "Strict mode",
      description: "Guard asks before most actions including new network connections and file writes. Higher noise, maximum protection.",
      tone: "attention"
    };
  }
  if (level === "balanced") {
    return {
      label: "Balanced (default)",
      description: "Guard asks for secrets, destructive commands, and new network destinations. Low noise, solid coverage.",
      tone: "green"
    };
  }
  if (level === "gentle" || level === "relaxed") {
    return {
      label: "Low noise",
      description: "Guard only asks for the highest-risk actions. Minimal interruptions.",
      tone: "slate"
    };
  }
  return {
    label: level ?? "Custom",
    description: "Custom policy rules apply. Review individual rules below.",
    tone: "slate"
  };
}
function resolveCloudPolicyBundleCopy(snapshot) {
  const bundleVersion = snapshot.cloud_policy_bundle_version?.trim();
  if (!bundleVersion) {
    return null;
  }
  const rollout = snapshot.cloud_policy_rollout_state?.trim() || "unknown";
  const syncError = snapshot.cloud_policy_sync_error?.trim();
  if (syncError) {
    return {
      label: `Cloud bundle ${bundleVersion}`,
      detail: `Guard Cloud Controls owns rollout and authoring. Latest sync issue: ${syncError}.`,
      tone: "attention"
    };
  }
  return {
    label: `Cloud bundle ${bundleVersion}`,
    detail: `Guard Cloud Controls owns authoring and rollout. This local workspace reflects rollout state ${rollout}.`,
    tone: "green"
  };
}
const PAGE_SIZE = 30;
function resolveActionTone(action) {
  if (action === "allow") {
    return "success";
  }
  if (action === "block") {
    return "destructive";
  }
  if (action === "warn" || action === "require-reapproval") {
    return "warning";
  }
  return "default";
}
function PolicyRuleCard({ policy, cloudControlsUrl, onClear }) {
  const handleClear = reactExports.useCallback(() => onClear?.(policy), [onClear, policy]);
  const cloudManaged = isCloudManagedPolicy(policy.source);
  const display = resolvePolicyDisplay(policy);
  const canClear = onClear !== void 0 && !cloudManaged;
  return /* @__PURE__ */ jsxRuntimeExports.jsx("article", { className: "rounded-2xl border border-slate-100 bg-white px-4 py-3.5 shadow-sm", children: /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap items-start justify-between gap-3", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "min-w-0 flex-1 space-y-1.5", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap items-center gap-2", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(Badge, { tone: resolveActionTone(policy.action), children: policyActionLabel(policy.action) }),
        /* @__PURE__ */ jsxRuntimeExports.jsx(Tag, { tone: cloudManaged ? "blue" : "green", children: resolvePolicySourceLabel(policy.source) }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-xs text-slate-400", children: harnessDisplayName(policy.harness) })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("h3", { className: "text-base font-semibold leading-snug text-brand-dark", children: display.headline }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm text-slate-600", children: display.subtitle }),
      display.technicalId ? /* @__PURE__ */ jsxRuntimeExports.jsxs("details", { className: "text-xs text-slate-500", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("summary", { className: "cursor-pointer text-brand-blue hover:underline", children: "Technical id" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1 break-all font-mono text-[11px] text-slate-600", children: display.technicalId })
      ] }) : null
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex shrink-0 flex-col items-end gap-2 text-right", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-xs text-slate-400", children: policy.updated_at ? formatRelativeTime(policy.updated_at) : null }),
      !cloudManaged ? /* @__PURE__ */ jsxRuntimeExports.jsx(
        "a",
        {
          href: guardAwareHref(resolvePolicyEvidenceHref(policy)),
          className: "text-sm font-medium text-brand-blue hover:underline",
          children: "See approval record"
        }
      ) : null,
      cloudManaged && cloudControlsUrl ? /* @__PURE__ */ jsxRuntimeExports.jsxs(
        "a",
        {
          href: cloudControlsUrl,
          target: "_blank",
          rel: "noopener noreferrer",
          className: "inline-flex items-center gap-1 text-sm font-medium text-brand-blue hover:underline",
          children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniCloudArrowUp, { className: "h-4 w-4", "aria-hidden": "true" }),
            "View on cloud"
          ]
        }
      ) : null,
      canClear ? /* @__PURE__ */ jsxRuntimeExports.jsxs(
        "button",
        {
          type: "button",
          onClick: handleClear,
          className: "inline-flex items-center gap-1 text-xs font-medium text-slate-500 hover:text-red-600",
          children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniTrash, { className: "h-3.5 w-3.5", "aria-hidden": "true" }),
            "Remove rule"
          ]
        }
      ) : null
    ] })
  ] }) });
}
function PolicyRuleList({ policies, cloudControlsUrl, onClearPolicy, emptyTitle, emptyBody }) {
  const [visibleCount, setVisibleCount] = reactExports.useState(PAGE_SIZE);
  const visiblePolicies = reactExports.useMemo(() => policies.slice(0, visibleCount), [policies, visibleCount]);
  const hasMore = policies.length > visibleCount;
  const handleShowMore = reactExports.useCallback(() => {
    setVisibleCount((current) => current + PAGE_SIZE);
  }, []);
  if (policies.length === 0) {
    return /* @__PURE__ */ jsxRuntimeExports.jsx(EmptyState, { title: emptyTitle, body: emptyBody, tone: "teach" });
  }
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "space-y-3", children: [
    visiblePolicies.map((policy) => /* @__PURE__ */ jsxRuntimeExports.jsx(
      PolicyRuleCard,
      {
        policy,
        cloudControlsUrl,
        onClear: onClearPolicy
      },
      `${policy.harness}-${policy.scope}-${policy.artifact_id ?? policy.publisher ?? "global"}-${policy.updated_at ?? ""}-${policy.source}`
    )),
    hasMore ? /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "flex justify-center pt-1", children: /* @__PURE__ */ jsxRuntimeExports.jsxs(
      "button",
      {
        type: "button",
        onClick: handleShowMore,
        className: "rounded-full border border-slate-200 bg-white px-4 py-2 text-sm font-medium text-brand-dark hover:bg-slate-50",
        children: [
          "Show ",
          Math.min(PAGE_SIZE, policies.length - visibleCount),
          " more (",
          policies.length - visibleCount,
          " remaining)"
        ]
      }
    ) }) : null
  ] });
}
function GroupedPolicySection({
  title,
  description,
  policies,
  cloudControlsUrl,
  onClearPolicy,
  emptyTitle,
  emptyBody,
  defaultOpen = true
}) {
  const [open, setOpen] = reactExports.useState(defaultOpen);
  const handleToggle = reactExports.useCallback(() => setOpen((current) => !current), []);
  if (policies.length === 0) {
    return /* @__PURE__ */ jsxRuntimeExports.jsxs("section", { className: "space-y-2", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("h2", { className: "text-base font-semibold text-brand-dark", children: title }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm text-slate-500", children: description })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsx(EmptyState, { title: emptyTitle, body: emptyBody, tone: "teach" })
    ] });
  }
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("section", { className: "space-y-3", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs(
      "button",
      {
        type: "button",
        onClick: handleToggle,
        className: "flex w-full items-center justify-between gap-3 rounded-xl border border-slate-100 bg-slate-50/70 px-4 py-3 text-left",
        "aria-expanded": open,
        children: [
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("h2", { className: "text-base font-semibold text-brand-dark", children: title }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm text-slate-500", children: description })
          ] }),
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-center gap-2", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx(Tag, { tone: "slate", children: policies.length }),
            open ? /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniChevronUp, { className: "h-4 w-4 text-slate-400", "aria-hidden": "true" }) : /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniChevronDown, { className: "h-4 w-4 text-slate-400", "aria-hidden": "true" })
          ] })
        ]
      }
    ),
    open ? /* @__PURE__ */ jsxRuntimeExports.jsx(
      PolicyRuleList,
      {
        policies,
        cloudControlsUrl,
        onClearPolicy,
        emptyTitle,
        emptyBody
      }
    ) : null
  ] });
}
function resolveFamilyFilterLabel(family) {
  switch (family) {
    case "package-request":
      return "Package installs";
    case "tool-action":
      return "Commands";
    case "tool-output":
      return "Output";
    case "prompt":
      return "Prompts";
    default:
      return family.replace(/-/g, " ");
  }
}
function groupPoliciesByFamily(policies) {
  const counts = /* @__PURE__ */ new Map();
  for (const policy of policies) {
    const family = resolvePolicyMatcherFamily(policy) ?? "other";
    counts.set(family, (counts.get(family) ?? 0) + 1);
  }
  return counts;
}
function resolvePolicyViewLabel(view) {
  if (view === "rules") {
    return "Remembered rules";
  }
  if (view === "exceptions") {
    return "Exceptions";
  }
  return "Strict config";
}
function PolicyWorkspace({
  policies,
  snapshot,
  onClearPolicy,
  onOpenSettings,
  onOpenInbox,
  onRefreshPolicies
}) {
  const [activeView, setActiveView] = reactExports.useState("rules");
  const [searchQuery, setSearchQuery] = reactExports.useState("");
  const [appFilter, setAppFilter] = reactExports.useState("");
  const [familyFilter, setFamilyFilter] = reactExports.useState("");
  const [showExceptionForm, setShowExceptionForm] = reactExports.useState(false);
  const handleSearchChange = reactExports.useCallback((event) => {
    setSearchQuery(event.target.value);
  }, []);
  const handleViewChange = reactExports.useCallback((view) => {
    setActiveView(view);
    setShowExceptionForm(false);
  }, []);
  const handleOpenExceptionForm = reactExports.useCallback(() => {
    setShowExceptionForm(true);
  }, []);
  const handleCloseExceptionForm = reactExports.useCallback(() => {
    setShowExceptionForm(false);
  }, []);
  const handleExceptionSaved = reactExports.useCallback(() => {
    setShowExceptionForm(false);
    onRefreshPolicies?.();
  }, [onRefreshPolicies]);
  const modeCopy = reactExports.useMemo(() => resolveSecurityModeCopy(snapshot.security_level), [snapshot.security_level]);
  const cloudControlsUrl = reactExports.useMemo(() => resolveCloudPolicyControlsUrl(snapshot), [snapshot]);
  const cloudBundleCopy = reactExports.useMemo(() => resolveCloudPolicyBundleCopy(snapshot), [snapshot]);
  const filteredPolicies = reactExports.useMemo(() => {
    const query = searchQuery.trim().toLowerCase();
    return policies.filter((policy) => {
      if (appFilter && policy.harness !== appFilter) {
        return false;
      }
      if (familyFilter) {
        const family = resolvePolicyMatcherFamily(policy) ?? "other";
        if (family !== familyFilter) {
          return false;
        }
      }
      if (!query) {
        return true;
      }
      const display = resolvePolicyDisplay(policy);
      const displayHaystack = [
        policy.harness,
        policy.artifact_id,
        policy.workspace,
        policy.publisher,
        policy.scope,
        policy.action,
        policy.reason,
        display.headline,
        display.subtitle,
        harnessDisplayName(policy.harness),
        policyActionLabel(policy.action)
      ].filter(Boolean).join(" ").toLowerCase();
      return displayHaystack.includes(query);
    });
  }, [policies, searchQuery, appFilter, familyFilter]);
  const rememberedRules = reactExports.useMemo(
    () => filteredPolicies.filter((policy) => policy.action === "allow" || policy.action === "block").sort((a, b) => new Date(b.updated_at || 0).getTime() - new Date(a.updated_at || 0).getTime()),
    [filteredPolicies]
  );
  const localRules = reactExports.useMemo(
    () => rememberedRules.filter((policy) => !isCloudManagedPolicy(policy.source)),
    [rememberedRules]
  );
  const cloudRules = reactExports.useMemo(
    () => rememberedRules.filter((policy) => isCloudManagedPolicy(policy.source)),
    [rememberedRules]
  );
  const exceptionPolicies = reactExports.useMemo(
    () => filteredPolicies.filter((policy) => policy.action !== "allow" && policy.action !== "block").sort((a, b) => new Date(b.updated_at || 0).getTime() - new Date(a.updated_at || 0).getTime()),
    [filteredPolicies]
  );
  const appOptions = reactExports.useMemo(
    () => [...new Set(policies.map((policy) => policy.harness).filter(Boolean))].sort(),
    [policies]
  );
  const familyCounts = reactExports.useMemo(() => groupPoliciesByFamily(rememberedRules), [rememberedRules]);
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "space-y-6", children: [
    cloudBundleCopy ? /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: resolveCloudBundleSurfaceClass(cloudBundleCopy.tone), children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mb-2 flex flex-wrap items-center gap-2", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(SectionLabel, { children: "Guard Cloud bundle" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx(Tag, { tone: cloudBundleCopy.tone, children: cloudBundleCopy.label })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm text-brand-dark/75", children: cloudBundleCopy.detail })
    ] }) : null,
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "rounded-2xl border border-brand-blue/10 bg-brand-blue/[0.03] p-5 shadow-sm", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mb-2 flex flex-wrap items-center gap-2", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(SectionLabel, { children: "Active mode" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx(Tag, { tone: modeCopy.tone, children: modeCopy.label })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm text-brand-dark/75", children: modeCopy.description }),
      onOpenSettings ? /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-3", children: /* @__PURE__ */ jsxRuntimeExports.jsx(ActionButton, { variant: "secondary", onClick: onOpenSettings, children: "Open security settings" }) }) : null
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "flex flex-wrap gap-2 border-b border-slate-100 pb-3", children: ["rules", "exceptions", "strict"].map((view) => /* @__PURE__ */ jsxRuntimeExports.jsx(
      "button",
      {
        type: "button",
        onClick: () => handleViewChange(view),
        "aria-pressed": activeView === view,
        className: `rounded-full px-4 py-1.5 text-sm font-medium transition-colors focus:outline-none focus:ring-2 focus:ring-brand-blue/30 ${activeView === view ? "bg-brand-blue text-white" : "border border-slate-200 bg-white text-slate-600 hover:bg-slate-50"}`,
        children: resolvePolicyViewLabel(view)
      },
      view
    )) }),
    activeView === "rules" ? /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "space-y-4", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-col gap-3 lg:flex-row lg:items-center lg:justify-between", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-1 items-center gap-1.5 rounded-xl border border-slate-200 bg-white px-3 py-2", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniMagnifyingGlass, { className: "h-4 w-4 shrink-0 text-slate-400", "aria-hidden": "true" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx(
            "input",
            {
              type: "search",
              placeholder: "Search by app, action, or reason…",
              value: searchQuery,
              onChange: handleSearchChange,
              "aria-label": "Search policies",
              className: "w-full bg-transparent text-sm text-brand-dark placeholder:text-slate-400 focus:outline-none"
            }
          )
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap gap-2", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsxs(
            "select",
            {
              value: appFilter,
              onChange: (event) => setAppFilter(event.target.value),
              "aria-label": "Filter by app",
              className: "rounded-xl border border-slate-200 bg-white px-3 py-2 text-sm text-brand-dark",
              children: [
                /* @__PURE__ */ jsxRuntimeExports.jsx("option", { value: "", children: "All apps" }),
                appOptions.map((app) => /* @__PURE__ */ jsxRuntimeExports.jsx("option", { value: app, children: harnessDisplayName(app) }, app))
              ]
            }
          ),
          /* @__PURE__ */ jsxRuntimeExports.jsxs(
            "select",
            {
              value: familyFilter,
              onChange: (event) => setFamilyFilter(event.target.value),
              "aria-label": "Filter by action type",
              className: "rounded-xl border border-slate-200 bg-white px-3 py-2 text-sm text-brand-dark",
              children: [
                /* @__PURE__ */ jsxRuntimeExports.jsx("option", { value: "", children: "All action types" }),
                [...familyCounts.entries()].map(([family, count]) => /* @__PURE__ */ jsxRuntimeExports.jsxs("option", { value: family, children: [
                  resolveFamilyFilterLabel(family),
                  " (",
                  count,
                  ")"
                ] }, family))
              ]
            }
          )
        ] })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsx(
        GroupedPolicySection,
        {
          title: "Remembered on this device",
          description: "Choices you saved from Inbox. Each card explains what Guard will do next time.",
          policies: localRules,
          cloudControlsUrl,
          onClearPolicy,
          emptyTitle: "No local remembered rules yet",
          emptyBody: "Approve or block in Inbox and Guard remembers the decision here in plain language.",
          defaultOpen: true
        }
      ),
      /* @__PURE__ */ jsxRuntimeExports.jsx(
        GroupedPolicySection,
        {
          title: "From Guard Cloud",
          description: "Synced team rules are read-only here. Edit them in Guard Cloud Controls.",
          policies: cloudRules,
          cloudControlsUrl,
          emptyTitle: "No Guard Cloud rules synced",
          emptyBody: "Connect Guard Cloud to sync shared policy bundles.",
          defaultOpen: cloudRules.length > 0
        }
      )
    ] }) : null,
    activeView === "exceptions" ? /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "space-y-4", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap items-center justify-between gap-3", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm text-slate-600", children: "Exceptions change how Guard responds (warn, require review, block, or allow) without waiting for Inbox." }),
        !showExceptionForm ? /* @__PURE__ */ jsxRuntimeExports.jsxs(ActionButton, { variant: "primary", onClick: handleOpenExceptionForm, children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniPlus, { className: "mr-1.5 h-4 w-4", "aria-hidden": "true" }),
          "New exception"
        ] }) : null
      ] }),
      showExceptionForm ? /* @__PURE__ */ jsxRuntimeExports.jsx(
        PolicyExceptionForm,
        {
          policies,
          onSaved: handleExceptionSaved,
          onCancel: handleCloseExceptionForm
        }
      ) : null,
      exceptionPolicies.length === 0 && !showExceptionForm ? /* @__PURE__ */ jsxRuntimeExports.jsx(
        EmptyState,
        {
          title: "No exceptions yet",
          body: "Create one when you want Guard to warn, always review, block, or allow a whole class of actions.",
          tone: "teach"
        }
      ) : /* @__PURE__ */ jsxRuntimeExports.jsx(
        PolicyRuleList,
        {
          policies: exceptionPolicies,
          cloudControlsUrl,
          onClearPolicy,
          emptyTitle: "No active exceptions",
          emptyBody: "Saved warn, review, and custom rules appear here."
        }
      ),
      cloudControlsUrl ? /* @__PURE__ */ jsxRuntimeExports.jsxs(
        "a",
        {
          href: cloudControlsUrl,
          target: "_blank",
          rel: "noopener noreferrer",
          className: "inline-flex items-center gap-1 text-sm font-medium text-brand-blue hover:underline",
          children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniCloudArrowUp, { className: "h-4 w-4", "aria-hidden": "true" }),
            "Manage team exceptions in Guard Cloud"
          ]
        }
      ) : null
    ] }) : null,
    activeView === "strict" ? /* @__PURE__ */ jsxRuntimeExports.jsx(StrictModeView, { snapshot, onOpenSettings, onOpenInbox }) : null
  ] });
}
function StrictModeView({
  snapshot,
  onOpenSettings,
  onOpenInbox
}) {
  const isStrict = snapshot.security_level === "strict";
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "space-y-4", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: `rounded-2xl border p-5 ${isStrict ? "border-brand-green/20 bg-brand-green/[0.04]" : "border-slate-200 bg-slate-50/40"}`, children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mb-2 flex items-center gap-2", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(SectionLabel, { children: "Strict mode" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx(Tag, { tone: isStrict ? "green" : "slate", children: isStrict ? "Enabled" : "Disabled" })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mb-4 text-sm text-brand-dark/75", children: "Strict mode asks before new network connections, subprocess launches, file writes, and harness starts." }),
      !isStrict && onOpenSettings ? /* @__PURE__ */ jsxRuntimeExports.jsx(ActionButton, { variant: "secondary", onClick: onOpenSettings, children: "Enable strict mode" }) : null
    ] }),
    onOpenInbox ? /* @__PURE__ */ jsxRuntimeExports.jsx(ActionButton, { variant: "secondary", onClick: onOpenInbox, children: "Review pending Inbox items" }) : null
  ] });
}
export {
  PolicyWorkspace,
  groupPoliciesByHarness,
  resolveCloudPolicyBundleCopy,
  resolveSecurityModeCopy
};
