import { r as reactExports, ck as fetchResolvedApprovalGate, j as jsxRuntimeExports } from "../guard-dashboard.js";
import { A as ApprovalProofModal } from "./approval-proof-modal.js";
import { b as fetchEffectiveExtensionControls, r as recoverExtensionControlAuthority, E as ExtensionControlApiError } from "./extension-controls-api.js";
const PROTECTION_REPAIR_ROUTE = "/protection/repair";
const REPAIRABLE_HEALTH = /* @__PURE__ */ new Set(["tampered", "recovery-required"]);
function protectionRepairView(health, gateReady) {
  if (health === "protected") {
    return {
      title: "Trusted settings are protected",
      body: "Trusted settings pass their integrity check. Retry the blocked action. If it still fails, open Home to check Guard.",
      action: "home",
      actionLabel: "Back to Home"
    };
  }
  if (REPAIRABLE_HEALTH.has(health)) {
    if (!gateReady) {
      return {
        title: "Trusted protection needs repair",
        body: "Trusted protection settings need repair, and local approval is not set up yet. Set up approval, then return here and press Repair protection.",
        action: "setup",
        actionLabel: "Set up approval"
      };
    }
    return {
      title: "Trusted protection needs repair",
      body: "Trusted protection settings need repair before this action can run. Press Repair protection, approve it, then retry the blocked action.",
      action: "repair",
      actionLabel: "Repair protection"
    };
  }
  return {
    title: "Protection does not need this repair",
    body: "This page rebuilds trusted protection settings after they fail a check. Open Extensions to see the current state.",
    action: "extensions",
    actionLabel: "Open Extensions"
  };
}
function repairFailureMessage(error) {
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
function ProtectionRepairPage(props) {
  const [page, setPage] = reactExports.useState({ kind: "loading" });
  const [proofOpen, setProofOpen] = reactExports.useState(false);
  const [busy, setBusy] = reactExports.useState(false);
  const [error, setError] = reactExports.useState(null);
  const load = reactExports.useCallback(async () => {
    setPage({ kind: "loading" });
    setError(null);
    try {
      const [effective, gate] = await Promise.all([
        fetchEffectiveExtensionControls(),
        fetchResolvedApprovalGate()
      ]);
      setPage({
        kind: "ready",
        health: effective.health,
        gateReady: Boolean(gate?.configured && gate.enabled),
        approvalGate: gate
      });
    } catch {
      setPage({ kind: "error" });
    }
  }, []);
  reactExports.useEffect(() => {
    void load();
  }, [load]);
  const confirmRepair = reactExports.useCallback(async (credentials) => {
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
        approvalGate: page.kind === "ready" ? page.approvalGate : null
      });
    } catch (caught) {
      setError(repairFailureMessage(caught));
    } finally {
      setBusy(false);
    }
  }, [page]);
  if (page.kind === "loading") {
    return /* @__PURE__ */ jsxRuntimeExports.jsxs("section", { className: "mx-auto w-full max-w-prose pt-6", "aria-busy": "true", "aria-labelledby": "protection-repair-heading", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("h1", { id: "protection-repair-heading", className: "text-2xl font-semibold text-brand-dark", children: "Repair protection" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-3 text-base leading-7 text-brand-dark/80", children: "Checking protection status." })
    ] });
  }
  if (page.kind === "error") {
    return /* @__PURE__ */ jsxRuntimeExports.jsxs("section", { className: "mx-auto w-full max-w-prose pt-6", "aria-labelledby": "protection-repair-heading", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("h1", { id: "protection-repair-heading", className: "text-2xl font-semibold text-brand-dark", children: "Repair protection" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-3 max-w-prose text-base leading-7 text-brand-dark/80", children: "HOL Guard could not load protection status." }),
      /* @__PURE__ */ jsxRuntimeExports.jsx(
        "button",
        {
          type: "button",
          className: "mt-6 inline-flex min-h-11 w-full items-center justify-center rounded-xl bg-brand-blue px-4 text-sm font-semibold text-white hover:bg-brand-dark focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-brand-blue sm:w-auto",
          onClick: () => {
            void load();
          },
          children: "Try again"
        }
      )
    ] });
  }
  const view = protectionRepairView(page.health, page.gateReady);
  const buttonDisabled = busy;
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("section", { className: "mx-auto w-full max-w-prose pt-6", "aria-labelledby": "protection-repair-heading", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx("h1", { id: "protection-repair-heading", className: "text-2xl font-semibold text-balance text-brand-dark", children: view.title }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-3 max-w-prose text-base leading-7 text-brand-dark/80", children: view.body }),
    /* @__PURE__ */ jsxRuntimeExports.jsx(
      "button",
      {
        type: "button",
        className: "mt-6 inline-flex min-h-11 w-full items-center justify-center rounded-xl bg-brand-blue px-4 text-sm font-semibold text-white hover:bg-brand-dark focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-brand-blue disabled:cursor-not-allowed disabled:opacity-60 sm:w-auto",
        disabled: buttonDisabled,
        "aria-busy": busy,
        onClick: () => {
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
        },
        children: busy ? "Repairing…" : view.actionLabel
      }
    ),
    error ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { role: "alert", className: "mt-4 rounded-xl border border-red-200 bg-red-50 px-3 py-2 text-sm leading-6 text-red-800", children: error }) : null,
    proofOpen && view.action === "repair" ? /* @__PURE__ */ jsxRuntimeExports.jsx(
      ApprovalProofModal,
      {
        title: "Repair protection",
        detail: "Rebuilding the trusted settings needs your approval password. Guard verifies the repair before protection changes unlock again.",
        confirmLabel: "Repair protection",
        approvalGate: page.approvalGate,
        requireFreshTotp: page.approvalGate?.totp_enabled === true,
        busy,
        busyLabel: "Repairing…",
        error,
        onCancel: () => {
          if (!busy) setProofOpen(false);
        },
        onConfirm: (credentials) => {
          void confirmRepair(credentials);
        }
      }
    ) : null
  ] });
}
export {
  PROTECTION_REPAIR_ROUTE,
  ProtectionRepairPage,
  protectionRepairView
};
