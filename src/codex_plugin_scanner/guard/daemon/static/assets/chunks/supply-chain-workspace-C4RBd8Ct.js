import { j as jsxRuntimeExports, r as reactExports, A as ActionButton, s as HiMiniCheckCircle, c as HiMiniChevronDown, ab as HiMiniExclamationCircle } from "../guard-dashboard.js";
import { r as resolveSupplyChainIssues } from "./supply-chain-issues-DeC2Wyty.js";
import { r as resolveHomeProtectionStatus } from "./home-protection-module-Du65PsUR.js";
import { b as buildSupplyChainStats } from "./supply-chain-protection-stats-CJkxdP0r.js";
import { B as BrandHero, b as BrandHeroBadge, a as BrandHeroFacts } from "./brand-hero-CPRrEfls.js";
import { s as supplyChainFixAllIsPending, a as supplyChainFixAllNeedsCloudConnect, b as supplyChainFixAllButtonLabel } from "./supply-chain-hub-workspace-BuT7YuDN.js";
import "./feed-health-workspace-Bb4acrba.js";
const PROTECTION_BADGE = {
  protected: "Protected",
  partial: "Partly protected",
  staged: "Restart to finish",
  unprotected: "Not protected",
  unknown: "Checking"
};
function protectionLiveLabel(status, stats) {
  if (status === "protected") {
    return `Guarding ${stats.protectedManagers} tool${stats.protectedManagers === 1 ? "" : "s"}`;
  }
  if (status === "staged") {
    return "Restart pending";
  }
  if (status === "partial" || status === "unprotected") {
    const open = stats.unprotectedManagers + stats.repairRequiredManagers;
    return `${open} unprotected`;
  }
  return "Checking";
}
function protectionTitle(status) {
  if (status === "protected") {
    return "Package installs are protected on this device";
  }
  if (status === "partial") {
    return "Protection is only partly set up";
  }
  if (status === "staged") {
    return "Finish setup in a new terminal";
  }
  if (status === "unprotected") {
    return "Package installs are not protected yet";
  }
  return "Checking package protection on this device";
}
function protectionDetail(snapshot, status) {
  const protection = snapshot.supply_chain?.package_manager_protection;
  if (status === "protected" && protection) {
    return `${protection.protected_managers.length} package tool${protection.protected_managers.length === 1 ? "" : "s"} active. Guard can block risky installs before they run.`;
  }
  if (status === "partial" && protection) {
    return `${protection.unprotected_managers.length} tool${protection.unprotected_managers.length === 1 ? "" : "s"} still open: ${protection.unprotected_managers.join(", ")}.`;
  }
  if (status === "staged") {
    return "Guard saved your shell setup. Open a new terminal or restart AI apps so the updated PATH takes effect, then refresh status here.";
  }
  if (status === "unprotected") {
    return "Turn on protection for npm, pip, and other tools in the firewall panel below.";
  }
  return "Refresh status after installing package tools on this machine.";
}
function protectionTone(status) {
  if (status === "protected") {
    return "green";
  }
  if (status === "staged") {
    return "blue";
  }
  if (status === "partial" || status === "unprotected") {
    return "attention";
  }
  return "slate";
}
function cloudLabel(snapshot) {
  const label = snapshot.cloud_state_label ?? "";
  if (snapshot.cloud_state === "paired_active") {
    return label.trim().length > 0 ? label : "Guard Cloud connected";
  }
  if (snapshot.cloud_state === "paired_waiting") {
    return label.trim().length > 0 ? label : "Pairing in progress";
  }
  return label.trim().length > 0 ? label : "On this device only";
}
function resolveSupplyChainWorkspaceHero(snapshot, options) {
  const protectionStatus = resolveHomeProtectionStatus(snapshot);
  const stats = buildSupplyChainStats(snapshot);
  const preventedLabel = stats.preventedInstalls > 0 ? `${stats.preventedInstalls} blocked install${stats.preventedInstalls === 1 ? "" : "s"}` : "No blocked installs yet";
  const stagedGuidance = protectionStatus === "staged" ? protectionDetail(snapshot, protectionStatus) : null;
  const openManagers = stats.unprotectedManagers + stats.repairRequiredManagers;
  const facts = [
    `${stats.protectedManagers} tool${stats.protectedManagers === 1 ? "" : "s"} protected`,
    openManagers > 0 ? `${openManagers} tool${openManagers === 1 ? "" : "s"} unprotected` : null,
    preventedLabel,
    cloudLabel(snapshot)
  ].filter((fact) => fact !== null);
  const openIssueCount = options?.openIssueCount ?? 0;
  if (openIssueCount > 0) {
    const issueSummary = `${openIssueCount} setup step${openIssueCount === 1 ? "" : "s"} ${openIssueCount === 1 ? "needs" : "need"} attention on this device.`;
    return {
      cloudMode: snapshot.cloud_state,
      cloudLabel: cloudLabel(snapshot),
      protectionStatus,
      title: "Work through the steps below",
      detail: stagedGuidance ? `${issueSummary} ${stagedGuidance}` : issueSummary,
      stagedGuidance,
      tone: protectionTone(protectionStatus),
      statLine: `${stats.protectedManagers} protected · ${stats.unprotectedManagers} open · ${preventedLabel}`,
      badge: "Needs repair",
      liveLabel: `${openIssueCount} to fix`,
      facts
    };
  }
  return {
    cloudMode: snapshot.cloud_state,
    cloudLabel: cloudLabel(snapshot),
    protectionStatus,
    title: protectionTitle(protectionStatus),
    detail: protectionDetail(snapshot, protectionStatus),
    stagedGuidance,
    tone: protectionTone(protectionStatus),
    statLine: `${stats.protectedManagers} protected · ${stats.unprotectedManagers} open · ${preventedLabel}`,
    badge: PROTECTION_BADGE[protectionStatus],
    liveLabel: protectionLiveLabel(protectionStatus, stats),
    facts
  };
}
function supplyChainBrandTone(tone) {
  if (tone === "green") return "clear";
  if (tone === "attention") return "review";
  return "setup";
}
function SupplyChainWorkspaceHero({ hero }) {
  const tone = supplyChainBrandTone(hero.tone);
  return /* @__PURE__ */ jsxRuntimeExports.jsxs(
    BrandHero,
    {
      tone,
      liveLabel: hero.liveLabel,
      ariaLabel: "Supply chain protection status",
      testId: "supply-chain-workspace-hero",
      markOnSmall: "inline",
      compact: true,
      children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(BrandHeroBadge, { tone, children: hero.badge }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "max-w-2xl", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("h2", { className: "guard-hero-title text-2xl font-semibold tracking-tight text-white sm:text-3xl", children: hero.title }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-3 max-w-xl text-[15px] leading-relaxed text-white/80", children: hero.detail })
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsx(BrandHeroFacts, { facts: hero.facts })
      ]
    }
  );
}
function recoverySummary(issueCount) {
  return `${issueCount} issue${issueCount === 1 ? "" : "s"} to resolve. Check Cloud access, approve device changes once, then restore package protection.`;
}
function SupplyChainRecovery({
  issues,
  state,
  onFixAll,
  guidance = null,
  facts = []
}) {
  const [detailsOpen, setDetailsOpen] = reactExports.useState(false);
  const handleDetailsToggle = reactExports.useCallback(() => {
    setDetailsOpen((open) => !open);
  }, []);
  const pending = supplyChainFixAllIsPending(state.phase);
  const showResult = state.message !== null;
  const remainingSteps = state.remainingSteps ?? [];
  const failures = [...new Set(state.failedSteps)].filter((message) => message !== state.message);
  const needsCloudConnect = supplyChainFixAllNeedsCloudConnect(state);
  const isHardFailure = state.phase === "error" || state.phase === "incomplete" && state.failedSteps.length > 0;
  const buttonLabel = supplyChainFixAllButtonLabel(
    state.phase,
    state.remainingAction ?? null,
    state.failedSteps.length
  );
  return /* @__PURE__ */ jsxRuntimeExports.jsxs(
    BrandHero,
    {
      tone: "review",
      liveLabel: `${issues.length} to fix`,
      ariaLabel: "Supply-chain recovery",
      testId: "supply-chain-recovery",
      markOnSmall: "inline",
      compact: true,
      children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(BrandHeroBadge, { tone: "review", children: "Needs repair" }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "max-w-2xl", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("h2", { className: "guard-hero-title text-2xl font-semibold tracking-tight text-white sm:text-3xl", children: "Restore supply-chain protection" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-3 max-w-xl text-[15px] leading-relaxed text-white/80", children: recoverySummary(issues.length) }),
          guidance ? /* @__PURE__ */ jsxRuntimeExports.jsx(
            "p",
            {
              className: "mt-2 max-w-xl text-sm font-medium text-white",
              "data-testid": "supply-chain-restart-guidance",
              children: guidance
            }
          ) : null
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "guard-hero-ctas flex flex-wrap gap-3", children: /* @__PURE__ */ jsxRuntimeExports.jsx(ActionButton, { onClick: onFixAll, disabled: pending, "aria-busy": pending, "data-primary": "true", children: buttonLabel }) }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: showResult ? void 0 : "!mt-0", "aria-live": "polite", children: showResult ? /* @__PURE__ */ jsxRuntimeExports.jsxs(jsxRuntimeExports.Fragment, { children: [
          /* @__PURE__ */ jsxRuntimeExports.jsxs(
            "p",
            {
              className: `flex items-start gap-2 text-sm ${isHardFailure ? "text-[#fecaca]" : "text-white/80"}`,
              children: [
                state.phase === "success" || needsCloudConnect ? /* @__PURE__ */ jsxRuntimeExports.jsx(
                  HiMiniCheckCircle,
                  {
                    className: "mt-0.5 h-4 w-4 shrink-0 text-brand-green",
                    "aria-hidden": "true"
                  }
                ) : null,
                state.message
              ]
            }
          ),
          failures.length > 0 ? /* @__PURE__ */ jsxRuntimeExports.jsx("ul", { className: "mt-2 space-y-1 text-xs text-[#fecaca]", children: failures.map((failure, index) => /* @__PURE__ */ jsxRuntimeExports.jsx("li", { children: failure }, `failed:${index}:${failure}`)) }) : null,
          state.phase === "access_required" ? /* @__PURE__ */ jsxRuntimeExports.jsx("a", { className: "mt-2 inline-block text-sm font-medium text-white underline underline-offset-4 focus-visible:outline focus-visible:outline-2 focus-visible:outline-white", href: "https://hol.org/guard/pricing", target: "_blank", rel: "noopener noreferrer", children: "Review Cloud plan" }) : null,
          remainingSteps.length > 0 ? /* @__PURE__ */ jsxRuntimeExports.jsx("ul", { className: "mt-2 space-y-1 text-xs font-medium text-white", children: remainingSteps.map((remaining, index) => /* @__PURE__ */ jsxRuntimeExports.jsx("li", { children: remaining }, `remaining:${index}:${remaining}`)) }) : null
        ] }) : null }),
        /* @__PURE__ */ jsxRuntimeExports.jsx(BrandHeroFacts, { facts }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs(
          "button",
          {
            type: "button",
            onClick: handleDetailsToggle,
            "aria-expanded": detailsOpen,
            className: "-ml-1 inline-flex min-h-11 items-center gap-1 rounded-md px-1 text-sm font-medium text-white/85 hover:text-white hover:underline focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-white",
            children: [
              "View issue details",
              /* @__PURE__ */ jsxRuntimeExports.jsx(
                HiMiniChevronDown,
                {
                  className: `h-4 w-4 transition-transform ${detailsOpen ? "rotate-180" : ""}`,
                  "aria-hidden": "true"
                }
              )
            ]
          }
        ),
        detailsOpen ? /* @__PURE__ */ jsxRuntimeExports.jsx("ul", { className: "!mt-2 rounded-xl border border-white/15 bg-white/[0.06] px-3", children: issues.map((issue) => /* @__PURE__ */ jsxRuntimeExports.jsxs(
          "li",
          {
            className: "flex items-start gap-2 border-t border-white/10 py-3 first:border-t-0",
            children: [
              /* @__PURE__ */ jsxRuntimeExports.jsx(
                HiMiniExclamationCircle,
                {
                  className: "mt-0.5 h-3.5 w-3.5 shrink-0 text-[#ffd58a]",
                  "aria-hidden": "true"
                }
              ),
              /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { className: "text-sm text-white/80", children: [
                /* @__PURE__ */ jsxRuntimeExports.jsx("strong", { className: "block font-semibold text-white", children: issue.title }),
                issue.detail
              ] })
            ]
          },
          issue.id
        )) }) : null
      ]
    }
  );
}
function SupplyChainWorkspace({ snapshot, fixAllState, onFixAll }) {
  const supplyChainIssues = reactExports.useMemo(() => resolveSupplyChainIssues(snapshot), [snapshot]);
  const workspaceHero = reactExports.useMemo(
    () => resolveSupplyChainWorkspaceHero(snapshot, { openIssueCount: supplyChainIssues.length }),
    [snapshot, supplyChainIssues.length]
  );
  return supplyChainIssues.length > 0 ? /* @__PURE__ */ jsxRuntimeExports.jsx(
    SupplyChainRecovery,
    {
      issues: supplyChainIssues,
      state: fixAllState,
      onFixAll,
      guidance: workspaceHero.stagedGuidance,
      facts: workspaceHero.facts
    }
  ) : /* @__PURE__ */ jsxRuntimeExports.jsx(SupplyChainWorkspaceHero, { hero: workspaceHero });
}
export {
  SupplyChainWorkspace,
  buildSupplyChainStats
};
