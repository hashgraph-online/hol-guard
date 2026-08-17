import { r as reactExports, j as jsxRuntimeExports, K as HiMiniExclamationTriangle } from "../guard-dashboard.js";
const PROTECTION_POSTURE_COPY = {
  protected: {
    label: "Protected",
    help: "Stops theft, wipes, and Guard bypass. Asks once about new tools or first-time secret access, then remembers."
  },
  extra_careful: {
    label: "Extra careful",
    help: "Same as Protected, and also asks the first time this project talks to a new site or installs a new tool."
  },
  watch: {
    label: "Watch",
    help: "Records what Guard would have stopped, but does not stop anything. Use only while debugging."
  }
};
const WATCH_BANNER_COPY = "Protection is off. Guard is only recording.";
const POSTURE_OUTCOME_COLUMNS = {
  protected: {
    stops: "Credential theft, Guard bypass, encoded exfil, known-bad tools",
    asks: "First secret read, new destructive command, first package script, new MCP or skill",
    runs: "Remembered actions, routine browsing, verified-benign work"
  },
  extra_careful: {
    stops: "The same automatic stops as Protected",
    asks: "Everything Protected asks, plus first new site, first new tool, and cloud advisories",
    runs: "Remembered actions and verified-benign work"
  },
  watch: {
    stops: "Nothing. Guard only records.",
    asks: "Nothing. Inbox shows what would have stopped.",
    runs: "Every action, including known-bad work"
  }
};
function isProtectionPosture(value) {
  return value === "protected" || value === "extra_careful" || value === "watch";
}
function deriveProtectionPosture(mode, securityLevel) {
  if (mode === "observe") return "watch";
  if (securityLevel === "strict" || securityLevel === "paranoid") return "extra_careful";
  return "protected";
}
function WatchProtectionBanner(props) {
  const handleTurnOn = reactExports.useCallback(() => {
    props.onTurnProtectionOn?.();
  }, [props.onTurnProtectionOn]);
  return /* @__PURE__ */ jsxRuntimeExports.jsxs(
    "div",
    {
      className: "flex flex-col gap-3 rounded-xl border border-brand-attention/30 bg-brand-attention/[0.06] px-4 py-3 sm:flex-row sm:items-center sm:justify-between",
      role: "status",
      children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-start gap-3", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniExclamationTriangle, { className: "mt-0.5 h-5 w-5 shrink-0 text-brand-attention", "aria-hidden": "true" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm font-semibold text-brand-dark", children: WATCH_BANNER_COPY })
        ] }),
        props.onTurnProtectionOn ? /* @__PURE__ */ jsxRuntimeExports.jsx(
          "button",
          {
            type: "button",
            onClick: handleTurnOn,
            className: "inline-flex min-h-11 items-center justify-center rounded-lg bg-brand-attention px-4 text-sm font-semibold text-white",
            children: "Turn protection on"
          }
        ) : null
      ]
    }
  );
}
export {
  PROTECTION_POSTURE_COPY as P,
  WatchProtectionBanner as W,
  POSTURE_OUTCOME_COLUMNS as a,
  deriveProtectionPosture as d,
  isProtectionPosture as i
};
