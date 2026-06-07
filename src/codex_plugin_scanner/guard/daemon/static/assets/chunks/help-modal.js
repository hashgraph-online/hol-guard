import { r as reactExports, j as jsxRuntimeExports, an as HiMiniCommandLine, q as HiMiniXMark, t as HiMiniQuestionMarkCircle } from "../guard-dashboard.js";
import { u as useFocusTrap } from "./use-focus-trap.js";
const shortcuts = [
  {
    title: "Review",
    items: [
      { keys: ["A"], description: "Allow the current action" },
      { keys: ["B"], description: "Block the current action" },
      { keys: ["↑", "↓"], description: "Navigate queue items" },
      { keys: ["Enter"], description: "Open selected queue item" },
      { keys: ["1"], description: "Select 'Just this time' scope" },
      { keys: ["2"], description: "Select 'This project' scope" },
      { keys: ["3"], description: "Select 'This source' scope" },
      { keys: ["4"], description: "Select 'This app' scope" },
      { keys: ["5"], description: "Select 'Everywhere' scope" }
    ]
  },
  {
    title: "History",
    items: [
      { keys: ["f"], description: "Focus search" },
      { keys: ["e"], description: "Export current view" },
      { keys: ["g"], description: "Toggle grouping" },
      { keys: ["t"], description: "Toggle time range" }
    ]
  },
  {
    title: "Navigation",
    items: [
      { keys: ["/"], description: "Focus search input" },
      { keys: ["?"], description: "Open this help" },
      { keys: ["Esc"], description: "Close modal or drawer" }
    ]
  }
];
function HelpModal(props) {
  const dialogRef = reactExports.useRef(null);
  useFocusTrap(props.open, dialogRef);
  reactExports.useEffect(() => {
    if (!props.open) return;
    function handleKeyDown(event) {
      if (event.key === "Escape") {
        event.preventDefault();
        props.onClose();
      }
    }
    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [props.open, props.onClose]);
  const handleBackdropClick = reactExports.useCallback(
    (e) => {
      if (e.target === e.currentTarget) props.onClose();
    },
    [props.onClose]
  );
  if (!props.open) return null;
  return /* @__PURE__ */ jsxRuntimeExports.jsx(
    "div",
    {
      className: "guard-fade-in fixed inset-0 z-50 flex items-center justify-center bg-black/30 p-4 backdrop-blur-sm",
      onClick: handleBackdropClick,
      role: "dialog",
      "aria-modal": "true",
      "aria-label": "Keyboard shortcuts help",
      children: /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { ref: dialogRef, className: "guard-fade-in w-full max-w-lg rounded-2xl border border-slate-200/70 bg-white/95 p-6 shadow-2xl", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-center justify-between", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-center gap-2.5", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniCommandLine, { className: "h-5 w-5 text-brand-blue", "aria-hidden": "true" }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("h2", { className: "text-lg font-semibold tracking-tight text-brand-dark", children: "Keyboard shortcuts" })
          ] }),
          /* @__PURE__ */ jsxRuntimeExports.jsx(
            "button",
            {
              type: "button",
              onClick: props.onClose,
              "aria-label": "Close help",
              className: "rounded-full p-1.5 text-slate-400 transition-colors hover:bg-slate-100 hover:text-brand-dark",
              children: /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniXMark, { className: "h-5 w-5", "aria-hidden": "true" })
            }
          )
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-2 text-sm text-muted-foreground", children: "Use these shortcuts to review actions faster. Shortcuts work when you are not typing in a text field." }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-5 space-y-5", children: shortcuts.map((group) => /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "font-mono text-[10px] font-semibold uppercase tracking-[0.22em] text-muted-foreground", children: group.title }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-2 space-y-2", children: group.items.map((item) => /* @__PURE__ */ jsxRuntimeExports.jsxs(
            "div",
            {
              className: "flex items-center justify-between gap-3",
              children: [
                /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-sm text-brand-dark", children: item.description }),
                /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "flex shrink-0 gap-1", children: item.keys.map((key) => /* @__PURE__ */ jsxRuntimeExports.jsx(
                  "kbd",
                  {
                    className: "inline-flex h-7 min-w-7 items-center justify-center rounded-md border border-slate-200 bg-slate-50 px-1.5 font-mono text-[11px] font-semibold text-brand-dark shadow-sm",
                    children: key
                  },
                  key
                )) })
              ]
            },
            item.description
          )) })
        ] }, group.title)) }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-6 flex items-center gap-2 rounded-xl border border-brand-blue/15 bg-brand-blue/[0.04] px-4 py-3", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniQuestionMarkCircle, { className: "h-4 w-4 shrink-0 text-brand-blue", "aria-hidden": "true" }),
          /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "text-xs text-muted-foreground", children: [
            "Press ",
            /* @__PURE__ */ jsxRuntimeExports.jsx("kbd", { className: "rounded bg-slate-100 px-1 py-0.5 font-mono text-[10px]", children: "?" }),
            " anytime to open this help."
          ] })
        ] })
      ] })
    }
  );
}
export {
  HelpModal
};
