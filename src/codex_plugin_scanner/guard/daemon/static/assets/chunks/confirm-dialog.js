import { r as reactExports, j as jsxRuntimeExports, b4 as GuardModalLayer, P as HiMiniExclamationTriangle, a3 as HiMiniWrenchScrewdriver } from "../guard-dashboard.js";
function ConfirmDialogPanel(props) {
  const tone = props.tone ?? "default";
  const destructive = tone === "destructive";
  const cancelLabel = props.cancelLabel ?? "Cancel";
  const ToneIcon = destructive ? HiMiniExclamationTriangle : HiMiniWrenchScrewdriver;
  const confirmButton = /* @__PURE__ */ jsxRuntimeExports.jsx(
    "button",
    {
      type: "button",
      autoFocus: !destructive,
      onClick: props.onConfirm,
      className: `inline-flex min-h-11 items-center rounded-lg px-4 text-sm font-semibold text-white transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand-blue/40 focus-visible:ring-offset-2 ${destructive ? "bg-brand-attention hover:bg-brand-attention/90" : "bg-brand-blue hover:bg-brand-blue/90"}`,
      children: props.confirmLabel
    }
  );
  const cancelButton = /* @__PURE__ */ jsxRuntimeExports.jsx(
    "button",
    {
      type: "button",
      autoFocus: destructive,
      onClick: props.onCancel,
      className: "inline-flex min-h-11 items-center rounded-lg border border-slate-200 bg-white px-4 text-sm font-medium text-brand-dark transition-colors hover:bg-slate-50 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand-blue/40 focus-visible:ring-offset-2",
      children: cancelLabel
    }
  );
  return /* @__PURE__ */ jsxRuntimeExports.jsxs(
    "div",
    {
      className: `rounded-2xl border bg-white p-6 shadow-xl ${destructive ? "border-brand-attention/15" : "border-brand-blue/15"}`,
      children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-start gap-3", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx(
            "span",
            {
              className: `inline-flex h-10 w-10 shrink-0 items-center justify-center rounded-full ${destructive ? "bg-brand-attention/10" : "bg-brand-blue/10"}`,
              children: /* @__PURE__ */ jsxRuntimeExports.jsx(
                ToneIcon,
                {
                  className: `h-5 w-5 ${destructive ? "text-brand-attention" : "text-brand-blue"}`,
                  "aria-hidden": "true"
                }
              )
            }
          ),
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("h3", { className: "text-base font-semibold text-brand-dark", children: props.title }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("p", { id: props.descriptionId, className: "mt-2 text-sm text-slate-500", children: props.description })
          ] })
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-6 flex flex-wrap gap-2", children: destructive ? /* @__PURE__ */ jsxRuntimeExports.jsxs(jsxRuntimeExports.Fragment, { children: [
          cancelButton,
          confirmButton
        ] }) : /* @__PURE__ */ jsxRuntimeExports.jsxs(jsxRuntimeExports.Fragment, { children: [
          confirmButton,
          cancelButton
        ] }) })
      ]
    }
  );
}
function ConfirmDialog(props) {
  const descriptionId = reactExports.useId();
  return /* @__PURE__ */ jsxRuntimeExports.jsx(
    GuardModalLayer,
    {
      ariaLabel: props.title,
      ariaDescribedBy: descriptionId,
      onClose: props.onCancel,
      panelClassName: "w-full max-w-sm",
      children: /* @__PURE__ */ jsxRuntimeExports.jsx(ConfirmDialogPanel, { ...props, descriptionId })
    }
  );
}
function useConfirmDialog() {
  const [pending, setPending] = reactExports.useState(null);
  const pendingRef = reactExports.useRef(null);
  const confirm = reactExports.useCallback((options) => {
    return new Promise((resolve) => {
      pendingRef.current?.resolve(false);
      const next = { options, resolve };
      pendingRef.current = next;
      setPending(next);
    });
  }, []);
  const settle = reactExports.useCallback((value) => {
    pendingRef.current?.resolve(value);
    pendingRef.current = null;
    setPending(null);
  }, []);
  reactExports.useEffect(() => {
    return () => {
      pendingRef.current?.resolve(false);
    };
  }, []);
  const dialog = pending !== null ? /* @__PURE__ */ jsxRuntimeExports.jsx(
    ConfirmDialog,
    {
      ...pending.options,
      onConfirm: () => settle(true),
      onCancel: () => settle(false)
    }
  ) : null;
  return { confirm, dialog };
}
export {
  useConfirmDialog as u
};
