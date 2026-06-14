import { j as jsxRuntimeExports, S as SectionLabel, o as HiMiniXMark, B as Badge, bd as scopeLabel, m as formatRelativeTime, b6 as HiMiniCloudArrowUp, r as reactExports, be as createCloudExceptionRequest, A as ActionButton, h as harnessDisplayName, b as EmptyState, p as HiMiniChevronUp, q as HiMiniChevronDown, ac as Tag, bf as policyActionLabel, bg as fetchCloudExceptions, bh as fetchCloudExceptionRequests, bb as guardAwareHref, ax as HiMiniTrash, ad as HiMiniMagnifyingGlass } from "../guard-dashboard.js";
const CLOUD_EXCEPTION_EXPIRING_SOON_DAYS = 7;
function parseCloudExceptionTimestamp(value) {
  if (!value || !value.trim()) {
    return null;
  }
  const normalized = value.replace("Z", "+00:00");
  const parsed = new Date(normalized);
  return Number.isNaN(parsed.getTime()) ? null : parsed;
}
function resolveCloudExceptionExpiryValue(item) {
  const expiry = item.expiry?.trim();
  if (expiry) {
    return expiry;
  }
  const legacyExpiry = item.expires_at?.trim();
  return legacyExpiry || null;
}
function resolveCloudExceptionExpiryTimestamp(item) {
  return parseCloudExceptionTimestamp(resolveCloudExceptionExpiryValue(item));
}
function isCloudExceptionActive(item, now = /* @__PURE__ */ new Date()) {
  const expiry = resolveCloudExceptionExpiryTimestamp(item);
  if (expiry === null) {
    return false;
  }
  return expiry.getTime() > now.getTime();
}
function isCloudExceptionExpiringSoon(item, now = /* @__PURE__ */ new Date(), withinDays = CLOUD_EXCEPTION_EXPIRING_SOON_DAYS) {
  if (!isCloudExceptionActive(item, now)) {
    return false;
  }
  const expiry = resolveCloudExceptionExpiryTimestamp(item);
  if (expiry === null) {
    return false;
  }
  const thresholdMs = now.getTime() + withinDays * 24 * 60 * 60 * 1e3;
  return expiry.getTime() <= thresholdMs;
}
function isCloudExceptionAckFailure(item) {
  return item.ack_status === "failed" || item.ack_status === "offline";
}
function resolveCloudExceptionScopeTarget(item) {
  if (typeof item.artifact_id === "string" && item.artifact_id.trim()) {
    return item.artifact_id.trim();
  }
  if (item.scope === "artifact" && item.id.startsWith("artifact:")) {
    return item.id.slice("artifact:".length);
  }
  if (typeof item.publisher === "string" && item.publisher.trim()) {
    return item.publisher.trim();
  }
  if (item.scope === "publisher" && item.id.startsWith("publisher:")) {
    return item.id.slice("publisher:".length);
  }
  if (item.harness) {
    return item.harness;
  }
  if (item.scope === "harness" && item.id.startsWith("harness:")) {
    return item.id.slice("harness:".length);
  }
  return item.id;
}
function resolveCloudExceptionHeadline(item) {
  const target = resolveCloudExceptionScopeTarget(item);
  if (item.scope === "artifact" && target) {
    return target;
  }
  if (item.scope === "publisher" && target) {
    return `Publisher ${target}`;
  }
  if (item.scope === "harness" && target) {
    return `${target} harness`;
  }
  if (item.scope === "workspace") {
    return "Workspace scope";
  }
  if (item.scope === "global") {
    return "Global risk acceptance";
  }
  return item.id;
}
function resolvePersonDisplayLabel(value) {
  if (!value || !value.trim()) {
    return "Unknown";
  }
  const trimmed = value.trim();
  if (trimmed.includes("@")) {
    const localPart = trimmed.split("@")[0] ?? trimmed;
    return localPart.replace(/[._-]+/g, " ").trim() || trimmed;
  }
  return trimmed;
}
function resolvePersonInitials(value) {
  const label = resolvePersonDisplayLabel(value);
  const parts = label.split(/\s+/).filter(Boolean);
  if (parts.length >= 2) {
    return `${parts[0]?.[0] ?? ""}${parts[1]?.[0] ?? ""}`.toUpperCase();
  }
  return label.slice(0, 2).toUpperCase();
}
function summarizeCloudExceptions(exceptions, pendingRequests, now = /* @__PURE__ */ new Date()) {
  const active = exceptions.filter((item) => isCloudExceptionActive(item, now));
  const expiringSoon = active.filter((item) => isCloudExceptionExpiringSoon(item, now));
  const ackFailures = active.filter((item) => isCloudExceptionAckFailure(item));
  const pending = pendingRequests.filter((item) => item.status === "pending");
  return {
    activeCount: active.length,
    pendingCount: pending.length,
    expiringSoonCount: expiringSoon.length,
    ackFailureCount: ackFailures.length
  };
}
function groupCloudExceptions(exceptions, pendingRequests, now = /* @__PURE__ */ new Date()) {
  const active = exceptions.filter((item) => isCloudExceptionActive(item, now)).sort((left, right) => {
    const leftExpiry = resolveCloudExceptionExpiryTimestamp(left)?.getTime() ?? Number.MAX_SAFE_INTEGER;
    const rightExpiry = resolveCloudExceptionExpiryTimestamp(right)?.getTime() ?? Number.MAX_SAFE_INTEGER;
    return leftExpiry - rightExpiry;
  });
  const pending = pendingRequests.filter((item) => item.status === "pending").sort(
    (left, right) => (parseCloudExceptionTimestamp(right.requestedAt)?.getTime() ?? 0) - (parseCloudExceptionTimestamp(left.requestedAt)?.getTime() ?? 0)
  );
  const expiringSoon = active.filter((item) => isCloudExceptionExpiringSoon(item, now));
  const ackFailures = active.filter((item) => isCloudExceptionAckFailure(item));
  return { active, pending, expiringSoon, ackFailures };
}
function PersonRow({
  label,
  value
}) {
  const display = resolvePersonDisplayLabel(value);
  const initials = resolvePersonInitials(value);
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-center gap-3", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx(
      "span",
      {
        "aria-hidden": "true",
        className: "inline-flex h-9 w-9 shrink-0 items-center justify-center rounded-full bg-brand-blue/10 text-xs font-semibold text-brand-blue",
        children: initials
      }
    ),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs font-medium uppercase tracking-wide text-slate-500", children: label }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm font-medium text-brand-dark", children: display })
    ] })
  ] });
}
function DetailField({ label, value }) {
  if (!value) {
    return null;
  }
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs font-medium uppercase tracking-wide text-slate-500", children: label }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1 break-all text-sm text-brand-dark", children: value })
  ] });
}
function resolveAckCopy(item) {
  if (item.ack_status === "synced") {
    return { label: "Synced", detail: "This device acknowledged the signed policy bundle." };
  }
  if (item.ack_status === "pending") {
    return { label: "Pending ack", detail: "Waiting for this device to acknowledge the signed bundle on next sync." };
  }
  if (item.ack_status === "failed") {
    return {
      label: "Ack failed",
      detail: item.rejection_reason?.trim() || "The local daemon could not acknowledge this exception bundle."
    };
  }
  if (item.ack_status === "offline") {
    return {
      label: "Offline",
      detail: "This device was offline when the signed bundle was issued."
    };
  }
  return { label: "Unknown", detail: "Local acknowledgement status is unavailable." };
}
function PolicyCloudExceptionDetailPanel({
  exception,
  cloudControlsUrl,
  onClose
}) {
  const expiryTimestamp = resolveCloudExceptionExpiryTimestamp(exception);
  const expiryValue = resolveCloudExceptionExpiryValue(exception);
  const ackCopy = resolveAckCopy(exception);
  const headline = resolveCloudExceptionHeadline(exception);
  return /* @__PURE__ */ jsxRuntimeExports.jsxs(
    "aside",
    {
      className: "rounded-2xl border border-slate-200 bg-white p-5 shadow-sm",
      "aria-label": "Cloud exception details",
      children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mb-4 flex items-start justify-between gap-3", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx(SectionLabel, { children: "Exception detail" }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("h3", { className: "mt-1 text-lg font-semibold text-brand-dark", children: headline })
          ] }),
          /* @__PURE__ */ jsxRuntimeExports.jsx(
            "button",
            {
              type: "button",
              onClick: onClose,
              className: "rounded-lg p-1.5 text-slate-500 hover:bg-slate-100 hover:text-brand-dark",
              "aria-label": "Close exception detail",
              children: /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniXMark, { className: "h-5 w-5", "aria-hidden": "true" })
            }
          )
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mb-4 flex flex-wrap gap-2", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx(Badge, { tone: "success", children: exception.effect }),
          /* @__PURE__ */ jsxRuntimeExports.jsx(Badge, { tone: "default", children: scopeLabel(exception.scope) }),
          isCloudExceptionAckFailure(exception) ? /* @__PURE__ */ jsxRuntimeExports.jsx(Badge, { tone: "warning", children: ackCopy.label }) : null
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "space-y-4", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx(PersonRow, { label: "Owner", value: exception.owner }),
          /* @__PURE__ */ jsxRuntimeExports.jsx(PersonRow, { label: "Approved by", value: exception.approver }),
          /* @__PURE__ */ jsxRuntimeExports.jsx(
            DetailField,
            {
              label: "Expiry",
              value: expiryTimestamp && expiryValue ? `${expiryTimestamp.toLocaleString()} (${formatRelativeTime(expiryValue)})` : expiryValue
            }
          ),
          /* @__PURE__ */ jsxRuntimeExports.jsx(DetailField, { label: "Harness", value: exception.harness }),
          /* @__PURE__ */ jsxRuntimeExports.jsx(DetailField, { label: "Source receipt", value: exception.source_receipt_id }),
          /* @__PURE__ */ jsxRuntimeExports.jsx(DetailField, { label: "Signed bundle hash", value: exception.bundle_hash }),
          /* @__PURE__ */ jsxRuntimeExports.jsx(
            DetailField,
            {
              label: "Last used",
              value: exception.last_used_at ? formatRelativeTime(exception.last_used_at) : null
            }
          ),
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "rounded-xl border border-slate-100 bg-slate-50/80 p-3", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs font-medium uppercase tracking-wide text-slate-500", children: "Local daemon acknowledgement" }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1 text-sm font-medium text-brand-dark", children: ackCopy.label }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1 text-sm text-slate-600", children: ackCopy.detail }),
            isCloudExceptionAckFailure(exception) ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-2 text-xs text-slate-500", children: "Run Guard sync to retry bundle acknowledgement." }) : null
          ] })
        ] }),
        cloudControlsUrl ? /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-5", children: /* @__PURE__ */ jsxRuntimeExports.jsxs(
          "a",
          {
            href: cloudControlsUrl,
            target: "_blank",
            rel: "noopener noreferrer",
            className: "inline-flex items-center gap-1.5 text-sm font-medium text-brand-blue hover:underline",
            children: [
              /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniCloudArrowUp, { className: "h-4 w-4", "aria-hidden": "true" }),
              "Open in Guard Cloud"
            ]
          }
        ) }) : null
      ]
    }
  );
}
const SCOPE_VALUES = ["artifact", "publisher", "harness", "workspace"];
const SCOPE_OPTIONS = [
  {
    value: "artifact",
    label: "One specific action",
    description: "Limit the exception to a single artifact fingerprint."
  },
  {
    value: "publisher",
    label: "Publisher",
    description: "Apply to packages or plugins from one publisher."
  },
  {
    value: "harness",
    label: "App",
    description: "Apply across one harness such as Codex or Cursor."
  },
  {
    value: "workspace",
    label: "Project",
    description: "Apply within the current project folder on this device."
  }
];
function defaultExpiryIso() {
  const date = /* @__PURE__ */ new Date();
  date.setDate(date.getDate() + 30);
  return date.toISOString();
}
function toDatetimeLocalValue(iso) {
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) {
    return "";
  }
  const pad = (value) => String(value).padStart(2, "0");
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}T${pad(date.getHours())}:${pad(date.getMinutes())}`;
}
function fromDatetimeLocalValue(value) {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return (/* @__PURE__ */ new Date()).toISOString();
  }
  return date.toISOString();
}
function parseScopeValue(value) {
  if (SCOPE_VALUES.includes(value)) {
    return value;
  }
  return null;
}
function resolveDefaultWorkingDirectory(snapshot) {
  const install = snapshot.managed_installs?.find((entry) => entry.workspace?.trim());
  return install?.workspace?.trim() ?? "";
}
function PolicyCloudExceptionRequestPanel({
  snapshot,
  onSubmitted,
  onCancel
}) {
  const receiptOptions = snapshot.latest_receipts ?? [];
  const harnessOptions = reactExports.useMemo(() => {
    const fromReceipts = receiptOptions.map((receipt) => receipt.harness).filter(Boolean);
    const fromInstalls = (snapshot.managed_installs ?? []).map((entry) => entry.harness).filter(Boolean);
    return [.../* @__PURE__ */ new Set([...fromReceipts, ...fromInstalls, "codex", "cursor"])].sort();
  }, [receiptOptions, snapshot.managed_installs]);
  const [scope, setScope] = reactExports.useState("artifact");
  const [harness, setHarness] = reactExports.useState(harnessOptions[0] ?? "codex");
  const [artifactId, setArtifactId] = reactExports.useState(receiptOptions[0]?.artifact_id ?? "");
  const [publisher, setPublisher] = reactExports.useState("");
  const [workingDirectory, setWorkingDirectory] = reactExports.useState(resolveDefaultWorkingDirectory(snapshot));
  const [sourceReceiptId, setSourceReceiptId] = reactExports.useState(receiptOptions[0]?.receipt_id ?? "");
  const [requestedBy, setRequestedBy] = reactExports.useState("");
  const [owner, setOwner] = reactExports.useState("");
  const [reason, setReason] = reactExports.useState("");
  const [requestedExpiresAt, setRequestedExpiresAt] = reactExports.useState(defaultExpiryIso());
  const [submitting, setSubmitting] = reactExports.useState(false);
  const [error, setError] = reactExports.useState(null);
  const [successMessage, setSuccessMessage] = reactExports.useState(null);
  const handleScopeChange = reactExports.useCallback((event) => {
    const nextScope = parseScopeValue(event.target.value);
    if (nextScope) {
      setScope(nextScope);
    }
  }, []);
  const handleReceiptChange = reactExports.useCallback(
    (event) => {
      const receiptId = event.target.value;
      setSourceReceiptId(receiptId);
      const receipt = receiptOptions.find((entry) => entry.receipt_id === receiptId);
      if (!receipt) {
        return;
      }
      setHarness(receipt.harness);
      setArtifactId(receipt.artifact_id);
    },
    [receiptOptions]
  );
  const handleArtifactIdChange = reactExports.useCallback((event) => {
    setArtifactId(event.target.value);
  }, []);
  const handlePublisherChange = reactExports.useCallback((event) => {
    setPublisher(event.target.value);
  }, []);
  const handleHarnessChange = reactExports.useCallback((event) => {
    setHarness(event.target.value);
  }, []);
  const handleWorkingDirectoryChange = reactExports.useCallback((event) => {
    setWorkingDirectory(event.target.value);
  }, []);
  const handleRequestedByChange = reactExports.useCallback((event) => {
    setRequestedBy(event.target.value);
  }, []);
  const handleOwnerChange = reactExports.useCallback((event) => {
    setOwner(event.target.value);
  }, []);
  const handleReasonChange = reactExports.useCallback((event) => {
    setReason(event.target.value);
  }, []);
  const handleExpiryChange = reactExports.useCallback((event) => {
    setRequestedExpiresAt(fromDatetimeLocalValue(event.target.value));
  }, []);
  const handleSubmit = reactExports.useCallback(
    async (event) => {
      event.preventDefault();
      setSubmitting(true);
      setError(null);
      setSuccessMessage(null);
      const payload = {
        scope,
        requestedBy: requestedBy.trim(),
        owner: owner.trim(),
        reason: reason.trim(),
        requestedExpiresAt,
        sourceReceiptId: sourceReceiptId.trim() || null
      };
      if (scope === "artifact") {
        payload.harness = harness.trim() || null;
        payload.artifactId = artifactId.trim() || null;
      } else if (scope === "publisher") {
        payload.publisher = publisher.trim() || null;
      } else if (scope === "harness") {
        payload.harness = harness.trim() || null;
      } else if (scope === "workspace") {
        payload.workingDirectory = workingDirectory.trim() || null;
      }
      try {
        const response = await createCloudExceptionRequest(payload);
        const created = response.items.find((item) => item.status === "pending") ?? response.items[0];
        setSuccessMessage(
          created ? `Cloud exception request ${created.requestId} is pending Guard Cloud review.` : "Cloud exception request submitted."
        );
      } catch (submitError) {
        const message = submitError instanceof Error && submitError.message.trim() ? submitError.message : "Unable to submit the Cloud exception request.";
        setError(message);
      } finally {
        setSubmitting(false);
      }
    },
    [
      artifactId,
      harness,
      owner,
      publisher,
      reason,
      requestedBy,
      requestedExpiresAt,
      scope,
      sourceReceiptId,
      workingDirectory
    ]
  );
  const handleDone = reactExports.useCallback(() => {
    onSubmitted();
  }, [onSubmitted]);
  if (receiptOptions.length === 0) {
    return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "rounded-2xl border border-slate-200 bg-white p-5 shadow-sm", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(SectionLabel, { children: "Request cloud exception" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-2 text-sm text-brand-dark/75", children: "Guard needs at least one receipt on this device to anchor a Cloud exception request. Run a protected action first, then return here from Evidence or Inbox." }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-4", children: /* @__PURE__ */ jsxRuntimeExports.jsx(ActionButton, { variant: "secondary", onClick: onCancel, children: "Back" }) })
    ] });
  }
  if (successMessage) {
    return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "space-y-4 rounded-2xl border border-emerald-200 bg-emerald-50/60 p-5 shadow-sm", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(SectionLabel, { children: "Request submitted" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm text-emerald-800", children: successMessage }),
      /* @__PURE__ */ jsxRuntimeExports.jsx(ActionButton, { variant: "primary", onClick: handleDone, children: "Done" })
    ] });
  }
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("form", { className: "space-y-5 rounded-2xl border border-slate-200 bg-white p-5 shadow-sm", onSubmit: handleSubmit, children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(SectionLabel, { children: "Request cloud exception" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-2 text-sm text-brand-dark/75", children: "Submit a governed risk acceptance to Guard Cloud. This does not create a local remembered rule." })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("label", { className: "block space-y-1", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-sm font-medium text-brand-dark", children: "Source receipt" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx(
        "select",
        {
          className: "w-full rounded-xl border border-slate-200 px-3 py-2 text-sm",
          value: sourceReceiptId,
          onChange: handleReceiptChange,
          required: true,
          children: receiptOptions.map((receipt) => /* @__PURE__ */ jsxRuntimeExports.jsxs("option", { value: receipt.receipt_id, children: [
            harnessDisplayName(receipt.harness),
            " · ",
            receipt.artifact_name ?? receipt.artifact_id
          ] }, receipt.receipt_id))
        }
      )
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("label", { className: "block space-y-1", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-sm font-medium text-brand-dark", children: "Scope" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("select", { className: "w-full rounded-xl border border-slate-200 px-3 py-2 text-sm", value: scope, onChange: handleScopeChange, children: SCOPE_OPTIONS.map((option) => /* @__PURE__ */ jsxRuntimeExports.jsx("option", { value: option.value, children: option.label }, option.value)) }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs text-slate-500", children: SCOPE_OPTIONS.find((option) => option.value === scope)?.description })
    ] }),
    scope === "artifact" ? /* @__PURE__ */ jsxRuntimeExports.jsxs("label", { className: "block space-y-1", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-sm font-medium text-brand-dark", children: "Artifact fingerprint" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx(
        "input",
        {
          className: "w-full rounded-xl border border-slate-200 px-3 py-2 text-sm",
          value: artifactId,
          onChange: handleArtifactIdChange,
          required: true
        }
      )
    ] }) : null,
    scope === "publisher" ? /* @__PURE__ */ jsxRuntimeExports.jsxs("label", { className: "block space-y-1", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-sm font-medium text-brand-dark", children: "Publisher" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx(
        "input",
        {
          className: "w-full rounded-xl border border-slate-200 px-3 py-2 text-sm",
          value: publisher,
          onChange: handlePublisherChange,
          required: true
        }
      )
    ] }) : null,
    scope === "harness" || scope === "artifact" ? /* @__PURE__ */ jsxRuntimeExports.jsxs("label", { className: "block space-y-1", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-sm font-medium text-brand-dark", children: "App" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx(
        "select",
        {
          className: "w-full rounded-xl border border-slate-200 px-3 py-2 text-sm",
          value: harness,
          onChange: handleHarnessChange,
          required: true,
          children: harnessOptions.map((option) => /* @__PURE__ */ jsxRuntimeExports.jsx("option", { value: option, children: harnessDisplayName(option) }, option))
        }
      )
    ] }) : null,
    scope === "workspace" ? /* @__PURE__ */ jsxRuntimeExports.jsxs("label", { className: "block space-y-1", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-sm font-medium text-brand-dark", children: "Project folder" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx(
        "input",
        {
          className: "w-full rounded-xl border border-slate-200 px-3 py-2 text-sm",
          value: workingDirectory,
          onChange: handleWorkingDirectoryChange,
          required: true
        }
      )
    ] }) : null,
    /* @__PURE__ */ jsxRuntimeExports.jsxs("label", { className: "block space-y-1", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-sm font-medium text-brand-dark", children: "Requested by" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx(
        "input",
        {
          className: "w-full rounded-xl border border-slate-200 px-3 py-2 text-sm",
          type: "email",
          value: requestedBy,
          onChange: handleRequestedByChange,
          required: true
        }
      )
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("label", { className: "block space-y-1", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-sm font-medium text-brand-dark", children: "Risk owner" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx(
        "input",
        {
          className: "w-full rounded-xl border border-slate-200 px-3 py-2 text-sm",
          type: "email",
          value: owner,
          onChange: handleOwnerChange,
          required: true
        }
      )
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("label", { className: "block space-y-1", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-sm font-medium text-brand-dark", children: "Reason" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx(
        "textarea",
        {
          className: "min-h-24 w-full rounded-xl border border-slate-200 px-3 py-2 text-sm",
          value: reason,
          onChange: handleReasonChange,
          required: true
        }
      )
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("label", { className: "block space-y-1", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-sm font-medium text-brand-dark", children: "Expires" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx(
        "input",
        {
          className: "w-full rounded-xl border border-slate-200 px-3 py-2 text-sm",
          type: "datetime-local",
          value: toDatetimeLocalValue(requestedExpiresAt),
          onChange: handleExpiryChange,
          required: true
        }
      )
    ] }),
    error ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm text-red-600", children: error }) : null,
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap gap-2", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(ActionButton, { variant: "primary", type: "submit", disabled: submitting, children: submitting ? "Submitting…" : "Submit to Guard Cloud" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx(ActionButton, { variant: "secondary", type: "button", onClick: onCancel, disabled: submitting, children: "Cancel" })
    ] })
  ] });
}
function GroupSection({ title, description, defaultOpen = true, children }) {
  const [open, setOpen] = reactExports.useState(defaultOpen);
  const handleToggle = reactExports.useCallback(() => {
    setOpen((current) => !current);
  }, []);
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("section", { className: "rounded-2xl border border-slate-100 bg-white shadow-sm", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs(
      "button",
      {
        type: "button",
        onClick: handleToggle,
        className: "flex w-full items-start justify-between gap-3 px-4 py-3 text-left",
        "aria-expanded": open,
        children: [
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("h3", { className: "text-sm font-semibold text-brand-dark", children: title }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-0.5 text-xs text-slate-500", children: description })
          ] }),
          open ? /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniChevronUp, { className: "mt-0.5 h-4 w-4 shrink-0 text-slate-400", "aria-hidden": "true" }) : /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniChevronDown, { className: "mt-0.5 h-4 w-4 shrink-0 text-slate-400", "aria-hidden": "true" })
        ]
      }
    ),
    open ? /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "space-y-2 border-t border-slate-100 px-3 py-3", children }) : null
  ] });
}
function ExceptionCard({
  item,
  selected,
  onSelect
}) {
  const handleSelect = reactExports.useCallback(() => {
    onSelect(item);
  }, [item, onSelect]);
  const expiryTimestamp = resolveCloudExceptionExpiryTimestamp(item);
  const expiryValue = resolveCloudExceptionExpiryValue(item);
  const headline = resolveCloudExceptionHeadline(item);
  return /* @__PURE__ */ jsxRuntimeExports.jsxs(
    "button",
    {
      type: "button",
      onClick: handleSelect,
      "aria-pressed": selected,
      className: `w-full rounded-xl border px-3.5 py-3 text-left transition ${selected ? "border-brand-blue/30 bg-brand-blue/[0.04] ring-1 ring-brand-blue/20" : "border-slate-100 bg-white hover:border-brand-blue/20 hover:bg-brand-blue/[0.02]"}`,
      children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap items-center gap-2", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx(Badge, { tone: "success", children: item.effect }),
          /* @__PURE__ */ jsxRuntimeExports.jsx(Tag, { tone: "slate", children: scopeLabel(item.scope) }),
          isCloudExceptionAckFailure(item) ? /* @__PURE__ */ jsxRuntimeExports.jsx(Badge, { tone: "warning", children: "Ack issue" }) : null
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-2 text-sm font-semibold text-brand-dark", children: headline }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "mt-1 text-xs text-slate-500", children: [
          "Owner ",
          resolvePersonDisplayLabel(item.owner),
          expiryTimestamp && expiryValue ? ` · expires ${formatRelativeTime(expiryValue)}` : null
        ] })
      ]
    }
  );
}
function PendingRequestCard({ item }) {
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("article", { className: "rounded-xl border border-amber-100 bg-amber-50/40 px-3.5 py-3", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap items-center gap-2", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(Badge, { tone: "warning", children: "Pending" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx(Tag, { tone: "slate", children: scopeLabel(item.scope) })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-2 text-sm font-semibold text-brand-dark", children: item.reason }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "mt-1 text-xs text-slate-600", children: [
      "Requested by ",
      resolvePersonDisplayLabel(item.owner),
      " · expires",
      " ",
      formatRelativeTime(item.requestedExpiresAt)
    ] })
  ] });
}
function PolicyCloudExceptionsList({
  active,
  pending,
  expiringSoon,
  selectedExceptionId,
  onSelectException,
  cloudConnected
}) {
  const expiringSoonIds = reactExports.useMemo(() => new Set(expiringSoon.map((item) => item.id)), [expiringSoon]);
  const activeWithoutExpiringGroup = reactExports.useMemo(
    () => active.filter((item) => !expiringSoonIds.has(item.id)),
    [active, expiringSoonIds]
  );
  if (!cloudConnected) {
    return null;
  }
  const hasAnyRows = active.length > 0 || pending.length > 0;
  if (!hasAnyRows) {
    return /* @__PURE__ */ jsxRuntimeExports.jsx(
      EmptyState,
      {
        title: "No Cloud exceptions synced yet",
        body: "Approved Cloud risk acceptances will appear here after Guard Cloud syncs a signed policy bundle to this device.",
        tone: "teach"
      }
    );
  }
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "space-y-3", role: "list", "aria-label": "Cloud exception groups", children: [
    activeWithoutExpiringGroup.length > 0 ? /* @__PURE__ */ jsxRuntimeExports.jsx(
      GroupSection,
      {
        title: "Active on this device",
        description: "Synced Cloud risk acceptances currently enforced locally.",
        defaultOpen: true,
        children: activeWithoutExpiringGroup.map((item) => /* @__PURE__ */ jsxRuntimeExports.jsx(
          ExceptionCard,
          {
            item,
            selected: selectedExceptionId === item.id,
            onSelect: onSelectException
          },
          item.id
        ))
      }
    ) : null,
    pending.length > 0 ? /* @__PURE__ */ jsxRuntimeExports.jsx(
      GroupSection,
      {
        title: "Pending in Guard Cloud",
        description: "Requests waiting for Cloud approval before they can sync to this device.",
        defaultOpen: true,
        children: pending.map((item) => /* @__PURE__ */ jsxRuntimeExports.jsx(PendingRequestCard, { item }, item.requestId))
      }
    ) : null,
    expiringSoon.length > 0 ? /* @__PURE__ */ jsxRuntimeExports.jsx(
      GroupSection,
      {
        title: "Expiring soon",
        description: "Active acceptances nearing expiry. Renew or revoke them in Guard Cloud.",
        defaultOpen: true,
        children: expiringSoon.map((item) => /* @__PURE__ */ jsxRuntimeExports.jsx(
          ExceptionCard,
          {
            item,
            selected: selectedExceptionId === item.id,
            onSelect: onSelectException
          },
          `expiring-${item.id}`
        ))
      }
    ) : null
  ] });
}
const SUMMARY_TONE_CLASSES = {
  blue: "text-brand-blue",
  amber: "text-amber-700",
  attention: "text-brand-attention",
  slate: "text-brand-dark"
};
function SummaryCard({
  label,
  value,
  tone = "slate"
}) {
  const toneClass = SUMMARY_TONE_CLASSES[tone];
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "rounded-xl border border-slate-200/70 bg-white p-3 text-center shadow-sm", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: `text-2xl font-semibold tabular-nums ${toneClass}`, children: value }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1 text-[10px] font-medium uppercase tracking-wider text-muted-foreground", children: label })
  ] });
}
function SummarySkeleton() {
  return /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "grid grid-cols-2 gap-3 md:grid-cols-4", children: [0, 1, 2, 3].map((index) => /* @__PURE__ */ jsxRuntimeExports.jsx(
    "div",
    {
      className: "h-[72px] animate-pulse rounded-xl border border-slate-200/70 bg-slate-100",
      "aria-hidden": "true"
    },
    index
  )) });
}
function PolicyCloudExceptionsSummary({
  activeCount,
  pendingCount,
  expiringSoonCount,
  ackFailureCount,
  loading = false
}) {
  if (loading) {
    return /* @__PURE__ */ jsxRuntimeExports.jsx(SummarySkeleton, {});
  }
  return /* @__PURE__ */ jsxRuntimeExports.jsxs(
    "div",
    {
      className: "grid grid-cols-2 gap-3 md:grid-cols-4",
      "aria-label": "Cloud exception summary",
      children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(SummaryCard, { label: "Active synced", value: activeCount, tone: "blue" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx(SummaryCard, { label: "Pending approval", value: pendingCount, tone: "amber" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx(SummaryCard, { label: "Expiring soon", value: expiringSoonCount, tone: "attention" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx(SummaryCard, { label: "Local ack failures", value: ackFailureCount, tone: "attention" })
      ]
    }
  );
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
function resolveCloudExceptionsConnected(snapshot) {
  return snapshot.cloud_state === "paired_active" || snapshot.cloud_state === "paired_waiting";
}
function PolicyCloudExceptionsTab({
  snapshot
}) {
  const [requestOpen, setRequestOpen] = reactExports.useState(false);
  const [loadState, setLoadState] = reactExports.useState("loading");
  const [loadError, setLoadError] = reactExports.useState(null);
  const [exceptions, setExceptions] = reactExports.useState([]);
  const [pendingRequests, setPendingRequests] = reactExports.useState([]);
  const [selectedExceptionId, setSelectedExceptionId] = reactExports.useState(null);
  const [reloadToken, setReloadToken] = reactExports.useState(0);
  const cloudControlsUrl = resolveCloudPolicyControlsUrl(snapshot);
  const cloudConnected = resolveCloudExceptionsConnected(snapshot);
  const connectUrl = snapshot.connect_url?.trim() || null;
  const reloadData = reactExports.useCallback(async () => {
    if (!cloudConnected) {
      setExceptions([]);
      setPendingRequests([]);
      setLoadState("ready");
      setLoadError(null);
      return;
    }
    setLoadState("loading");
    setLoadError(null);
    try {
      const [nextExceptions, nextRequests] = await Promise.all([
        fetchCloudExceptions(),
        fetchCloudExceptionRequests()
      ]);
      setExceptions(nextExceptions);
      setPendingRequests(nextRequests.items ?? []);
      setLoadState("ready");
    } catch (error) {
      setLoadState("error");
      setLoadError(error instanceof Error ? error.message : "Unable to load Cloud exceptions.");
    }
  }, [cloudConnected]);
  reactExports.useEffect(() => {
    void reloadData();
  }, [reloadData, reloadToken]);
  const handleOpenRequestPanel = reactExports.useCallback(() => {
    setRequestOpen(true);
  }, []);
  const handleCloseRequestPanel = reactExports.useCallback(() => {
    setRequestOpen(false);
  }, []);
  const handleRequestSubmitted = reactExports.useCallback(() => {
    setRequestOpen(false);
    setReloadToken((current) => current + 1);
  }, []);
  const handleRetryLoad = reactExports.useCallback(() => {
    setReloadToken((current) => current + 1);
  }, []);
  const handleSelectException = reactExports.useCallback((exception) => {
    setSelectedExceptionId(exception.id);
  }, []);
  const handleCloseDetail = reactExports.useCallback(() => {
    setSelectedExceptionId(null);
  }, []);
  const summary = reactExports.useMemo(
    () => summarizeCloudExceptions(exceptions, pendingRequests),
    [exceptions, pendingRequests]
  );
  const groups = reactExports.useMemo(
    () => groupCloudExceptions(exceptions, pendingRequests),
    [exceptions, pendingRequests]
  );
  const selectedException = reactExports.useMemo(
    () => exceptions.find((item) => item.id === selectedExceptionId) ?? null,
    [exceptions, selectedExceptionId]
  );
  if (requestOpen) {
    return /* @__PURE__ */ jsxRuntimeExports.jsx(
      PolicyCloudExceptionRequestPanel,
      {
        snapshot,
        onSubmitted: handleRequestSubmitted,
        onCancel: handleCloseRequestPanel
      }
    );
  }
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "space-y-4", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "rounded-2xl border border-brand-blue/10 bg-brand-blue/[0.03] p-5 shadow-sm", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(SectionLabel, { children: "Cloud risk acceptances" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-2 text-sm text-brand-dark/75", children: "Cloud exceptions are governed risk acceptances with an owner, approver, reason, expiry, and signed bundle. They are managed in Guard Cloud and synced to this device after approval." }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-2 text-sm text-slate-600", children: "Fast remembered approvals from Review stay on the Remembered rules tab. They are separate from Cloud exceptions." })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap items-center gap-2", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(
        ActionButton,
        {
          variant: "primary",
          onClick: handleOpenRequestPanel,
          disabled: !cloudConnected,
          children: "Request cloud exception"
        }
      ),
      cloudControlsUrl ? /* @__PURE__ */ jsxRuntimeExports.jsxs(ActionButton, { href: cloudControlsUrl, variant: "secondary", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniCloudArrowUp, { className: "mr-1.5 h-4 w-4", "aria-hidden": "true" }),
        "Open Guard Cloud"
      ] }) : null,
      !cloudConnected && connectUrl ? /* @__PURE__ */ jsxRuntimeExports.jsx(ActionButton, { href: connectUrl, variant: "secondary", children: "Connect Guard Cloud" }) : null
    ] }),
    !cloudConnected ? /* @__PURE__ */ jsxRuntimeExports.jsx(
      EmptyState,
      {
        title: "Guard Cloud is not connected",
        body: "Cloud exceptions are managed in Guard Cloud. Connect this device to request a risk acceptance or view synced exceptions here.",
        tone: "teach"
      }
    ) : loadState === "error" ? /* @__PURE__ */ jsxRuntimeExports.jsx(
      EmptyState,
      {
        title: "Could not load Cloud exceptions",
        body: loadError ?? "Try again after Guard Cloud sync completes.",
        action: /* @__PURE__ */ jsxRuntimeExports.jsx(ActionButton, { variant: "secondary", onClick: handleRetryLoad, children: "Retry" })
      }
    ) : /* @__PURE__ */ jsxRuntimeExports.jsxs(jsxRuntimeExports.Fragment, { children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(
        PolicyCloudExceptionsSummary,
        {
          activeCount: summary.activeCount,
          pendingCount: summary.pendingCount,
          expiringSoonCount: summary.expiringSoonCount,
          ackFailureCount: summary.ackFailureCount,
          loading: loadState === "loading"
        }
      ),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "grid gap-4 lg:grid-cols-[minmax(0,1fr)_320px] lg:items-start", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(
          PolicyCloudExceptionsList,
          {
            active: groups.active,
            pending: groups.pending,
            expiringSoon: groups.expiringSoon,
            selectedExceptionId,
            onSelectException: handleSelectException,
            cloudConnected
          }
        ),
        selectedException ? /* @__PURE__ */ jsxRuntimeExports.jsx(
          PolicyCloudExceptionDetailPanel,
          {
            exception: selectedException,
            cloudControlsUrl,
            onClose: handleCloseDetail
          }
        ) : null
      ] })
    ] })
  ] });
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
        /* @__PURE__ */ jsxRuntimeExports.jsx(Tag, { tone: "slate", children: scopeLabel(policy.scope) }),
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
function PolicyRememberedCloudRules({
  policies,
  cloudControlsUrl
}) {
  return /* @__PURE__ */ jsxRuntimeExports.jsx(
    GroupedPolicySection,
    {
      title: "From Guard Cloud",
      description: "Synced team rules are read-only here. Edit them in Guard Cloud Controls.",
      policies,
      cloudControlsUrl,
      emptyTitle: "No Guard Cloud rules synced",
      emptyBody: "Connect Guard Cloud to sync shared policy bundles.",
      defaultOpen: policies.length > 0
    }
  );
}
function PolicyRememberedLocalRules({
  policies,
  cloudControlsUrl,
  onClearPolicy
}) {
  return /* @__PURE__ */ jsxRuntimeExports.jsx(
    GroupedPolicySection,
    {
      title: "Remembered on this device",
      description: "Choices you saved from Inbox. Each card explains what Guard will do next time.",
      policies,
      cloudControlsUrl,
      onClearPolicy,
      emptyTitle: "No local remembered rules yet",
      emptyBody: "Approve or block in Inbox and Guard remembers the decision here in plain language.",
      defaultOpen: true
    }
  );
}
const REVIEW_SCOPE_LADDER = [
  { scope: "artifact", detail: "Guard remembers only the next matching retry." },
  { scope: "workspace", detail: "Guard remembers the same action in this project folder." },
  { scope: "publisher", detail: "Guard remembers actions from the same source in this app." },
  { scope: "harness", detail: "Guard remembers the action across this app." },
  { scope: "global", detail: "Guard remembers the action on every project on this device." }
];
function PolicyRememberedRulesRightRail({
  onOpenCloudExceptions
}) {
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("aside", { className: "space-y-4 lg:sticky lg:top-4", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "rounded-2xl border border-slate-200 bg-slate-50/80 p-4 text-sm text-slate-600", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "font-medium text-brand-dark", children: "Remembered rules vs Cloud exceptions" }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("ul", { className: "mt-2 list-disc space-y-1 pl-5", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("li", { children: "Review and Inbox keep fast allow/block decisions for the work in front of you." }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("li", { children: "Remembered rules on this tab explain what Guard will do next time for matching actions." }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("li", { children: "Cloud exceptions are separate governed risk acceptances managed in Guard Cloud." })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsx(
        "button",
        {
          type: "button",
          onClick: onOpenCloudExceptions,
          className: "mt-3 text-sm font-medium text-brand-blue hover:underline",
          children: "Open Cloud exceptions tab"
        }
      )
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "rounded-2xl border border-slate-200 bg-white p-4 text-sm text-slate-600 shadow-sm", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "font-medium text-brand-dark", children: "Review scope ladder" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1 text-xs leading-relaxed text-slate-500", children: "When you approve in Inbox, you pick how broadly Guard should remember the decision. Wider scopes apply to more future actions." }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("ol", { className: "mt-3 space-y-2.5", children: REVIEW_SCOPE_LADDER.map((step, index) => /* @__PURE__ */ jsxRuntimeExports.jsxs("li", { className: "flex gap-2.5", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "flex h-5 w-5 shrink-0 items-center justify-center rounded-full bg-brand-blue/10 text-[11px] font-semibold text-brand-blue", children: index + 1 }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm font-medium text-brand-dark", children: scopeLabel(step.scope) }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs leading-relaxed text-slate-500", children: step.detail })
        ] })
      ] }, step.scope)) })
    ] })
  ] });
}
function PolicyRememberedRulesTab({
  policies,
  cloudControlsUrl,
  onClearPolicy,
  onOpenCloudExceptions
}) {
  const [searchQuery, setSearchQuery] = reactExports.useState("");
  const [appFilter, setAppFilter] = reactExports.useState("");
  const [familyFilter, setFamilyFilter] = reactExports.useState("");
  const handleSearchChange = reactExports.useCallback((event) => {
    setSearchQuery(event.target.value);
  }, []);
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
  const appOptions = reactExports.useMemo(
    () => [...new Set(policies.map((policy) => policy.harness).filter(Boolean))].sort(),
    [policies]
  );
  const familyCounts = reactExports.useMemo(() => groupPoliciesByFamily(rememberedRules), [rememberedRules]);
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "grid gap-4 lg:grid-cols-[minmax(0,1fr)_260px] lg:items-start", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "space-y-4", children: [
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
        PolicyRememberedLocalRules,
        {
          policies: localRules,
          cloudControlsUrl,
          onClearPolicy
        }
      ),
      /* @__PURE__ */ jsxRuntimeExports.jsx(PolicyRememberedCloudRules, { policies: cloudRules, cloudControlsUrl })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsx(PolicyRememberedRulesRightRail, { onOpenCloudExceptions })
  ] });
}
function resolvePolicyViewLabel(view) {
  if (view === "rules") {
    return "Remembered rules";
  }
  if (view === "exceptions") {
    return "Cloud exceptions";
  }
  return "Strict config";
}
function PolicyWorkspace({
  policies,
  snapshot,
  onClearPolicy,
  onOpenSettings,
  onOpenInbox
}) {
  const [activeView, setActiveView] = reactExports.useState("rules");
  const handleViewChange = reactExports.useCallback((view) => {
    setActiveView(view);
  }, []);
  const handleOpenCloudExceptions = reactExports.useCallback(() => {
    setActiveView("exceptions");
  }, []);
  const modeCopy = reactExports.useMemo(() => resolveSecurityModeCopy(snapshot.security_level), [snapshot.security_level]);
  const cloudBundleCopy = reactExports.useMemo(() => resolveCloudPolicyBundleCopy(snapshot), [snapshot]);
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
    activeView === "rules" ? /* @__PURE__ */ jsxRuntimeExports.jsx(
      PolicyRememberedRulesTab,
      {
        policies,
        cloudControlsUrl: resolveCloudPolicyControlsUrl(snapshot),
        onClearPolicy,
        onOpenCloudExceptions: handleOpenCloudExceptions
      }
    ) : null,
    activeView === "exceptions" ? /* @__PURE__ */ jsxRuntimeExports.jsx(PolicyCloudExceptionsTab, { snapshot }) : null,
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
  resolvePolicyViewLabel,
  resolveSecurityModeCopy
};
