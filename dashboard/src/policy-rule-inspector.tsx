import { useCallback, useEffect, useRef, useState } from "react";
import type { MouseEvent } from "react";
import { HiMiniArrowTopRightOnSquare, HiMiniCheckCircle, HiMiniNoSymbol, HiMiniTrash, HiMiniXMark } from "react-icons/hi2";
import { Tag } from "./approval-center-primitives";
import { formatRelativeTime, harnessDisplayName, scopeLabel } from "./approval-center-utils";
import { guardAwareHref } from "./guard-api";
import type { GuardPolicyDecision } from "./guard-types";
import {
  formatPolicyDateTime,
  isCloudManagedPolicy,
  resolveExactApprovedAction,
  resolvePolicyApprovalRecordLabel,
  resolvePolicyDisplay,
  resolvePolicyEvidenceHref,
  resolvePolicyRowFolder,
  resolvePolicyRowTitle,
} from "./policy-workspace-helpers";
import { resolvePolicyRowSourceLabel } from "./policy-managed-authority";
import { GoverningExtensionLink } from "./policy-governing-extension-link";

export function PolicyRuleInspector(props: {
  policy: GuardPolicyDecision;
  cloudControlsUrl: string | null;
  onClose: () => void;
  onClear?: (policy: GuardPolicyDecision) => void | Promise<void>;
  onNavigate?: (pathname: string) => void;
}) {
  const { policy, onClose } = props;
  const dialogRef = useRef<HTMLDivElement>(null);
  const display = resolvePolicyDisplay(policy);
  const title = resolvePolicyRowTitle(policy, display);
  const exactAction = resolveExactApprovedAction(policy);
  const cloudManaged = isCloudManagedPolicy(policy.source);
  const canClear = props.onClear !== undefined && !cloudManaged;
  const folder = resolvePolicyRowFolder(policy);
  const evidenceHref = resolvePolicyEvidenceHref(policy);
  const exactUpdated = formatPolicyDateTime(policy.updated_at);

  useEffect(() => {
    const dialog = dialogRef.current;
    const previouslyFocused = document.activeElement as HTMLElement | null;
    dialog?.querySelector<HTMLElement>("[data-inspector-close]")?.focus();
    const handleKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        event.preventDefault();
        onClose();
        return;
      }
      if (event.key !== "Tab" || !dialog) return;
      const focusable = [...dialog.querySelectorAll<HTMLElement>("button, a[href], input, [tabindex]:not([tabindex='-1'])")]
        .filter((el) => !el.hasAttribute("disabled"));
      if (focusable.length === 0) return;
      const first = focusable[0];
      const last = focusable[focusable.length - 1];
      if (event.shiftKey && document.activeElement === first) {
        event.preventDefault();
        last.focus();
      } else if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault();
        first.focus();
      }
    };
    document.addEventListener("keydown", handleKeyDown);
    return () => {
      document.removeEventListener("keydown", handleKeyDown);
      previouslyFocused?.focus?.();
    };
    // Mount-only: depending on the whole props object would re-run on every
    // parent render and steal focus from wherever the user has tabbed to.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const [removing, setRemoving] = useState(false);
  const [removeError, setRemoveError] = useState<string | null>(null);
  const handleBackdropClick = useCallback(() => props.onClose(), [props]);
  const handleClear = useCallback(async () => {
    if (removing) return;
    setRemoving(true);
    setRemoveError(null);
    try {
      await props.onClear?.(policy);
      props.onClose();
    } catch {
      setRemoveError("This rule could not be removed. It is still in force — try again.");
    } finally {
      setRemoving(false);
    }
  }, [policy, props, removing]);
  const handleEvidenceClick = useCallback((event: MouseEvent<HTMLAnchorElement>) => {
    if (!props.onNavigate) return;
    event.preventDefault();
    props.onNavigate(evidenceHref);
  }, [evidenceHref, props]);

  return (
    <div className="fixed inset-0 z-50 flex items-end justify-center sm:items-center sm:p-4" role="presentation">
      <button type="button" aria-label="Close rule details" onClick={handleBackdropClick} className="absolute inset-0 bg-brand-dark/40" />
      <div
        ref={dialogRef}
        role="dialog"
        aria-modal="true"
        aria-label={`Rule details: ${title}`}
        className="guard-surface-in relative max-h-[88vh] w-full max-w-lg overflow-y-auto rounded-t-2xl bg-white p-5 shadow-xl sm:rounded-2xl sm:p-6"
      >
        <div className="flex items-start justify-between gap-3">
          <span
            className={`inline-flex items-center gap-1 rounded-full border px-2.5 py-0.5 text-xs font-semibold ${
              policy.action === "allow"
                ? "border-emerald-300 bg-emerald-50 text-emerald-800"
                : policy.action === "block"
                  ? "border-rose-300 bg-rose-50 text-rose-800"
                  : "border-amber-300 bg-amber-50 text-amber-900"
            }`}
          >
            {policy.action === "allow" ? <HiMiniCheckCircle className="h-3.5 w-3.5" aria-hidden="true" /> : policy.action === "block" ? <HiMiniNoSymbol className="h-3.5 w-3.5" aria-hidden="true" /> : null}
            {policy.action === "allow" ? "Allow" : policy.action === "block" ? "Block" : policy.action}
          </span>
          <button
            type="button"
            data-inspector-close
            onClick={props.onClose}
            aria-label="Close"
            className="rounded-lg p-1.5 text-slate-500 hover:bg-slate-100 hover:text-brand-dark focus:outline-none focus:ring-2 focus:ring-brand-blue/30"
          >
            <HiMiniXMark className="h-5 w-5" aria-hidden="true" />
          </button>
        </div>

        <h2 className="mt-3 break-words text-lg font-semibold leading-snug text-brand-dark">{title}</h2>
        <p className="mt-2 text-sm leading-relaxed text-slate-600">{display.rememberSentence}</p>
        {display.kindLine ? <p className="mt-1 text-sm text-slate-500">{display.kindLine}</p> : null}

        {exactAction ? (
          <div className="mt-4">
            <p className="text-[11px] font-medium uppercase tracking-wider text-slate-500">
              {policy.action === "block" ? "Exact action blocked" : "Exact action approved"}
            </p>
            <pre className="mt-1.5 max-h-44 overflow-auto whitespace-pre-wrap break-words rounded-xl bg-slate-900 px-3 py-2.5 font-mono text-xs leading-relaxed text-slate-50">{exactAction}</pre>
            <p className="mt-1.5 text-xs leading-relaxed text-slate-500">
              {policy.action === "block"
                ? "This is the exact action this rule blocks. Guard stops it without asking while the rule stands."
                : "This is the exact action this rule was approved for. Guard repeats it without asking while the rule stands."}
            </p>
          </div>
        ) : null}

        <dl className="mt-5 grid grid-cols-1 gap-px overflow-hidden rounded-xl border border-slate-200 bg-slate-100 sm:grid-cols-2">
          {[
            ["Source", resolvePolicyRowSourceLabel(policy)],
            ["Scope", scopeLabel(policy.scope, "policy")],
            ["App", harnessDisplayName(policy.harness)],
            ...(folder ? [["Folder", folder] as [string, string]] : []),
            ...(policy.updated_at ? [["Last remembered", `${formatRelativeTime(policy.updated_at)}${exactUpdated ? ` (${exactUpdated})` : ""}`] as [string, string]] : []),
            ...(display.technicalId ? [["Matcher", display.technicalId] as [string, string]] : []),
          ].map(([label, value]) => (
            <div key={label} className="bg-white px-4 py-3">
              <dt className="text-[11px] font-medium uppercase tracking-wider text-slate-500">{label}</dt>
              <dd className="mt-1 break-words text-sm text-brand-dark">{value}</dd>
            </div>
          ))}
        </dl>

        <div className="mt-4 flex flex-wrap items-center gap-2">
          <Tag tone={cloudManaged ? "slate" : "blue"}>{cloudManaged ? "Managed in Guard Cloud" : "Remembered on this device"}</Tag>
          <GoverningExtensionLink policy={policy} onNavigate={props.onNavigate} />
        </div>

        {removeError ? (
          <p className="mt-4 text-sm text-rose-700" role="alert">{removeError}</p>
        ) : null}
        <div className="mt-6 flex flex-wrap items-center gap-2 border-t border-slate-100 pt-4">
          {!cloudManaged ? (
            <a
              href={guardAwareHref(evidenceHref)}
              onClick={handleEvidenceClick}
              className="inline-flex min-h-10 items-center gap-1.5 rounded-xl border border-slate-200 bg-white px-3 text-sm font-medium text-brand-dark hover:border-brand-blue/30 focus:outline-none focus:ring-2 focus:ring-brand-blue/30"
            >
              {resolvePolicyApprovalRecordLabel(policy)}
              <HiMiniArrowTopRightOnSquare className="h-4 w-4" aria-hidden="true" />
            </a>
          ) : props.cloudControlsUrl ? (
            <a
              href={props.cloudControlsUrl}
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex min-h-10 items-center gap-1.5 rounded-xl border border-slate-200 bg-white px-3 text-sm font-medium text-brand-dark hover:border-brand-blue/30"
            >
              View on cloud
              <HiMiniArrowTopRightOnSquare className="h-4 w-4" aria-hidden="true" />
            </a>
          ) : null}
          {canClear ? (
            <button
              type="button"
              onClick={handleClear}
              disabled={removing}
              className="inline-flex min-h-10 items-center gap-1.5 rounded-xl bg-rose-600 px-3 text-sm font-medium text-white hover:bg-rose-700 focus:outline-none focus:ring-2 focus:ring-rose-600/30 disabled:opacity-50"
            >
              <HiMiniTrash className="h-4 w-4" aria-hidden="true" />
              {removing ? "Removing…" : "Remove rule"}
            </button>
          ) : cloudManaged ? (
            <p className="text-sm text-slate-500">Read-only here — change it in Guard Cloud or its governing Extension.</p>
          ) : null}
        </div>
      </div>
    </div>
  );
}
