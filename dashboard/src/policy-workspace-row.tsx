import { useCallback } from "react";
import {
  HiMiniCloudArrowUp,
  HiMiniCommandLine,
  HiMiniCube,
  HiMiniDocumentText,
  HiMiniGlobeAlt,
  HiMiniShieldCheck,
  HiMiniNoSymbol,
  HiMiniCheckCircle,
} from "react-icons/hi2";
import { Tag } from "./approval-center-primitives";
import { harnessDisplayName, formatRelativeTime, scopeLabel, policyActionLabel } from "./approval-center-utils";
import type { GuardPolicyDecision } from "./guard-types";
import { EvidenceTableCell, EvidenceTableRow } from "./evidence/evidence-table";
import {
  isCloudManagedPolicy,
  resolvePolicyDisplay,
  resolvePolicyMatcherFamily,
  resolvePolicyRowFolder,
  resolvePolicyRowTitle,
} from "./policy-workspace-helpers";
import { resolvePolicyRowSourceLabel } from "./policy-managed-authority";
import { GoverningExtensionLink } from "./policy-governing-extension-link";
import { isBulkRemovablePolicy } from "./policy-rules-overview-model";
import { isBroadAllow, isStaleRule } from "./policy-rules-hero-model";

function PolicyActionBadge({ action }: { action: string }) {
  if (action === "allow") {
    return (
      <span className="inline-flex items-center gap-1 rounded-full border border-emerald-300 bg-emerald-50 px-2.5 py-0.5 text-xs font-semibold text-emerald-800">
        <HiMiniCheckCircle className="h-3.5 w-3.5" aria-hidden="true" />
        Allow
      </span>
    );
  }
  if (action === "block") {
    return (
      <span className="inline-flex items-center gap-1 rounded-full border border-rose-300 bg-rose-50 px-2.5 py-0.5 text-xs font-semibold text-rose-800">
        <HiMiniNoSymbol className="h-3.5 w-3.5" aria-hidden="true" />
        Block
      </span>
    );
  }
  return (
    <span className="inline-flex items-center gap-1 rounded-full border border-amber-300 bg-amber-50 px-2.5 py-0.5 text-xs font-semibold text-amber-900">
      {policyActionLabel(action)}
    </span>
  );
}

function resolveFamilyIcon(family: string | null) {
  if (family === "package-request") {
    return HiMiniCube;
  }
  if (family === "tool-action" || family === "tool-output") {
    return HiMiniCommandLine;
  }
  if (family === "prompt" || family === "prompt-env-read") {
    return HiMiniDocumentText;
  }
  if (family === "mcp") {
    return HiMiniGlobeAlt;
  }
  return HiMiniShieldCheck;
}

type PolicyRuleRowProps = {
  policy: GuardPolicyDecision;
  cloudControlsUrl: string | null;
  onClear?: (policy: GuardPolicyDecision) => void;
  onNavigate?: (pathname: string) => void;
  cloudVariant?: boolean;
  selected?: boolean;
  onToggleSelect?: (policy: GuardPolicyDecision) => void;
  onInspect?: (policy: GuardPolicyDecision) => void;
};

export function PolicyRuleRow({ policy, cloudControlsUrl, onClear, onNavigate, cloudVariant = false, selected = false, onToggleSelect, onInspect }: PolicyRuleRowProps) {
  const handleClear = useCallback(() => onClear?.(policy), [onClear, policy]);
  const handleInspect = useCallback(() => onInspect?.(policy), [onInspect, policy]);
  const handleToggleSelect = useCallback(() => onToggleSelect?.(policy), [onToggleSelect, policy]);
  const cloudManaged = cloudVariant || isCloudManagedPolicy(policy.source);
  const display = resolvePolicyDisplay(policy);
  const canClear = onClear !== undefined && !cloudManaged;
  const family = resolvePolicyMatcherFamily(policy);
  const Icon = resolveFamilyIcon(family);
  const title = resolvePolicyRowTitle(policy, display);
  const kindLine = display.kindLine;
  const scopeTag = scopeLabel(policy.scope, "policy");
  const folder = resolvePolicyRowFolder(policy);

  return (
    <EvidenceTableRow>
      <EvidenceTableCell className="w-10">
        <div className="flex items-center gap-2">
          {canClear && onToggleSelect && isBulkRemovablePolicy(policy) ? (
            <input
              type="checkbox"
              checked={selected}
              onChange={handleToggleSelect}
              aria-label={`Select rule ${title} for removal`}
              className="h-4 w-4 shrink-0 rounded border-slate-300 accent-brand-blue focus:outline-none focus:ring-2 focus:ring-brand-blue/30"
            />
          ) : null}
          <span className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-slate-100 text-slate-500">
            <Icon className="h-4 w-4" aria-hidden="true" />
          </span>
        </div>
      </EvidenceTableCell>

      <EvidenceTableCell className="w-[88px] whitespace-nowrap">
        <PolicyActionBadge action={policy.action} />
      </EvidenceTableCell>

      <EvidenceTableCell className="min-w-[150px] max-w-[260px] sm:min-w-[200px]">
        <p className="truncate font-semibold leading-snug text-brand-dark" title={title}>
          {title}
        </p>
        {kindLine ? (
          <p className="mt-0.5 truncate text-xs leading-relaxed text-slate-500" title={kindLine}>
            {kindLine}
          </p>
        ) : null}
        <p className="mt-1 break-words text-xs leading-relaxed text-slate-600">{display.rememberSentence}</p>
        {isBroadAllow(policy) || isStaleRule(policy, new Date()) ? (
          <span className="guard-state-pill mt-1.5" data-tone="attention">
            <span className="guard-state-pill-dot" aria-hidden="true" />
            {isBroadAllow(policy) ? "Broad allow" : "Not changed in 90+ days"}
          </span>
        ) : null}
        <div className="mt-2 flex flex-wrap gap-x-3 gap-y-1 text-xs text-slate-600 lg:hidden">
          <span>
            <span className="font-medium text-slate-700">Source:</span> {resolvePolicyRowSourceLabel(policy)}
          </span>
          <span>
            <span className="font-medium text-slate-700">Scope:</span> {scopeTag}
          </span>
          {folder ? (
            <span>
              <span className="font-medium text-slate-700">Folder:</span> {folder}
            </span>
          ) : null}
          <span>
            <span className="font-medium text-slate-700">App:</span> {harnessDisplayName(policy.harness)}
          </span>
          {policy.updated_at ? (
            <span>
              <span className="font-medium text-slate-700">Updated:</span> {formatRelativeTime(policy.updated_at)}
            </span>
          ) : null}
          {onInspect ? (
            <button type="button" onClick={handleInspect} className="font-semibold text-brand-blue" aria-label={`Inspect rule ${title}`}>
              Inspect
            </button>
          ) : null}
        </div>
        <GoverningExtensionLink policy={policy} onNavigate={onNavigate} />
      </EvidenceTableCell>

      <EvidenceTableCell className="hidden w-[88px] whitespace-nowrap lg:table-cell">
        <Tag tone={cloudManaged ? "slate" : "blue"}>{resolvePolicyRowSourceLabel(policy)}</Tag>
      </EvidenceTableCell>

      <EvidenceTableCell className="hidden w-[110px] whitespace-nowrap lg:table-cell">
        <span className="font-medium text-brand-blue">{harnessDisplayName(policy.harness)}</span>
        <span className="mt-0.5 block text-xs font-normal text-slate-500">{scopeTag}</span>
        {policy.updated_at ? (
          <span className="mt-0.5 block text-xs font-normal text-slate-400">{formatRelativeTime(policy.updated_at)}</span>
        ) : null}
      </EvidenceTableCell>

      <EvidenceTableCell className="hidden w-[150px] text-right lg:table-cell">
        <div className="flex items-center justify-end gap-2">
          {cloudManaged ? (
            <span className="whitespace-nowrap text-xs font-medium text-slate-500">Read-only</span>
          ) : null}
          {cloudManaged && cloudControlsUrl ? (
            <a
              href={cloudControlsUrl}
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-1 whitespace-nowrap text-xs font-medium text-brand-blue hover:underline"
            >
              <HiMiniCloudArrowUp className="h-3.5 w-3.5" aria-hidden="true" />
              View on cloud
            </a>
          ) : null}
          {onInspect ? (
            <button
              type="button"
              onClick={handleInspect}
              className="inline-flex min-h-8 items-center whitespace-nowrap rounded-lg px-2 text-xs font-semibold text-brand-blue hover:bg-brand-blue/[0.06]"
              aria-label={`Inspect rule ${title}`}
            >
              Inspect
            </button>
          ) : null}
          {canClear ? (
            <button
              type="button"
              onClick={handleClear}
              className="inline-flex items-center gap-1 whitespace-nowrap text-xs font-medium text-rose-600 hover:text-rose-700"
            >
              Remove rule
            </button>
          ) : null}
        </div>
      </EvidenceTableCell>
    </EvidenceTableRow>
  );
}
