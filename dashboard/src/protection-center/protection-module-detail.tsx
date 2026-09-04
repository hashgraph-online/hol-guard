import { useCallback, useEffect, useState, type KeyboardEvent } from "react";
import { HiMiniArrowLeft, HiMiniArrowTopRightOnSquare, HiMiniLockClosed } from "react-icons/hi2";

import {
  controlProvenance,
  extensionEffectiveState,
  permissionForRule,
  treatmentLabel,
  type ExtensionDetailUrlState,
} from "../extension-control-center-model";
import type { EffectiveExtensionControls, ExtensionCatalogItem } from "../extension-controls-api";
import { ExtensionPolicyPanel } from "../extension-policy-panel";
import type { GuardRuntimeSnapshot } from "../guard-types";
import { buildLocalProtectionView } from "../managed-controls/local-protection-model";
import {
  ExtensionManagedControlsPanel,
  extensionLocalProtectionInput,
} from "../managed-controls/extension-managed-controls-panel";
import { TechnicalDetails } from "./components/protection-primitives";
import { ExtensionBrandMark } from "./components/extension-brand-mark";
import { ExtensionActivity } from "./extension-activity";
import { ProtectionTestLab } from "./protection-test-lab";

export type ProtectionDetailTab = "overview" | "permissions" | "managed-controls" | "activity" | "technical";

const DETAIL_TABS: ReadonlyArray<{ id: ProtectionDetailTab; label: string }> = [
  { id: "overview", label: "Overview" },
  { id: "permissions", label: "Permissions" },
  { id: "managed-controls", label: "Managed controls" },
  { id: "activity", label: "Activity" },
  { id: "technical", label: "Technical details" },
];

export function canonicalProtectionDetailTab(tab: ExtensionDetailUrlState["tab"]): ProtectionDetailTab {
  if (tab === "commands" || tab === "policy") return "permissions";
  if (tab === "test-lab") return "activity";
  if (tab === "managed-controls" || tab === "permissions" || tab === "technical") return tab;
  return tab === "activity" ? "activity" : "overview";
}

function requiredLine(extension: ExtensionCatalogItem): string | null {
  if (!extension.required) return null;
  return "Required by Guard — this protection stays on. The command patterns below can still follow recommended settings or be blocked on this device.";
}

function availabilityCopy(extension: ExtensionCatalogItem, enabled: boolean): string {
  if (extension.trust_class === "external") {
    if (enabled) {
      return "Matching commands follow the protection settings below. Turn off to leave this community tool inactive.";
    }
    return "This community tool stays off until you turn it on.";
  }
  if (enabled) {
    return "Matching commands follow the protection settings below. Turn off to block every command this tool owns on this device.";
  }
  return "Every command this tool owns is blocked on this device. Turn on to follow the protection settings below.";
}

function protectionStateLabel(state: "allowed" | "blocked" | "partial" | "required" | "lockdown"): string {
  return state.charAt(0).toUpperCase() + state.slice(1);
}

function DeveloperModuleDetails(props: {
  extension: ExtensionCatalogItem;
  effective: EffectiveExtensionControls;
  catalogDigest: string;
}) {
  return (
    <TechnicalDetails title="Developer details" testId="protection-more-detail">
      <div className="grid gap-5">
        <section>
          <h3 className="font-semibold text-brand-dark">Canonical module</h3>
          <dl className="mt-3 grid gap-3 sm:grid-cols-2">
            <div>
              <dt className="text-xs text-brand-dark/80">Extension ID</dt>
              <dd><code className="break-all text-xs">{props.extension.extension_id}</code></dd>
            </div>
            <div>
              <dt className="text-xs text-brand-dark/80">Version</dt>
              <dd className="text-sm">{props.extension.version}</dd>
            </div>
            <div>
              <dt className="text-xs text-brand-dark/80">Catalog digest</dt>
              <dd><code className="break-all text-xs">{props.catalogDigest}</code></dd>
            </div>
            <div>
              <dt className="text-xs text-brand-dark/80">Provenance</dt>
              <dd className="text-sm">{controlProvenance(props.effective, "extension", props.extension.extension_id).join(" · ")}</dd>
            </div>
          </dl>
        </section>
        <section>
          <h3 className="font-semibold text-brand-dark">Detections</h3>
          <div className="mt-3 max-h-96 overflow-auto">
            <table className="min-w-full text-left text-xs">
              <thead className="sticky top-0 bg-[var(--surface-1)] text-brand-dark/80">
                <tr>
                  <th className="px-3 py-2">Detection</th>
                  <th className="px-3 py-2">Severity</th>
                  <th className="px-3 py-2">Matcher</th>
                  <th className="px-3 py-2">Default</th>
                </tr>
              </thead>
              <tbody>
                {props.extension.rules.map((rule) => (
                  <tr key={rule.rule_id} className="border-t border-[rgba(63,65,116,0.08)]">
                    <td className="px-3 py-2">
                      <div className="font-medium text-brand-dark/80">{rule.title}</div>
                      <code className="break-all text-[10px] text-brand-dark/80">{rule.rule_id}</code>
                    </td>
                    <td className="px-3 py-2">{rule.severity}</td>
                    <td className="px-3 py-2">{rule.matcher_kind}</td>
                    <td className="px-3 py-2">{treatmentLabel(rule.default_mode)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
        <section>
          <h3 className="font-semibold text-brand-dark">Protection setting identifiers</h3>
          <div className="mt-2 space-y-2">
            {props.extension.permissions.map((permission) => (
              <div key={permission.permission_id} className="py-2">
                <div className="text-sm font-medium text-brand-dark/80">{permission.label}</div>
                <code className="mt-1 block break-all text-[11px] text-brand-dark/80">{permission.permission_id}</code>
                <div className="mt-1 text-xs text-brand-dark/80">{permission.action_classes.join(", ") || "No action classes"}</div>
              </div>
            ))}
          </div>
        </section>
      </div>
    </TechnicalDetails>
  );
}

export function ProtectionModuleDetail(props: {
  extension: ExtensionCatalogItem;
  effective: EffectiveExtensionControls;
  catalogDigest: string;
  runtime?: GuardRuntimeSnapshot | null;
  urlState?: ExtensionDetailUrlState;
  onUrlState?: (state: ExtensionDetailUrlState) => void;
  onBack: () => void;
  onRefresh: () => Promise<void> | void;
  onRequestExtensionChange?: (extension: ExtensionCatalogItem, enabled: boolean) => void;
}) {
  const [policyDirty, setPolicyDirty] = useState(false);
  useEffect(() => {
    let highlightTimer = 0;
    let highlighted: HTMLElement | null = null;
    const clearHighlight = () => {
      if (highlightTimer) window.clearTimeout(highlightTimer);
      highlightTimer = 0;
      highlighted?.classList.remove("guard-pattern-row-highlight");
      highlighted = null;
    };
    const highlight = () => {
      const anchor = window.location.hash;
      let rowId: string | null = null;
      let ruleId: string | null = null;
      if (anchor.startsWith("#pattern-")) {
        rowId = anchor.slice(1);
      } else if (anchor.startsWith("#rule-")) {
        ruleId = anchor.slice("#rule-".length);
      } else {
        const fragment = anchor.startsWith("#") ? anchor.slice(1) : anchor;
        const requested = new URLSearchParams(fragment).get("rule");
        if (requested) ruleId = requested;
      }
      if (ruleId) {
        const rule = props.extension.rules.find((item) => item.rule_id === ruleId);
        const permission = rule ? permissionForRule(props.extension, rule) : null;
        rowId = permission ? `pattern-${permission.permission_id}` : null;
      }
      clearHighlight();
      if (!rowId) return;
      const row = document.getElementById(rowId);
      if (!row) return;
      row.scrollIntoView({ behavior: "smooth", block: "center" });
      row.classList.add("guard-pattern-row-highlight");
      highlighted = row;
      highlightTimer = window.setTimeout(clearHighlight, 2400);
    };
    highlight();
    window.addEventListener("hashchange", highlight);
    return () => {
      window.removeEventListener("hashchange", highlight);
      clearHighlight();
    };
  }, [props.extension.extension_id, props.extension.rules]);
  const requiredNote = requiredLine(props.extension);
  const extensionEnabled = extensionEffectiveState(props.effective, props.extension) === "enabled";
  const requestExtensionChange = props.extension.required ? undefined : props.onRequestExtensionChange;
  const activeTab = canonicalProtectionDetailTab(props.urlState?.tab ?? "overview");
  const protectionView = buildLocalProtectionView(
    extensionLocalProtectionInput(props.extension, props.effective, props.runtime),
  );
  const orgManaged = protectionView.sources.some(
    (source) => source === "Synced from Guard Cloud" || source.startsWith("Managed by "),
  );
  const cloudControlsUrl = props.runtime?.dashboard_url?.trim() || props.runtime?.connect_url?.trim() || undefined;
  const setActiveTab = useCallback((tab: ProtectionDetailTab): boolean => {
    if (!props.onUrlState) return false;
    if (
      tab !== activeTab
      && policyDirty
      && !window.confirm("Discard your unreviewed protection setting changes?")
    ) {
      return false;
    }
    props.onUrlState({
      ...(props.urlState ?? {
        tab: "overview",
        query: "",
        risk: "all",
        state: "all",
        configurable: "all",
        source: "all",
        deprecated: "all",
        type: "all",
        sort: "name",
        ruleId: null,
      }),
      tab,
      ruleId: null,
    });
    return true;
  }, [activeTab, policyDirty, props.onUrlState, props.urlState]);
  const handleTabKeyDown = (event: KeyboardEvent<HTMLButtonElement>, tab: ProtectionDetailTab) => {
    if (!event.key.startsWith("Arrow") && event.key !== "Home" && event.key !== "End") return;
    const index = DETAIL_TABS.findIndex((item) => item.id === tab);
    let nextIndex = index;
    if (event.key === "ArrowRight") nextIndex = (index + 1) % DETAIL_TABS.length;
    if (event.key === "ArrowLeft") nextIndex = (index - 1 + DETAIL_TABS.length) % DETAIL_TABS.length;
    if (event.key === "Home") nextIndex = 0;
    if (event.key === "End") nextIndex = DETAIL_TABS.length - 1;
    if (nextIndex === index && event.key !== "Home" && event.key !== "End") return;
    event.preventDefault();
    const next = DETAIL_TABS[nextIndex];
    if (!next) return;
    if (!setActiveTab(next.id)) return;
    window.requestAnimationFrame(() => document.getElementById(`protection-tab-${next.id}`)?.focus());
  };
  const handleBack = () => {
    if (policyDirty && !window.confirm("Discard your unreviewed protection setting changes?")) return;
    props.onBack();
  };

  return (
    <div data-testid="protection-module-detail" className="w-full">
      <button type="button" onClick={handleBack} className="inline-flex min-h-11 items-center gap-2 rounded-lg px-1 text-sm font-semibold text-brand-dark/80 hover:text-brand-dark">
        <HiMiniArrowLeft className="size-4" aria-hidden="true" />
        Extensions
      </button>
      <header className="mt-4 border-b border-slate-200 pb-6">
        <div className="flex items-start gap-4">
          <ExtensionBrandMark
            extension_id={props.extension.extension_id}
            name={props.extension.name}
            executables={props.extension.executables}
            ecosystem_ids={props.extension.ecosystem_ids}
            size="lg"
          />
          <div className="min-w-0 flex-1">
            <p className="font-mono text-xs font-semibold tracking-[0.14em] text-slate-400">{props.extension.executables.join(" · ")}</p>
            <h1 className="mt-2 text-2xl font-semibold tracking-tight text-brand-dark">{props.extension.name}</h1>
            <p className="mt-2 max-w-2xl text-sm leading-6 text-slate-500">{props.extension.description}</p>
            <span className="mt-3 inline-flex rounded-full border border-slate-200 bg-slate-50 px-3 py-1 text-xs font-semibold text-brand-dark">
              {protectionView.source}
            </span>
          </div>
        </div>
        {requiredNote ? <p className="mt-3 max-w-2xl text-sm leading-6 text-brand-dark/80">{requiredNote}</p> : null}
        {requestExtensionChange ? (
          <div className="mt-4 flex flex-wrap items-center gap-3">
            <button
              type="button"
              role="switch"
              aria-checked={extensionEnabled}
              disabled={props.effective.health !== "protected"}
              onClick={() => requestExtensionChange(props.extension, !extensionEnabled)}
              className="guard-tool-switch"
              data-testid="extension-availability-switch"
            >
              <span className="guard-tool-switch-knob" />
            </button>
            <div>
              <p className="text-sm font-semibold text-brand-dark">Commands available</p>
              <p className="text-xs leading-5 text-brand-dark/75">
                {availabilityCopy(props.extension, extensionEnabled)}
              </p>
            </div>
          </div>
        ) : null}
        {orgManaged ? (
          <p className="mt-3 text-sm text-brand-dark/80">Your organization controls part of this protection. Local changes cannot weaken organization policy.</p>
        ) : null}
        {props.effective.global_lockdown ? (
          <p role="status" className="mt-4 flex gap-2 text-sm text-brand-dark">
            <HiMiniLockClosed className="mt-0.5 size-4 shrink-0" />
            Emergency Lockdown currently controls this module. Matching optional actions remain blocked.
          </p>
        ) : null}
      </header>
      <nav className="mt-5 flex gap-5 overflow-x-auto border-b border-slate-200" role="tablist" aria-label="Extension detail sections">
        {DETAIL_TABS.map((tab) => (
          <button
            key={tab.id}
            id={`protection-tab-${tab.id}`}
            type="button"
            role="tab"
            aria-selected={activeTab === tab.id}
            aria-controls={`protection-panel-${tab.id}`}
            tabIndex={activeTab === tab.id ? 0 : -1}
            onClick={() => setActiveTab(tab.id)}
            onKeyDown={(event) => handleTabKeyDown(event, tab.id)}
            className={`-mb-px min-h-11 shrink-0 whitespace-nowrap border-b-2 px-1 pb-3 text-sm font-semibold focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-brand-blue ${activeTab === tab.id ? "border-brand-blue text-brand-blue" : "border-transparent text-brand-dark/60 hover:text-brand-dark"}`}
          >
            {tab.label}
          </button>
        ))}
      </nav>
      {activeTab === "overview" ? (
        <section id="protection-panel-overview" role="tabpanel" aria-labelledby="protection-tab-overview" className="mt-6 grid gap-4 lg:grid-cols-2">
          <article className="rounded-3xl border border-slate-200 bg-white p-5 shadow-sm">
            <h2 className="text-lg font-semibold text-brand-dark">Effective protection</h2>
            <p className="mt-2 text-sm leading-6 text-brand-dark/75">{protectionView.summary}</p>
            <dl className="mt-5 grid gap-4 sm:grid-cols-2">
              <div><dt className="text-xs font-semibold uppercase text-brand-dark/55">State</dt><dd className="mt-1 text-sm font-semibold text-brand-dark">{protectionStateLabel(protectionView.effectiveState)}</dd></div>
              <div><dt className="text-xs font-semibold uppercase text-brand-dark/55">Source</dt><dd className="mt-1 text-sm font-semibold text-brand-dark">{protectionView.source}</dd></div>
              {protectionView.sources.length > 1 ? <div><dt className="text-xs font-semibold uppercase text-brand-dark/55">Contributors</dt><dd className="mt-1 text-sm text-brand-dark">{protectionView.sources.join(" · ")}</dd></div> : null}
              <div><dt className="text-xs font-semibold uppercase text-brand-dark/55">Required</dt><dd className="mt-1 text-sm text-brand-dark">{props.extension.required ? "Yes" : "No"}</dd></div>
              <div><dt className="text-xs font-semibold uppercase text-brand-dark/55">Delegated protection</dt><dd className="mt-1 text-sm text-brand-dark">{props.extension.delegated_protection === "package-firewall" ? "Package Firewall" : props.extension.delegated_protection ?? "None"}</dd></div>
            </dl>
            {props.extension.delegated_protection === "package-firewall" ? (
              <a href="/supply-chain" className="mt-4 inline-flex min-h-11 items-center gap-2 text-sm font-semibold text-brand-blue hover:underline">
                Open Package Firewall enforcement <HiMiniArrowTopRightOnSquare className="size-4" aria-hidden="true" />
              </a>
            ) : null}
          </article>
          <article className="rounded-3xl border border-slate-200 bg-white p-5 shadow-sm">
            <h2 className="text-lg font-semibold text-brand-dark">What this Extension protects</h2>
            <p className="mt-2 text-sm leading-6 text-brand-dark/75">Choose Permissions to review effective behavior, built-in floors, and settings you may tighten locally.</p>
            <dl className="mt-5 grid gap-4 sm:grid-cols-2">
              <div><dt className="text-xs font-semibold uppercase text-brand-dark/55">Permissions</dt><dd className="mt-1 text-sm text-brand-dark">{props.extension.permission_count}</dd></div>
              <div><dt className="text-xs font-semibold uppercase text-brand-dark/55">Detection rules</dt><dd className="mt-1 text-sm text-brand-dark">{props.extension.rule_count}</dd></div>
              <div><dt className="text-xs font-semibold uppercase text-brand-dark/55">Baseline floors</dt><dd className="mt-1 text-sm text-brand-dark">{[...new Set(props.extension.permissions.map((permission) => treatmentLabel(permission.baseline_floor)))].join(", ") || "Built-in"}</dd></div>
              <div><dt className="text-xs font-semibold uppercase text-brand-dark/55">Configurable</dt><dd className="mt-1 text-sm text-brand-dark">{props.extension.permissions.filter((permission) => permission.configurable).length} of {props.extension.permission_count}</dd></div>
            </dl>
          </article>
        </section>
      ) : null}
      {activeTab === "permissions" ? <div id="protection-panel-permissions" role="tabpanel" aria-labelledby="protection-tab-permissions" className="mt-6">
        <ExtensionPolicyPanel
          extension={props.extension}
          effective={props.effective}
          catalogDigest={props.catalogDigest}
          onRefresh={props.onRefresh}
          onDirtyChange={setPolicyDirty}
          cloudControlsUrl={cloudControlsUrl}
        />
      </div> : null}
      {activeTab === "managed-controls" ? <div id="protection-panel-managed-controls" role="tabpanel" aria-labelledby="protection-tab-managed-controls" className="mt-6">
        <ExtensionManagedControlsPanel
          extension={props.extension}
          effective={props.effective}
          runtime={props.runtime}
          onRefresh={props.onRefresh}
        />
      </div> : null}
      {activeTab === "activity" ? <div id="protection-panel-activity" role="tabpanel" aria-labelledby="protection-tab-activity" className="mt-6 space-y-6">
        <ExtensionActivity extension={props.extension} receipts={props.runtime?.latest_receipts ?? []} />
        <ProtectionTestLab extension={props.extension} />
      </div> : null}
      {activeTab === "technical" ? <div id="protection-panel-technical" role="tabpanel" aria-labelledby="protection-tab-technical" className="mt-6">
        <DeveloperModuleDetails extension={props.extension} effective={props.effective} catalogDigest={props.catalogDigest} />
      </div> : null}
    </div>
  );
}
