import { useMemo, useState } from "react";
import {
  HiMiniArrowLeft,
  HiMiniArrowTopRightOnSquare,
  HiMiniCheckCircle,
  HiMiniLockClosed,
  HiMiniShieldCheck,
} from "react-icons/hi2";

import {
  controlProvenance,
  extensionEffectiveState,
  extensionStateLabel,
  permissionEffectiveState,
  permissionStateLabel,
  treatmentLabel,
} from "../extension-control-center-model";
import type {
  EffectiveExtensionControls,
  ExtensionCatalogItem,
  ExtensionPermission,
} from "../extension-controls-api";
import { commandReasonLabel } from "../command-activity/command-activity-presenters";
import { ExtensionPolicyPanel } from "../extension-policy-panel";
import { ProtectionDecisionBadge, ProtectionDensityControl, SettingSource, TechnicalDetails, useProtectionDensity, WhyThisHappened } from "./components/protection-primitives";
import { protectionCategoryForExtension } from "./model/protection-categories";
import { recentProtectionDecisions } from "./model/protection-landing";
import { ProtectionRepairCard } from "./protection-repair-card";
import { ProtectionTestLab } from "./protection-test-lab";
import { EXTENSION_KICKER_CLASS, EXTENSION_PANEL_CLASS, EXTENSION_SURFACE_CLASS, EXTENSION_TITLE_CLASS } from "./protection-surface";
import { useProtectionModuleActivity } from "./use-protection-module-activity";

function sourceForTarget(effective: EffectiveExtensionControls, targetKind: "extension" | "permission", targetId: string): "built-in" | "device" | "organization" {
  for (const layer of effective.layers) {
    if (!layer.controls.some((control) => control.target_kind === targetKind && control.target_id === targetId)) continue;
    return layer.kind === "signed-cloud" ? "organization" : "device";
  }
  return "built-in";
}

function plainBehavior(effective: EffectiveExtensionControls, extension: ExtensionCatalogItem): string {
  const state = extensionStateLabel(effective, extension);
  if (state === "Managed") return "Managed by your organization";
  if (state === "Required") return "Required protection";
  if (state === "Lockdown") return "Blocked by Emergency Lockdown";
  if (state === "Unavailable") return "Guard is staying fail-safe until protection can be verified";
  return state === "Allowed" ? "Guard evaluates matching actions normally" : "Matching actions are blocked on this device";
}

function permissionSummary(effective: EffectiveExtensionControls, extension: ExtensionCatalogItem, permission: ExtensionPermission) {
  const effectiveState = permissionEffectiveState(effective, extension, permission);
  const label = permissionStateLabel(effective, extension, permission);
  return {
    effectiveState,
    label,
    behavior: label === "Managed"
      ? "Managed by your organization"
      : label === "Required"
        ? "Required by Guard"
        : label === "Inherited"
          ? "Recommended"
          : effectiveState === "enabled"
            ? "Allowed within Guard safety rules"
            : "Blocked",
    source: sourceForTarget(effective, "permission", permission.permission_id),
  };
}

function safeReferenceUrl(value: string): string | null {
  try {
    const url = new URL(value);
    return url.protocol === "https:" || url.protocol === "http:" ? url.toString() : null;
  } catch {
    return null;
  }
}

function WhatThisProtects({ extension }: { extension: ExtensionCatalogItem }) {
  const category = protectionCategoryForExtension(extension);
  const examples = [
    ...extension.executables.slice(0, 4).map((item) => `Actions performed with ${item}`),
    ...extension.ecosystem_ids.slice(0, 3).map((item) => `${item} ecosystem operations`),
    ...extension.rules.slice(0, 3).map((rule) => rule.title),
  ].filter((value, index, all) => all.indexOf(value) === index).slice(0, 6);
  return (
    <section aria-labelledby="module-what-heading" className={EXTENSION_PANEL_CLASS}>
      <div className="flex items-start gap-3">
        <span className="grid size-10 shrink-0 place-items-center rounded-xl bg-blue-50 text-brand-blue">
          <HiMiniShieldCheck className="size-5" aria-hidden="true" />
        </span>
        <div>
          <h2 id="module-what-heading" className="text-lg font-semibold text-brand-dark">What this protects</h2>
          <p className="mt-1 text-sm leading-6 text-brand-dark/80">{extension.description}</p>
          <p className="mt-2 text-xs font-semibold text-brand-dark/80">{category.label}</p>
        </div>
      </div>
      <div className="mt-5">
        <h3 className="text-sm font-semibold text-brand-dark">Common examples</h3>
        {examples.length ? (
          <ul className="mt-2 grid gap-2 sm:grid-cols-2">
            {examples.map((example) => (
              <li key={example} className="rounded-xl bg-white/55 px-3 py-2 text-sm text-brand-dark/80">{example}</li>
            ))}
          </ul>
        ) : (
          <p className="mt-2 text-sm text-brand-dark/80">Guard applies this protection whenever the matching capability is detected.</p>
        )}
      </div>
    </section>
  );
}

function SimpleSettingsSummary(props: {
  extension: ExtensionCatalogItem;
  effective: EffectiveExtensionControls;
  onChange?: () => void;
}) {
  const configurable = props.extension.permissions.filter((permission) => permission.configurable);
  const blocked = props.extension.permissions.filter((permission) => permissionEffectiveState(props.effective, props.extension, permission) === "disabled").length;
  const source = sourceForTarget(props.effective, "extension", props.extension.extension_id);
  const canChange = props.effective.health === "protected" && configurable.length > 0;
  return (
    <section aria-labelledby="module-settings-heading" className={EXTENSION_PANEL_CLASS}>
      <div className="flex flex-col gap-4 sm:flex-row sm:items-start sm:justify-between">
        <div>
          <h2 id="module-settings-heading" className="text-lg font-semibold text-brand-dark">Protection settings</h2>
          <p className="mt-1 text-sm text-brand-dark/80">{plainBehavior(props.effective, props.extension)}.</p>
        </div>
        {props.onChange && canChange ? (
          <button type="button" onClick={props.onChange} className="min-h-11 shrink-0 rounded-xl border border-brand-blue/25 bg-white px-4 text-sm font-semibold text-brand-blue hover:bg-blue-50">
            Change settings
          </button>
        ) : null}
      </div>
      <div className="mt-4 flex flex-wrap gap-3 text-xs text-brand-dark/80">
        <SettingSource source={source} />
        <span>{configurable.length} changeable setting{configurable.length === 1 ? "" : "s"}</span>
        {blocked ? <span>{blocked} blocked setting{blocked === 1 ? "" : "s"}</span> : null}
      </div>
      {source === "organization" ? (
        <p className="mt-4 rounded-xl border border-indigo-200 bg-indigo-50 p-3 text-sm text-indigo-900">
          Your organization controls part of this protection. Local changes cannot weaken organization policy.
        </p>
      ) : null}
      {props.extension.required ? (
        <p className="mt-4 rounded-xl bg-white/55 p-3 text-sm text-brand-dark/80">
          This protection is required by Guard and cannot be turned off.
        </p>
      ) : null}
    </section>
  );
}

function ModuleRecentDecisions(props: { extension: ExtensionCatalogItem }) {
  const activity = useProtectionModuleActivity(props.extension.extension_id);
  const decisions = useMemo(() => recentProtectionDecisions(activity.items, [props.extension], 5), [activity.items, props.extension]);
  return (
    <section aria-labelledby="module-recent-heading" className={EXTENSION_PANEL_CLASS}>
      <h2 id="module-recent-heading" className="text-lg font-semibold text-brand-dark">Activity</h2>
      <p className="mt-1 text-sm text-brand-dark/80">Recent privacy-safe decisions on this device. Raw commands and paths are not shown.</p>
      <p className="mt-2 text-xs leading-5 text-brand-dark/80">Local activity works without Cloud. Guard Cloud adds longer retention, synchronization, advanced search, evidence exports, and team history according to your plan.</p>
      {activity.loading ? (
        <div className="guard-skeleton mt-4 h-20 w-full" aria-label="Loading recent decisions" />
      ) : activity.unavailable ? (
        <p className="mt-4 rounded-xl bg-white/55 p-3 text-sm text-brand-dark/80">Recent local activity is unavailable right now. This does not change the protection status above.</p>
      ) : decisions.length ? (
        <div className="mt-4 space-y-2">
          {decisions.map((decision) => (
            <article key={decision.activityId} className="rounded-2xl bg-white/55 px-3 py-3">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <ProtectionDecisionBadge result={decision.result} />
                <time dateTime={decision.occurredAt} className="text-xs text-brand-dark/80">{new Date(decision.occurredAt).toLocaleString()}</time>
              </div>
              <details className="mt-2">
                <summary className="cursor-pointer text-xs font-semibold text-brand-blue">Why?</summary>
                <p className="mt-2 text-sm leading-6 text-brand-dark/80">{commandReasonLabel(decision.reasonCode)}</p>
              </details>
            </article>
          ))}
        </div>
      ) : (
        <p className="mt-4 rounded-xl bg-white/55 p-3 text-sm text-brand-dark/80">No recent decisions are recorded for this protection yet.</p>
      )}
    </section>
  );
}

function AdvancedModuleDetails(props: { extension: ExtensionCatalogItem; effective: EffectiveExtensionControls }) {
  const source = sourceForTarget(props.effective, "extension", props.extension.extension_id);
  return (
    <div className="space-y-5">
      <section className={EXTENSION_PANEL_CLASS}>
        <h2 className="text-lg font-semibold text-brand-dark">Advanced protection details</h2>
        <dl className="mt-4 grid gap-4 sm:grid-cols-2">
          <div>
            <dt className="text-xs font-semibold uppercase tracking-wide text-brand-dark/80">Current behavior</dt>
            <dd className="mt-1 text-sm text-brand-dark/80">{plainBehavior(props.effective, props.extension)}</dd>
          </div>
          <div>
            <dt className="text-xs font-semibold uppercase tracking-wide text-brand-dark/80">Setting source</dt>
            <dd className="mt-1"><SettingSource source={source} /></dd>
          </div>
          <div>
            <dt className="text-xs font-semibold uppercase tracking-wide text-brand-dark/80">Required</dt>
            <dd className="mt-1 text-sm text-brand-dark/80">{props.extension.required ? "Yes" : "No"}</dd>
          </div>
          <div>
            <dt className="text-xs font-semibold uppercase tracking-wide text-brand-dark/80">Changeable settings</dt>
            <dd className="mt-1 text-sm text-brand-dark/80">{props.extension.permissions.filter((item) => item.configurable).length} of {props.extension.permissions.length}</dd>
          </div>
        </dl>
        {props.extension.dependencies.length || props.extension.conflicts.length ? (
          <div className="mt-5 grid gap-3 sm:grid-cols-2">
            <div className="rounded-xl bg-white/55 p-3">
              <div className="text-xs font-semibold text-brand-dark/80">Depends on</div>
              <div className="mt-1 text-sm text-brand-dark/80">{props.extension.dependencies.length ? props.extension.dependencies.join(", ") : "None"}</div>
            </div>
            <div className="rounded-xl bg-white/55 p-3">
              <div className="text-xs font-semibold text-brand-dark/80">Conflicts with</div>
              <div className="mt-1 text-sm text-brand-dark/80">{props.extension.conflicts.length ? props.extension.conflicts.join(", ") : "None"}</div>
            </div>
          </div>
        ) : null}
      </section>
      <section className={EXTENSION_PANEL_CLASS}>
        <h2 className="text-lg font-semibold text-brand-dark">Protection settings</h2>
        <div className="mt-4 space-y-3">
          {props.extension.permissions.map((permission) => {
            const summary = permissionSummary(props.effective, props.extension, permission);
            return (
              <article key={permission.permission_id} className="rounded-2xl bg-white/55 p-4">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <strong className="text-sm text-brand-dark">{permission.label}</strong>
                  <span className="text-xs font-semibold text-brand-dark/80">{summary.behavior}</span>
                </div>
                <p className="mt-1 text-sm text-brand-dark/80">{permission.description}</p>
                <div className="mt-2 flex flex-wrap gap-3 text-xs text-brand-dark/80">
                  <SettingSource source={summary.source} />
                  <span>{permission.configurable ? "Changeable" : "Fixed"}</span>
                  <span>Minimum: {treatmentLabel(permission.baseline_floor)}</span>
                </div>
                {!permission.configurable && permission.fixed_reason ? (
                  <p className="mt-3 rounded-xl bg-white/55 p-3 text-xs leading-5 text-brand-dark/80">{permission.fixed_reason}</p>
                ) : null}
              </article>
            );
          })}
        </div>
      </section>
    </div>
  );
}

function DeveloperModuleDetails(props: { extension: ExtensionCatalogItem; effective: EffectiveExtensionControls; catalogDigest: string }) {
  return (
    <TechnicalDetails title="Developer details">
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
          <div className="mt-3 max-h-96 overflow-auto rounded-xl border border-[rgba(63,65,116,0.12)]">
            <table className="min-w-full text-left text-xs">
              <thead className="sticky top-0 bg-white/55 text-brand-dark/80">
                <tr>
                  <th className="px-3 py-2">Detection</th>
                  <th className="px-3 py-2">Severity</th>
                  <th className="px-3 py-2">Matcher</th>
                  <th className="px-3 py-2">Default</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[rgba(63,65,116,0.08)]">
                {props.extension.rules.map((rule) => (
                  <tr key={rule.rule_id}>
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
              <div key={permission.permission_id} className="rounded-xl bg-white p-3">
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
  onBack: () => void;
  onRefresh: () => Promise<void> | void;
}) {
  const [density, setDensity] = useProtectionDensity();
  const [editing, setEditing] = useState(false);
  const [policyDirty, setPolicyDirty] = useState(false);
  const category = protectionCategoryForExtension(props.extension);
  const state = extensionEffectiveState(props.effective, props.extension);
  const handleBack = () => {
    if (policyDirty && !window.confirm("Discard your unreviewed protection setting changes?")) return;
    props.onBack();
  };
  const settingSource = sourceForTarget(props.effective, "extension", props.extension.extension_id);
  let whySummary = "Guard is using its built-in recommended behavior for this protection.";
  if (settingSource === "organization") {
    whySummary = "Your organization's signed policy is contributing to the current behavior. Local changes cannot weaken it.";
  } else if (settingSource === "device") {
    whySummary = "A protection setting on this device contributes to the current behavior.";
  }
  const statusTone = state === "enabled"
    ? "border-emerald-200 bg-emerald-50 text-emerald-800"
    : "border-red-200 bg-red-50 text-red-800";

  return (
    <main data-testid="protection-module-detail" className={`${EXTENSION_SURFACE_CLASS} mx-auto w-full max-w-6xl px-4 pb-10 pt-5 sm:px-6 lg:px-8`}>
      <div className="flex flex-wrap items-center justify-between gap-3">
        <button type="button" onClick={handleBack} className="inline-flex min-h-11 items-center gap-2 rounded-lg px-2 text-sm font-semibold text-brand-dark/80 hover:bg-white/70">
          <HiMiniArrowLeft className="size-4" aria-hidden="true" />
          Extensions
        </button>
        <ProtectionDensityControl value={density} onChange={setDensity} />
      </div>
      <header className={`mt-3 ${EXTENSION_PANEL_CLASS}`}>
        <div className="flex flex-col gap-5 lg:flex-row lg:items-start lg:justify-between">
          <div>
            <p className={EXTENSION_KICKER_CLASS}>Extension</p>
            <h1 className={EXTENSION_TITLE_CLASS}>{props.extension.name}</h1>
            <p className="mt-2 text-sm font-medium text-brand-dark/80">{category.label}</p>
            <p className="mt-4 max-w-3xl text-sm leading-6 text-brand-dark/80">{props.extension.description}</p>
          </div>
          <span className={`inline-flex rounded-full border px-3 py-1.5 text-xs font-semibold ${statusTone}`}>
            {plainBehavior(props.effective, props.extension)}
          </span>
        </div>
        {props.effective.global_lockdown ? (
          <p role="status" className="mt-5 flex gap-2 rounded-xl bg-brand-dark p-3 text-sm text-[#f8fbff]">
            <HiMiniLockClosed className="mt-0.5 size-4 shrink-0" />
            Emergency Lockdown currently controls this module. Matching optional actions remain blocked.
          </p>
        ) : null}
      </header>
      <ProtectionRepairCard effective={props.effective} onRefresh={props.onRefresh} />
      <div className="mt-6 grid gap-5 lg:grid-cols-2">
        <WhatThisProtects extension={props.extension} />
        <SimpleSettingsSummary extension={props.extension} effective={props.effective} onChange={() => setEditing(true)} />
      </div>
      {editing ? (
        <div className="mt-5">
          <ExtensionPolicyPanel extension={props.extension} effective={props.effective} catalogDigest={props.catalogDigest} onRefresh={props.onRefresh} onDirtyChange={setPolicyDirty} />
        </div>
      ) : null}
      <div className="mt-5">
        <WhyThisHappened summary={whySummary} />
      </div>
      <div className="mt-5 grid gap-5 lg:grid-cols-2">
        <section className={EXTENSION_PANEL_CLASS}>
          <h2 className="text-lg font-semibold text-brand-dark">Safer alternatives</h2>
          {props.extension.safer_alternatives.length ? (
            <ul className="mt-3 space-y-2">
              {props.extension.safer_alternatives.map((alternative) => (
                <li key={alternative} className="flex gap-2 text-sm leading-6 text-brand-dark/80">
                  <HiMiniCheckCircle className="mt-1 size-4 shrink-0 text-emerald-800" aria-hidden="true" />
                  {alternative}
                </li>
              ))}
            </ul>
          ) : (
            <p className="mt-2 text-sm text-brand-dark/80">No module-level alternative is registered. Guard still evaluates each matching action using its built-in safety rules.</p>
          )}
          {props.extension.reference_urls.length ? (
            <div className="mt-4 flex flex-wrap gap-2">
              {props.extension.reference_urls.slice(0, 4).map((value) => {
                const href = safeReferenceUrl(value);
                return href ? (
                  <a key={value} href={href} target="_blank" rel="noopener noreferrer" referrerPolicy="no-referrer" className="inline-flex min-h-10 items-center gap-2 rounded-xl border border-[rgba(63,65,116,0.16)] px-3 text-xs font-semibold text-brand-blue">
                    Reference <HiMiniArrowTopRightOnSquare className="size-4" aria-hidden="true" />
                  </a>
                ) : null;
              })}
            </div>
          ) : null}
        </section>
        <ModuleRecentDecisions extension={props.extension} />
      </div>
      <div className="mt-5">
        <ProtectionTestLab extension={props.extension} />
      </div>
      {density !== "simple" ? (
        <div className="mt-6">
          <AdvancedModuleDetails extension={props.extension} effective={props.effective} />
        </div>
      ) : null}
      {density === "developer" ? (
        <div className="mt-6">
          <DeveloperModuleDetails extension={props.extension} effective={props.effective} catalogDigest={props.catalogDigest} />
        </div>
      ) : null}
    </main>
  );
}
