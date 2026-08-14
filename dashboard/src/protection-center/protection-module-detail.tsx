import { useEffect, useState } from "react";
import { HiMiniArrowLeft, HiMiniLockClosed } from "react-icons/hi2";

import { controlProvenance, permissionForRule, treatmentLabel } from "../extension-control-center-model";
import type { EffectiveExtensionControls, ExtensionCatalogItem } from "../extension-controls-api";
import { ExtensionPolicyPanel } from "../extension-policy-panel";
import { ProtectionDensityControl, TechnicalDetails, useProtectionDensity } from "./components/protection-primitives";
import { ProtectionRepairCard } from "./protection-repair-card";
import { ProtectionTestLab } from "./protection-test-lab";
import { EXTENSION_SURFACE_CLASS, EXTENSION_TITLE_CLASS } from "./protection-surface";

function sourceForTarget(
  effective: EffectiveExtensionControls,
  targetKind: "extension" | "permission",
  targetId: string,
): "built-in" | "device" | "organization" {
  for (const layer of effective.layers) {
    if (!layer.controls.some((control) => control.target_kind === targetKind && control.target_id === targetId)) continue;
    return layer.kind === "signed-cloud" ? "organization" : "device";
  }
  return "built-in";
}

function requiredLine(extension: ExtensionCatalogItem): string | null {
  if (!extension.required) return null;
  return "This tool stays on. Individual command patterns below can follow recommended settings or be blocked on this device.";
}

function DeveloperModuleDetails(props: {
  extension: ExtensionCatalogItem;
  effective: EffectiveExtensionControls;
  catalogDigest: string;
}) {
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
  onBack: () => void;
  onRefresh: () => Promise<void> | void;
  onRequestExtensionChange?: (extension: ExtensionCatalogItem, enabled: boolean) => void;
}) {
  const [density, setDensity] = useProtectionDensity();
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
  const extensionEnabled = !props.effective.layers.some((layer) =>
    layer.controls.some((control) => control.target_kind === "extension" && control.target_id === props.extension.extension_id && control.state === "disabled"),
  );
  const orgManaged = sourceForTarget(props.effective, "extension", props.extension.extension_id) === "organization";
  const handleBack = () => {
    if (policyDirty && !window.confirm("Discard your unreviewed protection setting changes?")) return;
    props.onBack();
  };

  return (
    <main data-testid="protection-module-detail" className={`${EXTENSION_SURFACE_CLASS} mx-auto w-full max-w-3xl px-4 pb-10 pt-5 sm:px-6`}>
      <button type="button" onClick={handleBack} className="inline-flex min-h-11 items-center gap-2 rounded-lg px-1 text-sm font-semibold text-brand-dark/80 hover:text-brand-dark">
        <HiMiniArrowLeft className="size-4" aria-hidden="true" />
        Extensions
      </button>
      <header className="mt-4 border-b border-[rgba(63,65,116,0.12)] pb-5">
        <p className="text-xs font-semibold uppercase tracking-[0.14em] text-brand-dark/55">Extension</p>
        <h1 className={EXTENSION_TITLE_CLASS}>{props.extension.name}</h1>
        {requiredNote ? <p className="mt-3 max-w-2xl text-sm leading-6 text-brand-dark/80">{requiredNote}</p> : (
          <p className="mt-3 max-w-2xl text-sm leading-6 text-brand-dark/80">{props.extension.description}</p>
        )}
        {props.extension.required ? (
          <p className="mt-2 text-sm text-brand-dark/70">This protection is required by Guard and cannot be turned off.</p>
        ) : props.onRequestExtensionChange ? (
          <div className="mt-3 flex flex-wrap items-center gap-3">
            <button
              type="button"
              role="switch"
              aria-checked={extensionEnabled}
              disabled={props.effective.health !== "protected"}
              onClick={() => props.onRequestExtensionChange?.(props.extension, !extensionEnabled)}
              className="guard-tool-switch"
              data-testid="extension-availability-switch"
            >
              <span className="guard-tool-switch-knob" />
            </button>
            <div>
              <p className="text-sm font-semibold text-brand-dark">Commands available</p>
              <p className="text-xs leading-5 text-brand-dark/75">
                {extensionEnabled
                  ? "Matching commands follow the protection settings below. Turn off to block every command this tool owns on this device."
                  : "Every command this tool owns is blocked on this device. Turn on to follow the protection settings below."}
              </p>
            </div>
          </div>
        ) : null}
        {orgManaged ? (
          <p className="mt-2 text-sm text-brand-dark/80">Your organization controls part of this protection. Local changes cannot weaken organization policy.</p>
        ) : null}
        {props.effective.global_lockdown ? (
          <p role="status" className="mt-4 flex gap-2 text-sm text-brand-dark">
            <HiMiniLockClosed className="mt-0.5 size-4 shrink-0" />
            Emergency Lockdown currently controls this module. Matching optional actions remain blocked.
          </p>
        ) : null}
      </header>
      <ProtectionRepairCard effective={props.effective} onRefresh={props.onRefresh} />
      <div className="mt-2">
        <ExtensionPolicyPanel
          extension={props.extension}
          effective={props.effective}
          catalogDigest={props.catalogDigest}
          onRefresh={props.onRefresh}
          onDirtyChange={setPolicyDirty}
        />
      </div>
      <div className="mt-10">
        <ProtectionTestLab extension={props.extension} />
      </div>
      <details className="mt-8" data-testid="protection-more-detail">
        <summary className="cursor-pointer text-sm font-semibold text-brand-dark">More detail</summary>
        <div className="mt-3">
          <ProtectionDensityControl value={density} onChange={setDensity} />
        </div>
      </details>
      {density === "developer" ? (
        <div className="mt-6">
          <DeveloperModuleDetails extension={props.extension} effective={props.effective} catalogDigest={props.catalogDigest} />
        </div>
      ) : null}
    </main>
  );
}
