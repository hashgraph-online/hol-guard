import { useCallback, useMemo, useRef } from "react";
import { HiMiniFunnel, HiMiniGlobeAlt } from "react-icons/hi2";

import {
  catalogRowSecondLine,
  extensionDisplayName,
  extensionStateLabel,
} from "../extension-control-center-model";
import type { EffectiveExtensionControls, ExtensionCatalogSummary } from "../extension-controls-api";
import { extensionProtectionSource } from "../managed-controls/extension-managed-controls-panel";
import { useDiscoveryMeasurement } from "./discovery-measurement";
import {
  featuredWindowLabel,
  sponsoredCardLabel,
  type JoinedDiscoveryCard,
} from "./extensions-discover-model";
import {
  ExtensionStatePill,
  extensionStatePillLabel,
  ProtectionModuleRow,
  type ExtensionRowState,
} from "./components/protection-primitives";

function sourceIsManaged(effective: EffectiveExtensionControls, extensionId: string): boolean {
  return effective.layers.some((layer) =>
    layer.kind === "signed-cloud"
    && layer.controls.some((control) =>
      control.target_kind === "extension" && control.target_id === extensionId
    ));
}

export function CatalogExtensionRow(props: {
  extension: ExtensionCatalogSummary;
  effective: EffectiveExtensionControls;
  onOpen: (extension: ExtensionCatalogSummary) => void;
}) {
  const handleOpen = useCallback(() => {
    props.onOpen(props.extension);
  }, [props]);
  const source = extensionProtectionSource(props.effective, props.extension);
  const cloudSource = source === "Synced from Guard Cloud" || source.startsWith("Managed by ");
  const state = extensionStateLabel(props.effective, props.extension);
  return (
    <ProtectionModuleRow
      extensionId={props.extension.extension_id}
      name={extensionDisplayName(props.extension.name)}
      description={props.extension.description}
      behavior={catalogRowSecondLine(props.extension, state)}
      state={state}
      ruleCount={props.extension.rule_count}
      permissionCount={props.extension.permission_count}
      publisher={props.extension.publisher?.displayName}
      required={props.extension.required}
      mcp={props.extension.surface === "mcp"}
      external={props.extension.trust_class === "external"}
      managed={cloudSource || sourceIsManaged(props.effective, props.extension.extension_id)}
      managedLabel={cloudSource ? source : undefined}
      executables={props.extension.executables}
      ecosystemIds={props.extension.ecosystem_ids}
      onOpen={handleOpen}
    />
  );
}

/**
 * A paid featured row in the Manage list. The label, who paid, and the
 * advertiser headline sit above the ordinary row, which keeps its real
 * protection state: payment buys position, never trust.
 */
export function PaidCatalogRow(props: {
  entry: JoinedDiscoveryCard;
  snapshotId: string | null;
  effective: EffectiveExtensionControls;
  onOpen: (extension: ExtensionCatalogSummary) => void;
}) {
  const ref = useRef<HTMLDivElement | null>(null);
  const featured = props.entry.placement.product !== "sponsored";
  const recordOpen = useDiscoveryMeasurement(
    ref,
    props.snapshotId,
    props.entry.placement,
    featured ? "extensions_featured" : "extensions_feed",
  );
  const { onOpen } = props;
  const open = useCallback((extension: ExtensionCatalogSummary) => {
    recordOpen();
    onOpen(extension);
  }, [onOpen, recordOpen]);
  const { placement } = props.entry;
  const brand = placement.creative.brandName?.trim();
  const headline = placement.creative.headline?.trim();
  const window = featuredWindowLabel(placement);
  return (
    <div
      ref={ref}
      className="guard-featured-row"
      data-testid="catalog-featured-row"
      data-sponsored-placement-id={placement.publicPlacementId}
    >
      <div className="flex flex-wrap items-center gap-x-2 gap-y-1 px-4 pt-3">
        <span className="guard-sponsor-label" data-sponsored-label>{sponsoredCardLabel(featured)}</span>
        {brand ? <span className="text-xs text-brand-dark/60">Paid for by <span className="font-semibold text-brand-dark">{brand}</span></span> : null}
        {window ? <span className="text-xs text-brand-dark/60">{window}</span> : null}
        {headline ? <span className="basis-full text-sm font-medium text-brand-dark/80">{headline}</span> : null}
      </div>
      <CatalogExtensionRow extension={props.entry.catalog} effective={props.effective} onOpen={open} />
    </div>
  );
}

export function ConnectorDiscoveryControl(props: {
  discovering: boolean;
  showProgress: boolean;
  error: string | null;
  onRetry: () => void;
}) {
  const message = props.discovering
    ? (props.showProgress ? "Checking host connections…" : "")
    : (props.error ?? "");
  return (
    <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
      <p aria-live="polite" aria-atomic="true" className="text-sm text-brand-dark/70">{message}</p>
      {props.discovering ? null : (
        <button
          type="button"
          className="inline-flex min-h-11 items-center rounded-lg text-sm font-semibold text-brand-blue hover:text-brand-dark focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-brand-blue"
          onClick={props.onRetry}
        >
          {props.error ? "Check for connectors again" : "Check host connections"}
        </button>
      )}
    </div>
  );
}

export function CatalogFilterEmpty(props: { onClear: () => void }) {
  return (
    <div className="mt-6 flex flex-col items-start gap-1 rounded-2xl border border-dashed border-[rgba(63,65,116,0.2)] bg-white px-5 py-8 sm:items-center sm:text-center">
      <span className="mb-2 grid size-10 place-items-center rounded-full bg-brand-blue/10 text-brand-blue" aria-hidden="true">
        <HiMiniFunnel className="size-5" />
      </span>
      <p className="text-sm font-semibold text-brand-dark">No extensions match these filters.</p>
      <p className="max-w-[46ch] text-sm leading-6 text-brand-dark/70">Remove a filter or start over to see the full catalog again.</p>
      <button type="button" className="guard-extensions-chip mt-1" onClick={props.onClear}>
        Clear filters
      </button>
    </div>
  );
}

const POSTURE_ORDER: readonly ExtensionRowState[] = ["Allowed", "Required", "Managed", "Blocked", "Lockdown", "Unavailable"];

/**
 * One glance at what Guard is doing across the whole catalog: how many tools
 * run, how many are held back, and how many came from outside the built-ins.
 */
export function CatalogPostureSummary(props: {
  extensions: readonly ExtensionCatalogSummary[];
  effective: EffectiveExtensionControls;
}) {
  const { counts, external } = useMemo(() => {
    const tally = new Map<ExtensionRowState, number>();
    let externalCount = 0;
    for (const extension of props.extensions) {
      const state = extensionStateLabel(props.effective, extension);
      tally.set(state, (tally.get(state) ?? 0) + 1);
      if (extension.trust_class === "external") externalCount += 1;
    }
    return { counts: POSTURE_ORDER.flatMap((state) => (tally.get(state) ? [{ state, count: tally.get(state) ?? 0 }] : [])), external: externalCount };
  }, [props.effective, props.extensions]);
  const total = props.extensions.length;
  if (total === 0) return null;
  return (
    <div className="mt-4 rounded-2xl border border-[rgba(63,65,116,0.1)] bg-white px-4 py-3" data-testid="catalog-posture-summary">
      <div className="guard-posture-bar" role="img" aria-label={counts.map(({ state, count }) => `${count} ${extensionStatePillLabel(state).toLowerCase()}`).join(", ")}>
        {counts.map(({ state, count }) => (
          <span key={state} className="guard-posture-segment" data-state={state} style={{ flexGrow: count }} />
        ))}
      </div>
      <ul className="mt-3 flex flex-wrap items-center gap-x-4 gap-y-2" aria-label="Catalog status">
        {counts.map(({ state, count }) => (
          <li key={state} className="inline-flex items-center gap-1.5 text-sm text-brand-dark/75">
            <ExtensionStatePill state={state} />
            <span className="font-semibold tabular-nums text-brand-dark">{count}</span>
          </li>
        ))}
        {external > 0 ? (
          <li className="inline-flex items-center gap-1.5 text-sm text-brand-dark/70 sm:ml-auto">
            <HiMiniGlobeAlt className="size-4 text-brand-dark/45" aria-hidden="true" />
            <span><span className="font-semibold tabular-nums text-brand-dark">{external}</span> from outside the built-ins</span>
          </li>
        ) : null}
      </ul>
    </div>
  );
}

/**
 * The scan failure, on the list the reader is looking at. The custom list
 * carries the full control, so a failed scan would otherwise sit behind a
 * switch the reader has no reason to press. The status region stays mounted
 * so the message is announced when it arrives.
 */
export function ConnectorDiscoveryNotice(props: { error: string | null; onRetry: () => void }) {
  return (
    <div role="status" className={props.error ? "mt-3 flex flex-wrap items-center gap-x-3 gap-y-1" : undefined}>
      {props.error ? (
        <>
          <p className="text-sm text-brand-dark/70">{props.error}</p>
          <button
            type="button"
            className="inline-flex min-h-11 items-center rounded-lg text-sm font-semibold text-brand-blue hover:text-brand-dark focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-brand-blue"
            onClick={props.onRetry}
          >
            Check for connectors again
          </button>
        </>
      ) : null}
    </div>
  );
}
