import { useCallback, useState } from "react";

import {
  extensionDisplayName,
  extensionStateLabel,
} from "../extension-control-center-model";
import type { EffectiveExtensionControls, ExtensionCatalogItem } from "../extension-controls-api";
import { addedCustomExtensions, type LocalCliItem } from "../local-cli-api";
import { WorkspacePageHeader } from "../workspace-page-header";
import {
  AddCustomExtensionButton,
  CustomExtensionsSection,
} from "./local-clis-panel";
import { PatternSearchConsole } from "./components/pattern-search-console";
import {
  InlineError,
  ProtectionModuleRow,
  ProtectionStatusHero,
} from "./components/protection-primitives";
import { PROTECTION_TERMS } from "./copy/protection-copy";
import type { ProtectionStatusView } from "./model/protection-presentation";
import { extensionProtectionSource } from "../managed-controls/extension-managed-controls-panel";

function sourceIsManaged(effective: EffectiveExtensionControls, extensionId: string): boolean {
  return effective.layers.some((layer) =>
    layer.kind === "signed-cloud"
    && layer.controls.some((control) =>
      control.target_kind === "extension" && control.target_id === extensionId
    ));
}

/**
 * The row's second line carries the state only when it deviates from the
 * default. A healthy, enabled tool has nothing to decide, so the line shows
 * the tool's executables (or its description) instead — information that
 * helps recognition rather than repeating "Allowed" fifty-nine times.
 */
function catalogRowSecondLine(extension: ExtensionCatalogItem, state: string): string {
  if (state === "Blocked" || state === "Managed" || state === "Lockdown" || state === "Unavailable") return state;
  if (extension.trust_class === "external" && !extension.enabled) return "Off until you turn it on";
  const executables = extension.executables.join(" · ").trim();
  return executables || extension.description;
}

function CatalogExtensionRow(props: {
  extension: ExtensionCatalogItem;
  effective: EffectiveExtensionControls;
  onOpen: (extension: ExtensionCatalogItem) => void;
}) {
  const handleOpen = useCallback(() => {
    props.onOpen(props.extension);
  }, [props]);
  const source = extensionProtectionSource(props.effective, props.extension);
  const cloudSource = source === "Synced from Guard Cloud" || source.startsWith("Managed by ");
  return (
    <ProtectionModuleRow
      extensionId={props.extension.extension_id}
      name={extensionDisplayName(props.extension.name)}
      description={props.extension.description}
      behavior={catalogRowSecondLine(props.extension, extensionStateLabel(props.effective, props.extension))}
      required={props.extension.required}
      external={props.extension.trust_class === "external"}
      managed={cloudSource || sourceIsManaged(props.effective, props.extension.extension_id)}
      managedLabel={cloudSource ? source : undefined}
      executables={props.extension.executables}
      ecosystemIds={props.extension.ecosystem_ids}
      onOpen={handleOpen}
    />
  );
}

export function ExtensionsOverview(props: {
  catalogExtensions: ExtensionCatalogItem[];
  effective: EffectiveExtensionControls;
  localCliItems: LocalCliItem[];
  localCliError: string | null;
  mutationError: string | null;
  recoveryStatus: string | null;
  healthBroken: boolean;
  status: ProtectionStatusView;
  active: boolean;
  onPrimaryStatusAction?: () => void;
  onRefresh: () => Promise<void> | void;
  onOpenExtension: (extension: ExtensionCatalogItem) => void;
  onOpenLocalCli: (cliId: string) => void;
  onAddCustom: () => void;
}) {
  const [query, setQuery] = useState("");
  // An active search replaces the catalogs below it: results, then the Tools
  // match group. Rendering the full list under the results would force the
  // operator to visually skip fifty-nine unchanged rows.
  const searching = query.trim().length > 0;
  // Suggestion-only responses (discovered servers, observed CLIs not yet
  // added) render no custom section: the section lists added extensions, and
  // its Add button would otherwise be the section's only content.
  const addedCustomCount = addedCustomExtensions(props.localCliItems).length;
  return (
    <div hidden={!props.active} inert={!props.active || undefined}>
      <WorkspacePageHeader
        eyebrow="On this device"
        title={PROTECTION_TERMS.pageTitle}
        description="Choose an Extension to review its permissions and effective protection."
      />
      <div className="mt-6">
        <ProtectionStatusHero
          status={props.status}
          onPrimaryAction={props.status.primaryAction === "review-lockdown" ? props.onPrimaryStatusAction : undefined}
        />
        {props.recoveryStatus && !props.healthBroken ? (
          <p role="status" className="mt-3 text-sm font-medium text-emerald-800">{props.recoveryStatus}</p>
        ) : null}
      </div>
      {props.mutationError ? (
        <div className="mt-4">
          <InlineError message={props.mutationError} />
        </div>
      ) : null}
      {props.localCliError ? (
        <div className="mt-4">
          <InlineError message={props.localCliError} />
        </div>
      ) : null}

      <PatternSearchConsole
        catalog={props.catalogExtensions}
        effective={props.effective}
        active={props.active}
        query={query}
        onQueryChange={setQuery}
        onRefresh={props.onRefresh}
        onOpenExtension={props.onOpenExtension}
        actionSlot={searching ? <AddCustomExtensionButton onClick={props.onAddCustom} /> : null}
      />

      {searching ? null : (
        <>
          {addedCustomCount ? (
            <CustomExtensionsSection
              items={props.localCliItems}
              onOpen={props.onOpenLocalCli}
              onAdd={props.onAddCustom}
            />
          ) : null}

          <section className="mt-10" aria-labelledby="all-tools-heading">
            <div className="flex flex-col gap-1 sm:flex-row sm:items-end sm:justify-between">
              <div>
                <h2 id="all-tools-heading" className="text-xl font-semibold tracking-tight text-brand-dark">All tools</h2>
                <p className="mt-1 text-sm text-slate-500">Every built-in tool Guard can watch on this device. Open one to adjust its command patterns.</p>
              </div>
              <div className="flex flex-wrap items-center gap-3">
                {addedCustomCount ? null : <AddCustomExtensionButton onClick={props.onAddCustom} />}
                <span className="text-sm text-brand-dark/70">{props.catalogExtensions.length} tools</span>
              </div>
            </div>
            <div className="mt-4">
              {props.catalogExtensions.map((extension) => (
                <CatalogExtensionRow
                  key={extension.extension_id}
                  extension={extension}
                  effective={props.effective}
                  onOpen={props.onOpenExtension}
                />
              ))}
            </div>
          </section>
        </>
      )}

    </div>
  );
}
