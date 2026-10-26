import { useCallback, useEffect, useState, type ComponentProps } from "react";

import { CATALOG_SNAPSHOT_EXPIRED, type CatalogReadModel } from "../extension-catalog-v2";
import { ExtensionControlApiError, type ExtensionCatalogItem, type ExtensionCatalogSummary } from "../extension-controls-api";
import { ProtectionModuleDetail } from "./protection-module-detail";
import { ExtensionsLoadError, ExtensionsLoadingState } from "./protection-workspace-states";

type DetailState =
  | { kind: "loading"; key: string }
  | { kind: "ready"; key: string; extension: ExtensionCatalogItem }
  | { kind: "error"; key: string; message: string; stale: boolean };

/**
 * Reads one extension's permissions, rules and MCP tools only when its page
 * opens. The list renders from index summaries and never loads details.
 */
export function CatalogExtensionDetail(props: Omit<ComponentProps<typeof ProtectionModuleDetail>, "extension"> & {
  readModel: CatalogReadModel;
  summary: ExtensionCatalogSummary;
}) {
  const { readModel, summary, ...detailProps } = props;
  const key = `${readModel.catalog_digest}|${summary.extension_id}|${summary.content_revision ?? ""}`;
  const [state, setState] = useState<DetailState>({ kind: "loading", key });
  const [attempt, setAttempt] = useState(0);
  useEffect(() => {
    let cancelled = false;
    setState({ kind: "loading", key });
    readModel.detail(summary.extension_id).then(
      (extension) => { if (!cancelled) setState({ kind: "ready", key, extension }); },
      (error: unknown) => {
        if (cancelled) return;
        const stale = error instanceof ExtensionControlApiError && error.code === CATALOG_SNAPSHOT_EXPIRED;
        setState({ kind: "error", key, stale, message: error instanceof Error ? error.message : "Extension details are unavailable" });
      },
    );
    return () => { cancelled = true; };
  }, [attempt, key, readModel, summary.extension_id]);
  const { onRefresh } = detailProps;
  const stale = state.kind === "error" && state.stale;
  // A replaced catalog snapshot needs a fresh index before the detail read. An
  // unchanged digest keeps the same read model, so the read is retried as well.
  const retry = useCallback(async () => {
    if (stale) await onRefresh();
    setAttempt((value) => value + 1);
  }, [onRefresh, stale]);

  if (state.key !== key || state.kind === "loading") return <ExtensionsLoadingState label="Loading extension" />;
  if (state.kind === "error") {
    return <ExtensionsLoadError title="Extension details unavailable" detail={state.message} onRetry={() => { void retry(); }} />;
  }
  return <ProtectionModuleDetail {...detailProps} extension={state.extension} />;
}
