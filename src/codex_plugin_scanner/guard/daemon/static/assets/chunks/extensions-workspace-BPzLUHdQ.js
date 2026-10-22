import { r as reactExports, bt as fetchExtensionCatalog, bu as ExtensionControlApiError, bv as normalizeExtensionCatalogSummary, bw as normalizeExtensionPermission, bx as ExtensionControlProtocolError, by as normalizeExtensionCatalogItem, bz as guardApiCacheScope, bA as fetchExtensionCatalogV2Api, bB as localPermissionDraftState, bC as setLocalPermissionDraftState, bD as extensionPolicyAuthorityUnchanged, bE as newExtensionPolicyDraftIdentity, bF as extensionPolicyDraftIsDirty, bG as setLocalPermissionDraftStates, bH as buildExtensionPolicyDraftMutation, bI as fetchEffectiveExtensionControls, bJ as previewExtensionMutation, bK as isCurrentExtensionPolicyDraft, bL as applyExtensionMutation, bM as fetchExtensionControlHistory, j as jsxRuntimeExports, bN as managedPermissionState, Z as HiMiniSparkles, s as HiMiniCheckCircle, g as HiMiniNoSymbol, v as HiMiniLockClosed, a4 as HiMiniExclamationTriangle, bO as controlProvenance, bP as treatmentLabel, aR as isApprovalProofSubmitDisabled, _ as HiMiniXMark, aQ as ApprovalProofFieldInputs, bQ as useResolvedApprovalGate, bR as groupPermissionsByFamily, d as HiMiniArrowPath, R as HiMiniShieldCheck, bS as HiMiniInformationCircle, aS as buildApprovalProofCredentials, bT as LocalCliApiError, bU as approvalProofRecentlySatisfied, p as HiMiniMagnifyingGlass, bV as bulkCommandState, H as HiMiniChevronRight, bW as fetchLocalCliApi, bX as ExtensionBrandMark, c as HiMiniChevronDown, bY as fetchMcpProviderActions, bZ as previewLocalCliMutation, b_ as applyLocalCliMutation, b$ as LOCAL_CLI_CAPABILITIES, c0 as readJson, c1 as enrollablePackageScriptCommands, c2 as seenSuggestionMeta, c3 as HiMiniPlus, c4 as looksLikeProjectRelocatePaste, c5 as packageScriptFilterNeedle, e as HiMiniCheck, c6 as suggestedPackageScriptExtensions, c7 as filterExtensionSuggestions, c8 as suggestedHarnessExtensions, c9 as suggestedSeenExtensions, ca as keepsPackageScriptCatalog, cb as recognizeLocalCli, cc as preferredPackageScriptExtension, cd as looksLikePackageScriptPaste, ce as enrollmentCommandStates, cf as isBulkApproveGateReady, cg as HiMiniArrowLeft, ch as fetchLocalCliList, ci as normalizeLocalCliList, cj as refreshMcpInventory, ck as startGuardCloudConnect, cl as extensionEffectiveState, cm as permissionEffectiveState, cn as HiMiniArrowTopRightOnSquare, a0 as HiMiniCloud, co as fetchExtensionControlApi, cp as permissionForRule, cq as refreshEffectiveExtensionControls, aD as HiMiniClipboardDocumentCheck, aE as HiMiniClipboard, aG as ApprovalProofModal, cr as fetchExtensionDiscoveryApi, t as HiMiniArrowRight, cs as HiMiniClock, B as createCommandActivityClient, C as fetchCommandActivityApi, ct as startCancelableDiscoveryJob, cu as waitForMcpDiscoveryJob, cv as isLocalCliId, bc as guardAwareHref, cw as localCliHref, cx as filterCodexHostApps, cy as connectorWorkspaceItems, cz as customExtensionNeedsReview, aM as HiMiniAdjustmentsHorizontal, cA as extensionDisplayName, cB as catalogRowSecondLine, cC as extensionStateLabel, cD as HiMiniGlobeAlt, cE as HiMiniFunnel, cF as discoveryFailureMessage, ba as WorkspacePageHeader, cG as refreshCodexHostInventory, cH as CODEX_HOST_FALLBACK, cI as CONFIGURED_CONNECTIONS_FALLBACK, cJ as loadCurrentDashboardBuild, cK as canonicalExtensionId, cL as extensionDetailHref, cM as DEFAULT_EXTENSION_DETAIL_URL_STATE, cN as acknowledgeDegradedExtensionControlAuthority, cO as recoverExtensionControlAuthority, cP as readExtensionDetailUrlState, cQ as parseProtectionRoute, cR as addCustomExtensionHref } from "../guard-dashboard.js";
import { u as useConfirmDialog } from "./confirm-dialog-DoiBaaXB.js";
const PROFILE_SETUP_COMMANDS = { wrangler: "npx wrangler" };
const PROFILE_COMMAND_PARAM = "command";
function profileSetupCommand(item) {
  return item.profile_id ? PROFILE_SETUP_COMMANDS[item.profile_id] ?? null : null;
}
function customExtensionDisplayName(item) {
  return item.display_name ?? item.name;
}
function customExtensionBadge(item) {
  if (item.seeded === true) return "Set up";
  if (item.surface === "cli" && item.state === "unset" && item.suggestable) return "Detected";
  return null;
}
function hasSuggestedRules(item) {
  return item.commands.some((command) => command.suggested_state !== void 0);
}
function prefillSuggestedStates(item) {
  if (item.state !== "unset") return item.commands;
  return item.commands.map((command) => command.state === "inherit" && command.suggested_state !== void 0 && command.suggested_state !== "inherit" ? { ...command, state: command.suggested_state } : command);
}
function addCustomExtensionPrefillHref(base, command) {
  if (!command || !Object.values(PROFILE_SETUP_COMMANDS).includes(command)) return base;
  return `${base}?${PROFILE_COMMAND_PARAM}=${encodeURIComponent(command)}`;
}
function initialAddCommand(search) {
  const value = new URLSearchParams(search).get(PROFILE_COMMAND_PARAM);
  return value !== null && Object.values(PROFILE_SETUP_COMMANDS).includes(value) ? value : "";
}
const SETUP_REQUEST_ID = /^[A-Za-z0-9._:-]{1,128}$/;
const SETUP_IDENTITY = /^[0-9a-f]{64}$/;
function connectorSetupLinkFromSearch(search) {
  const params = new URLSearchParams(search);
  const requestId = params.get("setup");
  const identityHash = params.get("identity");
  if (requestId === null || identityHash === null) return null;
  if (!SETUP_REQUEST_ID.test(requestId) || !SETUP_IDENTITY.test(identityHash)) return null;
  return { requestId, identityHash };
}
function connectorSetupMatch(item, link) {
  if (item.identity_hash !== link.identityHash) return "identity_changed";
  return item.state === "unset" ? "ready" : "decided";
}
function shortIdentity(identityHash) {
  return identityHash.slice(0, 12);
}
function connectorGroupOutcome(body) {
  if (typeof body !== "object" || body === null) return null;
  const group = body.connector_group;
  if (typeof group !== "object" || group === null) return null;
  const record2 = group;
  const continuation = record2.continuation;
  const retryHint = typeof continuation === "object" && continuation !== null ? continuation.retry_hint : null;
  return {
    status: typeof record2.status === "string" ? record2.status : "failed",
    resolvedCount: typeof record2.resolved_count === "number" ? record2.resolved_count : 0,
    retryHint: typeof retryHint === "string" && retryHint.trim() ? retryHint.trim() : null
  };
}
const FOCUSABLE_SELECTOR = [
  "a[href]",
  "button:not([disabled])",
  "input:not([disabled])",
  "select:not([disabled])",
  "textarea:not([disabled])",
  "[tabindex]:not([tabindex='-1'])"
].join(",");
function focusableElements(root) {
  return Array.from(root.querySelectorAll(FOCUSABLE_SELECTOR)).filter(
    (element) => !element.hasAttribute("hidden") && element.getAttribute("aria-hidden") !== "true"
  );
}
function useModalDialog(onClose, canClose = true) {
  const dialogRef = reactExports.useRef(null);
  const closeRef = reactExports.useRef(onClose);
  const canCloseRef = reactExports.useRef(canClose);
  closeRef.current = onClose;
  canCloseRef.current = canClose;
  reactExports.useEffect(() => {
    const root = dialogRef.current;
    if (!root) return;
    const previous = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    const initial = focusableElements(root)[0] ?? root;
    initial.focus();
    const handleKeyDown = (event) => {
      if (event.key === "Escape" && canCloseRef.current) {
        event.preventDefault();
        closeRef.current();
        return;
      }
      if (event.key !== "Tab") return;
      const focusable = focusableElements(root);
      if (focusable.length === 0) {
        event.preventDefault();
        root.focus();
        return;
      }
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
      if (previous?.isConnected) previous.focus();
    };
  }, []);
  return dialogRef;
}
const CATALOG_V2_PATH = "/v2/extension-controls/catalog/";
const PAGE_LIMIT = 100;
const MAX_CATALOG_V2_PAGE_BYTES = 262144;
const MAX_TRAVERSAL_PAGES = 4096;
const MAX_TRAVERSAL_BYTES = 64 * 1024 * 1024;
const MAX_CACHE_ENTRIES = 256;
const UNSUPPORTED = /* @__PURE__ */ new Set(["404:", "404:not_found", "501:catalog_read_model_unavailable"]);
const CATALOG_SNAPSHOT_EXPIRED = "catalog_snapshot_expired";
const UNAVAILABLE_RETRY_DELAYS_MS = [250, 500, 1e3, 2e3, 4e3, 4e3];
const CATALOG_PREPARATION_FAILED = "catalog_read_preparation_failed";
class CatalogV2UnsupportedError extends ExtensionControlApiError {
}
const readCache = /* @__PURE__ */ new Map();
function isRecord(value) {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
function protocolError(message, code) {
  return new ExtensionControlApiError(message, code === CATALOG_SNAPSHOT_EXPIRED ? 409 : 502, code);
}
async function readOnce(path, ifNoneMatch, signal) {
  const headers = ifNoneMatch ? { "If-None-Match": ifNoneMatch } : {};
  const response = await fetchExtensionCatalogV2Api(path, { headers, cache: "no-store", signal });
  const etag = response.headers.get("ETag");
  if (response.status === 304) return { status: 304, etag };
  const declared = Number(response.headers.get("Content-Length") ?? "0");
  if (declared > MAX_CATALOG_V2_PAGE_BYTES) throw protocolError("Guard returned an oversized catalog page");
  const text = await response.text();
  const size = new TextEncoder().encode(text).byteLength;
  if (size > MAX_CATALOG_V2_PAGE_BYTES) throw protocolError("Guard returned an oversized catalog page");
  let payload;
  try {
    payload = JSON.parse(text);
  } catch {
    payload = void 0;
  }
  if (!response.ok) {
    const code = isRecord(payload) && typeof payload.error === "string" ? payload.error : void 0;
    if (UNSUPPORTED.has(`${response.status}:${code ?? ""}`)) {
      throw new CatalogV2UnsupportedError("Guard does not serve the v2 catalog", response.status, code);
    }
    throw new ExtensionControlApiError(code ?? `Request failed (${response.status})`, response.status, code);
  }
  if (!isRecord(payload)) throw protocolError(`Guard returned invalid JSON (${response.status})`);
  return { status: 200, etag, payload, size };
}
function waitBeforeRetry(delayMs, signal) {
  signal?.throwIfAborted();
  return new Promise((resolve, reject) => {
    const abort = () => {
      clearTimeout(timer);
      reject(signal?.reason);
    };
    const timer = setTimeout(() => {
      signal?.removeEventListener("abort", abort);
      resolve();
    }, delayMs);
    signal?.addEventListener("abort", abort, { once: true });
  });
}
async function readAvailable(path, ifNoneMatch, signal) {
  for (const delayMs of UNAVAILABLE_RETRY_DELAYS_MS) {
    try {
      return await readOnce(path, ifNoneMatch, signal);
    } catch (error) {
      if (!(error instanceof ExtensionControlApiError) || error.status !== 503) throw error;
      if (error.code === CATALOG_PREPARATION_FAILED) throw error;
    }
    await waitBeforeRetry(delayMs, signal);
  }
  return readOnce(path, ifNoneMatch, signal);
}
async function readSized(route, query, signal) {
  const path = `${CATALOG_V2_PATH}${route}${query ? `?${query}` : ""}`;
  const key = `${guardApiCacheScope()}|${path}`;
  const cached = readCache.get(key);
  let response = await readAvailable(path, cached?.etag ?? null, signal);
  if (response.status === 304) {
    if (cached && response.etag === cached.etag) {
      readCache.delete(key);
      readCache.set(key, cached);
      return cached;
    }
    response = await readAvailable(path, null, signal);
    if (response.status !== 200) throw protocolError("Guard answered 304 to an unconditional catalog request");
  }
  if (!response.etag) throw protocolError("Guard catalog response is missing its validator");
  const entry = { etag: response.etag, payload: response.payload, size: response.size };
  readCache.delete(key);
  readCache.set(key, entry);
  while (readCache.size > MAX_CACHE_ENTRIES) {
    const oldest = readCache.keys().next().value;
    if (oldest === void 0) break;
    readCache.delete(oldest);
  }
  return entry;
}
function pageFields(page) {
  const { snapshot_id, native_catalog_digest, total_count, items, next_cursor } = page;
  if (typeof snapshot_id !== "string" || typeof native_catalog_digest !== "string" || !Number.isSafeInteger(total_count) || !Array.isArray(items) || !items.every(isRecord) || !(next_cursor === null || next_cursor === void 0 || typeof next_cursor === "string")) {
    throw protocolError("Guard returned an invalid catalog page");
  }
  return { snapshot_id, digest: native_catalog_digest, total: total_count, items, next: next_cursor ?? null };
}
async function traverseOnce(route, itemKey, params, signal) {
  const items = [];
  const seenItems = /* @__PURE__ */ new Set();
  const seenCursors = /* @__PURE__ */ new Set();
  let first = null;
  let cursor = null;
  let consumed = 0;
  for (let index = 0; index < MAX_TRAVERSAL_PAGES; index += 1) {
    signal?.throwIfAborted();
    const query = { limit: String(PAGE_LIMIT), ...params, ...cursor ? { cursor } : {} };
    const encoded = new URLSearchParams(Object.entries(query).sort(([left], [right]) => left.localeCompare(right))).toString();
    const read = await readSized(route, encoded, signal);
    consumed += read.size;
    if (consumed > MAX_TRAVERSAL_BYTES) throw protocolError("Guard catalog traversal exceeded its byte budget");
    const page = pageFields(read.payload);
    if (first === null) {
      first = page;
    } else if (page.snapshot_id !== first.snapshot_id || page.digest !== first.digest || page.total !== first.total) {
      throw protocolError("Guard catalog changed during the read", CATALOG_SNAPSHOT_EXPIRED);
    }
    for (const item of page.items) {
      const identity = item[itemKey];
      if (typeof identity !== "string" || seenItems.has(identity)) throw protocolError("Guard catalog traversal returned a duplicate item");
      seenItems.add(identity);
      items.push(item);
    }
    if (page.next === null) {
      if (items.length !== first.total) throw protocolError("Guard catalog traversal was incomplete");
      return { snapshot_id: first.snapshot_id, digest: first.digest, items };
    }
    if (seenCursors.has(page.next) || page.items.length === 0) throw protocolError("Guard catalog traversal did not advance");
    seenCursors.add(page.next);
    cursor = page.next;
  }
  throw protocolError("Guard catalog traversal exceeded its page budget");
}
async function traverse(route, itemKey, params = {}, signal) {
  try {
    return await traverseOnce(route, itemKey, params, signal);
  } catch (error) {
    if (!(error instanceof ExtensionControlApiError) || error.code !== CATALOG_SNAPSHOT_EXPIRED) throw error;
  }
  return traverseOnce(route, itemKey, params, signal);
}
function extensionRoute(extensionId, collection) {
  const route = `extensions/${encodeURIComponent(extensionId)}`;
  return collection ? `${route}/${collection}` : route;
}
function sortedByName(items) {
  return [...items].sort((left, right) => left.name.localeCompare(right.name));
}
function requireSnapshot(observed, expected) {
  if (observed !== expected) throw protocolError("Guard catalog changed. Reload to continue.", CATALOG_SNAPSHOT_EXPIRED);
}
async function v2Detail(extensionId, snapshotId) {
  const detail = (await readSized(extensionRoute(extensionId), "")).payload;
  const { extension, collections } = detail;
  if (typeof detail.snapshot_id !== "string" || !isRecord(extension) || !isRecord(collections) || !isRecord(extension.catalog_defaults)) {
    throw protocolError("Guard returned an invalid catalog detail");
  }
  requireSnapshot(detail.snapshot_id, snapshotId);
  const { catalog_defaults: defaults, content_revision: _revision, ...fields } = extension;
  const reads = await Promise.all([
    traverse(extensionRoute(extensionId, "permissions"), "permission_id"),
    traverse(extensionRoute(extensionId, "rules"), "rule_id"),
    "mcp_tools" in collections ? traverse(extensionRoute(extensionId, "mcp-tools"), "name") : null
  ]);
  for (const read of reads) if (read) requireSnapshot(read.snapshot_id, snapshotId);
  const [permissions, rules, tools] = reads;
  return normalizeExtensionCatalogItem({
    ...fields,
    enabled: defaults.enabled,
    activation: defaults.activation,
    permissions: permissions?.items,
    rules: rules?.items,
    ...tools ? { mcp_tools: tools.items } : {}
  }, `catalog.extensions.${extensionId}`);
}
function searchTerms(query) {
  return query.toLowerCase().split(/\s+/).filter(Boolean);
}
async function loadV2() {
  const index = await traverse("index", "extension_id");
  const summaries = index.items.map((item, position) => normalizeExtensionCatalogSummary(item, `catalog.index[${position}]`));
  const byId = new Map(summaries.map((summary) => [summary.extension_id, summary]));
  const details = /* @__PURE__ */ new Map();
  return {
    protocol: "v2",
    catalog_digest: index.digest,
    extensions: sortedByName(summaries),
    detail(extensionId) {
      const summary = byId.get(extensionId);
      if (!summary) return Promise.reject(new ExtensionControlProtocolError(`Unknown extension ${extensionId}`));
      const key = `${extensionId}|${summary.content_revision ?? ""}`;
      let pending = details.get(key);
      if (!pending) {
        pending = v2Detail(extensionId, index.snapshot_id);
        details.set(key, pending);
        pending.catch(() => details.delete(key));
      }
      return pending;
    },
    async searchPermissions(query, signal) {
      const terms = searchTerms(query);
      if (!terms.length) return [];
      const result = await traverse("permissions", "permission_id", { q: terms.join(" ") }, signal);
      requireSnapshot(result.snapshot_id, index.snapshot_id);
      return result.items.map((item, position) => {
        const permission = normalizeExtensionPermission(item, `catalog.permissions[${position}]`);
        const extension = byId.get(permission.extension_id);
        if (!extension) throw protocolError("Guard returned a permission for an unknown extension");
        return { extension, permission };
      });
    }
  };
}
function catalogReadModelFromCatalog(catalog, degraded) {
  const byId = new Map(catalog.extensions.map((item) => [item.extension_id, item]));
  const localSearch = (query) => {
    const terms = searchTerms(query);
    if (!terms.length) return [];
    return catalog.extensions.flatMap((extension) => extension.permissions.filter((permission) => {
      const text = [
        permission.label,
        permission.example_command ?? "",
        permission.permission_id,
        permission.description,
        permission.family ?? "",
        extension.name,
        extension.extension_id,
        ...extension.executables
      ].join(" ").toLowerCase();
      return terms.every((term) => text.includes(term));
    }).map((permission) => ({ extension, permission })));
  };
  return {
    protocol: "v1",
    ...degraded ? { degraded } : {},
    catalog_digest: catalog.catalog_digest,
    extensions: sortedByName(catalog.extensions),
    detail(extensionId) {
      const item = byId.get(extensionId);
      return item ? Promise.resolve(item) : Promise.reject(new ExtensionControlProtocolError(`Unknown extension ${extensionId}`));
    },
    searchPermissions: (query) => Promise.resolve(localSearch(query)),
    localSearch
  };
}
async function loadCatalogReadModel() {
  try {
    return await loadV2();
  } catch (error) {
    if (error instanceof CatalogV2UnsupportedError) return catalogReadModelFromCatalog(await fetchExtensionCatalog());
    if (error instanceof ExtensionControlApiError && error.code === CATALOG_PREPARATION_FAILED) {
      try {
        return catalogReadModelFromCatalog(await fetchExtensionCatalog(), CATALOG_PREPARATION_FAILED);
      } catch {
        throw error;
      }
    }
    throw error;
  }
}
function permissionSuffix(permissionId) {
  const marker = ".permission.";
  const index = permissionId.indexOf(marker);
  return index < 0 ? null : permissionId.slice(index + marker.length);
}
function latestPermissionId(original, oldExtension, latestExtension) {
  if (latestExtension.permissions.some((permission) => permission.permission_id === original)) return original;
  if (latestExtension.extension_id !== oldExtension.extension_id && latestExtension.aliases.includes(oldExtension.extension_id)) {
    const suffix = permissionSuffix(original);
    if (!suffix) return null;
    const candidate = `${latestExtension.extension_id}.permission.${suffix}`;
    if (latestExtension.permissions.some((permission) => permission.permission_id === candidate)) return candidate;
  }
  return null;
}
function rebaseExtensionPolicyDraft(oldEffective, latestEffective, oldExtension, latestExtension, draftLayers, rebasedLayers) {
  const onto = rebasedLayers ?? latestEffective.layers;
  let rebased = onto.map((layer) => ({ ...layer, controls: layer.controls.map((control) => ({ ...control })) }));
  const conflicts = [];
  const remapped = {};
  for (const permission of oldExtension.permissions) {
    const baseState = localPermissionDraftState(oldEffective.layers, permission.permission_id);
    const requestedState = localPermissionDraftState(draftLayers, permission.permission_id);
    if (baseState === requestedState) continue;
    const mapped = latestPermissionId(permission.permission_id, oldExtension, latestExtension);
    if (!mapped) {
      conflicts.push({
        original_permission_id: permission.permission_id,
        latest_permission_id: null,
        kind: "removed",
        base_state: baseState,
        latest_state: "inherit",
        requested_state: requestedState
      });
      continue;
    }
    remapped[permission.permission_id] = mapped;
    const latestState = localPermissionDraftState(latestEffective.layers, mapped);
    if (latestState !== baseState && latestState !== requestedState) {
      conflicts.push({
        original_permission_id: permission.permission_id,
        latest_permission_id: mapped,
        kind: "overlap",
        base_state: baseState,
        latest_state: latestState,
        requested_state: requestedState
      });
      continue;
    }
    rebased = setLocalPermissionDraftState(rebased, latestEffective.catalog_digest, mapped, requestedState);
  }
  return { draft_layers: rebased, conflicts, remapped_permission_ids: remapped };
}
function keepExtensionPolicyRebaseConflicts(result, latestEffective) {
  let layers = result.draft_layers;
  for (const conflict of result.conflicts) {
    if (conflict.kind !== "overlap" || !conflict.latest_permission_id) continue;
    layers = setLocalPermissionDraftState(
      layers,
      latestEffective.catalog_digest,
      conflict.latest_permission_id,
      conflict.requested_state
    );
  }
  return layers;
}
const POLICY_CONFLICT_CODES = ["revision_conflict", "catalog_conflict", "authority_conflict"];
function isExtensionPolicyConflict(caught) {
  return caught instanceof ExtensionControlApiError && POLICY_CONFLICT_CODES.includes(caught.code ?? "");
}
function extensionPolicyRepairBase(base, latest) {
  if (latest.revision === base.revision) return null;
  return extensionPolicyAuthorityUnchanged(base, latest) ? latest : null;
}
function sameReviewedExtensionPolicyEffect(candidate, reviewed) {
  if (candidate.previous_revision === reviewed.previous_revision) {
    return candidate.canonical_diff_digest === reviewed.canonical_diff_digest;
  }
  return candidate.catalog_digest === reviewed.catalog_digest && candidate.global_lockdown === reviewed.global_lockdown && candidate.controls === reviewed.controls && JSON.stringify(candidate.semantic_preview) === JSON.stringify(reviewed.semantic_preview);
}
function cloneLayers(effective) {
  return effective.layers.map((layer) => ({ ...layer, controls: layer.controls.map((control) => ({ ...control })) }));
}
function useExtensionPolicyDraft(props) {
  const [baseEffective, setBaseEffective] = reactExports.useState(props.effective);
  const [draftLayers, setDraftLayers] = reactExports.useState(() => cloneLayers(props.effective));
  const [identity, setIdentity] = reactExports.useState(() => newExtensionPolicyDraftIdentity());
  const [preview, setPreview] = reactExports.useState(null);
  const [previewBusy, setPreviewBusy] = reactExports.useState(false);
  const [applyBusy, setApplyBusy] = reactExports.useState(false);
  const [approvalOpen, setApprovalOpen] = reactExports.useState(false);
  const [reviewOpen, setReviewOpen] = reactExports.useState(false);
  const [error, setError] = reactExports.useState(null);
  const [stale, setStale] = reactExports.useState(false);
  const [pendingRebase, setPendingRebase] = reactExports.useState(null);
  const [refreshRequired, setRefreshRequired] = reactExports.useState(false);
  const [lastApplied, setLastApplied] = reactExports.useState(null);
  const draftGeneration = reactExports.useRef(0);
  const { onRefresh } = props;
  const dirty = reactExports.useMemo(() => extensionPolicyDraftIsDirty(baseEffective, draftLayers), [baseEffective, draftLayers]);
  reactExports.useEffect(() => {
    draftGeneration.current += 1;
    setBaseEffective(props.effective);
    setDraftLayers(cloneLayers(props.effective));
    setIdentity(newExtensionPolicyDraftIdentity());
    setRefreshRequired(false);
    setPreview(null);
    setReviewOpen(false);
    setError(null);
    setStale(false);
    setPendingRebase(null);
  }, [props.effective.revision, props.effective.catalog_digest, props.effective.health, props.effective.global_lockdown]);
  const changeCountFor = reactExports.useCallback((permissionIds) => {
    return permissionIds.filter(
      (permissionId) => localPermissionDraftState(baseEffective.layers, permissionId) !== localPermissionDraftState(draftLayers, permissionId)
    ).length;
  }, [baseEffective, draftLayers]);
  const changedPermissionCount = reactExports.useMemo(
    () => changeCountFor([...new Set(
      baseEffective.layers.concat(draftLayers).flatMap((layer) => layer.controls).map((control) => control.target_kind === "permission" ? control.target_id : null).filter((id) => Boolean(id))
    )]),
    [baseEffective.layers, changeCountFor, draftLayers]
  );
  const resetDraft = reactExports.useCallback(() => {
    draftGeneration.current += 1;
    setDraftLayers(cloneLayers(baseEffective));
    setIdentity(newExtensionPolicyDraftIdentity());
    setPreview(null);
    setReviewOpen(false);
    setError(null);
    setStale(false);
    setPendingRebase(null);
  }, [baseEffective]);
  const setPermissionState = reactExports.useCallback((permissionId, state) => {
    draftGeneration.current += 1;
    setDraftLayers((current) => setLocalPermissionDraftState(current, baseEffective.catalog_digest, permissionId, state));
    setPreview(null);
    setReviewOpen(false);
    setError(null);
    setStale(false);
    setPendingRebase(null);
    setLastApplied(null);
  }, [baseEffective.catalog_digest]);
  const setPermissionStates = reactExports.useCallback((permissionIds, state) => {
    if (!permissionIds.length) return;
    draftGeneration.current += 1;
    setDraftLayers((current) => setLocalPermissionDraftStates(
      current,
      baseEffective.catalog_digest,
      permissionIds,
      state
    ));
    setIdentity(newExtensionPolicyDraftIdentity());
    setPreview(null);
    setReviewOpen(false);
    setError(null);
    setStale(false);
    setPendingRebase(null);
    setLastApplied(null);
  }, [baseEffective.catalog_digest]);
  const mutationOn = reactExports.useCallback(
    (base, draftIdentity) => buildExtensionPolicyDraftMutation(base, base.catalog_digest, draftLayers, draftIdentity),
    [draftLayers]
  );
  const repairedBase = reactExports.useCallback(async (base, caught) => {
    if (!isExtensionPolicyConflict(caught)) return null;
    let latest;
    try {
      latest = await fetchEffectiveExtensionControls();
    } catch {
      return null;
    }
    return extensionPolicyRepairBase(base, latest);
  }, []);
  const handleApiError = reactExports.useCallback((caught, fallback) => {
    if (isExtensionPolicyConflict(caught)) {
      setStale(true);
      setError("The authoritative extension policy changed while this draft was open. Rebase the draft before applying; Guard will not silently overwrite security policy.");
      return;
    }
    setError(caught instanceof Error ? caught.message : fallback);
  }, []);
  const runPreview = reactExports.useCallback(async () => {
    if (!dirty) return;
    const generation = draftGeneration.current;
    setPreviewBusy(true);
    setError(null);
    setStale(false);
    try {
      let base = baseEffective;
      let next;
      try {
        next = await previewExtensionMutation(mutationOn(base, identity));
      } catch (caught) {
        const repaired = await repairedBase(base, caught);
        if (!repaired) throw caught;
        base = repaired;
        next = await previewExtensionMutation(mutationOn(base, identity));
      }
      if (!isCurrentExtensionPolicyDraft(generation, draftGeneration.current)) return;
      if (base !== baseEffective) setBaseEffective(base);
      setPreview(next);
      setReviewOpen(true);
    } catch (caught) {
      if (isCurrentExtensionPolicyDraft(generation, draftGeneration.current)) handleApiError(caught, "Guard could not preview this draft.");
    } finally {
      setPreviewBusy(false);
    }
  }, [baseEffective, dirty, handleApiError, identity, mutationOn, repairedBase]);
  const commitDraft = reactExports.useCallback(async (base, draftIdentity, credentials, reviewed) => {
    const payload = mutationOn(base, draftIdentity);
    const proofPreview = await previewExtensionMutation({
      ...payload,
      ...credentials,
      session_nonce: crypto.randomUUID().replaceAll("-", "")
    });
    if (!proofPreview.proof_id) throw new Error("Guard did not issue an approval proof for this exact draft.");
    if (!sameReviewedExtensionPolicyEffect(proofPreview, reviewed)) throw new Error("The policy draft changed after preview. Preview it again before applying.");
    return applyExtensionMutation({ ...payload, proof_id: proofPreview.proof_id });
  }, [mutationOn]);
  const apply = reactExports.useCallback(async (credentials) => {
    if (!preview || !dirty || stale) return;
    setApplyBusy(true);
    setError(null);
    try {
      let base = baseEffective;
      const appliedLayersBefore = cloneLayers(base);
      let applied;
      try {
        applied = await commitDraft(base, identity, credentials, preview);
      } catch (caught) {
        const repaired = await repairedBase(base, caught);
        if (!repaired) throw caught;
        base = repaired;
        const retryIdentity = newExtensionPolicyDraftIdentity();
        setIdentity(retryIdentity);
        applied = await commitDraft(base, retryIdentity, credentials, preview);
      }
      setApprovalOpen(false);
      setPreview(null);
      setReviewOpen(false);
      setError(null);
      setStale(false);
      if (applied.revision <= base.revision) throw new Error("Guard did not advance the committed extension-control revision.");
      const changedPermissionIds = base.layers.flatMap((layer) => layer.controls).concat(draftLayers.flatMap((layer) => layer.controls)).map((control) => control.target_kind === "permission" ? control.target_id : null).filter((id) => Boolean(id));
      const previouslyRequested = new Set(
        draftLayers.flatMap((layer) => layer.controls).map((control) => control.target_kind === "permission" ? control.target_id : null).filter((id) => Boolean(id))
      );
      setLastApplied({
        revision: applied.revision,
        previousLayers: appliedLayersBefore,
        changedPermissionIds: [...new Set(changedPermissionIds)].filter((id) => previouslyRequested.has(id) || localPermissionDraftState(base.layers, id) !== localPermissionDraftState(draftLayers, id))
      });
      draftGeneration.current += 1;
      setBaseEffective(base);
      setDraftLayers(cloneLayers(base));
      setIdentity(newExtensionPolicyDraftIdentity());
      setRefreshRequired(true);
      try {
        await onRefresh();
      } catch {
        setError("The policy was applied, but Guard could not refresh the latest state. Refresh this page to confirm the committed policy.");
      }
    } catch (caught) {
      handleApiError(caught, "Guard could not apply this draft.");
    } finally {
      setApplyBusy(false);
    }
  }, [baseEffective, commitDraft, dirty, draftLayers, handleApiError, identity, onRefresh, preview, repairedBase, stale]);
  const rebaseDraft = reactExports.useCallback(async (touched) => {
    const generation = draftGeneration.current;
    setPreviewBusy(true);
    setError(null);
    try {
      const oldExtensions = typeof touched === "function" ? await touched() : touched;
      const [latestCatalog, latestEffective] = await Promise.all([loadCatalogReadModel(), fetchEffectiveExtensionControls()]);
      const matches = oldExtensions.map((oldExtension) => {
        const exact = latestCatalog.extensions.find((item) => item.extension_id === oldExtension.extension_id);
        if (exact) return { oldExtension, latestId: exact.extension_id };
        const aliasMatches = latestCatalog.extensions.filter((item) => item.aliases.includes(oldExtension.extension_id));
        return aliasMatches.length === 1 ? { oldExtension, latestId: aliasMatches[0].extension_id } : null;
      }).filter((match) => Boolean(match));
      const pairs = await Promise.all(matches.map(async ({ oldExtension, latestId }) => ({ oldExtension, latestExtension: await latestCatalog.detail(latestId) })));
      if (!pairs.length) {
        setError("These extensions no longer exist in the authoritative catalog. Discard the draft and refresh before continuing.");
        return;
      }
      if (!isCurrentExtensionPolicyDraft(generation, draftGeneration.current)) {
        setError("The draft changed while Guard was loading current policy. Rebase again to preserve the latest edits.");
        return;
      }
      const chained = pairs.reduce((result2, { oldExtension, latestExtension }) => {
        const next = rebaseExtensionPolicyDraft(
          baseEffective,
          latestEffective,
          oldExtension,
          latestExtension,
          draftLayers,
          result2?.draft_layers
        );
        return {
          draft_layers: next.draft_layers,
          conflicts: [...result2?.conflicts ?? [], ...next.conflicts],
          remapped_permission_ids: { ...result2?.remapped_permission_ids ?? {}, ...next.remapped_permission_ids }
        };
      }, null);
      if (!chained) {
        setError("Guard could not rebase this draft against the current catalog.");
        return;
      }
      const result = chained;
      setBaseEffective(latestEffective);
      setIdentity(newExtensionPolicyDraftIdentity());
      setPreview(null);
      setReviewOpen(false);
      if (result.conflicts.length) {
        setPendingRebase({ result, latestEffective, latestExtensions: pairs.map((pair) => pair.latestExtension) });
        setDraftLayers(result.draft_layers);
        setStale(true);
        setError("The latest policy overlaps this draft. Choose whether to keep your overlapping changes or use current authoritative values. Removed permissions cannot be restored.");
      } else {
        setDraftLayers(result.draft_layers);
        setPendingRebase(null);
        setStale(false);
        setError(null);
      }
    } catch (caught) {
      if (isCurrentExtensionPolicyDraft(generation, draftGeneration.current)) handleApiError(caught, "Guard could not rebase this draft.");
    } finally {
      setPreviewBusy(false);
    }
  }, [baseEffective, draftLayers]);
  const keepConflicts = reactExports.useCallback(() => {
    if (!pendingRebase) return;
    setDraftLayers(keepExtensionPolicyRebaseConflicts(pendingRebase.result, pendingRebase.latestEffective));
    setPendingRebase(null);
    setStale(false);
    setError(null);
    setIdentity(newExtensionPolicyDraftIdentity());
  }, [pendingRebase]);
  const useCurrent = reactExports.useCallback(() => {
    if (!pendingRebase) return;
    setDraftLayers(cloneLayers(pendingRebase.latestEffective));
    setPendingRebase(null);
    setStale(false);
    setError(null);
    setPreview(null);
    setIdentity(newExtensionPolicyDraftIdentity());
  }, [pendingRebase]);
  const applyProfile = reactExports.useCallback((permissions, profile) => {
    if (profile === "custom") return;
    draftGeneration.current += 1;
    let next = cloneLayers(baseEffective);
    for (const permission of permissions) {
      if (!permission.configurable) continue;
      const state = profile === "recommended" ? "inherit" : "block";
      next = setLocalPermissionDraftState(next, baseEffective.catalog_digest, permission.permission_id, state);
    }
    setDraftLayers(next);
    setIdentity(newExtensionPolicyDraftIdentity());
    setPreview(null);
    setReviewOpen(false);
    setError(null);
    setStale(false);
    setPendingRebase(null);
    setLastApplied(null);
  }, [baseEffective]);
  const useHistoricalDraft = reactExports.useCallback((historicalLayers) => {
    draftGeneration.current += 1;
    const historicalLocal = historicalLayers.find((layer) => layer.kind === "local-admin");
    const next = baseEffective.layers.flatMap((layer) => layer.kind === "local-admin" ? historicalLocal ? [historicalLocal] : [] : [layer]);
    if (historicalLocal && !baseEffective.layers.some((layer) => layer.kind === "local-admin")) next.push(historicalLocal);
    setDraftLayers(next);
    setIdentity(newExtensionPolicyDraftIdentity());
    setPreview(null);
    setReviewOpen(false);
    setError(null);
    setStale(false);
    setPendingRebase(null);
  }, [baseEffective.layers]);
  const undoLastApplied = reactExports.useCallback(() => {
    if (!lastApplied) return false;
    draftGeneration.current += 1;
    setDraftLayers(cloneLayers({ ...baseEffective, layers: lastApplied.previousLayers }));
    setIdentity(newExtensionPolicyDraftIdentity());
    setPreview(null);
    setReviewOpen(false);
    setError(null);
    setStale(false);
    setPendingRebase(null);
    setLastApplied(null);
    return true;
  }, [baseEffective, lastApplied]);
  return {
    baseEffective,
    draftLayers,
    dirty,
    preview,
    previewBusy,
    applyBusy,
    reviewOpen,
    approvalOpen,
    error,
    stale,
    pendingRebase,
    refreshRequired,
    lastApplied,
    undoLastApplied,
    changedPermissionCount,
    setReviewOpen,
    setApprovalOpen,
    permissionState: reactExports.useCallback((permissionId) => localPermissionDraftState(draftLayers, permissionId), [draftLayers]),
    changeCountFor,
    setPermissionState,
    setPermissionStates,
    resetDraft,
    runPreview,
    apply,
    rebaseDraft,
    keepConflicts,
    useCurrent,
    applyProfile,
    useHistoricalDraft
  };
}
function ProtectionSettingsHistory(props) {
  const [items, setItems] = reactExports.useState([]);
  const [loading, setLoading] = reactExports.useState(true);
  const [error, setError] = reactExports.useState(null);
  reactExports.useEffect(() => {
    let active = true;
    setLoading(true);
    fetchExtensionControlHistory().then((history) => {
      if (!active) return;
      setItems(history.items.filter((item) => item.catalog_digest === props.catalogDigest));
      setError(null);
    }).catch(() => {
      if (active) setError("Local settings history is unavailable until Guard verifies settings integrity.");
    }).finally(() => {
      if (active) setLoading(false);
    });
    return () => {
      active = false;
    };
  }, [props.catalogDigest]);
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("details", { className: "mt-5", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx("summary", { className: "cursor-pointer text-sm font-semibold text-brand-dark", children: "Settings history" }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-2 text-xs leading-5 text-brand-dark/80", children: "Guard verifies the authenticated local history before showing it. Restoring a version only prepares the device layer as a draft. Current organization policy stays in force, and nothing changes until you review and approve it." }),
    loading ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-3 text-xs text-brand-dark/70", children: "Loading verified history…" }) : error ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-3 text-xs text-amber-950", children: error }) : items.length ? /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-3 space-y-2", children: items.slice(0, 10).map((item) => /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-col gap-2 py-2 sm:flex-row sm:items-center sm:justify-between", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "text-sm font-medium text-brand-dark", children: [
          "Device settings revision ",
          item.revision
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("time", { className: "text-xs text-brand-dark/70", dateTime: item.occurred_at, children: new Date(item.occurred_at).toLocaleString() })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("button", { type: "button", disabled: props.disabled, onClick: () => props.onUse(item.layers, item.revision), className: "min-h-10 px-1 text-xs font-semibold text-brand-blue disabled:opacity-40", children: "Use this version as draft" })
    ] }, item.revision)) }) : /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-3 text-xs text-brand-dark/70", children: "No earlier authenticated device settings are available yet." })
  ] });
}
const QUICK_APPLY_CHOICES = [
  {
    state: "inherit",
    label: "Recommended",
    detail: "Use Guard defaults for every matching capability.",
    icon: HiMiniSparkles
  },
  {
    state: "allow",
    label: "Allow all",
    detail: "Allow every matching capability that organization policy permits.",
    icon: HiMiniCheckCircle
  },
  {
    state: "block",
    label: "Deny all",
    detail: "Add a local block to every matching capability.",
    icon: HiMiniNoSymbol
  }
];
const DEFAULT_QUICK_APPLY_SUBJECT = {
  one: "matching capability",
  other: "matching capabilities"
};
function quickApplyPermissionIds(permissions, effective, state) {
  return permissions.filter((permission) => permission.configurable).filter((permission) => state !== "allow" || managedPermissionState(effective, permission.permission_id) !== "disabled").map((permission) => permission.permission_id);
}
function QuickApplyToolbar(props) {
  const subject = props.subject ?? DEFAULT_QUICK_APPLY_SUBJECT;
  const configurableCount = props.permissions.filter((permission) => permission.configurable).length;
  const managedBlockCount = props.permissions.filter(
    (permission) => permission.configurable && managedPermissionState(props.effective, permission.permission_id) === "disabled"
  ).length;
  let managedBlockCopy = "";
  if (managedBlockCount) {
    const blockCopy = managedBlockCount === 1 ? "block stays" : "blocks stay";
    managedBlockCopy = ` ${managedBlockCount} organization ${blockCopy} enforced.`;
  }
  if (!configurableCount) return null;
  const heading = `Quick apply to ${configurableCount} ${configurableCount === 1 ? subject.one : subject.other}`;
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-4 flex flex-col gap-3 border-y border-[rgba(63,65,116,0.12)] bg-[rgba(85,153,254,0.045)] px-3 py-3 sm:flex-row sm:items-center sm:justify-between sm:px-4", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "min-w-0", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm font-semibold text-brand-dark", children: heading }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "mt-0.5 text-xs leading-5 text-brand-dark/65", children: [
        "Changes stay in draft until you review and approve them.",
        managedBlockCopy
      ] })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("div", { role: "group", "aria-label": `Quick apply to ${configurableCount} ${subject.other}`, className: "flex flex-wrap gap-2", children: QUICK_APPLY_CHOICES.map((choice) => /* @__PURE__ */ jsxRuntimeExports.jsx(
      QuickApplyButton,
      {
        choice,
        permissionIds: quickApplyPermissionIds(props.permissions, props.effective, choice.state),
        disabled: props.disabled,
        permissionState: props.permissionState,
        onApply: props.onApply
      },
      choice.state
    )) })
  ] });
}
function QuickApplyButton(props) {
  const active = props.permissionIds.length > 0 && props.permissionIds.every((permissionId) => props.permissionState(permissionId) === props.choice.state);
  const handleClick = reactExports.useCallback(() => {
    props.onApply(props.permissionIds, props.choice.state);
  }, [props.choice.state, props.onApply, props.permissionIds]);
  const Icon = props.choice.icon;
  return /* @__PURE__ */ jsxRuntimeExports.jsxs(
    "button",
    {
      type: "button",
      "aria-pressed": active,
      title: props.choice.detail,
      disabled: props.disabled || props.permissionIds.length === 0,
      onClick: handleClick,
      className: "inline-flex min-h-10 items-center gap-2 rounded-lg border border-[rgba(63,65,116,0.18)] bg-white px-3 text-xs font-semibold text-brand-dark shadow-sm transition-colors hover:border-brand-blue hover:text-brand-blue disabled:cursor-not-allowed disabled:opacity-45 aria-pressed:border-brand-blue aria-pressed:bg-brand-blue aria-pressed:text-white",
      children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(Icon, { className: "size-4", "aria-hidden": "true" }),
        props.choice.label
      ]
    }
  );
}
function PolicyEditingLocks(props) {
  return /* @__PURE__ */ jsxRuntimeExports.jsxs(jsxRuntimeExports.Fragment, { children: [
    props.globalLockdown ? /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { role: "status", className: "mt-4 flex gap-2 text-sm text-brand-dark", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniLockClosed, { className: "mt-0.5 size-4 shrink-0" }),
      "Emergency Lockdown remains dominant. You can prepare a local draft, but matching commands stay blocked while lockdown is active."
    ] }) : null,
    props.health !== void 0 && props.health !== "protected" ? /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { role: "alert", className: "mt-4 flex gap-2 text-sm text-amber-950", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniExclamationTriangle, { className: "mt-0.5 size-4 shrink-0" }),
      "Settings cannot be changed until Guard verifies local settings integrity."
    ] }) : null,
    props.refreshRequired ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { role: "status", className: "mt-4 text-sm text-blue-950", children: "Settings applied. Editing stays locked until Guard reloads the current protected state." }) : null
  ] });
}
function managedControlsHref(input) {
  if (!input.cloudControlsUrl) {
    return null;
  }
  let target;
  try {
    target = new URL("/guard/controls", input.cloudControlsUrl);
  } catch {
    return null;
  }
  if (input.extensionId) {
    target.searchParams.set("extensionId", input.extensionId);
  }
  if (input.permissionId) {
    target.searchParams.set("permissionId", input.permissionId);
  }
  return target.toString();
}
function buildLocalProtectionView(input) {
  const sources = input.sources?.length ? input.sources : [input.source];
  const technicalDetails = [
    ...sources.length > 1 ? [{ label: "Contributors", value: sources.join(" · ") }] : [],
    ...input.catalogDigest ? [{ label: "Catalog digest", value: input.catalogDigest }] : [],
    ...input.acknowledgementRevision !== void 0 ? [{ label: "Acknowledgement revision", value: String(input.acknowledgementRevision) }] : [],
    ...input.controlSetName ? [{ label: "Control Set", value: input.controlSetName }] : [],
    ...input.controlSetVersion !== void 0 ? [{ label: "Control Set version", value: String(input.controlSetVersion) }] : [],
    ...input.workspace ? [{ label: "Workspace", value: input.workspace }] : [],
    ...input.authorityMode ? [{ label: "Authority mode", value: input.authorityMode }] : [],
    ...input.acknowledgementStatus ? [{ label: "Acknowledgement", value: input.acknowledgementStatus }] : [],
    ...input.lastAcknowledgedAt ? [{ label: "Last acknowledged", value: input.lastAcknowledgedAt }] : [],
    ...input.effectiveProjectionDigest ? [{ label: "Effective projection digest", value: input.effectiveProjectionDigest }] : []
  ];
  if (input.recovery === "unsupported-version") {
    return {
      title: input.extensionName,
      summary: "Update Guard before this managed setting can be applied.",
      source: input.source,
      sources,
      effectiveState: input.effectiveState,
      status: "unsupported",
      primaryAction: { label: "Check for updates", action: "refresh" },
      technicalDetails
    };
  }
  if (input.recovery) {
    let recoverySummary = "Guard is using the last verified setting while it checks for an update.";
    if (input.recovery === "catalog-mismatch") {
      recoverySummary = "Guard is using the last verified setting because this Control Set and the local Extension catalog do not match.";
    } else if (input.recovery === "degraded") {
      recoverySummary = "Guard is preserving the last verified authority while local control recovery is required.";
    }
    return {
      title: input.extensionName,
      summary: recoverySummary,
      source: input.source,
      sources,
      effectiveState: input.effectiveState,
      status: "needs-attention",
      primaryAction: { label: "Check again", action: "refresh" },
      technicalDetails
    };
  }
  let status = "protected";
  if (input.effectiveState === "lockdown") {
    status = "lockdown";
  } else if (input.source === "Organization Control Set" || input.source.startsWith("Managed by ")) {
    status = "managed";
  }
  let summary = "Guard checks matching actions before they run.";
  if (input.effectiveState === "blocked") {
    summary = "Matching actions are blocked.";
  } else if (input.effectiveState === "partial") {
    summary = "Some matching actions are blocked while the remaining actions stay available.";
  } else if (input.effectiveState === "required") {
    summary = "This protection stays on.";
  } else if (input.effectiveState === "lockdown") {
    summary = "Emergency Lockdown blocks governed actions.";
  }
  const controlsHref = managedControlsHref(input);
  const hasManagedContributor = sources.some(
    (source) => source === "Organization Control Set" || source === "Synced from Guard Cloud" || source.startsWith("Managed by ")
  );
  const primaryAction = controlsHref ? {
    label: hasManagedContributor ? "Manage in Guard Cloud" : "Apply across my devices",
    href: controlsHref
  } : { label: "Connect Guard Cloud", action: "connect-cloud" };
  return {
    title: input.extensionName,
    summary,
    source: input.source,
    sources,
    effectiveState: input.effectiveState,
    status,
    primaryAction,
    technicalDetails
  };
}
function AppliedPolicyToast(props) {
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { role: "status", "data-testid": "extension-policy-applied-toast", className: "mt-4 flex flex-wrap items-center justify-between gap-3 rounded-xl border border-emerald-200 bg-emerald-50 px-4 py-3", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "text-sm font-medium text-emerald-950", children: [
      "Applied · revision ",
      props.revision
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap gap-2", children: [
      props.applyAcrossHref ? /* @__PURE__ */ jsxRuntimeExports.jsx("a", { href: props.applyAcrossHref, target: "_blank", rel: "noopener noreferrer", className: "inline-flex min-h-11 items-center rounded-xl border border-emerald-300 bg-white/70 px-3 text-sm font-semibold text-emerald-950", children: "Apply across my devices" }) : null,
      /* @__PURE__ */ jsxRuntimeExports.jsx("button", { type: "button", onClick: props.onViewHistory, className: "min-h-11 rounded-xl border border-emerald-300 bg-white/70 px-3 text-sm font-semibold text-emerald-950", children: "View history" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("button", { type: "button", onClick: props.onUndo, className: "min-h-11 rounded-xl bg-emerald-800 px-3 text-sm font-semibold text-white", children: "Undo" })
    ] })
  ] });
}
function appliedPolicyCloudHref(input) {
  return managedControlsHref({
    extensionName: input.extensionName,
    extensionId: input.extensionId,
    permissionId: input.changedPermissionIds.length === 1 ? input.changedPermissionIds[0] : void 0,
    effectiveState: "allowed",
    source: "Set on this device",
    cloudControlsUrl: input.cloudControlsUrl
  });
}
const RISK_TONE = {
  critical: "border-red-200 bg-red-50 text-red-950",
  high: "border-orange-200 bg-orange-50 text-orange-950",
  medium: "border-amber-200 bg-amber-50 text-amber-950",
  low: "border-[rgba(63,65,116,0.16)] text-brand-dark"
};
function Pill(props) {
  return /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: `inline-flex rounded-full border px-2.5 py-1 text-xs font-semibold ${props.tone ?? "border-[rgba(63,65,116,0.16)] text-brand-dark"}`, children: props.children });
}
function extensionPolicyRadioTabStop(choices, state, groupDisabled) {
  if (groupDisabled) return -1;
  const selected = choices.findIndex((choice) => choice.value === state && !choice.disabled);
  return selected >= 0 ? selected : choices.findIndex((choice) => !choice.disabled);
}
function nextExtensionPolicyRadioIndex(choices, index, key, groupDisabled) {
  if (groupDisabled || !["ArrowLeft", "ArrowRight", "ArrowUp", "ArrowDown"].includes(key)) return -1;
  const direction = key === "ArrowLeft" || key === "ArrowUp" ? -1 : 1;
  for (let offset = 1; offset <= choices.length; offset += 1) {
    const next = (index + direction * offset + choices.length) % choices.length;
    if (!choices[next]?.disabled) return next;
  }
  return -1;
}
function DraftControl(props) {
  const managed = managedPermissionState(props.effective, props.permission.permission_id);
  const choices = [
    { value: "inherit", label: "Recommended" },
    { value: "allow", label: "Allow", disabled: managed === "disabled" },
    { value: "block", label: "Block" }
  ];
  const tabStopIndex = extensionPolicyRadioTabStop(choices, props.state, props.disabled);
  const chooseAdjacent = (event, index) => {
    const next = nextExtensionPolicyRadioIndex(choices, index, event.key, props.disabled);
    if (next < 0) return;
    event.preventDefault();
    props.onChange(choices[next].value);
    event.currentTarget.parentElement?.querySelectorAll('[role="radio"]')[next]?.focus();
  };
  return /* @__PURE__ */ jsxRuntimeExports.jsx("div", { role: "radiogroup", "aria-label": `${props.permission.label} protection setting`, className: "guard-segmented", children: choices.map((choice, index) => /* @__PURE__ */ jsxRuntimeExports.jsx(
    "button",
    {
      type: "button",
      role: "radio",
      "aria-checked": props.state === choice.value,
      tabIndex: !props.disabled && index === tabStopIndex ? 0 : -1,
      disabled: props.disabled || choice.disabled,
      title: choice.disabled ? "Your organization already blocks this capability; this device cannot weaken it." : void 0,
      onKeyDown: (event) => chooseAdjacent(event, index),
      onClick: () => props.onChange(choice.value),
      className: "disabled:cursor-not-allowed disabled:opacity-45",
      children: choice.label
    },
    choice.value
  )) });
}
function PermissionPolicyRow(props) {
  const managed = managedPermissionState(props.effective, props.permission.permission_id);
  const provenance = controlProvenance(props.effective, "permission", props.permission.permission_id);
  const example = props.permission.example_command ?? (props.extension.executables[0]?.trim() || props.permission.label);
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("article", { id: `pattern-${props.permission.permission_id}`, className: "guard-pattern-row", "data-permission-id": props.permission.permission_id, children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "min-w-0", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("h3", { className: "text-sm font-semibold text-brand-dark", children: props.permission.label }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "guard-pattern-example mt-1", children: example }),
      !props.permission.configurable ? /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "mt-2 text-xs leading-5 text-brand-dark", children: [
        "Why this cannot be changed: ",
        props.permission.fixed_reason ?? "Guard marks this safety permission as immutable."
      ] }) : null,
      managed === "disabled" ? /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "mt-2 flex items-start gap-2 text-xs leading-5 text-indigo-950", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniLockClosed, { className: "mt-0.5 size-4 shrink-0" }),
        "Your organization blocks this capability. You can keep the organization setting or add a local block, but this device cannot weaken it."
      ] }) : null,
      /* @__PURE__ */ jsxRuntimeExports.jsxs("details", { className: "mt-2 text-xs text-brand-dark", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("summary", { className: "cursor-pointer font-semibold", children: "Technical setting details" }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-2 flex flex-wrap gap-x-4 gap-y-1", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { children: [
            "Minimum protection: ",
            /* @__PURE__ */ jsxRuntimeExports.jsx("strong", { children: treatmentLabel(props.permission.baseline_floor) })
          ] }),
          /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { children: [
            props.permission.rule_ids.length,
            " governed rule",
            props.permission.rule_ids.length === 1 ? "" : "s"
          ] }),
          /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { children: [
            "Managed by: ",
            provenance.join(" · ")
          ] })
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("code", { className: "mt-2 block break-all text-[11px] text-brand-dark/80", children: props.permission.permission_id })
      ] })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsx(
      DraftControl,
      {
        permission: props.permission,
        effective: props.effective,
        state: props.draftState,
        disabled: props.disabled || !props.permission.configurable || props.effective.health !== "protected",
        onChange: props.onChange
      }
    )
  ] });
}
function PreviewPanel(props) {
  const semantic = props.preview.semantic_preview;
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs font-bold uppercase tracking-[0.18em] text-brand-blue", children: "Protection review" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("h3", { className: "mt-1 text-lg font-semibold text-brand-dark", children: "What will change" })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap gap-2", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs(Pill, { children: [
          semantic.changed_target_count,
          " target",
          semantic.changed_target_count === 1 ? "" : "s"
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs(Pill, { children: [
          semantic.affected_permission_count,
          " permissions"
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs(Pill, { children: [
          semantic.affected_rule_count,
          " rules"
        ] })
      ] })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("dl", { className: "mt-4 grid gap-3 sm:grid-cols-3", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("dt", { className: "text-xs text-brand-dark/80", children: "Newly blocked settings" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("dd", { className: "mt-1 text-2xl font-semibold text-brand-dark", children: semantic.summary.newly_blocked_permissions })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("dt", { className: "text-xs text-brand-dark/80", children: "Newly allowed settings" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("dd", { className: "mt-1 text-2xl font-semibold text-brand-dark", children: semantic.summary.newly_allowed_permissions })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("dt", { className: "text-xs text-brand-dark/80", children: "Settings changing" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("dd", { className: "mt-1 text-2xl font-semibold text-brand-dark", children: semantic.summary.effective_change_count })
      ] })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-4 space-y-3", children: semantic.changed_targets.map((target) => /* @__PURE__ */ jsxRuntimeExports.jsxs("article", { className: "border-b border-[rgba(63,65,116,0.12)] py-3", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap items-center gap-2", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("strong", { className: "text-sm text-brand-dark", children: target.label }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs(Pill, { children: [
          target.before_explicit,
          " → ",
          target.after_explicit
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs(Pill, { children: [
          target.before_effective,
          " → ",
          target.after_effective
        ] }),
        target.baseline_risk ? /* @__PURE__ */ jsxRuntimeExports.jsxs(Pill, { tone: RISK_TONE[target.baseline_risk], children: [
          target.baseline_risk,
          " baseline"
        ] }) : null
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-2 text-xs text-brand-dark/80", children: [
        "Affects ",
        target.affected_permission_ids.length,
        " permission",
        target.affected_permission_ids.length === 1 ? "" : "s",
        " and ",
        target.affected_rule_ids.length,
        " rule",
        target.affected_rule_ids.length === 1 ? "" : "s",
        "."
      ] }),
      target.affected_rule_ids.length ? /* @__PURE__ */ jsxRuntimeExports.jsxs("details", { className: "mt-3", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("summary", { className: "cursor-pointer text-xs font-semibold text-brand-blue", children: "Developer details" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-2 max-h-40 overflow-auto", children: target.affected_rule_ids.map((id) => /* @__PURE__ */ jsxRuntimeExports.jsx("code", { className: "block break-all text-[11px] text-brand-dark/80", children: id }, id)) })
      ] }) : null,
      target.warnings.map((warning, index) => /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "mt-3 flex items-start gap-2 text-xs leading-5 text-amber-950", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniExclamationTriangle, { className: "mt-0.5 size-4 shrink-0" }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { children: [
          /* @__PURE__ */ jsxRuntimeExports.jsxs("strong", { children: [
            warning.code,
            ":"
          ] }),
          " ",
          warning.message
        ] })
      ] }, `${warning.code}-${index}`))
    ] }, `${target.target.kind}:${target.target.target_id}`)) }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("details", { className: "mt-4", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("summary", { className: "cursor-pointer text-xs font-semibold text-brand-dark/80", children: "Developer change identity" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("code", { className: "mt-2 block break-all text-[11px] text-brand-dark/80", children: props.preview.canonical_diff_digest })
    ] })
  ] });
}
function PolicyReviewSheet(props) {
  const ref = useModalDialog(props.onClose, !props.busy);
  const [password, setPassword] = reactExports.useState("");
  const [totpCode, setTotpCode] = reactExports.useState("");
  const count = props.preview.semantic_preview.changed_target_count;
  const submitDisabled = isApprovalProofSubmitDisabled(props.approvalGate, { approvalPassword: password, approvalTotpCode: totpCode }, props.busy, false, true);
  const handleSubmit = (event) => {
    event.preventDefault();
    if (submitDisabled) return;
    props.onApply(buildApprovalProofCredentials(props.approvalGate, { approvalPassword: password, approvalTotpCode: totpCode }));
  };
  return /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "fixed inset-0 z-50 bg-brand-dark/40", children: /* @__PURE__ */ jsxRuntimeExports.jsxs(
    "form",
    {
      ref,
      tabIndex: -1,
      role: "dialog",
      "aria-modal": "true",
      "aria-labelledby": "extension-policy-review-title",
      onSubmit: handleSubmit,
      className: "absolute inset-y-0 right-0 flex w-full max-w-2xl flex-col overflow-y-auto bg-[var(--surface-1)] p-5 focus:outline-none sm:p-6",
      children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-start justify-between gap-4", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs font-bold uppercase tracking-[0.18em] text-brand-blue", children: "Protection review" }),
            /* @__PURE__ */ jsxRuntimeExports.jsxs("h2", { id: "extension-policy-review-title", className: "mt-1 text-xl font-semibold text-brand-dark", children: [
              "Review and apply ",
              count,
              " protection setting change",
              count === 1 ? "" : "s"
            ] })
          ] }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("button", { type: "button", disabled: props.busy, "aria-label": "Close protection review", onClick: props.onClose, className: "grid size-11 place-items-center rounded-full text-brand-dark disabled:opacity-50", children: /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniXMark, { className: "size-5" }) })
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-5 flex-1", children: /* @__PURE__ */ jsxRuntimeExports.jsx(PreviewPanel, { preview: props.preview }) }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-5 border-t border-[rgba(63,65,116,0.12)] pt-4", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm font-semibold text-brand-dark", children: "Authenticate this exact change" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1 text-xs leading-5 text-brand-dark/75", children: "Guard uses a one-time local proof and rejects the apply if the reviewed settings changed." }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-3", children: /* @__PURE__ */ jsxRuntimeExports.jsx(
            ApprovalProofFieldInputs,
            {
              approvalGate: props.approvalGate,
              approvalPassword: password,
              approvalTotpCode: totpCode,
              requireGate: true,
              onApprovalPasswordChange: (event) => setPassword(event.target.value),
              onApprovalTotpCodeChange: (event) => setTotpCode(event.target.value)
            }
          ) }),
          props.error ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { role: "alert", className: "mt-3 text-sm text-red-950", children: props.error }) : null,
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "sticky bottom-0 z-10 -mx-5 mt-4 flex flex-wrap items-center justify-end gap-2 bg-[var(--surface-1)] px-5 pb-1 pt-3 sm:-mx-6 sm:px-6", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("button", { type: "button", disabled: props.busy, onClick: props.onClose, className: "inline-flex min-h-11 items-center justify-center rounded-xl border border-[rgba(63,65,116,0.2)] px-4 text-center text-sm font-semibold text-brand-dark", children: "Continue editing" }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("button", { type: "submit", disabled: submitDisabled, className: "inline-flex min-h-11 items-center justify-center rounded-xl bg-brand-blue px-4 text-center text-sm font-semibold text-[#f4f7fb] disabled:opacity-40", children: props.busy ? "Applying…" : `Apply ${count} reviewed change${count === 1 ? "" : "s"}` })
          ] })
        ] })
      ]
    }
  ) });
}
function ExtensionPolicyPanel(props) {
  const [policyExtension, setPolicyExtension] = reactExports.useState(props.extension);
  const draft = useExtensionPolicyDraft({ effective: props.effective, onRefresh: props.onRefresh });
  const {
    baseEffective,
    dirty,
    preview,
    previewBusy,
    applyBusy,
    reviewOpen,
    error,
    stale,
    pendingRebase,
    refreshRequired,
    lastApplied,
    undoLastApplied,
    setReviewOpen,
    setPermissionState,
    resetDraft,
    runPreview,
    apply,
    rebaseDraft,
    keepConflicts,
    useCurrent,
    useHistoricalDraft,
    permissionState,
    setPermissionStates
  } = draft;
  const { resolvedApprovalGate, resolveApprovalGate } = useResolvedApprovalGate(null);
  reactExports.useEffect(() => {
    props.onDirtyChange?.(dirty);
  }, [dirty, props.onDirtyChange]);
  reactExports.useEffect(() => {
    const beforeUnload = (event) => {
      if (!dirty) return;
      event.preventDefault();
      event.returnValue = "";
    };
    window.addEventListener("beforeunload", beforeUnload);
    return () => window.removeEventListener("beforeunload", beforeUnload);
  }, [dirty]);
  reactExports.useEffect(() => {
    setPolicyExtension(props.extension);
    resetDraft();
  }, [props.extension.extension_id]);
  reactExports.useEffect(() => {
    if (!reviewOpen) return;
    void resolveApprovalGate({ failClosed: true }).catch(() => {
    });
  }, [reviewOpen, resolveApprovalGate]);
  const managedCount = policyExtension.permissions.filter((permission) => managedPermissionState(baseEffective, permission.permission_id) !== null).length;
  const changeCount = draft.changeCountFor(policyExtension.permissions.map((permission) => permission.permission_id));
  const applyAcrossHref = appliedPolicyCloudHref({
    extensionName: policyExtension.name,
    extensionId: policyExtension.extension_id,
    changedPermissionIds: lastApplied?.changedPermissionIds ?? [],
    cloudControlsUrl: props.cloudControlsUrl
  });
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("section", { id: "extension-policy-editor", "aria-labelledby": "extension-policy-heading", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx("h2", { id: "extension-policy-heading", className: "text-lg font-semibold text-brand-dark", children: "Protection settings" }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-2 max-w-2xl text-sm leading-6 text-brand-dark/80", children: "Recommended follows Guard defaults. Allow is available only where built-in safety and organization policy still permit it. Block is a stricter local floor." }),
    /* @__PURE__ */ jsxRuntimeExports.jsx(
      QuickApplyToolbar,
      {
        permissions: policyExtension.permissions,
        effective: baseEffective,
        permissionState,
        onApply: setPermissionStates,
        disabled: refreshRequired || previewBusy || applyBusy || baseEffective.health !== "protected",
        subject: { one: "changeable setting", other: "changeable settings" }
      }
    ),
    /* @__PURE__ */ jsxRuntimeExports.jsx("div", { id: "extension-settings-history", children: /* @__PURE__ */ jsxRuntimeExports.jsx(ProtectionSettingsHistory, { catalogDigest: baseEffective.catalog_digest, disabled: baseEffective.health !== "protected" || refreshRequired, onUse: (layers) => useHistoricalDraft(layers) }) }),
    /* @__PURE__ */ jsxRuntimeExports.jsx(
      PolicyEditingLocks,
      {
        health: baseEffective.health,
        globalLockdown: baseEffective.global_lockdown
      }
    ),
    managedCount ? /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "mt-4 text-sm text-indigo-950", children: [
      managedCount,
      " setting",
      managedCount === 1 ? " is" : "s are",
      " managed by your organization. This device can add stricter blocks but cannot weaken an organization block."
    ] }) : null,
    lastApplied ? /* @__PURE__ */ jsxRuntimeExports.jsx(
      AppliedPolicyToast,
      {
        revision: lastApplied.revision,
        applyAcrossHref,
        onUndo: () => {
          undoLastApplied();
        },
        onViewHistory: () => {
          document.getElementById("extension-settings-history")?.scrollIntoView({ behavior: "smooth", block: "start" });
        }
      }
    ) : refreshRequired ? /* @__PURE__ */ jsxRuntimeExports.jsx(PolicyEditingLocks, { refreshRequired: true }) : null,
    /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-4", children: (() => {
      const { ungrouped, families } = groupPermissionsByFamily(policyExtension.permissions);
      const renderRow = (permission) => /* @__PURE__ */ jsxRuntimeExports.jsx(
        PermissionPolicyRow,
        {
          permission,
          extension: policyExtension,
          effective: baseEffective,
          draftState: permissionState(permission.permission_id),
          disabled: refreshRequired,
          onChange: (state) => setPermissionState(permission.permission_id, state)
        },
        permission.permission_id
      );
      return /* @__PURE__ */ jsxRuntimeExports.jsxs(jsxRuntimeExports.Fragment, { children: [
        ungrouped.map(renderRow),
        families.map((group) => /* @__PURE__ */ jsxRuntimeExports.jsxs("section", { "aria-label": `${group.heading} variants`, className: "guard-pattern-family", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsxs("h3", { className: "guard-pattern-family-heading", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("code", { children: group.heading }),
            /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { children: [
              group.permissions.length,
              " variant",
              group.permissions.length === 1 ? "" : "s"
            ] })
          ] }),
          group.permissions.map(renderRow)
        ] }, group.family))
      ] });
    })() }),
    dirty ? /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "guard-review-bar", children: /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "text-sm text-brand-dark", children: [
        changeCount,
        " unsaved setting change",
        changeCount === 1 ? "" : "s",
        "."
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap gap-2", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("button", { type: "button", disabled: previewBusy || applyBusy, onClick: resetDraft, className: "min-h-11 rounded-xl border border-[rgba(63,65,116,0.2)] px-4 text-sm font-semibold text-brand-dark", children: "Reset changes" }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("button", { type: "button", disabled: previewBusy || applyBusy || baseEffective.health !== "protected" || stale, onClick: () => {
          void runPreview();
        }, className: "inline-flex min-h-11 items-center gap-2 rounded-xl bg-brand-blue px-4 text-sm font-semibold text-[#f4f7fb] disabled:opacity-40", children: [
          previewBusy ? /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniArrowPath, { className: "size-4 animate-spin motion-reduce:animate-none" }) : /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniShieldCheck, { className: "size-4" }),
          "Review ",
          changeCount,
          " change",
          changeCount === 1 ? "" : "s"
        ] })
      ] })
    ] }) }) : null,
    error ? /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { role: "alert", className: "mt-4 text-sm text-red-950", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-start gap-2", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniExclamationTriangle, { className: "mt-0.5 size-5 shrink-0" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("span", { children: error })
      ] }),
      stale && !pendingRebase ? /* @__PURE__ */ jsxRuntimeExports.jsx("button", { type: "button", disabled: previewBusy, onClick: () => {
        void rebaseDraft([policyExtension]);
      }, className: "mt-3 min-h-11 rounded-xl bg-red-800 px-4 text-sm font-semibold text-[#f4f7fb]", children: "Update draft with latest protection" }) : null,
      pendingRebase ? /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-4", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("ul", { className: "space-y-2", children: pendingRebase.result.conflicts.map((conflict) => /* @__PURE__ */ jsxRuntimeExports.jsxs("li", { className: "text-xs text-brand-dark", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("code", { className: "break-all", children: conflict.original_permission_id }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-1", children: conflict.kind === "removed" ? "Target removed from the current catalog." : `Current ${conflict.latest_state}; your draft requests ${conflict.requested_state}.` })
        ] }, conflict.original_permission_id)) }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-3 flex flex-wrap gap-2", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("button", { type: "button", onClick: keepConflicts, className: "min-h-11 rounded-xl bg-red-800 px-4 text-sm font-semibold text-[#f4f7fb]", children: "Keep my compatible changes" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("button", { type: "button", onClick: useCurrent, className: "min-h-11 rounded-xl border border-red-300 px-4 text-sm font-semibold text-red-950", children: "Use current protection" })
        ] })
      ] }) : null
    ] }) : dirty && !preview ? /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-4 flex items-start gap-3 text-sm text-brand-dark", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniInformationCircle, { className: "mt-0.5 size-5 shrink-0" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { children: "Review is required before approval. Guard calculates the real outcome from current protections, dependencies, organization settings, and Emergency Lockdown before anything can change." })
    ] }) : null,
    reviewOpen && preview ? /* @__PURE__ */ jsxRuntimeExports.jsx(
      PolicyReviewSheet,
      {
        preview,
        approvalGate: resolvedApprovalGate,
        busy: applyBusy,
        error,
        onClose: () => {
          if (!applyBusy) setReviewOpen(false);
        },
        onApply: (credentials) => {
          void apply(credentials);
        }
      }
    ) : null
  ] });
}
function mcpToolCanReceiveDirectAllow(command) {
  if (command.command_id === "other") return false;
  const name = command.usage.split("__").at(-1)?.toLowerCase();
  return !name?.startsWith("composio_") || ["composio_search_tools", "composio_get_tool_schemas"].includes(name);
}
function mcpCatalogCopy(item) {
  if (item.surface !== "mcp") return null;
  const catalog = item.mcp_catalog;
  if (!catalog && item.remote_origin) return {
    title: "Remote connector",
    description: "Guard does not connect to remote servers, so it cannot list this connector's tools. Tools appear here after your host app calls them."
  };
  if (!catalog) return {
    title: "Inventory not checked",
    description: "Guard knows observed tools from this connector. Its full inventory has not been verified."
  };
  const count = `${catalog.known_count} ${catalog.known_count === 1 ? "tool" : "tools"}`;
  if (catalog.complete && catalog.fresh_until && Date.parse(catalog.fresh_until) <= Date.now()) return {
    title: `${count} cached · Refresh available`,
    description: "This inventory's freshness window ended. Existing choices are kept; list tools again to check for changes."
  };
  if (catalog.complete) return {
    title: `${count} listed`,
    description: "Discovery finished. Permission choices apply separately to each tool."
  };
  if (catalog.reason === "catalog_changed") return {
    title: "Inventory changed during discovery",
    description: "Guard kept your choices. List tools again to review a consistent inventory."
  };
  if (catalog.reason === "refresh_failed" || catalog.reason === "list_failed") return {
    title: catalog.stale ? `${count} cached · Refresh failed` : "Discovery did not finish",
    description: catalog.known_count > 0 ? "Known tools and choices are still available. Retry discovery to check the current inventory." : "Guard could not finish listing tools. Retry discovery to check this connector."
  };
  return {
    title: `${count} known · Inventory incomplete`,
    description: "Discovery reached a limit or returned an incomplete inventory. Unknown tools still need review."
  };
}
function rebaseCommandDraft(current, previous, next, changedToolNames = []) {
  const changed = new Set(changedToolNames);
  const previousStates = new Map(previous.map((command) => [command.command_id, command.state]));
  const edits = new Map(current.filter((command) => previousStates.has(command.command_id) && command.state !== previousStates.get(command.command_id)).map((command) => [command.command_id, command.state]));
  return next.map((command) => edits.has(command.command_id) && !(edits.get(command.command_id) === "allow" && (changed.has(command.command_id) || changed.has(command.usage))) ? { ...command, state: edits.get(command.command_id) } : command);
}
function commandPermissionChanges(previous, next) {
  const states = new Map(previous.map((command) => [command.command_id, command.state]));
  return next.filter((command) => command.state !== states.get(command.command_id)).map((command) => ({
    commandId: command.command_id,
    name: command.name,
    before: states.get(command.command_id) ?? null,
    after: command.state
  }));
}
const words = (code) => code.replaceAll("-", " ");
const explanations = {
  "reviewed-provider-mapping:v1": "Reviewed provider contract",
  "schema:content-fields": "Schema accepts content",
  "schema:credential-fields": "Schema accepts credentials",
  "schema:destination-fields": "Schema accepts a recipient or endpoint",
  "schema:execution-fields": "Schema accepts executable content",
  "provider-annotations:unverified": "Provider behavior claims, not verified by Guard"
};
function McpClassificationEvidence({ value }) {
  if (!value) return null;
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("details", { className: "mt-2 text-xs leading-5 text-brand-dark/75", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("summary", { className: "min-h-11 cursor-pointer py-3 font-semibold", children: [
      value.effect === "unknown" ? "Effect not resolved" : `Suggested effect: ${words(value.effect)}`,
      " · View evidence"
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("dl", { className: "grid gap-x-4 gap-y-2 sm:grid-cols-2", children: [
      ["Effect", value.effect],
      ["Data", value.data],
      ["Destination", value.destination],
      ["Reversibility", value.reversibility]
    ].map(([label, content]) => /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("dt", { className: "font-semibold", children: label }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("dd", { children: words(content) })
    ] }, label)) }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "mt-3", children: [
      "Evidence quality: ",
      value.confidence === "reviewed-mapping" ? "reviewed contract" : "limited",
      ". These suggestions do not verify behavior, account, or permission."
    ] }),
    value.evidence.length ? /* @__PURE__ */ jsxRuntimeExports.jsx("ul", { className: "mt-2 list-disc pl-5", children: value.evidence.map((code) => /* @__PURE__ */ jsxRuntimeExports.jsx("li", { children: explanations[code] ?? "Unrecognized evidence" }, code)) }) : null,
    value.warnings.length ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-2 font-semibold", children: value.warnings.map(words).join(" · ") }) : null
  ] });
}
const COLLAPSE_GROUPS_AT = 30;
const STATE_RANK = { block: 0, review: 1, allow: 2, inherit: 3 };
const SPECIAL_COMMAND_IDS = /* @__PURE__ */ new Set(["root", "other"]);
function commandMatchesQuery(command, query) {
  const terms = query.trim().toLowerCase().split(/\s+/).filter(Boolean);
  if (terms.length === 0) return true;
  const haystack = `${command.name}
${command.usage}
${command.description}`.toLowerCase();
  return terms.every((term) => haystack.includes(term));
}
function commandChanged(command, saved) {
  return (saved.get(command.command_id) ?? "inherit") !== command.state;
}
function savedStateMap(saved) {
  return new Map(saved.map((command) => [command.command_id, command.state]));
}
function commandMatchesFilter(command, filter, saved) {
  if (filter === "all") return true;
  if (filter === "changed") return commandChanged(command, saved);
  return command.state === filter;
}
function stateFilterCounts(commands, saved) {
  const counts = { all: commands.length, changed: 0, inherit: 0, allow: 0, review: 0, block: 0 };
  for (const command of commands) {
    counts[command.state] += 1;
    if (commandChanged(command, saved)) counts.changed += 1;
  }
  return counts;
}
function sortCommands(commands, sort) {
  if (sort === "catalog") return [...commands];
  const byName = (left, right) => left.name.localeCompare(right.name, void 0, { numeric: true, sensitivity: "base" });
  if (sort === "name") return [...commands].sort(byName);
  return [...commands].sort((left, right) => STATE_RANK[left.state] - STATE_RANK[right.state] || byName(left, right));
}
function commandGroupKey(command, surface) {
  if (SPECIAL_COMMAND_IDS.has(command.command_id) || surface === "mcp") return `id:${command.command_id}`;
  if (surface === "package-scripts") {
    const colon = command.name.indexOf(":");
    return `name:${colon > 0 ? command.name.slice(0, colon) : command.name}`;
  }
  return `id:${command.parent_id ? command.parent_id.split(".")[0] : command.command_id}`;
}
function groupCommands(commands, surface) {
  const groups = /* @__PURE__ */ new Map();
  const names = new Map(commands.map((command) => [command.command_id, command.name]));
  for (const command of commands) {
    const key = commandGroupKey(command, surface);
    let group = groups.get(key);
    if (!group) {
      const raw = key.slice(key.indexOf(":") + 1);
      group = { key, label: key.startsWith("name:") ? raw : names.get(raw) ?? raw, commands: [] };
      groups.set(key, group);
    }
    group.commands.push(command);
  }
  return [...groups.values()];
}
function commandNamePrefix(name, groupLabel) {
  return name.startsWith(`${groupLabel}:`) ? `${groupLabel}:` : "";
}
function groupStateSummary(commands) {
  const counts = stateFilterCounts(commands, /* @__PURE__ */ new Map());
  const parts = [
    counts.allow > 0 ? `${counts.allow} allowed` : "",
    counts.review > 0 ? `${counts.review} ask` : "",
    counts.block > 0 ? `${counts.block} blocked` : ""
  ].filter(Boolean);
  if (parts.length === 0) return "All Recommended";
  if (counts.inherit > 0) parts.push(`${counts.inherit} Recommended`);
  return parts.join(" · ");
}
function commandRowUsageFor(command, surface) {
  const usage = command.usage.trim();
  if (usage === "" || usage === command.name) return null;
  if (surface === "package-scripts" && usage.endsWith(` ${command.name}`)) return null;
  return usage;
}
function commandDescriptionIsCode(command, surface) {
  return surface === "package-scripts" && !SPECIAL_COMMAND_IDS.has(command.command_id);
}
function commandStatesPayload(commands) {
  return commands.map((command) => ({ command_id: command.command_id, state: command.state }));
}
function withCommandState(commands, commandId, state) {
  return commands.map((command) => command.command_id === commandId ? { ...command, state } : command);
}
function emptyCommandCopy(surface) {
  if (surface === "mcp") {
    return "Guard has not loaded tools for this MCP server yet. Find the server again to list its tools.";
  }
  if (surface === "package-scripts") {
    return "Guard has not loaded scripts from package.json yet. Paste npm run, a project folder, or package.json.";
  }
  return "Guard has not loaded commands for this tool yet. Find the tool again to read its --help output.";
}
function CustomExtensionCommandRow(props) {
  const handleChange = reactExports.useCallback((state) => {
    props.onChange(props.command.command_id, state);
  }, [props]);
  const prefix = props.groupLabel === void 0 ? "" : commandNamePrefix(props.command.name, props.groupLabel);
  const usage = commandRowUsageFor(props.command, props.surface);
  const descriptionIsCode = commandDescriptionIsCode(props.command, props.surface);
  return /* @__PURE__ */ jsxRuntimeExports.jsxs(
    "article",
    {
      className: "guard-pattern-row px-4 py-3",
      "data-command-id": props.command.command_id,
      "data-changed": props.changed ? "true" : void 0,
      children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "min-w-0 pr-3", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex min-w-0 flex-wrap items-baseline gap-x-2 gap-y-1", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsxs("h3", { className: "min-w-0 break-words text-sm font-semibold text-brand-dark", children: [
              prefix ? /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "font-medium text-brand-dark/55", children: prefix }) : null,
              props.command.name.slice(prefix.length)
            ] }),
            props.changed ? /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { className: "inline-flex items-center gap-1 text-xs font-semibold text-brand-blue", children: [
              /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "size-1.5 rounded-full bg-brand-blue", "aria-hidden": "true" }),
              props.changedLabel ?? "Unsaved"
            ] }) : null
          ] }),
          usage ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "guard-pattern-example mt-1 truncate", title: props.command.usage, children: usage }) : null,
          props.command.description ? descriptionIsCode ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "guard-pattern-example mt-1 truncate", title: props.command.description, children: props.command.description }) : /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1 text-xs leading-5 text-brand-dark/70", children: props.command.description }) : null,
          /* @__PURE__ */ jsxRuntimeExports.jsx(McpClassificationEvidence, { value: props.command.classification }),
          props.surface === "mcp" && !mcpToolCanReceiveDirectAllow(props.command) ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1.5 text-xs leading-5 text-brand-dark/75", children: props.command.command_id === "other" ? "New tools require review. You can deny tools outside this inventory." : "Review the actions and account inside this tool. A wrapper permission cannot allow execution." }) : null
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsx(
          CommandDraftControl,
          {
            label: props.command.name,
            state: props.command.state,
            disabled: props.disabled,
            mcpPolicy: props.surface === "mcp",
            allowDisabled: props.surface === "mcp" && !mcpToolCanReceiveDirectAllow(props.command),
            onChange: handleChange
          }
        )
      ]
    }
  );
}
function CommandDraftControl(props) {
  const choices = [
    { value: "inherit", label: props.mcpPolicy ? "Policy" : "Recommended" },
    { value: "allow", label: "Allow", disabled: props.allowDisabled },
    ...props.mcpPolicy ? [{ value: "review", label: "Ask" }] : [],
    { value: "block", label: props.mcpPolicy ? "Deny" : "Block" }
  ];
  const tabStopIndex = extensionPolicyRadioTabStop(choices, props.state, props.disabled);
  const chooseAdjacent = (event, index) => {
    const next = nextExtensionPolicyRadioIndex(choices, index, event.key, props.disabled);
    if (next < 0) return;
    event.preventDefault();
    props.onChange(choices[next].value);
    event.currentTarget.parentElement?.querySelectorAll('[role="radio"]')[next]?.focus();
  };
  return /* @__PURE__ */ jsxRuntimeExports.jsx(
    "div",
    {
      role: "radiogroup",
      "aria-label": `${props.label} protection setting`,
      className: props.mcpPolicy ? "guard-segmented !grid grid-cols-2 sm:!flex [&_[role=radio]]:!min-h-11" : "guard-segmented",
      children: choices.map((choice, index) => /* @__PURE__ */ jsxRuntimeExports.jsx(
        CommandChoiceButton,
        {
          choice,
          checked: props.state === choice.value,
          tabIndex: !props.disabled && index === tabStopIndex ? 0 : -1,
          disabled: props.disabled || choice.disabled === true,
          index,
          onChoose: props.onChange,
          onAdjacent: chooseAdjacent
        },
        choice.value
      ))
    }
  );
}
function CommandChoiceButton(props) {
  const handleClick = reactExports.useCallback(() => {
    props.onChoose(props.choice.value);
  }, [props]);
  const handleKeyDown = reactExports.useCallback((event) => {
    props.onAdjacent(event, props.index);
  }, [props]);
  return /* @__PURE__ */ jsxRuntimeExports.jsx(
    "button",
    {
      type: "button",
      role: "radio",
      "aria-checked": props.checked,
      tabIndex: props.tabIndex,
      disabled: props.disabled,
      onKeyDown: handleKeyDown,
      onClick: handleClick,
      className: "disabled:cursor-not-allowed disabled:opacity-45",
      children: props.choice.label
    }
  );
}
function BulkPolicyPicker(props) {
  const choices = [
    { value: "inherit", label: props.mcpPolicy ? "Use policy" : "Recommended" },
    { value: "allow", label: props.allowLabel ?? "Allow all" },
    ...props.mcpPolicy ? [{ value: "review", label: "Ask listed" }] : [],
    { value: "block", label: props.blockLabel ?? "Block all" }
  ];
  const mixed = props.value === "mixed";
  const selected = mixed ? "inherit" : props.value;
  const groupLabel = props.groupLabel ?? "All tools protection setting";
  const tabStopIndex = extensionPolicyRadioTabStop(choices, selected, props.disabled);
  const chooseAdjacent = (event, index) => {
    const next = nextExtensionPolicyRadioIndex(choices, index, event.key, props.disabled);
    if (next < 0) return;
    event.preventDefault();
    props.onChange(choices[next].value);
    event.currentTarget.parentElement?.querySelectorAll('[role="radio"]')[next]?.focus();
  };
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: props.className ?? "mt-4", "data-testid": "custom-extension-bulk-policy", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx(
      "div",
      {
        role: "radiogroup",
        "aria-label": mixed ? `${groupLabel}. Custom mix` : groupLabel,
        "aria-describedby": mixed ? "bulk-policy-mixed" : void 0,
        className: props.mcpPolicy ? "guard-segmented w-fit !grid grid-cols-2 sm:!flex [&_[role=radio]]:!min-h-11" : "guard-segmented w-fit",
        children: choices.map((choice, index) => /* @__PURE__ */ jsxRuntimeExports.jsx(
          BulkPolicyChoice,
          {
            choice,
            checked: props.value === choice.value,
            tabIndex: !props.disabled && index === tabStopIndex ? 0 : -1,
            disabled: props.disabled,
            index,
            onChoose: props.onChange,
            onAdjacent: chooseAdjacent
          },
          choice.value
        ))
      }
    ),
    props.value === "mixed" ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { id: "bulk-policy-mixed", className: "mt-2 text-xs leading-5 text-brand-dark/70", children: props.mixedCopy ?? `Custom mix. Pick Recommended, ${props.allowLabel ?? "Allow all"}, or Block all to reset every tool.` }) : null
  ] });
}
function BulkPolicyChoice(props) {
  const handleClick = reactExports.useCallback(() => {
    props.onChoose(props.choice.value);
  }, [props]);
  const handleKeyDown = reactExports.useCallback((event) => {
    props.onAdjacent(event, props.index);
  }, [props]);
  return /* @__PURE__ */ jsxRuntimeExports.jsx(
    "button",
    {
      type: "button",
      role: "radio",
      "aria-checked": props.checked,
      tabIndex: props.tabIndex,
      disabled: props.disabled,
      onKeyDown: handleKeyDown,
      onClick: handleClick,
      className: "min-h-11 px-4 text-sm font-semibold disabled:cursor-not-allowed disabled:opacity-45",
      children: props.choice.label
    }
  );
}
function customExtensionContinuityView(state) {
  const privacyDisclosure = "Guard Cloud receives stable identity and compatibility metadata, not local source paths.";
  switch (state) {
    case "local-only":
      return {
        state,
        title: "Available on this device",
        description: "This custom protection remains local until portable continuity is enabled.",
        canApplyAcrossDevices: false,
        privacyDisclosure
      };
    case "identity-matched":
      return {
        state,
        title: "Matched on another device",
        description: "Guard matched the stable identity. Each device still uses its own verified definition.",
        canApplyAcrossDevices: true,
        privacyDisclosure
      };
    case "portable":
      return {
        state,
        title: "Portable continuity enabled",
        description: "A verified portable definition is available to compatible devices.",
        canApplyAcrossDevices: true,
        privacyDisclosure
      };
    case "incompatible":
      return {
        state,
        title: "Needs a compatible definition",
        description: "This device cannot apply the shared custom protection safely.",
        canApplyAcrossDevices: false,
        privacyDisclosure
      };
    case "pending-observation":
      return {
        state,
        title: "Waiting for this device",
        description: "Cloud settings stay pending until Guard observes the same extension identity locally.",
        canApplyAcrossDevices: false,
        privacyDisclosure
      };
    case "changed-identity":
      return {
        state,
        title: "Identity changed",
        description: "Guard refused the Cloud settings because this device observed a different identity.",
        canApplyAcrossDevices: false,
        privacyDisclosure
      };
    case "locally-overridden":
      return {
        state,
        title: "Changed on this device",
        description: "Guard kept this device's local setting until a newer Cloud revision is available.",
        canApplyAcrossDevices: false,
        privacyDisclosure
      };
    case "removed":
      return {
        state,
        title: "Removed on this device",
        description: "The local setting was removed. Guard did not delete the script, executable, or MCP configuration.",
        canApplyAcrossDevices: false,
        privacyDisclosure
      };
    case "stale":
      return {
        state,
        title: "Cloud observation is stale",
        description: "Guard kept the last-known-good local setting and did not apply expired Cloud state.",
        canApplyAcrossDevices: false,
        privacyDisclosure
      };
  }
}
function customExtensionActionLabel(item) {
  if (item.seeded === true) return `Set up ${item.display_name ?? item.name}`;
  if (item.state !== "unset" || item.surface !== "cli" || !item.suggestable) return null;
  return hasSuggestedRules(item) ? "Review suggested rules" : "Review and add";
}
const SUGGESTED_RULES_NOTICE = "Suggested rules are pre-selected for commands you have not set yet. Nothing changes until you review and confirm.";
function randomToken$2() {
  return crypto.randomUUID().replaceAll("-", "");
}
function customExtensionRowDescription(item, catalogTitle) {
  if (item.seeded === true) return `${item.display_name ?? item.name} is not set up yet. Set it up to review its commands.`;
  if (catalogTitle) return [item.source_label, catalogTitle].filter(Boolean).join(" · ");
  if (item.source_label) return `${item.example_label} · ${item.source_label}`;
  return item.example_label;
}
function nativePublicationMessage(publication, permissionScope) {
  if (permissionScope === "configured-connection") {
    return publication?.state === "failed" ? "Your choices are stored, but policy publication failed. Guard has not confirmed enforcement for this connection." : "Your choices are stored for this configured connection. Native host-hook calls use separately observed tool permissions until Guard verifies a binding to this connection.";
  }
  if (publication?.state === "acknowledged") {
    return `Native policy acknowledged saved revision ${publication.revision}. Live calls still check host namespace and tool authority.`;
  }
  if (publication?.state === "pending") {
    return "Your choices are stored. Waiting for the native runtime to acknowledge this revision before showing them as enforced.";
  }
  if (publication?.state === "failed") {
    return "Your choices are stored, but native publication failed. Enforcement readiness is not confirmed.";
  }
  return "Your choices are stored. Native enforcement readiness has not been confirmed.";
}
function mcpPermissionStatusLabel(publication, permissionScope) {
  if (permissionScope === "configured-connection") return "Connection choices stored · host binding unverified";
  if (publication?.state === "acknowledged") return "Tool permissions saved and acknowledged";
  if (publication?.state === "pending") return "Waiting for policy confirmation";
  return "Policy confirmation unavailable";
}
function detailPolicyCopy(surface) {
  if (surface === "mcp") {
    return "Ask requires approval. Allow and Deny apply within the scope shown in Connection details. Allow does not override stricter Guard policy, so protected MCP actions may still need fresh approval. Execution wrappers require review of their underlying actions.";
  }
  if (surface === "package-scripts") {
    return "Recommended keeps Guard's usual review. Allow or block applies to that npm, pnpm, yarn, or bun script in this project. Nested names such as guard:audit stay grouped.";
  }
  return "Recommended keeps Guard's usual review. Allow or block applies to that command from this file. Pipes, wrappers, and destructive commands stay under Guard's usual rules.";
}
function detailCatalogHeading(surface) {
  if (surface === "mcp") return "MCP tools";
  if (surface === "package-scripts") return "Package scripts";
  return "Command patterns";
}
function detailCatalogHelper(surface) {
  if (surface === "mcp") {
    return "Choose Allow, Ask, or Deny for each tool. Policy follows Guard's existing rules.";
  }
  if (surface === "package-scripts") {
    return "Recommended keeps Guard's usual review. Allow or Block applies to that script in this project. Scripts that share a prefix, such as build:web, sit together.";
  }
  return "Recommended keeps Guard's usual review. Allow or Block applies to that command from this file. Pipes, wrappers, and destructive commands stay under Guard's usual rules.";
}
function commandBrowserCopy(surface) {
  if (surface === "mcp") {
    return {
      searchLabel: "Find a tool",
      searchPlaceholder: "Find a tool by name or description",
      catalogOrder: "Server order",
      units: "tools",
      unit: (count) => count === 1 ? "tool" : "tools"
    };
  }
  if (surface === "package-scripts") {
    return {
      searchLabel: "Find a script",
      searchPlaceholder: "Find a script by name or what it runs",
      catalogOrder: "package.json order",
      units: "scripts",
      unit: (count) => count === 1 ? "script" : "scripts"
    };
  }
  return {
    searchLabel: "Find a command",
    searchPlaceholder: "Find a command by name or usage",
    catalogOrder: "Help order",
    units: "commands",
    unit: (count) => count === 1 ? "command" : "commands"
  };
}
function bulkPolicyCopy(surface) {
  if (surface === "mcp") {
    return {
      groupLabel: "Listed tools with direct permissions",
      mixedCopy: "Custom mix. Use policy, allow, ask, or deny the listed tools with direct permissions."
    };
  }
  if (surface === "package-scripts") {
    return {
      groupLabel: "All scripts protection setting",
      mixedCopy: "Custom mix. Pick Recommended, Allow all, or Block all to reset every script."
    };
  }
  return {
    groupLabel: "All commands protection setting",
    mixedCopy: "Custom mix. Pick Recommended, Allow all, or Block all to reset every command."
  };
}
const FRESH_TOTP_REQUIRED_MESSAGE = "Enter the current six-digit code from your authenticator.";
function isFreshTotpRequired(error) {
  return error instanceof LocalCliApiError && error.code === "approval_gate_totp_required";
}
function reviewTitle(name, state) {
  if (state === "allowed") return `Save ${name} command settings`;
  if (state === "blocked") return `Block ${name}`;
  return `Remove ${name}`;
}
function reviewModalDetail(gate, requireFreshTotp = false) {
  if (!requireFreshTotp && approvalProofRecentlySatisfied(gate)) {
    return "Recently confirmed with your authenticator. A new code is not needed yet.";
  }
  if (gate?.totp_enabled === true) {
    return "Enter the current authenticator code to save these settings on this device.";
  }
  return "This custom Extension remains local to this device until portable continuity is enabled.";
}
function customExtensionUnits(surface) {
  if (surface === "mcp") return { unit: "tool", units: "tools", source: "this server" };
  if (surface === "package-scripts") return { unit: "script", units: "scripts", source: "this project" };
  return { unit: "command", units: "commands", source: "this file" };
}
function customExtensionStateLabel(item) {
  if (item.seeded === true) return "Not set up yet. Guard keeps its usual review until you add it.";
  if (item.state === "unset" && item.surface === "cli" && item.suggestable) {
    return hasSuggestedRules(item) ? "Guard detected this tool. Review suggested rules before adding it." : "Guard detected this tool. Review it before adding it.";
  }
  const { unit, units, source } = customExtensionUnits(item.surface);
  if (item.stale) {
    if (item.surface === "mcp") return "This connection changed. Review its permissions again.";
    return item.surface === "package-scripts" ? "package.json scripts changed. Review the extension again." : "This file changed. Review the extension again.";
  }
  if (item.state === "blocked") return `Every ${unit} from ${source} is blocked.`;
  if (item.state === "allowed") {
    if (item.surface === "mcp") {
      const tools = item.commands.filter((command) => command.command_id !== "other");
      if (tools.length === 0) return item.remote_origin ? "No tools seen yet. Use one of its tools in your host app, then choose permissions here." : "No tools allowed yet. List the inventory to choose permissions.";
      const allowed2 = tools.filter((command) => command.state === "allow" && mcpToolCanReceiveDirectAllow(command)).length;
      const denied = tools.filter((command) => command.state === "block").length;
      const ask = tools.filter((command) => command.state === "review" || !mcpToolCanReceiveDirectAllow(command) && command.state !== "block").length;
      return `${allowed2} allowed · ${ask} ask · ${denied} denied. New tools require review.`;
    }
    if (item.commands.length === 0) {
      return `Matching ${units} from ${source} are allowed.`;
    }
    const allowed = item.commands.filter((command) => command.state === "allow").length;
    if (allowed > 0) return `${allowed} ${allowed === 1 ? unit : units} allowed. The rest follow Recommended.`;
    return `${units.charAt(0).toUpperCase()}${units.slice(1)} follow Recommended until you allow or block them.`;
  }
  return item.surface === "mcp" ? "Detected · Permissions not configured. Inspect this connection." : item.example_label;
}
function customExtensionRowBehavior(item) {
  const continuity = continuityCopy(item);
  return continuity ? `${continuity.title}. ${continuity.description}` : customExtensionStateLabel(item);
}
function customExtensionRowSource(item) {
  return item.surface === "mcp" && item.source_label ? item.source_label : void 0;
}
function continuityCopy(item) {
  const status = item.continuity?.status;
  if (status === "applied") {
    const view = customExtensionContinuityView("identity-matched");
    return { title: view.title, description: view.description };
  }
  if (status === "pending_observation") return customExtensionContinuityView("pending-observation");
  if (status === "changed_identity") return customExtensionContinuityView("changed-identity");
  if (status === "locally_overridden") return customExtensionContinuityView("locally-overridden");
  if (status === "removed") return customExtensionContinuityView("removed");
  if (status === "stale") return customExtensionContinuityView("stale");
  return null;
}
function connectorSetupCopy(match, name) {
  if (match === "identity_changed") {
    return {
      title: "This connector changed since the request was held",
      body: `The ${name} Guard sees now has a different identity from the one an agent was held on. Review it before you allow it. The held request stays in the Inbox.`
    };
  }
  if (match === "decided") {
    return {
      title: `${name} already has a decision`,
      body: "Requests held on it stay in the Inbox for a normal decision."
    };
  }
  return {
    title: `Set up ${name} for the held request`,
    body: "Guard held an agent action because it does not know this connector yet. Setting it up with the recommended settings allows its commands on this device, then approves the requests held on it once. Detector floors and sensitive-file reviews still apply, and nothing changes until you confirm."
  };
}
function heldRequests(count) {
  return `${count} held request${count === 1 ? "" : "s"}`;
}
function connectorGroupOutcomeCopy(outcome) {
  const hint = outcome.retryHint ? ` ${outcome.retryHint.replace(/\.?$/, ".")}` : "";
  if (outcome.status === "resolved") return `Set up. Guard approved ${heldRequests(outcome.resolvedCount)} once.${hint}`;
  if (outcome.status === "partial") {
    return `Set up. Guard approved ${heldRequests(outcome.resolvedCount)} once; the rest still need a decision in the Inbox.${hint}`;
  }
  if (outcome.status === "not_in_group") return "Set up. The held request is no longer waiting on this connector.";
  return "Set up. Guard could not approve the held requests here, so they are still in the Inbox.";
}
function CustomExtensionCommandBrowser(props) {
  const copy = commandBrowserCopy(props.surface);
  const searchId = reactExports.useId();
  const [query, setQuery] = reactExports.useState(props.initialQuery ?? "");
  const changedLabel = props.changedLabel ?? "Unsaved";
  const [filter, setFilter] = reactExports.useState("all");
  const [sort, setSort] = reactExports.useState("catalog");
  const saved = reactExports.useMemo(() => savedStateMap(props.savedCommands), [props.savedCommands]);
  const searched = reactExports.useMemo(
    () => props.commands.filter((command) => commandMatchesQuery(command, query)),
    [props.commands, query]
  );
  const counts = reactExports.useMemo(() => stateFilterCounts(searched, saved), [searched, saved]);
  const viewKey = [query, filter, sort, props.commands.map((command) => command.command_id).join("\n")].join("\0");
  const [frozen, setFrozen] = reactExports.useState({ key: viewKey, saved, commands: props.commands });
  let viewBase = frozen;
  if (frozen.key !== viewKey || frozen.saved !== saved) {
    viewBase = { key: viewKey, saved, commands: props.commands };
    setFrozen(viewBase);
  }
  const visible = reactExports.useMemo(() => {
    const live = new Map(props.commands.map((command) => [command.command_id, command]));
    return sortCommands(
      viewBase.commands.filter((command) => commandMatchesQuery(command, query) && commandMatchesFilter(command, filter, saved)),
      sort
    ).flatMap((command) => live.get(command.command_id) ?? []);
  }, [viewBase.commands, props.commands, query, filter, saved, sort]);
  const groups = reactExports.useMemo(() => groupCommands(visible, props.surface), [visible, props.surface]);
  const families = groups.filter((group) => group.commands.length > 1);
  const narrowed = query.trim() !== "" || filter !== "all";
  const familyKeys = reactExports.useMemo(
    () => groupCommands(props.commands, props.surface).filter((group) => group.commands.length > 1).map((group) => group.key),
    [props.commands, props.surface]
  );
  const longCatalog = props.commands.length > COLLAPSE_GROUPS_AT;
  const [collapsed, setCollapsed] = reactExports.useState(() => new Set(longCatalog ? familyKeys : []));
  const [knownFamilies, setKnownFamilies] = reactExports.useState(() => new Set(familyKeys));
  const newFamilies = familyKeys.filter((key) => !knownFamilies.has(key));
  if (newFamilies.length > 0) {
    setKnownFamilies(/* @__PURE__ */ new Set([...knownFamilies, ...newFamilies]));
    if (longCatalog) setCollapsed((current) => /* @__PURE__ */ new Set([...current, ...newFamilies]));
  }
  const anyCollapsed = !narrowed && families.some((group) => collapsed.has(group.key));
  const bulkTargets = visible.filter(props.bulkEligible);
  const toggleGroup = reactExports.useCallback((key) => {
    setCollapsed((current) => {
      const next = new Set(current);
      if (!next.delete(key)) next.add(key);
      return next;
    });
  }, []);
  const toggleAll = reactExports.useCallback(() => {
    setCollapsed(anyCollapsed ? /* @__PURE__ */ new Set() : new Set(families.map((group) => group.key)));
  }, [anyCollapsed, families]);
  const clearView = reactExports.useCallback(() => {
    setQuery("");
    setFilter("all");
  }, []);
  const applyToVisible = reactExports.useCallback((state) => {
    props.onBulkChange(new Set(bulkTargets.map((command) => command.command_id)), state);
  }, [bulkTargets, props]);
  if (props.commands.length === 0) {
    return /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-4 text-sm leading-6 text-brand-dark/75", children: emptyCommandCopy(props.surface) });
  }
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-4", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "sticky top-0 z-10 -mx-1 bg-white px-1 pb-3 pt-2", "data-testid": "custom-extension-command-toolbar", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap items-center gap-2", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs("label", { htmlFor: searchId, className: "relative block min-w-0 flex-1 basis-56", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "sr-only", children: copy.searchLabel }),
          /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniMagnifyingGlass, { className: "pointer-events-none absolute left-3 top-1/2 size-4 -translate-y-1/2 text-brand-dark/50", "aria-hidden": "true" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx(
            "input",
            {
              id: searchId,
              type: "search",
              value: query,
              placeholder: copy.searchPlaceholder,
              onChange: (event) => setQuery(event.target.value),
              className: "min-h-11 w-full rounded-xl border border-slate-300 bg-white pl-9 pr-3 text-sm text-brand-dark placeholder:text-brand-dark/50 focus-visible:border-brand-blue focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-1 focus-visible:outline-brand-blue"
            }
          )
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("label", { className: "inline-flex min-h-11 items-center gap-2 text-sm text-brand-dark/70", children: [
          "Sort",
          /* @__PURE__ */ jsxRuntimeExports.jsxs(
            "select",
            {
              value: sort,
              onChange: (event) => setSort(event.target.value),
              className: "min-h-11 rounded-xl border border-slate-300 bg-white px-3 text-sm font-semibold text-brand-dark focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-1 focus-visible:outline-brand-blue",
              children: [
                /* @__PURE__ */ jsxRuntimeExports.jsx("option", { value: "catalog", children: copy.catalogOrder }),
                /* @__PURE__ */ jsxRuntimeExports.jsx("option", { value: "name", children: "Name" }),
                /* @__PURE__ */ jsxRuntimeExports.jsx("option", { value: "state", children: "Setting" })
              ]
            }
          )
        ] }),
        families.length > 0 && !narrowed ? /* @__PURE__ */ jsxRuntimeExports.jsx(
          "button",
          {
            type: "button",
            onClick: toggleAll,
            className: "min-h-11 rounded-xl px-3 text-sm font-semibold text-brand-dark/80 hover:text-brand-dark",
            children: anyCollapsed ? "Expand all" : "Collapse all"
          }
        ) : null
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsx(StateFilterChips, { surface: props.surface, filter, counts, changedLabel, onChange: setFilter })
    ] }),
    bulkTargets.length > 0 ? /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-3", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm font-semibold text-brand-dark", "aria-hidden": "true", children: narrowed ? `Set the ${bulkTargets.length} ${copy.unit(bulkTargets.length)} shown` : `Set all ${bulkTargets.length} ${copy.unit(bulkTargets.length)}` }),
      /* @__PURE__ */ jsxRuntimeExports.jsx(
        BulkPolicyPicker,
        {
          className: "mt-2",
          value: bulkCommandState(bulkTargets),
          disabled: props.disabled,
          onChange: applyToVisible,
          groupLabel: narrowed ? `${bulkTargets.length} matching ${copy.unit(bulkTargets.length)} protection setting` : props.bulkGroupLabel,
          allowLabel: props.surface === "mcp" ? "Allow listed" : void 0,
          blockLabel: props.surface === "mcp" ? "Deny listed" : void 0,
          mcpPolicy: props.surface === "mcp",
          mixedCopy: narrowed ? `Custom mix. Pick one setting for the ${bulkTargets.length} ${copy.unit(bulkTargets.length)} shown.` : props.bulkMixedCopy
        }
      ),
      narrowed ? /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "mt-2 text-xs leading-5 text-brand-dark/75", "data-testid": "custom-extension-bulk-scope", children: [
        "Applies to the ",
        bulkTargets.length,
        " ",
        copy.unit(bulkTargets.length),
        " shown. Hidden ",
        copy.units,
        " keep their setting."
      ] }) : null
    ] }) : null,
    /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "sr-only", role: "status", "aria-live": "polite", children: narrowed ? `${visible.length} of ${props.commands.length} ${copy.units} shown` : "" }),
    visible.length === 0 && props.commands.length > 0 ? /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-6 rounded-xl border border-dashed border-slate-300 px-4 py-6 text-center", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "text-sm text-brand-dark/75", children: [
        "No ",
        copy.units,
        " match this view."
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs(
        "button",
        {
          type: "button",
          onClick: clearView,
          className: "mt-2 inline-flex min-h-11 items-center gap-1.5 rounded-xl px-3 text-sm font-semibold text-brand-blue",
          children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniXMark, { className: "size-4", "aria-hidden": "true" }),
            "Clear search and filters"
          ]
        }
      )
    ] }) : /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-3", children: groups.map((group) => group.commands.length > 1 ? /* @__PURE__ */ jsxRuntimeExports.jsx(
      CommandFamily,
      {
        group,
        open: narrowed || !collapsed.has(group.key),
        collapsible: !narrowed,
        unitLabel: copy.unit,
        surface: props.surface,
        disabled: props.disabled,
        saved,
        changedLabel,
        bulkEligible: props.bulkEligible,
        onToggle: toggleGroup,
        onChange: props.onChange,
        onBulkChange: props.onBulkChange
      },
      group.key
    ) : /* @__PURE__ */ jsxRuntimeExports.jsx(
      CustomExtensionCommandRow,
      {
        command: group.commands[0],
        disabled: props.disabled,
        surface: props.surface,
        groupLabel: "",
        changed: commandChanged(group.commands[0], saved),
        changedLabel,
        onChange: props.onChange
      },
      group.key
    )) })
  ] });
}
const FILTER_ORDER = ["all", "allow", "review", "block", "inherit", "changed"];
function StateFilterChips(props) {
  const mcp = props.surface === "mcp";
  const label = (value) => {
    if (value === "all") return "All";
    if (value === "allow") return "Allowed";
    if (value === "review") return "Ask";
    if (value === "block") return mcp ? "Denied" : "Blocked";
    if (value === "inherit") return mcp ? "Policy" : "Recommended";
    return props.changedLabel;
  };
  const shown = FILTER_ORDER.filter((value) => value === "all" || value === props.filter || props.counts[value] > 0);
  const narrows = shown.some((value) => value !== "all" && props.counts[value] > 0 && props.counts[value] < props.counts.all);
  if (props.filter === "all" && !narrows) return null;
  return /* @__PURE__ */ jsxRuntimeExports.jsx("div", { role: "group", "aria-label": "Show by setting", className: "mt-2 flex flex-wrap gap-1.5", children: shown.map((value) => /* @__PURE__ */ jsxRuntimeExports.jsxs(
    "button",
    {
      type: "button",
      "aria-pressed": props.filter === value,
      onClick: () => props.onChange(value),
      className: "inline-flex min-h-11 items-center gap-1.5 rounded-full border border-slate-300 bg-white px-3 text-xs font-semibold text-brand-dark/80 transition-colors hover:border-brand-blue/60 hover:text-brand-dark focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-brand-blue aria-pressed:border-brand-blue aria-pressed:bg-brand-blue/10 aria-pressed:text-brand-dark motion-reduce:transition-none",
      children: [
        label(value),
        /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "tabular-nums font-medium text-brand-dark/55", children: props.counts[value] })
      ]
    },
    value
  )) });
}
function CommandFamily(props) {
  const panelId = reactExports.useId();
  const eligible = props.group.commands.filter(props.bulkEligible);
  const unsaved = props.group.commands.filter((command) => commandChanged(command, props.saved)).length;
  const handleToggle = reactExports.useCallback(() => props.onToggle(props.group.key), [props]);
  const handleFamily = reactExports.useCallback((state) => {
    props.onBulkChange(new Set(eligible.map((command) => command.command_id)), state);
  }, [eligible, props]);
  const count = props.group.commands.length;
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("section", { "aria-label": `${props.group.label} ${props.unitLabel(count)}`, className: "border-b border-slate-200 last:border-b-0", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-col gap-2 py-2.5 pl-1 pr-4 sm:flex-row sm:items-center sm:justify-between", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs(
        "button",
        {
          type: "button",
          "aria-expanded": props.open,
          "aria-controls": panelId,
          disabled: !props.collapsible,
          onClick: handleToggle,
          className: "group flex min-h-11 min-w-0 items-center gap-2 rounded-lg px-2 text-left disabled:cursor-default",
          children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx(
              HiMiniChevronRight,
              {
                className: `size-4 shrink-0 text-brand-dark/55 transition-transform duration-150 motion-reduce:transition-none ${props.open ? "rotate-90" : ""}`,
                "aria-hidden": "true"
              }
            ),
            /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { className: "min-w-0", children: [
              /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "block truncate font-mono text-sm font-semibold text-brand-dark", children: props.group.label }),
              /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { className: "block text-xs text-brand-dark/60", children: [
                count,
                " ",
                props.unitLabel(count),
                " · ",
                groupStateSummary(props.group.commands),
                unsaved > 0 ? /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { className: "font-semibold text-brand-blue", children: [
                  " · ",
                  unsaved,
                  " ",
                  props.changedLabel.toLowerCase()
                ] }) : null
              ] })
            ] })
          ]
        }
      ),
      eligible.length > 0 ? /* @__PURE__ */ jsxRuntimeExports.jsx(
        CommandDraftControl,
        {
          label: `${props.group.label} family`,
          state: bulkCommandState(eligible),
          disabled: props.disabled,
          mcpPolicy: props.surface === "mcp",
          onChange: handleFamily
        }
      ) : null
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("div", { id: panelId, hidden: !props.open, className: "border-t border-slate-100 sm:pl-6 [&>article:last-child]:border-b-0", children: props.open ? props.group.commands.map((command) => /* @__PURE__ */ jsxRuntimeExports.jsx(
      CustomExtensionCommandRow,
      {
        command,
        disabled: props.disabled,
        surface: props.surface,
        groupLabel: props.group.label,
        changed: commandChanged(command, props.saved),
        changedLabel: props.changedLabel,
        onChange: props.onChange
      },
      command.command_id
    )) : null })
  ] });
}
const object$2 = (value) => Boolean(value) && typeof value === "object" && !Array.isArray(value);
const integer$1 = (value) => typeof value === "number" && Number.isSafeInteger(value) && value >= 0;
async function fetchMcpSkillMetadata(options) {
  const response = await fetchLocalCliApi("/v1/local-clis/mcp-skills", {
    method: "POST",
    signal: options.signal,
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      cli_id: options.cliId,
      offset: options.offset,
      search: options.search,
      ...options.revision === void 0 ? {} : { revision: options.revision }
    })
  });
  const body = await response.json();
  if (!response.ok) throw new Error(object$2(body) && typeof body.message === "string" ? body.message : "Could not load remote workflow metadata.");
  if (!object$2(body) || body.cli_id !== options.cliId || body.activation_supported !== false || !Array.isArray(body.entries) || body.entries.length > 50 || !integer$1(body.revision) || body.revision < 1 || body.next_offset !== null && body.next_offset !== options.offset + 50) throw new Error("Invalid remote workflow catalog");
  const entries = body.entries.map((entry) => {
    if (!object$2(entry) || entry.origin !== "mcp-served-skill" || entry.connection_identity_hash !== options.identityHash || entry.activation_supported !== false || entry.permissions_granted !== false || typeof entry.uri !== "string" || entry.uri.length > 8192 || !entry.uri.endsWith("/SKILL.md") || typeof entry.name !== "string" || entry.name.length > 64 || !/^[a-z0-9]+(?:-[a-z0-9]+)*$/.test(entry.name) || typeof entry.description !== "string" || entry.description.length > 1024 || typeof entry.dynamic !== "boolean" || (entry.dynamic ? entry.manifest_digest !== null || entry.resource_count !== null : typeof entry.manifest_digest !== "string" || !/^sha256:[a-f0-9]{64}$/.test(entry.manifest_digest) || !integer$1(entry.resource_count) || entry.resource_count < 1 || entry.resource_count > 512)) {
      throw new Error("Invalid remote workflow provenance");
    }
    return {
      uri: entry.uri,
      name: entry.name,
      description: entry.description,
      dynamic: entry.dynamic,
      manifest_digest: entry.manifest_digest,
      resource_count: entry.resource_count
    };
  });
  return { entries, revision: body.revision, nextOffset: body.next_offset };
}
function McpDeclaredSkills(props) {
  const [open, setOpen] = reactExports.useState(false);
  const [search, setSearch] = reactExports.useState("");
  const [input, setInput] = reactExports.useState("");
  const [offset, setOffset] = reactExports.useState(0);
  const [retry, setRetry] = reactExports.useState(0);
  const [page, setPage] = reactExports.useState(null);
  const [busy, setBusy] = reactExports.useState(false);
  const [error, setError] = reactExports.useState(null);
  const revision = reactExports.useRef(void 0);
  reactExports.useEffect(() => {
    if (input === search) return;
    const timer = window.setTimeout(() => {
      setSearch(input);
      setOffset(0);
    }, 250);
    return () => window.clearTimeout(timer);
  }, [input, search]);
  reactExports.useEffect(() => {
    if (!open) return;
    const controller = new AbortController();
    setBusy(true);
    setError(null);
    void fetchMcpSkillMetadata({
      cliId: props.cliId,
      identityHash: props.identityHash,
      offset,
      search,
      revision: offset > 0 ? revision.current : void 0,
      signal: controller.signal
    }).then((next) => {
      if (!controller.signal.aborted) {
        setPage(next);
        revision.current = next.revision;
      }
    }).catch((caught) => {
      if (!controller.signal.aborted) setError(caught instanceof Error ? caught.message : "Could not load workflows.");
    }).finally(() => {
      if (!controller.signal.aborted) setBusy(false);
    });
    return () => controller.abort();
  }, [open, props.cliId, props.identityHash, props.revision, offset, search, retry]);
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("details", { className: "mt-6 border-b border-slate-200 pb-5", onToggle: (event) => setOpen(event.currentTarget.open), children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("summary", { className: "min-h-11 cursor-pointer py-3 text-base font-semibold text-brand-dark", children: [
      "Remote workflows · ",
      props.knownCount,
      " cached"
    ] }),
    open ? /* @__PURE__ */ jsxRuntimeExports.jsxs("section", { "aria-label": "Remote workflow metadata", "aria-busy": busy, children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "max-w-2xl text-sm leading-6 text-brand-dark/75", children: [
        "This connection declares MCP Skills. ",
        props.complete ? "Its workflow metadata was listed." : "Its workflow inventory is incomplete.",
        "Instructions are not loaded. Guard has not enabled skill activation in this host; tool permissions remain separate."
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("label", { className: "mt-4 block max-w-xl text-sm font-semibold text-brand-dark", children: [
        "Find a remote workflow",
        /* @__PURE__ */ jsxRuntimeExports.jsx(
          "input",
          {
            type: "search",
            value: input,
            onChange: (event) => setInput(event.target.value),
            className: "mt-2 min-h-11 w-full rounded-xl border border-slate-300 bg-white px-3 font-normal"
          }
        )
      ] }),
      error ? /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { role: "alert", className: "mt-3 text-sm text-red-700", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { children: error }),
        /* @__PURE__ */ jsxRuntimeExports.jsx(
          "button",
          {
            type: "button",
            onClick: () => {
              setOffset(0);
              setRetry((current) => current + 1);
            },
            className: "mt-2 min-h-11 rounded-xl border border-slate-300 px-4 font-semibold text-brand-dark",
            children: "Reload workflow metadata"
          }
        )
      ] }) : null,
      !busy && !error && page?.entries.length === 0 ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-4 text-sm text-brand-dark/75", children: "No workflow metadata matches this search." }) : null,
      !busy && !error && page ? /* @__PURE__ */ jsxRuntimeExports.jsxs(jsxRuntimeExports.Fragment, { children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("ul", { className: "mt-4 divide-y divide-slate-200", children: page.entries.map((entry) => /* @__PURE__ */ jsxRuntimeExports.jsxs("li", { className: "py-4", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("h3", { className: "text-sm font-semibold text-brand-dark", children: entry.name }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1 max-w-2xl text-sm leading-6 text-brand-dark/75", children: entry.description }),
          /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "mt-2 break-all text-xs text-brand-dark/75", children: [
            "Origin: this MCP connection · ",
            entry.uri
          ] }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-2 text-xs text-brand-dark/75", children: entry.dynamic ? "Dynamic content cannot carry persisted content approval." : `${entry.resource_count} files in the declared manifest. Files must be verified when read.` })
        ] }, entry.uri)) }),
        offset > 0 || page.nextOffset !== null ? /* @__PURE__ */ jsxRuntimeExports.jsxs("nav", { "aria-label": "Remote workflow pages", className: "mt-3 flex flex-wrap items-center gap-3", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx(
            "button",
            {
              type: "button",
              disabled: offset === 0,
              onClick: () => setOffset(Math.max(0, offset - 50)),
              className: "min-h-11 rounded-xl border border-slate-300 px-4 text-sm font-semibold disabled:opacity-50",
              children: "Previous"
            }
          ),
          /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { className: "text-sm text-brand-dark/75", children: [
            "Page ",
            offset / 50 + 1
          ] }),
          /* @__PURE__ */ jsxRuntimeExports.jsx(
            "button",
            {
              type: "button",
              disabled: page.nextOffset === null,
              onClick: () => {
                if (page.nextOffset !== null) setOffset(page.nextOffset);
              },
              className: "min-h-11 rounded-xl border border-slate-300 px-4 text-sm font-semibold disabled:opacity-50",
              children: "Next"
            }
          )
        ] }) : null
      ] }) : null
    ] }) : null
  ] });
}
const EXTENSION_PANEL_CLASS = "guard-extensions-panel p-5 sm:p-6";
const EXTENSION_CHIP_CLASS = "guard-extensions-chip";
const EXTENSION_ROW_CLASS = "guard-extensions-row";
function ProtectionStatusHero(props) {
  const safe = props.status.tone === "safe";
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("section", { "aria-labelledby": "protection-status-heading", className: "guard-status-bar", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "guard-status-bar-icon", "data-tone": props.status.tone, "aria-hidden": "true", children: safe ? /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniShieldCheck, { className: "size-4" }) : /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniExclamationTriangle, { className: "size-4" }) }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "min-w-0 flex-1", children: /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap items-baseline gap-x-2", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm text-brand-dark/60", children: "Local protection" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("h2", { id: "protection-status-heading", className: "text-sm font-semibold text-brand-dark", children: props.status.title }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm leading-5 text-brand-dark/70", children: props.status.summary })
    ] }) }),
    /* @__PURE__ */ jsxRuntimeExports.jsx(
      ProtectionStatusAction,
      {
        busy: props.busy === true,
        safe,
        primaryActionLabel: props.status.primaryActionLabel,
        onPrimaryAction: props.onPrimaryAction
      }
    ),
    props.children ? /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "w-full border-t border-[rgba(63,65,116,0.08)] pt-2", children: props.children }) : null
  ] });
}
function ProtectionStatusAction(props) {
  if (props.primaryActionLabel && props.onPrimaryAction) {
    return /* @__PURE__ */ jsxRuntimeExports.jsx(
      "button",
      {
        type: "button",
        "aria-busy": props.busy,
        disabled: props.busy,
        onClick: props.onPrimaryAction,
        className: "min-h-11 shrink-0 rounded-xl bg-brand-blue px-4 text-sm font-semibold text-white shadow-sm hover:bg-brand-dark disabled:cursor-wait disabled:opacity-60",
        children: props.busy ? "Working…" : props.primaryActionLabel
      }
    );
  }
  if (props.safe) {
    return /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { className: "inline-flex shrink-0 items-center gap-1.5 self-center text-xs font-semibold text-emerald-800", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniCheckCircle, { className: "size-3.5" }),
      "No action required"
    ] });
  }
  return null;
}
function ProtectionDecisionBadge({ result }) {
  return /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: `inline-flex rounded-full border px-2.5 py-1 text-xs font-semibold ${decisionBadgeClasses(result)}`, children: decisionBadgeLabel(result) });
}
function decisionBadgeLabel(result) {
  if (result === "allowed") return "Allowed";
  if (result === "ask-first") return "Ask once";
  return "Blocked";
}
function decisionBadgeClasses(result) {
  if (result === "allowed") return "border-emerald-200 bg-emerald-50 text-emerald-800";
  if (result === "ask-first") return "border-amber-200 bg-amber-50 text-amber-800";
  return "border-red-200 bg-red-50 text-red-800";
}
function ProtectionModuleRow(props) {
  const meta = rowTrustMeta(props.ruleCount, props.permissionCount, props.publisher);
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("button", { type: "button", onClick: props.onOpen, className: `${EXTENSION_ROW_CLASS} group motion-reduce:transition-none`, children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx(
      ExtensionBrandMark,
      {
        extension_id: props.extensionId,
        name: props.name,
        executables: props.executables,
        ecosystem_ids: props.ecosystemIds,
        brand: props.brand,
        size: "md"
      }
    ),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { className: "min-w-0 flex-1", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { className: "flex flex-wrap items-center gap-2", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("strong", { className: "text-sm text-brand-dark", children: props.name }),
        props.required ? /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-[11px] font-semibold text-brand-dark/55", children: "Required by Guard" }) : null,
        props.mcp ? /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-[11px] font-semibold text-brand-dark/55", children: "MCP" }) : null,
        props.external ? /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-[11px] font-semibold text-brand-dark/55", children: "External" }) : null,
        props.managed ? /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-[11px] font-semibold text-brand-dark/55", children: props.managedLabel ?? "Synced from Guard Cloud" }) : null,
        props.custom ? /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-[11px] font-semibold text-brand-dark/55", children: "Custom" }) : null,
        props.source ? /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "max-w-[16rem] truncate text-[11px] font-semibold text-brand-dark/55", title: props.source, "data-testid": "extension-row-source", children: props.source }) : null,
        props.badge ? /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "rounded-full border border-brand-blue/30 bg-brand-blue/5 px-2 py-0.5 text-[11px] font-semibold text-brand-dark", "data-testid": "custom-extension-badge", children: props.badge }) : null
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "mt-0.5 block truncate text-sm text-brand-dark/70", children: props.behavior }),
      meta ? /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "mt-1 block truncate font-mono text-[11px] text-brand-dark/50", "data-testid": "extension-row-meta", children: meta }) : null,
      props.actionLabel ? /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "mt-1 block text-sm font-semibold text-brand-blue", children: props.actionLabel }) : null
    ] }),
    props.state ? /* @__PURE__ */ jsxRuntimeExports.jsx(ExtensionStatePill, { state: props.state }) : null,
    /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniChevronRight, { className: "size-5 shrink-0 text-brand-dark/35 transition-transform duration-150 group-hover:translate-x-0.5 motion-reduce:transition-none", "aria-hidden": "true" })
  ] });
}
const STATE_PILL = {
  Allowed: { label: "On", tone: "safe", description: "Guard allows this tool" },
  Blocked: { label: "Off", tone: "neutral", description: "Guard blocks this tool" },
  Required: { label: "Always on", tone: "info", description: "Guard needs this tool to protect the device" },
  Managed: { label: "Policy", tone: "info", description: "Your organization sets this tool" },
  Lockdown: { label: "Locked", tone: "danger", description: "Lockdown blocks every tool" },
  Unavailable: { label: "Paused", tone: "attention", description: "Protection is not running, so this setting is not enforced" }
};
function extensionStatePillLabel(state) {
  return STATE_PILL[state].label;
}
function ExtensionStatePill({ state }) {
  const pill = STATE_PILL[state];
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { className: "guard-state-pill shrink-0", "data-tone": pill.tone, "data-testid": "extension-state-pill", title: pill.description, children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "guard-state-pill-dot", "aria-hidden": "true" }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "sr-only", children: "Status: " }),
    pill.label
  ] });
}
function rowTrustMeta(ruleCount, permissionCount, publisher) {
  const parts = [];
  if (ruleCount && ruleCount > 0) parts.push(`${ruleCount} ${ruleCount === 1 ? "rule" : "rules"}`);
  if (permissionCount && permissionCount > 0) parts.push(`${permissionCount} ${permissionCount === 1 ? "permission" : "permissions"}`);
  if (publisher && publisher.trim()) parts.push(`by ${publisher.trim()}`);
  return parts.join(" · ");
}
function TechnicalDetails(props) {
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("details", { className: `${EXTENSION_PANEL_CLASS}`, "data-testid": props.testId, children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx("summary", { className: "cursor-pointer list-none text-sm font-semibold text-brand-dark", children: /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { className: "inline-flex items-center gap-2", children: [
      props.title ?? "Technical details",
      /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniChevronDown, { className: "size-4", "aria-hidden": "true" })
    ] }) }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-4 text-sm text-brand-dark/80", children: props.children })
  ] });
}
function InlineError({ message }) {
  return /* @__PURE__ */ jsxRuntimeExports.jsx("p", { role: "alert", className: "rounded-xl border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-800", children: message });
}
function actionTitle(action) {
  const prefix = `${action.toolkit.toUpperCase()}_`;
  const name = action.tool_slug.startsWith(prefix) ? action.tool_slug.slice(prefix.length) : action.tool_slug;
  const words2 = name.replaceAll("_", " ").toLowerCase();
  return words2.charAt(0).toUpperCase() + words2.slice(1);
}
function McpProviderActions(props) {
  const [input, setInput] = reactExports.useState("");
  const [search, setSearch] = reactExports.useState("");
  const [offset, setOffset] = reactExports.useState(0);
  const [page, setPage] = reactExports.useState(null);
  const [busy, setBusy] = reactExports.useState(true);
  const [error, setError] = reactExports.useState(null);
  const [retry, setRetry] = reactExports.useState(0);
  const catalogToken = reactExports.useRef(void 0);
  reactExports.useEffect(() => {
    if (input === search) return;
    const timer = window.setTimeout(() => {
      setSearch(input);
      setOffset(0);
    }, 250);
    return () => window.clearTimeout(timer);
  }, [input, search]);
  reactExports.useEffect(() => {
    const controller = new AbortController();
    setBusy(true);
    setError(null);
    void fetchMcpProviderActions(props.cliId, {
      search,
      offset,
      signal: controller.signal,
      catalogToken: offset > 0 ? catalogToken.current : void 0
    }).then((next) => {
      if (!controller.signal.aborted) {
        catalogToken.current = next.catalogToken;
        setPage(next);
      }
    }).catch((caught) => {
      if (!controller.signal.aborted) setError(caught instanceof Error ? caught.message : "Could not load discovered actions.");
    }).finally(() => {
      if (!controller.signal.aborted) setBusy(false);
    });
    return () => controller.abort();
  }, [props.cliId, props.authorityRevision, search, offset, retry]);
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("section", { className: "mt-6 border-b border-slate-200 pb-5", "aria-labelledby": "mcp-provider-heading", "aria-busy": busy, children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx("h2", { id: "mcp-provider-heading", className: "text-base font-semibold text-brand-dark", children: "Discovered app actions" }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "mt-2 max-w-2xl text-sm leading-6 text-brand-dark/75", children: [
      props.knownCount,
      " actions cached from discovery results. This is a partial inventory. Allow requires a verified account and enforcement of the action inside its execution wrapper. Deny applies to this action across all accounts in this host connection. Opaque workbench execution is blocked while any action is denied."
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("label", { className: "mt-4 block text-sm font-semibold text-brand-dark", htmlFor: "mcp-provider-search", children: "Search actions or apps" }),
    /* @__PURE__ */ jsxRuntimeExports.jsx(
      "input",
      {
        id: "mcp-provider-search",
        type: "search",
        maxLength: 128,
        value: input,
        onChange: (event) => setInput(event.target.value),
        className: "mt-2 min-h-11 w-full max-w-xl rounded-xl border border-slate-300 bg-white px-3 text-sm text-brand-dark"
      }
    ),
    busy ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { role: "status", className: "mt-3 text-sm text-brand-dark/75", children: "Loading discovered actions…" }) : null,
    error ? /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { role: "alert", className: "mt-3 text-sm text-red-700", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { children: error }),
      /* @__PURE__ */ jsxRuntimeExports.jsx(
        "button",
        {
          type: "button",
          className: "mt-2 min-h-11 rounded-xl border border-slate-300 px-4 font-semibold text-brand-dark",
          onClick: () => {
            setOffset(0);
            setRetry((value) => value + 1);
          },
          children: "Reload action inventory"
        }
      )
    ] }) : null,
    !busy && !error && page?.actions.length === 0 ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-4 text-sm leading-6 text-brand-dark/75", children: "No discovered actions match this search. Discovery may find more during use." }) : null,
    !error && page && !busy ? /* @__PURE__ */ jsxRuntimeExports.jsxs(jsxRuntimeExports.Fragment, { children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("ul", { className: "mt-4 divide-y divide-slate-200", children: page.actions.map((action) => /* @__PURE__ */ jsxRuntimeExports.jsxs("li", { className: "py-4", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap items-start justify-between gap-3", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "min-w-0 flex-1", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("h3", { className: "text-sm font-semibold text-brand-dark", children: actionTitle(action) }),
            /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "mt-1 text-xs text-brand-dark/75", children: [
              action.toolkit,
              " · Account not verified"
            ] })
          ] }),
          /* @__PURE__ */ jsxRuntimeExports.jsxs("label", { className: "flex items-center gap-2 text-xs font-semibold text-brand-dark", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { className: "sr-only", children: [
              "Permission for ",
              actionTitle(action)
            ] }),
            /* @__PURE__ */ jsxRuntimeExports.jsxs(
              "select",
              {
                disabled: props.disabled,
                "aria-label": `Permission for ${actionTitle(action)}`,
                value: props.drafts[action.tool_slug]?.state ?? action.permission_state,
                onChange: (event) => props.onChange(action, event.target.value),
                className: "min-h-11 rounded-xl border border-slate-300 bg-white px-3 text-sm",
                children: [
                  /* @__PURE__ */ jsxRuntimeExports.jsx("option", { value: "review", children: "Ask" }),
                  /* @__PURE__ */ jsxRuntimeExports.jsx("option", { value: "block", children: "Deny" })
                ]
              }
            )
          ] })
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-2 max-w-2xl break-words text-sm leading-6 text-brand-dark/75", children: action.description.slice(0, 260) }),
        /* @__PURE__ */ jsxRuntimeExports.jsx(McpClassificationEvidence, { value: action.classification }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("details", { className: "mt-1 text-xs text-brand-dark/75", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("summary", { className: "min-h-11 cursor-pointer py-3 font-semibold", children: "Action details" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "break-all font-mono", children: action.tool_slug }),
          /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "mt-2", children: [
            "Schema ",
            action.full_schema ? "available" : "incomplete",
            " · Revision ",
            action.revision
          ] }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-2", children: "Observed provider metadata. Execution permission has not been granted." })
        ] })
      ] }, action.tool_slug)) }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-3 flex flex-wrap items-center gap-3", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(
          "button",
          {
            type: "button",
            disabled: offset === 0,
            onClick: () => setOffset(Math.max(0, offset - 50)),
            className: "min-h-11 rounded-xl border border-slate-300 px-4 text-sm font-semibold text-brand-dark disabled:opacity-50",
            children: "Previous page"
          }
        ),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { className: "text-sm text-brand-dark/75", children: [
          "Page ",
          offset / 50 + 1
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsx(
          "button",
          {
            type: "button",
            disabled: page.nextOffset === null,
            onClick: () => {
              if (page.nextOffset !== null) setOffset(page.nextOffset);
            },
            className: "min-h-11 rounded-xl border border-slate-300 px-4 text-sm font-semibold text-brand-dark disabled:opacity-50",
            children: "Next page"
          }
        )
      ] })
    ] }) : null
  ] });
}
function object$1(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}
async function fetchProviderWorkflows(cliId, offset, signal) {
  const response = await fetchLocalCliApi("/v1/local-clis/provider-workflows", {
    method: "POST",
    signal,
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ cli_id: cliId, offset })
  });
  const body = await response.json();
  if (!response.ok) throw new Error(object$1(body) && typeof body.message === "string" ? body.message : "Could not load workflow suggestions.");
  if (!object$1(body) || body.cli_id !== cliId || !Array.isArray(body.proposals) || body.proposals.length > 10 || body.next_offset !== null && body.next_offset !== offset + 10) throw new Error("Invalid workflow suggestions");
  const proposals = body.proposals.map((entry) => {
    if (!object$1(entry) || typeof entry.proposal_id !== "string" || !/^[a-f0-9]{64}$/.test(entry.proposal_id) || entry.source !== "composio-search-guidance" || entry.permissions_granted !== false || entry.requirements_complete !== false || entry.account_binding !== "unverified" || typeof entry.guidance_present !== "boolean" || !Array.isArray(entry.requirements) || entry.requirements.length > 50) throw new Error("Invalid workflow provenance");
    const requirements = entry.requirements.map((part) => {
      if (!object$1(part) || typeof part.tool_slug !== "string" || !/^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$/.test(part.tool_slug) || !["primary", "supporting"].includes(String(part.role)) || !["ask", "saved-deny", "unresolved"].includes(String(part.state)) || typeof part.schema_observed !== "boolean") throw new Error("Invalid workflow dependency");
      return {
        slug: part.tool_slug,
        role: part.role,
        state: part.state,
        schemaObserved: part.schema_observed
      };
    });
    return { proposalId: entry.proposal_id, guidancePresent: entry.guidance_present, requirements };
  });
  return { proposals, nextOffset: body.next_offset };
}
const requirementLabels = { "saved-deny": "Saved Deny", unresolved: "Not observed", ask: "Needs review" };
function ProviderWorkflows({ cliId }) {
  const [open, setOpen] = reactExports.useState(false);
  const [offset, setOffset] = reactExports.useState(0);
  const [retry, setRetry] = reactExports.useState(0);
  const [busy, setBusy] = reactExports.useState(false);
  const [error, setError] = reactExports.useState(null);
  const [page, setPage] = reactExports.useState(null);
  reactExports.useEffect(() => {
    if (!open) return;
    const controller = new AbortController();
    setBusy(true);
    setError(null);
    setPage(null);
    void fetchProviderWorkflows(cliId, offset, controller.signal).then((result) => {
      if (!controller.signal.aborted) setPage(result);
    }).catch((caught) => {
      if (!controller.signal.aborted) setError(caught instanceof Error ? caught.message : "Could not load suggestions.");
    }).finally(() => {
      if (!controller.signal.aborted) setBusy(false);
    });
    return () => controller.abort();
  }, [cliId, open, offset, retry]);
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("details", { className: "mt-5 border-b border-slate-200 pb-5", onToggle: (event) => setOpen(event.currentTarget.open), children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx("summary", { className: "min-h-11 cursor-pointer py-3 text-base font-semibold text-brand-dark", children: "Suggested action workflows" }),
    open ? /* @__PURE__ */ jsxRuntimeExports.jsxs("section", { "aria-label": "Composio workflow suggestions", "aria-busy": busy, children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "max-w-2xl text-sm leading-6 text-brand-dark/75", children: "Suggestions from observed Composio search results. They are not MCP Skills, account verification, or permission grants. Search may omit a workflow, and each action still needs its own review." }),
      busy ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { role: "status", className: "mt-3 text-sm text-brand-dark/75", children: "Loading suggestions…" }) : null,
      error ? /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { role: "alert", className: "mt-3 text-sm text-red-700", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { children: error }),
        /* @__PURE__ */ jsxRuntimeExports.jsx(
          "button",
          {
            type: "button",
            onClick: () => {
              setOffset(0);
              setRetry((value) => value + 1);
            },
            className: "mt-2 min-h-11 rounded-xl border border-slate-300 px-4 font-semibold text-brand-dark",
            children: "Reload suggestions"
          }
        )
      ] }) : null,
      !busy && !error && page?.proposals.length === 0 ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-3 text-sm text-brand-dark/75", children: "No workflow suggestion was observed. Search Composio for a specific task to discover one." }) : null,
      !busy && !error && page ? /* @__PURE__ */ jsxRuntimeExports.jsxs(jsxRuntimeExports.Fragment, { children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("ol", { start: offset + 1, className: "mt-4 space-y-4", children: page.proposals.map((proposal) => /* @__PURE__ */ jsxRuntimeExports.jsxs(
          "li",
          {
            className: "rounded-xl border border-slate-200 bg-slate-50 p-4 text-sm text-brand-dark",
            children: [
              /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "font-semibold", children: [
                "Suggested workflow ",
                offset + page.proposals.indexOf(proposal) + 1
              ] }),
              /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1 text-brand-dark/75", children: proposal.guidancePresent ? "Composio also returned plan guidance; Guard kept only suggested action IDs." : "Action suggestions only; no plan guidance was returned." }),
              /* @__PURE__ */ jsxRuntimeExports.jsx("ul", { className: "mt-2 space-y-1", children: proposal.requirements.map((part) => /* @__PURE__ */ jsxRuntimeExports.jsxs("li", { className: "break-words", children: [
                part.slug.replaceAll("_", " ").toLowerCase(),
                " · ",
                part.role === "primary" ? "Primary" : "Supporting",
                " · ",
                requirementLabels[part.state],
                !part.schemaObserved && part.state !== "unresolved" ? " · Schema incomplete" : ""
              ] }, part.slug)) })
            ]
          },
          proposal.proposalId
        )) }),
        offset > 0 || page.nextOffset !== null ? /* @__PURE__ */ jsxRuntimeExports.jsxs("nav", { "aria-label": "Suggestion pages", className: "mt-3 flex items-center gap-3", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx(
            "button",
            {
              type: "button",
              disabled: offset === 0,
              onClick: () => setOffset(Math.max(0, offset - 10)),
              className: "min-h-11 rounded-xl border border-slate-300 px-4 text-sm font-semibold disabled:opacity-50",
              children: "Previous"
            }
          ),
          /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { className: "text-sm text-brand-dark/75", children: [
            "Page ",
            offset / 10 + 1
          ] }),
          /* @__PURE__ */ jsxRuntimeExports.jsx(
            "button",
            {
              type: "button",
              disabled: page.nextOffset === null,
              onClick: () => {
                if (page.nextOffset !== null) setOffset(page.nextOffset);
              },
              className: "min-h-11 rounded-xl border border-slate-300 px-4 text-sm font-semibold disabled:opacity-50",
              children: "Next"
            }
          )
        ] }) : null
      ] }) : null
    ] }) : null
  ] });
}
function ConnectorSetupBanner(props) {
  const copy = props.outcome ? { title: `${props.name} is set up`, body: "" } : connectorSetupCopy(props.match, props.name);
  const ready = props.outcome !== null || props.match === "ready";
  return /* @__PURE__ */ jsxRuntimeExports.jsxs(
    "section",
    {
      "data-testid": "connector-setup-banner",
      "aria-labelledby": "connector-setup-heading",
      className: `mt-4 max-w-2xl rounded-xl border p-4 ${ready ? "border-brand-blue/30 bg-brand-blue/5" : "border-amber-300 bg-amber-50"}`,
      children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("h2", { id: "connector-setup-heading", className: "text-sm font-semibold text-brand-dark", children: copy.title }),
        copy.body ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1 text-sm leading-6 text-slate-700", children: copy.body }) : null,
        /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "mt-2 text-xs text-slate-600", children: [
          "Held identity ",
          /* @__PURE__ */ jsxRuntimeExports.jsx("code", { className: "rounded bg-slate-100 px-1 font-mono text-brand-dark", children: shortIdentity(props.heldIdentityHash) })
        ] }),
        props.currentIdentityHash !== props.heldIdentityHash ? /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "mt-1 text-xs text-slate-600", children: [
          "Current identity ",
          /* @__PURE__ */ jsxRuntimeExports.jsx("code", { className: "rounded bg-slate-100 px-1 font-mono text-brand-dark", children: shortIdentity(props.currentIdentityHash) })
        ] }) : null,
        props.outcome ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { role: "status", className: "mt-2 text-sm font-medium text-emerald-800", children: props.outcome }) : ready ? /* @__PURE__ */ jsxRuntimeExports.jsx(
          "button",
          {
            type: "button",
            className: "mt-3 min-h-11 rounded-xl bg-brand-blue px-4 text-sm font-semibold text-white disabled:opacity-60",
            disabled: props.busy,
            onClick: props.onSetUp,
            children: "Set up with recommended"
          }
        ) : null
      ]
    }
  );
}
function CustomExtensionReviewModal(props) {
  const [password, setPassword] = reactExports.useState("");
  const [totp, setTotp] = reactExports.useState("");
  const dialogRef = useModalDialog(props.onCancel, !props.busy);
  const change = props.capabilityChange;
  const title = change ? `${change.next === "on" ? "Turn on" : "Turn off"} ${change.label.toLowerCase()} for ${props.item.name}` : props.providerUpdates.length > 0 ? "Review app action permissions" : reviewTitle(props.item.name, props.nextState);
  const handlePassword = reactExports.useCallback((event) => {
    setPassword(event.target.value);
  }, []);
  const handleTotp = reactExports.useCallback((event) => {
    const digits = event.target.value.replace(/\D/g, "").slice(0, 6);
    event.target.value = digits;
    setTotp(digits);
  }, []);
  const handleSubmit = reactExports.useCallback((event) => {
    event.preventDefault();
    props.onConfirm(buildApprovalProofCredentials(props.approvalGate, {
      approvalPassword: password,
      approvalTotpCode: totp
    }, props.requireFreshTotp === true));
  }, [password, props, totp]);
  const submitDisabled = isApprovalProofSubmitDisabled(
    props.approvalGate,
    { approvalPassword: password, approvalTotpCode: totp },
    props.busy,
    props.requireFreshTotp === true,
    true
  );
  return /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "fixed inset-0 z-50 grid place-items-center bg-slate-950/45 p-4 backdrop-blur-sm", children: /* @__PURE__ */ jsxRuntimeExports.jsxs("form", { ref: dialogRef, tabIndex: -1, role: "dialog", "aria-modal": "true", "aria-labelledby": "custom-extension-review-title", onSubmit: handleSubmit, className: "max-h-[calc(100dvh-2rem)] w-full max-w-lg overflow-y-auto rounded-3xl bg-white p-6 shadow-2xl focus:outline-none", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx("h2", { id: "custom-extension-review-title", className: "text-xl font-semibold text-brand-dark", children: title }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-2 text-sm leading-6 text-brand-dark/80", children: reviewModalDetail(props.approvalGate, props.requireFreshTotp === true) }),
    props.item.surface === "mcp" ? /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-3 text-sm leading-6 text-brand-dark", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { children: [
        props.item.source_label || "This host",
        " · This configured connection"
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { children: connectionReviewMessage(props.nextState) })
    ] }) : null,
    change ? /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "mt-4 text-sm leading-6 text-brand-dark", children: [
      change.label,
      ": ",
      change.next === "on" ? "Off → On" : "On → Off",
      ". This applies to this device only."
    ] }) : null,
    props.commandChanges.length > 0 ? /* @__PURE__ */ jsxRuntimeExports.jsxs("section", { "aria-label": "Permission changes", className: "mt-4 text-sm leading-6 text-brand-dark", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "font-semibold", children: [
        props.commandChanges.length,
        " ",
        props.item.surface === "mcp" ? "tool" : "command",
        " changes"
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("ul", { className: "mt-2 max-h-48 space-y-2 overflow-y-auto", children: props.commandChanges.map((change2) => /* @__PURE__ */ jsxRuntimeExports.jsxs("li", { className: "break-words", children: [
        change2.name,
        ": ",
        permissionLabel(change2.before),
        " → ",
        permissionLabel(change2.after)
      ] }, change2.commandId)) })
    ] }) : null,
    props.providerUpdates.length > 0 ? /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-3 max-h-48 overflow-y-auto text-sm leading-6 text-brand-dark", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { children: [
        props.providerUpdates.length,
        " action changes for this host connection, across all accounts."
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("ul", { className: "mt-2 space-y-1", children: props.providerUpdates.map((update) => /* @__PURE__ */ jsxRuntimeExports.jsxs("li", { className: "break-words", children: [
        update.tool_slug.replaceAll("_", " ").toLowerCase(),
        " → ",
        update.state === "block" ? "Deny" : "Ask"
      ] }, update.tool_slug)) }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-2", children: "Any Deny also blocks opaque workbench execution. Allow is unavailable until the account is verified." })
    ] }) : null,
    /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-5", children: /* @__PURE__ */ jsxRuntimeExports.jsx(
      ApprovalProofFieldInputs,
      {
        approvalGate: props.approvalGate,
        approvalPassword: password,
        approvalTotpCode: totp,
        requireFreshTotp: props.requireFreshTotp === true,
        requireGate: true,
        onApprovalPasswordChange: handlePassword,
        onApprovalTotpCodeChange: handleTotp
      }
    ) }),
    props.error ? /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-4", children: /* @__PURE__ */ jsxRuntimeExports.jsx(InlineError, { message: props.error }) }) : null,
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-6 flex justify-end gap-3", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("button", { type: "button", disabled: props.busy, onClick: props.onCancel, className: "min-h-11 rounded-xl px-4 text-sm font-semibold text-brand-dark", children: "Cancel" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("button", { type: "submit", disabled: submitDisabled, className: "min-h-11 rounded-xl bg-brand-blue px-5 text-sm font-semibold text-white disabled:opacity-60", children: props.busy ? "Saving…" : "Confirm" })
    ] })
  ] }) });
}
function permissionLabel(state) {
  if (state === null) return "Not previously listed";
  const labels = {
    allow: "Allow",
    block: "Deny",
    review: "Ask",
    inherit: "Policy"
  };
  return labels[state];
}
function connectionReviewMessage(state) {
  if (state === "blocked") return "The connection will deny every tool, including tools listed as Allow.";
  if (state === "unset") return "Saved connection permissions will be removed. Future calls return to Guard policy.";
  return "Unknown and future tools still require review. These choices do not verify the provider account.";
}
const CAPABILITY_COPY = {
  "loopback-network": {
    label: "Local network access",
    description: "Connect to services running on this computer, such as a local server.",
    blocked: "A run was stopped from connecting to this computer",
    need: "Turn this on if it needs a service running on this computer."
  },
  "state-dir-read": {
    label: "Read its settings",
    description: "Read its own configuration and saved state in your home folder.",
    blocked: "A run was stopped from reading its settings",
    need: "Turn this on if it needs its saved configuration to work."
  },
  "state-dir-write": {
    label: "Save its settings",
    description: "Write its own configuration and saved state in your home folder.",
    blocked: "A run was stopped from saving its settings",
    need: "Turn this on if it needs to keep its configuration between runs."
  }
};
function LocalCliCapabilities(props) {
  const { resolvedApprovalGate, refreshApprovalGate } = useResolvedApprovalGate(null);
  const [pending, setPending] = reactExports.useState(null);
  const [busy, setBusy] = reactExports.useState(false);
  const [error, setError] = reactExports.useState(null);
  const [freshTotpRequired, setFreshTotpRequired] = reactExports.useState(false);
  const name = customExtensionDisplayName(props.item);
  const states = props.item.capabilities;
  const suggested = props.item.suggested_capability;
  const request2 = reactExports.useCallback(async (change) => {
    setError(null);
    setFreshTotpRequired(false);
    try {
      await refreshApprovalGate({ failClosed: true });
    } catch {
      setError("Guard could not load your approval settings. Try again.");
      return;
    }
    setPending(change);
  }, [refreshApprovalGate]);
  const cancel = reactExports.useCallback(() => {
    if (!busy) setPending(null);
  }, [busy]);
  const confirm = reactExports.useCallback(async (credentials) => {
    if (pending === null) return;
    setBusy(true);
    setError(null);
    try {
      const payload = {
        cli_id: props.item.cli_id,
        identity_hash: props.item.identity_hash,
        name: props.item.name,
        kind: props.item.kind,
        example_label: props.item.example_label,
        interpreter_name: props.item.interpreter_name,
        state: "allowed",
        previous_revision: props.revision,
        session_nonce: randomToken$2(),
        // The saved command states, so this change carries no unsaved draft.
        commands: commandStatesPayload(props.item.commands),
        capabilities: { [pending.capability]: pending.next },
        ...credentials
      };
      await previewLocalCliMutation(payload);
      await applyLocalCliMutation(payload);
      await props.onRefresh();
      await refreshApprovalGate();
      setPending(null);
    } catch (caught) {
      if (isFreshTotpRequired(caught)) {
        setFreshTotpRequired(true);
        await refreshApprovalGate().catch(() => void 0);
        setError(FRESH_TOTP_REQUIRED_MESSAGE);
      } else {
        setError(caught instanceof LocalCliApiError ? caught.message : "Guard could not change this access.");
      }
    } finally {
      setBusy(false);
    }
  }, [pending, props, refreshApprovalGate]);
  if (states === void 0) return null;
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("section", { className: "mt-8 max-w-2xl", "aria-labelledby": "local-cli-capabilities-heading", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx("h2", { id: "local-cli-capabilities-heading", className: "text-lg font-semibold text-brand-dark", children: "Access on this device" }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "mt-1 text-sm leading-6 text-slate-600", children: [
      "Contained runs of ",
      name,
      " stay inside the workspace. Each access below widens that on this device only."
    ] }),
    suggested ? /* @__PURE__ */ jsxRuntimeExports.jsxs(
      "div",
      {
        role: "status",
        "data-testid": "local-cli-capability-suggestion",
        className: "mt-4 rounded-2xl border border-brand-blue/20 bg-blue-50/70 p-4",
        children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm font-semibold text-brand-dark", children: CAPABILITY_COPY[suggested].blocked }),
          /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "mt-1 text-sm leading-6 text-brand-dark/80", children: [
            CAPABILITY_COPY[suggested].need,
            " Everything else outside the workspace stays blocked."
          ] }),
          /* @__PURE__ */ jsxRuntimeExports.jsxs(
            "button",
            {
              type: "button",
              disabled: busy,
              onClick: () => void request2({ capability: suggested, next: "on" }),
              className: "mt-3 min-h-11 rounded-xl bg-brand-blue px-4 text-sm font-semibold text-white disabled:opacity-60",
              children: [
                "Turn on ",
                CAPABILITY_COPY[suggested].label.toLowerCase()
              ]
            }
          )
        ]
      }
    ) : null,
    /* @__PURE__ */ jsxRuntimeExports.jsx("ul", { className: "mt-4 divide-y divide-slate-200 border-y border-slate-200", children: LOCAL_CLI_CAPABILITIES.map((capability) => {
      const on = states[capability] === "on";
      const copy = CAPABILITY_COPY[capability];
      return /* @__PURE__ */ jsxRuntimeExports.jsxs("li", { className: "flex flex-col gap-3 py-4 sm:flex-row sm:items-center sm:justify-between", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "min-w-0", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "text-sm font-semibold text-brand-dark", children: [
            copy.label,
            /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "ml-2 font-normal text-slate-600", children: on ? "On" : "Off" })
          ] }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-0.5 text-sm leading-6 text-slate-600", children: copy.description })
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsx(
          "button",
          {
            type: "button",
            disabled: busy,
            "aria-label": `${on ? "Turn off" : "Turn on"} ${copy.label.toLowerCase()}`,
            onClick: () => void request2({ capability, next: on ? "off" : "on" }),
            className: "min-h-11 shrink-0 rounded-xl border border-slate-300 px-4 text-sm font-semibold text-brand-dark hover:bg-slate-50 disabled:opacity-60",
            children: on ? "Turn off" : "Turn on"
          }
        )
      ] }, capability);
    }) }),
    error && !pending ? /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-4", children: /* @__PURE__ */ jsxRuntimeExports.jsx(InlineError, { message: error }) }) : null,
    pending ? /* @__PURE__ */ jsxRuntimeExports.jsx(
      CustomExtensionReviewModal,
      {
        item: props.item,
        nextState: "allowed",
        commandChanges: [],
        providerUpdates: [],
        capabilityChange: { label: CAPABILITY_COPY[pending.capability].label, next: pending.next },
        busy,
        error,
        approvalGate: resolvedApprovalGate,
        requireFreshTotp: freshTotpRequired,
        onCancel: cancel,
        onConfirm: confirm
      }
    ) : null
  ] });
}
async function forgetLocalCli(item) {
  await readJson(await fetchLocalCliApi("/v1/local-clis/forget", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ cli_id: item.cli_id, identity_hash: item.identity_hash })
  }));
}
function lastSeenCopy(lastSeenAt) {
  if (!lastSeenAt) return null;
  const seen = new Date(lastSeenAt);
  if (Number.isNaN(seen.getTime())) return null;
  return `Last seen ${seen.toLocaleDateString(void 0, { year: "numeric", month: "short", day: "numeric" })}`;
}
function canForgetLocalCli(item) {
  return item.state === "unset" && item.observed_count > 0 && item.shares_enrolled_server !== true;
}
function ForgetLocalCliButton(props) {
  const { confirm, dialog } = useConfirmDialog();
  const [busy, setBusy] = reactExports.useState(false);
  const [error, setError] = reactExports.useState(null);
  const forget = reactExports.useCallback(async () => {
    const confirmed = await confirm({
      title: "Forget this connection?",
      description: "Guard removes it from this list. If an agent uses it again or an app still configures it, Guard lists it again.",
      confirmLabel: "Forget"
    });
    if (!confirmed) return;
    setBusy(true);
    setError(null);
    try {
      await forgetLocalCli(props.item);
      await props.onForgotten();
    } catch (caught) {
      setError(caught instanceof LocalCliApiError ? caught.message : "Guard could not forget this connection.");
    } finally {
      setBusy(false);
    }
  }, [confirm, props]);
  return /* @__PURE__ */ jsxRuntimeExports.jsxs(jsxRuntimeExports.Fragment, { children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx(
      "button",
      {
        type: "button",
        disabled: props.disabled || busy,
        onClick: () => void forget(),
        className: "min-h-11 rounded-xl px-4 text-sm font-semibold text-brand-dark/80 disabled:opacity-50",
        children: busy ? "Forgetting…" : "Forget this connection"
      }
    ),
    error ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { role: "alert", className: "basis-full text-sm leading-6 text-red-700", children: error }) : null,
    dialog
  ] });
}
function enrollableCount(item) {
  return Math.max(enrollablePackageScriptCommands(item.commands).length, 0);
}
const OBSERVED_MCP_LABEL_SUFFIXES = [" · observed tools", " · configured server"];
function isObservedMcpItem(item) {
  return item?.surface === "mcp" && item.example_label.startsWith("mcp__") && OBSERVED_MCP_LABEL_SUFFIXES.some((suffix) => item.source_label?.endsWith(suffix) === true);
}
function addDialogSubmitLabel(input) {
  if (input.recognized === null) {
    return input.busy ? "Looking…" : "Find this tool";
  }
  if (input.busy && input.recognized.surface === "mcp" && input.step !== "confirm") {
    return "Listing tools…";
  }
  if (input.step !== "confirm") {
    return "Continue";
  }
  if (input.busy) {
    return "Saving…";
  }
  if (input.pending === "blocked") {
    return blockActionLabel(input.recognized.surface);
  }
  return isObservedMcpItem(input.recognized) ? "Save tool permissions" : allowActionLabel(input.recognized.surface);
}
function enrollConfirmCopy(surface, recentlySatisfied, totpEnabled, gateReady) {
  if (gateReady === false) {
    return "Local approval isn't ready on this device. Set it up below, then come back to save these settings.";
  }
  if (recentlySatisfied) {
    return "Recently confirmed with your authenticator. Save these settings.";
  }
  if (!totpEnabled) {
    return "Enter your approval password to save these settings.";
  }
  if (surface === "mcp") {
    return "Enter the current authenticator code to save this server.";
  }
  if (surface === "package-scripts") {
    return "Enter the current authenticator code to save these scripts.";
  }
  return "Enter the current authenticator code to save this tool.";
}
function enrollSubmitDisabled(input) {
  if (input.recognized === null) return input.command.trim() === "" || input.busy;
  if (!input.confirming) return input.busy;
  return !input.proofReady || input.proofBlocked;
}
function commandFieldLabel(surface) {
  if (surface === "package-scripts") return "Find a script";
  if (surface === "mcp") return "Launch command";
  return "Command";
}
function allowActionLabel(surface) {
  if (surface === "mcp") return "Allow this server";
  if (surface === "package-scripts") return "Allow these scripts";
  return "Allow this tool";
}
function blockActionLabel(surface) {
  if (surface === "mcp") return "Block this server";
  if (surface === "package-scripts") return "Block these scripts";
  return "Block this tool";
}
function dialogIntro(hasProjects, surface, discovering = false, mcpHasTools = true, observedMcp = false) {
  if (surface === "package-scripts") {
    return "Adding this project allows its scripts, so Guard stops asking about them. Block any script you want stopped.";
  }
  if (surface === "mcp") {
    if (observedMcp) return "Review each detected tool before saving. Allow listed applies only to the tools shown here.";
    if (!mcpHasTools) {
      return "You can still add this server. List tools again to set Recommended, Allow, or Block on each tool.";
    }
    return "Choose Recommended, Allow all, or Block all, then confirm this server.";
  }
  if (discovering) {
    return "Looking for project scripts and app servers on this device.";
  }
  if (hasProjects) {
    return "Guard already found project scripts on this device. Pick a project, or paste another folder.";
  }
  return "Paste a script, binary, MCP launch, or package scripts such as npm run. Everyday commands such as rg, grep, and whoami are not custom extensions.";
}
function listToolsAgainLabel() {
  return "List tools again";
}
function mcpListingBusyCopy(name) {
  return `Listing tools from ${name}. This can take a few seconds.`;
}
function mcpListingRetryFailedCopy() {
  return "Guard still could not list tools. You can add the server anyway.";
}
function mcpCatalogHasTools(commands) {
  return commands.some((entry) => entry.command_id !== "other");
}
function mcpListingRetryError(helpStatus, commands) {
  if (mcpCatalogHasTools(commands) || helpStatus === "empty") return null;
  return mcpListingRetryFailedCopy();
}
function McpListingStatus(props) {
  if (props.busy) {
    return /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-4 max-w-xl text-sm leading-6 text-brand-dark/70", role: "status", "aria-live": "polite", children: mcpListingBusyCopy(props.name) });
  }
  return /* @__PURE__ */ jsxRuntimeExports.jsx(
    "button",
    {
      type: "button",
      onClick: props.onRetry,
      className: "mt-4 min-h-11 text-sm font-semibold text-brand-blue",
      children: listToolsAgainLabel()
    }
  );
}
function suggestionSummary(item) {
  if (isObservedMcpItem(item)) {
    const count = item.commands.filter((entry) => entry.command_id !== "other").length;
    return `${count} detected ${count === 1 ? "tool" : "tools"}. Set permissions for each one. New tools keep the usual review, and safety policy still applies.`;
  }
  if (item.surface === "package-scripts" && item.commands.length > 0) {
    const count = enrollableCount(item);
    const unit = count === 1 ? "script" : "scripts";
    return `${count} ${unit} from ${item.source_label ?? item.name}. Allow lets this project's scripts run. Nested names stay grouped.`;
  }
  if (item.surface === "package-scripts") {
    return `Find this tool to list npm scripts from ${item.name}.`;
  }
  if (item.surface === "mcp" && item.commands.length > 0) {
    return `${item.commands.length} tools from this server. Recommended keeps the usual review. Allow all lets them run.`;
  }
  if (item.surface === "mcp") {
    return `Find this tool to list MCP tools from ${item.name}.`;
  }
  if (item.commands.length > 0) {
    return `Guard loaded ${item.commands.length} commands. Recommended keeps the usual review. Allow or block each one.`;
  }
  return `Find this tool to read ${item.name} --help and load its commands.`;
}
function SuggestionPanel(props) {
  if (!props.hasSuggestions) {
    return /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-5 text-sm leading-6 text-brand-dark/70", role: "status", "aria-live": "polite", children: suggestionEmptyCopy(props.query, props.discovering === true) });
  }
  return /* @__PURE__ */ jsxRuntimeExports.jsxs(jsxRuntimeExports.Fragment, { children: [
    props.discovering === true ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-5 text-sm leading-6 text-brand-dark/70", role: "status", "aria-live": "polite", children: "Looking for more project scripts and app servers on this device." }) : null,
    /* @__PURE__ */ jsxRuntimeExports.jsx(
      SuggestionGroup,
      {
        heading: "From this device",
        helper: "Projects Guard has already seen, including nested names such as guard:audit.",
        items: props.packageScriptSuggestions,
        onSelect: props.onSelect
      }
    ),
    /* @__PURE__ */ jsxRuntimeExports.jsx(
      SuggestionGroup,
      {
        heading: "MCP servers and connectors",
        helper: "Configured in your apps or detected from tool activity. Pick one to review its tools.",
        items: props.harnessSuggestions,
        onSelect: props.onSelect
      }
    ),
    /* @__PURE__ */ jsxRuntimeExports.jsx(
      SuggestionGroup,
      {
        heading: "Seen on this device",
        helper: "Your own tools that agents have run. Common commands stay hidden.",
        items: props.seenSuggestions,
        onSelect: props.onSelect
      }
    )
  ] });
}
function suggestionEmptyCopy(query, discovering) {
  if (query.trim() !== "") {
    return "No matching tools. Try npm run, a project folder, or a nested script name. Everyday commands such as rg stay hidden.";
  }
  if (discovering) {
    return "Scanning this device for package scripts and app servers.";
  }
  return "No extra tools yet. Paste npm run, a project folder, a script, or an MCP launch.";
}
function SuggestionGroup(props) {
  if (props.items.length === 0) return null;
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-5", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm font-semibold text-brand-dark", children: props.heading }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1 text-xs leading-5 text-brand-dark/60", children: props.helper }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("ul", { className: "mt-2 divide-y divide-slate-200", children: props.items.map((item) => /* @__PURE__ */ jsxRuntimeExports.jsx("li", { children: /* @__PURE__ */ jsxRuntimeExports.jsx(SuggestionButton, { item, onSelect: props.onSelect }) }, item.cli_id)) })
  ] });
}
function SuggestionButton(props) {
  const handleSelect = reactExports.useCallback(() => {
    props.onSelect(props.item);
  }, [props]);
  let connectorLabel = "Load tools";
  if (mcpCatalogHasTools(props.item.commands)) {
    connectorLabel = `${props.item.commands.filter((entry) => entry.command_id !== "other").length} tools`;
  }
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("button", { type: "button", onClick: handleSelect, className: "flex min-h-14 w-full items-center justify-between gap-3 rounded-lg px-2 py-3 text-left hover:bg-brand-blue/5 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-brand-blue", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { className: "min-w-0", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "block truncate text-sm font-semibold text-brand-dark", children: props.item.name }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "block truncate text-xs text-brand-dark/60", children: props.item.source_label ?? seenSuggestionMeta(props.item) })
    ] }),
    props.item.surface === "mcp" ? /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "shrink-0 text-xs font-semibold text-brand-blue", children: connectorLabel }) : /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "max-w-[55%] truncate font-mono text-xs text-brand-dark/60", children: props.item.example_label })
  ] });
}
function scriptCount(item) {
  return enrollablePackageScriptCommands(item.commands).length;
}
function packageScriptQueryFrom(query, commands) {
  const trimmed = query.trim();
  if (!trimmed || looksLikeProjectRelocatePaste(trimmed)) return "";
  const needle = packageScriptFilterNeedle(trimmed);
  return needle && commands.some((command) => commandMatchesQuery(command, needle)) ? needle : "";
}
function projectFolderLabel(item) {
  const folder = item.source_label?.trim();
  return folder && folder !== item.name ? folder : null;
}
function projectMetaLine(item) {
  const count = scriptCount(item);
  const folder = projectFolderLabel(item);
  return [folder, `${count} ${count === 1 ? "script" : "scripts"}`].filter(Boolean).join(" · ");
}
function SelectedProject(props) {
  const listId = reactExports.useId();
  const [open, setOpen] = reactExports.useState(false);
  const others = props.projects.filter((project) => project.cli_id !== props.item.cli_id);
  const toggle = reactExports.useCallback(() => setOpen((current) => !current), []);
  const choose = reactExports.useCallback((project) => {
    setOpen(false);
    props.onSelect(project);
  }, [props]);
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("section", { "aria-labelledby": "custom-extension-selected", className: "mt-6 max-w-4xl border-b border-slate-200 pb-5", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap items-start justify-between gap-x-6 gap-y-3", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "min-w-0", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("h2", { id: "custom-extension-selected", className: "break-words text-xl font-semibold tracking-tight text-brand-dark", children: props.item.name }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "mt-1.5 flex min-w-0 flex-wrap items-center gap-x-2 gap-y-1 text-sm text-brand-dark/70", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("code", { className: "rounded-md bg-slate-100 px-1.5 py-0.5 font-mono text-xs font-semibold text-brand-dark", children: props.item.example_label }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "min-w-0 break-words", children: projectMetaLine(props.item) })
        ] })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs(
        "button",
        {
          type: "button",
          "aria-expanded": open,
          "aria-controls": listId,
          disabled: props.disabled,
          onClick: toggle,
          className: "inline-flex min-h-11 items-center gap-1.5 rounded-xl border border-slate-300 bg-white px-4 text-sm font-semibold text-brand-dark hover:border-brand-blue/60 disabled:opacity-60",
          children: [
            "Change project",
            /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniChevronDown, { className: `size-4 transition-transform duration-150 motion-reduce:transition-none ${open ? "rotate-180" : ""}`, "aria-hidden": "true" })
          ]
        }
      )
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("div", { id: listId, hidden: !open, children: open ? /* @__PURE__ */ jsxRuntimeExports.jsxs("ul", { className: "mt-4 divide-y divide-slate-200 overflow-hidden rounded-2xl border border-slate-200 bg-white", "aria-label": "Projects on this device", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("li", { children: /* @__PURE__ */ jsxRuntimeExports.jsx(ProjectOption, { project: props.item, current: true, onChoose: toggle }) }),
      others.map((project) => /* @__PURE__ */ jsxRuntimeExports.jsx("li", { children: /* @__PURE__ */ jsxRuntimeExports.jsx(ProjectOption, { project, current: false, onChoose: choose }) }, project.cli_id)),
      /* @__PURE__ */ jsxRuntimeExports.jsx("li", { children: /* @__PURE__ */ jsxRuntimeExports.jsxs(
        "button",
        {
          type: "button",
          onClick: props.onFindAnother,
          className: "flex min-h-12 w-full items-center gap-2 px-4 text-left text-sm font-semibold text-brand-blue hover:bg-brand-blue/5",
          children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniPlus, { className: "size-4", "aria-hidden": "true" }),
            "Use another folder or command"
          ]
        }
      ) })
    ] }) : null })
  ] });
}
function ProjectOption(props) {
  const handleChoose = reactExports.useCallback(() => props.onChoose(props.project), [props]);
  return /* @__PURE__ */ jsxRuntimeExports.jsxs(
    "button",
    {
      type: "button",
      onClick: handleChoose,
      "aria-current": props.current ? "true" : void 0,
      className: "flex min-h-14 w-full items-center justify-between gap-3 px-4 py-2.5 text-left hover:bg-brand-blue/5 aria-[current]:bg-brand-blue/5",
      children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { className: "min-w-0", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "block truncate text-sm font-semibold text-brand-dark", children: props.project.name }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "block truncate text-xs text-brand-dark/65", children: projectMetaLine(props.project) })
        ] }),
        props.current ? /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { className: "inline-flex shrink-0 items-center gap-1 text-xs font-semibold text-brand-blue", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniCheck, { className: "size-4", "aria-hidden": "true" }),
          "Selected"
        ] }) : null
      ]
    }
  );
}
const isSetupDigest = (value) => typeof value === "string" && /^[a-f0-9]{64}$/.test(value);
function parseRecentMcpSetups(value) {
  if (!Array.isArray(value) || value.length > 32) throw new Error("Could not verify recent setup history. Retry history.");
  const handles = /* @__PURE__ */ new Set();
  return value.map((entry) => {
    if (entry === null || typeof entry !== "object" || Array.isArray(entry) || !isSetupDigest(entry.rollback_handle) || !isSetupDigest(entry.selection_digest) || handles.has(entry.rollback_handle) || typeof entry.setup_name !== "string" || !/^[a-z0-9][a-z0-9_-]{0,63}$/.test(entry.setup_name) || !["remote", "package"].includes(entry.kind) || typeof entry.registry_name !== "string" || entry.registry_name.length > 256 || typeof entry.version !== "string" || entry.version.length > 80) {
      throw new Error("Could not verify recent setup history. Retry history.");
    }
    handles.add(entry.rollback_handle);
    if (entry.rollback_available !== void 0 && typeof entry.rollback_available !== "boolean") {
      throw new Error("Could not verify recent setup history. Retry history.");
    }
    return {
      rollback_handle: entry.rollback_handle,
      setup_name: entry.setup_name,
      kind: entry.kind,
      registry_name: entry.registry_name,
      version: entry.version,
      selection_digest: entry.selection_digest,
      ...entry.rollback_available === void 0 ? {} : { rollback_available: entry.rollback_available }
    };
  });
}
const object = (value) => value !== null && typeof value === "object" && !Array.isArray(value);
async function registrySearch(query, signal) {
  const response = await fetchLocalCliApi("/v1/local-clis/registry-search", {
    method: "POST",
    signal,
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ search: query })
  });
  const body = await response.json();
  if (!response.ok) throw new Error(object(body) && typeof body.message === "string" ? body.message : "Registry search failed.");
  if (!object(body) || body.source !== "official-mcp-registry" || body.coverage !== "search-page" || !Array.isArray(body.results) || body.results.length > 20 || typeof body.more_available !== "boolean") {
    throw new Error("Invalid registry response");
  }
  const entries = body.results.map((entry) => {
    if (!object(entry) || entry.provenance !== "official-mcp-registry" || entry.verified_package !== false || entry.configured !== false || entry.installed !== false || !["active", "deprecated", "unknown"].includes(String(entry.status)) || typeof entry.name !== "string" || entry.name.length > 256 || typeof entry.title !== "string" || entry.title.length > 120 || typeof entry.version !== "string" || entry.version.length > 80 || typeof entry.description !== "string" || entry.description.length > 500 || !Array.isArray(entry.remote_endpoints) || entry.remote_endpoints.length > 8 || !Array.isArray(entry.package_options) || entry.package_options.length > 8 || typeof entry.package_count !== "number" || !Number.isSafeInteger(entry.package_count) || entry.package_count < 0 || entry.package_count > 100) {
      throw new Error("Invalid registry provenance");
    }
    const endpoints = entry.remote_endpoints.map((remote) => {
      if (!object(remote) || typeof remote.url !== "string" || !remote.url.startsWith("https://") || !["streamable-http", "sse"].includes(String(remote.transport))) throw new Error("Invalid registry endpoint");
      return { url: remote.url, transport: remote.transport };
    });
    const packages = entry.package_options.map((option) => {
      if (!object(option) || !["npm", "pypi"].includes(String(option.registry_type)) || typeof option.identifier !== "string" || option.identifier.length > 160 || typeof option.version !== "string" || option.version.length > 80 || !["npx", "uvx"].includes(String(option.command)) || option.transport !== "stdio" || option.verified_package !== false || !Array.isArray(option.arguments) || option.arguments.length > (option.registry_type === "pypi" ? 17 : 18) || !option.arguments.every((argument) => typeof argument === "string" && argument.length <= 160)) {
        throw new Error("Invalid registry package option");
      }
      return option;
    });
    return {
      name: entry.name,
      version: entry.version,
      title: entry.title,
      description: entry.description,
      status: entry.status,
      remote_endpoints: endpoints,
      package_count: entry.package_count,
      package_options: packages,
      verified_package: false,
      configured: false,
      installed: false
    };
  });
  return { entries, moreAvailable: body.more_available };
}
function McpRegistrySearch({ items, approvalGate, onOpenChange, onConfigured }) {
  const [open, setOpen] = reactExports.useState(false);
  const [query, setQuery] = reactExports.useState("");
  const [entries, setEntries] = reactExports.useState(null);
  const [moreAvailable, setMoreAvailable] = reactExports.useState(false);
  const [busy, setBusy] = reactExports.useState(false);
  const [error, setError] = reactExports.useState(null);
  const controller = reactExports.useRef(null);
  const operation = reactExports.useRef(null);
  const interactionGeneration = reactExports.useRef(0);
  const historyGeneration = reactExports.useRef(0);
  const historyController = reactExports.useRef(null);
  const [recent, setRecent] = reactExports.useState([]);
  const [historyError, setHistoryError] = reactExports.useState(null);
  const [historyBusy, setHistoryBusy] = reactExports.useState(false);
  const returnFocus = reactExports.useRef(null);
  const [candidate, setCandidate] = reactExports.useState(null);
  const [configured, setConfigured] = reactExports.useState(null);
  const [password, setPassword] = reactExports.useState("");
  const [totp, setTotp] = reactExports.useState("");
  reactExports.useEffect(() => () => {
    controller.current?.abort();
    historyController.current?.abort();
  }, []);
  async function loadRecent() {
    historyController.current?.abort();
    const next = new AbortController();
    historyController.current = next;
    const generation = ++historyGeneration.current;
    setHistoryBusy(true);
    setHistoryError(null);
    try {
      const response = await fetchLocalCliApi("/v1/local-clis/registry-setup", {
        method: "POST",
        signal: next.signal,
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ operation: "recent" })
      });
      const body = await response.json();
      if (!response.ok || !object(body)) throw new Error("Recent setup history is unavailable. Retry history.");
      const setups = parseRecentMcpSetups(body.setups);
      if (!next.signal.aborted && historyGeneration.current === generation) setRecent(setups);
    } catch (caught) {
      if (!next.signal.aborted && historyGeneration.current === generation) {
        setHistoryError(caught instanceof Error ? caught.message : "Recent setup history is unavailable. Retry history.");
      }
    } finally {
      if (historyGeneration.current === generation) setHistoryBusy(false);
    }
  }
  function invalidateHistory() {
    historyGeneration.current += 1;
    historyController.current?.abort();
    setHistoryBusy(false);
  }
  async function previewUndo(setup, button) {
    if (operation.current) return;
    returnFocus.current = button;
    const generation = ++interactionGeneration.current;
    operation.current = "rollback-preview";
    const next = new AbortController();
    controller.current = next;
    setBusy(true);
    setError(null);
    setCandidate(null);
    setConfigured(null);
    setPassword("");
    setTotp("");
    try {
      const response = await fetchLocalCliApi("/v1/local-clis/registry-setup", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ operation: "rollback-preview", rollback_handle: setup.rollback_handle }),
        signal: next.signal
      });
      const body = await response.json();
      if (next.signal.aborted || interactionGeneration.current !== generation) return;
      if (!response.ok) {
        if (object(body) && (body.error === "codex_config_changed" || body.code === "codex_config_changed")) void loadRecent();
        throw new Error(object(body) && typeof body.message === "string" ? body.message : "Could not review removal. Review this connection in Codex.");
      }
      if (!object(body) || body.host !== "codex" || body.rollback_handle !== setup.rollback_handle || body.setup_name !== setup.setup_name || body.selection_digest !== setup.selection_digest || body.registry_name !== setup.registry_name || body.version !== setup.version || body.kind !== setup.kind || body.permissions_granted !== false || body.host_change_applied !== false || (body.kind === "remote" ? typeof body.endpoint !== "string" || body.endpoint.length > 2048 : typeof body.command !== "string" || body.command.length > 4096 || !Array.isArray(body.arguments) || body.arguments.length > 18 || !body.arguments.every((arg) => typeof arg === "string" && arg.length <= 160) || typeof body.package_identifier !== "string" || typeof body.package_version !== "string" || body.verified_package !== false)) throw new Error("Could not verify removal. Review this connection in Codex.");
      if (interactionGeneration.current === generation) setCandidate(body);
    } catch (caught) {
      if (!next.signal.aborted && interactionGeneration.current === generation) {
        setError(caught instanceof Error ? caught.message : "Could not review removal.");
      }
    } finally {
      if (controller.current === next && interactionGeneration.current === generation) {
        controller.current = null;
        operation.current = null;
        setBusy(false);
      }
    }
  }
  async function search() {
    if (query.trim().length < 2 || busy || operation.current) return;
    const generation = ++interactionGeneration.current;
    operation.current = "search";
    const next = new AbortController();
    controller.current = next;
    setBusy(true);
    setError(null);
    setEntries(null);
    setCandidate(null);
    setConfigured(null);
    try {
      const result = await registrySearch(query, next.signal);
      if (!next.signal.aborted) {
        setEntries(result.entries);
        setMoreAvailable(result.moreAvailable);
      }
    } catch (caught) {
      if (!next.signal.aborted) setError(caught instanceof Error ? caught.message : "Registry unavailable.");
    } finally {
      if (controller.current === next && interactionGeneration.current === generation) {
        controller.current = null;
        operation.current = null;
        setBusy(false);
      }
    }
  }
  async function preview(entry, target) {
    if (operation.current) return;
    const generation = ++interactionGeneration.current;
    operation.current = "preview";
    const next = new AbortController();
    controller.current = next;
    setBusy(true);
    setError(null);
    setCandidate(null);
    setConfigured(null);
    setPassword("");
    setTotp("");
    const setupName = entry.name.split("/").at(-1)?.toLowerCase().replace(/[^a-z0-9_-]/g, "-") ?? "mcp-server";
    try {
      const response = await fetchLocalCliApi("/v1/local-clis/registry-setup", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          operation: "preview",
          registry_name: entry.name,
          version: entry.version,
          setup_name: setupName,
          ..."endpoint" in target ? { kind: "remote", endpoint: target.endpoint } : {
            kind: "package",
            package_identifier: target.packageOption.identifier,
            package_version: target.packageOption.version
          }
        }),
        signal: next.signal
      });
      const body = await response.json();
      if (!response.ok) throw new Error(object(body) && typeof body.message === "string" ? body.message : "Could not review setup.");
      if (!object(body) || body.host !== "codex" || body.registry_name !== entry.name || body.version !== entry.version || body.setup_name !== setupName || body.permissions_granted !== false || body.host_change_applied !== false || typeof body.selection_digest !== "string" || !/^[a-f0-9]{64}$/.test(body.selection_digest)) throw new Error("Invalid Codex setup preview");
      if ("endpoint" in target) {
        if (body.endpoint !== target.endpoint || body.kind !== "remote") throw new Error("Invalid Codex endpoint preview");
      } else if (body.kind !== "package" || body.package_identifier !== target.packageOption.identifier || body.package_version !== target.packageOption.version || typeof body.command !== "string" || !Array.isArray(body.arguments) || !body.arguments.every((argument) => typeof argument === "string") || body.verified_package !== false) throw new Error("Invalid Codex package preview");
      if (!next.signal.aborted && interactionGeneration.current === generation) setCandidate(body);
    } catch (caught) {
      if (!next.signal.aborted && interactionGeneration.current === generation) {
        setError(caught instanceof Error ? caught.message : "Could not review setup.");
      }
    } finally {
      if (controller.current === next && interactionGeneration.current === generation) {
        controller.current = null;
        operation.current = null;
        setBusy(false);
      }
    }
  }
  async function apply() {
    if (!candidate || busy || operation.current || isApprovalProofSubmitDisabled(
      approvalGate,
      { approvalPassword: password, approvalTotpCode: totp },
      false
    )) return;
    const generation = ++interactionGeneration.current;
    operation.current = "apply";
    setBusy(true);
    setError(null);
    try {
      const proof = buildApprovalProofCredentials(
        approvalGate,
        { approvalPassword: password, approvalTotpCode: totp }
      );
      const response = await fetchLocalCliApi("/v1/local-clis/registry-setup", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          operation: candidate.rollback_handle ? "rollback" : "apply",
          ...candidate.rollback_handle ? { rollback_handle: candidate.rollback_handle } : {},
          registry_name: candidate.registry_name,
          version: candidate.version,
          setup_name: candidate.setup_name,
          ...candidate.kind === "package" ? {
            kind: "package",
            package_identifier: candidate.package_identifier,
            package_version: candidate.package_version
          } : { kind: "remote", endpoint: candidate.endpoint },
          selection_digest: candidate.selection_digest,
          confirm_host_change: true,
          session_nonce: crypto.randomUUID().replaceAll("-", ""),
          ...proof
        })
      });
      const body = await response.json();
      if (!response.ok) {
        if (candidate.rollback_handle && object(body) && (body.error === "codex_config_changed" || body.code === "codex_config_changed")) setCandidate(null);
        throw new Error(object(body) && typeof body.message === "string" ? body.message : "Codex setup did not finish.");
      }
      if (!object(body) || body.host !== "codex" || body.setup_name !== candidate.setup_name || body.kind !== (candidate.kind === "package" ? "package" : "remote") || body.host_change_applied !== true || body.permissions_granted !== false || (candidate.rollback_handle ? body.setup_rolled_back !== true : !isSetupDigest(body.rollback_handle))) {
        throw new Error("Codex setup outcome is uncertain. Check recent setup history and review this connection in Codex before retrying.");
      }
      invalidateHistory();
      if (candidate.rollback_handle) setRecent((previous) => previous.filter((setup) => setup.rollback_handle !== candidate.rollback_handle));
      else setRecent((previous) => [{
        rollback_handle: body.rollback_handle,
        setup_name: candidate.setup_name,
        kind: candidate.kind,
        registry_name: candidate.registry_name,
        version: candidate.version,
        selection_digest: candidate.selection_digest
      }, ...previous].slice(0, 32));
      void loadRecent();
      setConfigured({ name: candidate.setup_name, kind: candidate.kind, removed: Boolean(candidate.rollback_handle) });
      setCandidate(null);
      setPassword("");
      setTotp("");
      void Promise.resolve().then(onConfigured).then((outcome) => {
        if (outcome === "partial" && interactionGeneration.current === generation) setError("Codex configuration changed, but Guard could not fully rescan host connections. Existing connections remain visible. Retry discovery in Extensions.");
      }).catch(() => {
        if (interactionGeneration.current === generation) setError("Codex configuration changed, but Guard could not fully rescan host connections. Retry discovery in Extensions.");
      });
    } catch (caught) {
      setPassword("");
      setTotp("");
      void loadRecent();
      setError(caught instanceof Error ? caught.message : "Codex setup did not finish. Review this connection in Codex before retrying.");
    } finally {
      operation.current = null;
      setBusy(false);
    }
  }
  const setupStatus = reactExports.useMemo(() => {
    if (!configured) return null;
    const change = configured.removed ? "removed from" : "added to";
    let text = `${configured.name} was ${change} Codex. Restart Codex to load this configuration change.`;
    if (!configured.removed) {
      text += " Complete any provider-owned sign-in there.";
      if (configured.kind === "package") text += " Codex may download and run the pinned package on first use.";
      text += " Review each tool in Extensions after Codex loads it.";
    }
    return `${text} No tool permission was granted.`;
  }, [configured]);
  const setupReviewText = reactExports.useMemo(() => {
    if (!candidate || candidate.rollback_handle) return null;
    if (candidate.kind === "package") {
      return "This changes Codex configuration. Codex may download and execute this package on first use. It does not authenticate an account or allow tools in Guard.";
    }
    return "This changes Codex configuration. It does not download a package, authenticate an account, activate this session, or allow tools in Guard.";
  }, [candidate]);
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("details", { className: "mt-6 rounded-2xl border border-slate-200 bg-white p-4", onToggle: (event) => {
    setOpen(event.currentTarget.open);
    onOpenChange(event.currentTarget.open);
    if (event.currentTarget.open) void loadRecent();
    else {
      invalidateHistory();
      if (operation.current !== "apply") {
        controller.current?.abort();
        controller.current = null;
        operation.current = null;
        setBusy(false);
        interactionGeneration.current += 1;
        setCandidate(null);
        setPassword("");
        setTotp("");
      }
    }
  }, children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx("summary", { className: "min-h-11 cursor-pointer py-3 font-semibold text-brand-dark", children: "Find an MCP server in the public registry" }),
    open ? /* @__PURE__ */ jsxRuntimeExports.jsxs("section", { "aria-label": "Public MCP registry search", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm leading-6 text-brand-dark/75", children: "Search official listing metadata. Review a pinned package or HTTPS endpoint before adding it to Codex. A listing does not verify package safety, connect an account, or enable tools. App-owned connections stay in their host." }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-3 flex flex-wrap items-end gap-3", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs("label", { className: "block min-w-56 flex-1 text-sm font-semibold text-brand-dark", children: [
          "Server or app name",
          /* @__PURE__ */ jsxRuntimeExports.jsx(
            "input",
            {
              type: "search",
              minLength: 2,
              maxLength: 80,
              value: query,
              onChange: (event) => setQuery(event.target.value),
              onKeyDown: (event) => {
                if (event.key === "Enter") {
                  event.preventDefault();
                  void search();
                }
              },
              className: "mt-2 min-h-11 w-full rounded-xl border border-slate-300 px-3 font-normal"
            }
          )
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsx(
          "button",
          {
            type: "button",
            onClick: () => {
              void search();
            },
            disabled: busy || query.trim().length < 2,
            className: "min-h-11 rounded-xl bg-brand-blue px-4 text-sm font-semibold text-white disabled:opacity-50",
            children: "Search registry"
          }
        )
      ] }),
      busy ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { role: "status", className: "mt-3 text-sm text-brand-dark/75", children: {
        search: "Searching public listings…",
        preview: "Checking the exact registry listing…",
        "rollback-preview": "Checking the saved setup…",
        apply: candidate?.rollback_handle ? "Removing the reviewed connection from Codex…" : "Adding the reviewed connection to Codex…"
      }[operation.current ?? "apply"] }) : null,
      error ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { role: "alert", className: "mt-3 text-sm text-red-700", children: error }) : null,
      setupStatus ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { role: "status", className: "mt-3 text-sm text-brand-dark", children: setupStatus }) : null,
      candidate ? /* @__PURE__ */ jsxRuntimeExports.jsxs("section", { "aria-label": "Review Codex MCP setup", className: "mt-4 rounded-xl border border-slate-200 p-4 text-sm text-brand-dark", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("h3", { className: "font-semibold", children: candidate.rollback_handle ? "Review removal from Codex" : "Review Codex connection" }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "mt-2", children: [
          candidate.registry_name,
          " · version ",
          candidate.version
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "mt-1 break-all", children: [
          "Codex name: ",
          candidate.setup_name
        ] }),
        candidate.kind === "package" ? /* @__PURE__ */ jsxRuntimeExports.jsxs(jsxRuntimeExports.Fragment, { children: [
          /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "mt-2", children: [
            "Unverified registry package: ",
            candidate.package_identifier,
            " · pinned version ",
            candidate.package_version
          ] }),
          /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "mt-1 break-all font-mono text-xs", children: [
            "Launch: ",
            [candidate.command, ...candidate.arguments].map((part) => JSON.stringify(part)).join(" ")
          ] })
        ] }) : /* @__PURE__ */ jsxRuntimeExports.jsx(jsxRuntimeExports.Fragment, { children: /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "mt-1 break-all", children: [
          "HTTPS endpoint: ",
          candidate.endpoint
        ] }) }),
        setupReviewText ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-2", children: setupReviewText }) : null,
        candidate.rollback_handle ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-2", children: "Remove only the connection added by this setup. If Codex configuration has changed since then, Guard leaves it unchanged so you can review it in Codex. Removing setup does not revoke provider access or erase Guard tool choices." }) : null,
        /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-3 max-w-sm", children: /* @__PURE__ */ jsxRuntimeExports.jsx(
          ApprovalProofFieldInputs,
          {
            approvalGate,
            approvalPassword: password,
            approvalTotpCode: totp,
            onApprovalPasswordChange: (event) => setPassword(event.target.value),
            onApprovalTotpCodeChange: (event) => setTotp(event.target.value.replace(/\D/g, "").slice(0, 6))
          }
        ) }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-3 flex flex-wrap gap-3", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx(
            "button",
            {
              type: "button",
              disabled: busy || isApprovalProofSubmitDisabled(
                approvalGate,
                { approvalPassword: password, approvalTotpCode: totp },
                false
              ),
              onClick: () => {
                void apply();
              },
              className: "min-h-11 rounded-xl bg-brand-blue px-4 font-semibold text-white disabled:opacity-50",
              children: candidate.rollback_handle ? "Remove from Codex" : "Add to Codex"
            }
          ),
          /* @__PURE__ */ jsxRuntimeExports.jsx(
            "button",
            {
              type: "button",
              disabled: busy,
              onClick: () => {
                setCandidate(null);
                setPassword("");
                setTotp("");
                returnFocus.current?.focus();
              },
              className: "min-h-11 rounded-xl border border-slate-300 px-4 font-semibold",
              children: "Cancel"
            }
          )
        ] })
      ] }) : null,
      /* @__PURE__ */ jsxRuntimeExports.jsxs("section", { "aria-label": "Recent MCP setup", className: "mt-4 border-t border-slate-200 pt-4 text-sm text-brand-dark", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("h3", { className: "font-semibold", children: "Recent setup" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1 text-brand-dark/75", children: "Undo is available for up to an hour while this Guard runtime stays open. For older or changed connections, review configuration in Codex." }),
        historyBusy ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { role: "status", className: "mt-2", children: "Loading recent setup…" }) : null,
        historyError ? /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-2", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("p", { role: "alert", className: "text-red-700", children: historyError }),
          /* @__PURE__ */ jsxRuntimeExports.jsx(
            "button",
            {
              type: "button",
              disabled: historyBusy || busy,
              onClick: () => {
                void loadRecent();
              },
              className: "mt-2 min-h-11 rounded-xl border border-slate-300 px-4 font-semibold",
              children: "Retry history"
            }
          )
        ] }) : null,
        !historyBusy && !historyError && !recent.length ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-2 text-brand-dark/75", children: "No setup available to undo in this runtime." }) : null,
        recent.length ? /* @__PURE__ */ jsxRuntimeExports.jsx("ul", { className: "mt-2 divide-y divide-slate-200", children: recent.map((setup) => /* @__PURE__ */ jsxRuntimeExports.jsxs(
          "li",
          {
            className: "flex flex-wrap items-center justify-between gap-3 py-3",
            children: [
              /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "min-w-0 flex-1", children: [
                /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "break-all font-semibold", children: setup.setup_name }),
                /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "break-all text-brand-dark/75", children: [
                  setup.registry_name,
                  " · ",
                  setup.version
                ] }),
                setup.rollback_available === false ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1 text-brand-dark/75", children: "Configuration changed. Review this connection in Codex." }) : null
              ] }),
              /* @__PURE__ */ jsxRuntimeExports.jsx(
                "button",
                {
                  type: "button",
                  disabled: busy || setup.rollback_available === false,
                  onClick: (event) => {
                    void previewUndo(setup, event.currentTarget);
                  },
                  "aria-label": `Undo setup for ${setup.setup_name}`,
                  className: "min-h-11 rounded-xl border border-slate-300 px-4 font-semibold disabled:opacity-50",
                  children: "Undo setup"
                }
              )
            ]
          },
          setup.rollback_handle
        )) }) : null
      ] }),
      entries?.length === 0 ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-3 text-sm text-brand-dark/75", children: "No listing on this search page. Try another name." }) : null,
      moreAvailable && entries ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-3 text-sm text-brand-dark/75", children: "More listings match. Refine the name to find a specific server; this page is not the complete registry." }) : null,
      entries ? /* @__PURE__ */ jsxRuntimeExports.jsx("ul", { className: "mt-4 divide-y divide-slate-200", children: entries.map((entry) => {
        const basename = entry.name.split("/").at(-1)?.toLowerCase();
        const possibleExisting = items.some((item) => item.surface === "mcp" && (item.name.toLowerCase() === entry.title.toLowerCase() || item.name.toLowerCase() === basename));
        return /* @__PURE__ */ jsxRuntimeExports.jsxs("li", { className: "py-4 text-sm text-brand-dark", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "font-semibold", children: [
            entry.title,
            " · ",
            entry.version
          ] }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1 text-brand-dark/75", children: entry.description }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-2 break-all text-xs text-brand-dark/75", children: entry.name }),
          /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "mt-2 text-xs text-brand-dark/75", children: [
            entry.status,
            " listing · ",
            entry.remote_endpoints.length,
            " HTTPS endpoint(s) · ",
            entry.package_options.length,
            " reviewed launch option(s) of ",
            entry.package_count,
            " package listing(s) · Packages unverified"
          ] }),
          possibleExisting ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-2 text-xs font-semibold text-brand-dark", children: "Possible existing connection. Inspect it before adding another." }) : null,
          entry.status === "active" && !possibleExisting && entry.remote_endpoints.some((remote) => remote.transport === "streamable-http") ? /* @__PURE__ */ jsxRuntimeExports.jsx("button", { type: "button", disabled: busy, onClick: () => {
            const endpoint = entry.remote_endpoints.find((remote) => remote.transport === "streamable-http");
            if (endpoint) void preview(entry, { endpoint: endpoint.url });
          }, className: "mt-3 min-h-11 rounded-xl border border-slate-300 px-4 font-semibold text-brand-dark", children: "Review HTTPS setup" }) : null,
          entry.status === "active" && !possibleExisting ? entry.package_options.map((option) => /* @__PURE__ */ jsxRuntimeExports.jsxs(
            "button",
            {
              type: "button",
              disabled: busy,
              onClick: () => {
                void preview(entry, { packageOption: option });
              },
              className: "ml-2 mt-3 min-h-11 rounded-xl border border-slate-300 px-4 font-semibold text-brand-dark",
              children: [
                "Review ",
                option.registry_type,
                " package · ",
                option.identifier,
                "@",
                option.version
              ]
            },
            `${option.registry_type}/${option.identifier}/${option.version}`
          )) : null
        ] }, `${entry.name}/${entry.version}`);
      }) }) : null
    ] }) : null
  ] });
}
function randomToken$1() {
  return crypto.randomUUID().replaceAll("-", "");
}
function AddCustomExtensionWorkspace(props) {
  const { resolvedApprovalGate, resolveApprovalGate, refreshApprovalGate } = useResolvedApprovalGate(null);
  const [command, setCommand] = reactExports.useState(() => initialAddCommand(window.location.search));
  const [recognized, setRecognized] = reactExports.useState(null);
  const [commands, setCommands] = reactExports.useState([]);
  const [baseline, setBaseline] = reactExports.useState([]);
  const [summary, setSummary] = reactExports.useState(null);
  const [pending, setPending] = reactExports.useState(null);
  const [step, setStep] = reactExports.useState("pick");
  const [password, setPassword] = reactExports.useState("");
  const [totp, setTotp] = reactExports.useState("");
  const [busy, setBusy] = reactExports.useState(false);
  const [error, setError] = reactExports.useState(null);
  const [registryOpen, setRegistryOpen] = reactExports.useState(false);
  const recognizeGeneration = reactExports.useRef(0);
  const autoRecognizedCommand = reactExports.useRef("");
  const didAutoSelect = reactExports.useRef(false);
  const sawDiscovering = reactExports.useRef(false);
  const rememberedProjects = suggestedPackageScriptExtensions(props.items);
  const packageScriptSuggestions = filterExtensionSuggestions(rememberedProjects, command).slice(0, 8);
  const harnessSuggestions = filterExtensionSuggestions(suggestedHarnessExtensions(props.items), command).slice(0, 8);
  const seenSuggestions = filterExtensionSuggestions(suggestedSeenExtensions(props.items), command).slice(0, 6);
  const hasSuggestions = packageScriptSuggestions.length > 0 || harnessSuggestions.length > 0 || seenSuggestions.length > 0;
  reactExports.useEffect(() => {
    void resolveApprovalGate({ failClosed: true }).catch(() => {
      setError("Guard could not load local approval settings yet.");
    });
  }, [resolveApprovalGate]);
  const resetRecognition = reactExports.useCallback(() => {
    recognizeGeneration.current += 1;
    autoRecognizedCommand.current = "";
    setBusy(false);
    setRecognized(null);
    setCommands([]);
    setBaseline([]);
    setSummary(null);
    setPending(null);
    setStep("pick");
  }, []);
  const handleCommand = reactExports.useCallback((event) => {
    const value = event.target.value;
    const keepCatalog = recognized?.surface === "package-scripts" && keepsPackageScriptCatalog(value, commands);
    setCommand(value);
    setError(null);
    if (keepCatalog) return;
    resetRecognition();
  }, [commands, recognized, resetRecognition]);
  const handlePassword = reactExports.useCallback((event) => {
    setPassword(event.target.value);
  }, []);
  const handleTotp = reactExports.useCallback((event) => {
    const digits = event.target.value.replace(/\D/g, "").slice(0, 6);
    event.target.value = digits;
    setTotp(digits);
  }, []);
  const markRecognized = reactExports.useCallback((item, nextSummary) => {
    const prefilled = prefillSuggestedStates(item);
    setRecognized(item);
    setCommands(prefilled);
    setBaseline(prefilled);
    setSummary(nextSummary);
    setPending("allowed");
    setStep("review");
  }, []);
  const runRecognize = reactExports.useCallback(async (commandText, cliId, silent = false, keepOnError = false) => {
    const generation = recognizeGeneration.current + 1;
    recognizeGeneration.current = generation;
    setBusy(true);
    if (!silent) setError(null);
    try {
      const result = await recognizeLocalCli(commandText, cliId ? { cliId } : void 0);
      if (recognizeGeneration.current !== generation) return;
      markRecognized(result.item, result.summary);
      if (keepOnError) {
        setError(mcpListingRetryError(result.help_status, result.item.commands));
      } else {
        setError(null);
      }
    } catch (caught) {
      if (recognizeGeneration.current !== generation) return;
      if (!keepOnError) {
        setRecognized(null);
        setSummary(null);
        setStep("pick");
      }
      if (!silent) {
        setError(caught instanceof LocalCliApiError ? caught.message : "Guard could not identify that command.");
      }
    } finally {
      if (recognizeGeneration.current === generation) setBusy(false);
    }
  }, [markRecognized]);
  const selectSuggestion = reactExports.useCallback((item) => {
    if (item.surface !== "package-scripts") setCommand(item.example_label);
    setError(null);
    if (item.surface === "mcp" && item.commands.length === 0) {
      setRecognized(null);
      setCommands([]);
      setSummary(null);
      setPending(null);
      setStep("pick");
      void runRecognize(item.example_label, item.cli_id);
      return;
    }
    markRecognized(item, suggestionSummary(item));
  }, [markRecognized, runRecognize]);
  const findTool = reactExports.useCallback(async () => {
    await runRecognize(command);
  }, [command, runRecognize]);
  const retryMcpListing = reactExports.useCallback(() => {
    if (recognized === null) return;
    void runRecognize(command.trim() || recognized.example_label, recognized.cli_id, false, true);
  }, [command, recognized, runRecognize]);
  reactExports.useEffect(() => {
    if (props.discovering === true) sawDiscovering.current = true;
    if (!sawDiscovering.current || props.discovering === true || command.trim() !== "") return;
    const preferred = preferredPackageScriptExtension(props.items);
    if (preferred === null) return;
    if (recognized !== null) {
      if (recognized.cli_id !== preferred.cli_id) return;
      if (recognized.identity_hash === preferred.identity_hash && recognized.commands.length === preferred.commands.length) {
        return;
      }
      markRecognized(preferred, suggestionSummary(preferred));
      return;
    }
    if (didAutoSelect.current) return;
    didAutoSelect.current = true;
    selectSuggestion(preferred);
  }, [command, markRecognized, props.discovering, props.items, recognized, selectSuggestion]);
  reactExports.useEffect(() => {
    const trimmed = command.trim();
    if (recognized !== null || !looksLikePackageScriptPaste(trimmed)) return;
    if (autoRecognizedCommand.current === trimmed) return;
    const handle = window.setTimeout(() => {
      autoRecognizedCommand.current = trimmed;
      void runRecognize(trimmed, void 0, true);
    }, 280);
    return () => window.clearTimeout(handle);
  }, [busy, command, recognized, runRecognize]);
  const requestAllow = reactExports.useCallback(() => setPending("allowed"), []);
  const requestBlock = reactExports.useCallback(() => setPending("blocked"), []);
  const findAnotherProject = reactExports.useCallback(() => {
    resetRecognition();
    setCommand("");
    setError(null);
    window.requestAnimationFrame(() => document.getElementById("custom-extension-command")?.focus());
  }, [resetRecognition]);
  const backToReview = reactExports.useCallback(() => {
    setStep("review");
    setError(null);
  }, []);
  const showingPackageCatalog = recognized?.surface === "package-scripts";
  const enrollable = showingPackageCatalog ? enrollablePackageScriptCommands(commands) : commands;
  const bulkEligible = reactExports.useCallback((entry) => recognized?.surface === "mcp" ? mcpToolCanReceiveDirectAllow(entry) : true, [recognized]);
  const applyBulk = reactExports.useCallback((commandIds, state) => {
    setCommands((current) => current.map((entry) => commandIds.has(entry.command_id) && bulkEligible(entry) ? { ...entry, state } : entry));
    const blocksAll = showingPackageCatalog && state === "block" && enrollable.every((entry) => commandIds.has(entry.command_id));
    setPending(blocksAll ? "blocked" : "allowed");
  }, [bulkEligible, enrollable, showingPackageCatalog]);
  const switchProject = reactExports.useCallback((item) => {
    setCommand("");
    selectSuggestion(item);
  }, [selectSuggestion]);
  const savedStates = recognized === null || pending === null ? null : new Map(enrollmentCommandStates(enrollable, pending, recognized.surface).map((entry) => [entry.command_id, entry.state]));
  const savedPreview = enrollable.map((entry) => ({ ...entry, state: savedStates?.get(entry.command_id) ?? entry.state }));
  const handleSubmit = reactExports.useCallback(async (event) => {
    event.preventDefault();
    if (recognized === null) {
      await findTool();
      return;
    }
    if (step !== "confirm") {
      setStep("confirm");
      setError(null);
      setBusy(true);
      try {
        await refreshApprovalGate({ failClosed: true });
      } catch {
        setError("Guard could not load local approval settings yet.");
      } finally {
        setBusy(false);
      }
      return;
    }
    if (pending === null) return;
    setBusy(true);
    setError(null);
    try {
      const payload = {
        cli_id: recognized.cli_id,
        identity_hash: recognized.identity_hash,
        name: recognized.name,
        kind: recognized.kind,
        example_label: recognized.example_label,
        interpreter_name: recognized.interpreter_name,
        state: pending,
        previous_revision: props.revision,
        session_nonce: randomToken$1(),
        commands: enrollmentCommandStates(commands, pending, recognized.surface),
        ...buildApprovalProofCredentials(resolvedApprovalGate, {
          approvalPassword: password,
          approvalTotpCode: totp
        })
      };
      await previewLocalCliMutation(payload);
      await applyLocalCliMutation(payload);
      await refreshApprovalGate();
      props.onAdded(recognized.cli_id);
    } catch (caught) {
      setError(caught instanceof LocalCliApiError ? caught.message : "Guard could not add this custom extension.");
    } finally {
      setBusy(false);
    }
  }, [commands, findTool, password, pending, props, recognized, refreshApprovalGate, resolvedApprovalGate, step, totp]);
  const handleCommandState = reactExports.useCallback((commandId, state) => {
    setCommands((current) => withCommandState(current, commandId, state));
    setPending("allowed");
  }, []);
  const proofReady = pending !== null && recognized !== null;
  const confirming = step === "confirm" && recognized !== null;
  const submitDisabled = enrollSubmitDisabled({
    recognized,
    command,
    confirming,
    proofReady,
    proofBlocked: isApprovalProofSubmitDisabled(
      resolvedApprovalGate,
      { approvalPassword: password, approvalTotpCode: totp },
      busy,
      false,
      true
    ),
    busy
  });
  const showingMcpCatalog = recognized?.surface === "mcp";
  const observedMcp = isObservedMcpItem(recognized);
  const mcpHasTools = mcpCatalogHasTools(enrollable);
  const showMcpRetry = showingMcpCatalog && !mcpHasTools;
  let confirmTitle = allowActionLabel(recognized?.surface ?? "cli");
  if (pending === "blocked") {
    confirmTitle = blockActionLabel(recognized?.surface ?? "cli");
  } else if (observedMcp) {
    confirmTitle = "Save tool permissions";
  }
  const browserCopy = commandBrowserCopy(recognized?.surface);
  const bulkCopy = bulkPolicyCopy(recognized?.surface ?? "cli");
  const blockedSummary = observedMcp && pending === "blocked" ? "This connector will be blocked, including tools that have not been listed yet." : summary;
  const recentlySatisfied = approvalProofRecentlySatisfied(resolvedApprovalGate);
  const gateReady = resolvedApprovalGate === null ? null : isBulkApproveGateReady(resolvedApprovalGate);
  return /* @__PURE__ */ jsxRuntimeExports.jsxs(
    "form",
    {
      "data-testid": "add-custom-extension",
      onSubmit: handleSubmit,
      className: "flex min-h-[70vh] w-full flex-col",
      children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs(
          "button",
          {
            type: "button",
            onClick: confirming ? backToReview : props.onBack,
            className: "inline-flex min-h-11 w-fit items-center gap-2 rounded-lg px-1 text-sm font-semibold text-brand-dark/80 hover:text-brand-dark",
            children: [
              /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniArrowLeft, { className: "size-4", "aria-hidden": "true" }),
              confirming ? "Back to settings" : "Extensions"
            ]
          }
        ),
        confirming && recognized ? /* @__PURE__ */ jsxRuntimeExports.jsxs("section", { className: "mt-6 max-w-xl", "aria-labelledby": "custom-extension-confirm-title", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("h1", { id: "custom-extension-confirm-title", className: "text-2xl font-semibold tracking-tight text-brand-dark", children: confirmTitle }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-2 text-sm leading-6 text-slate-500", children: recognized.source_label ? `${recognized.name} · ${recognized.source_label}` : recognized.name }),
          summary ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-2 text-sm leading-6 text-brand-dark/70", children: observedMcp && pending === "blocked" ? "This connector will be blocked, including tools that have not been listed yet." : summary }) : null,
          /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-5 text-sm leading-6 text-brand-dark/80", children: enrollConfirmCopy(recognized.surface, recentlySatisfied, resolvedApprovalGate?.totp_enabled === true, gateReady) }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-5 max-w-sm", children: /* @__PURE__ */ jsxRuntimeExports.jsx(
            ApprovalProofFieldInputs,
            {
              approvalGate: resolvedApprovalGate,
              approvalPassword: password,
              approvalTotpCode: totp,
              requireGate: true,
              onApprovalPasswordChange: handlePassword,
              onApprovalTotpCodeChange: handleTotp
            }
          ) })
        ] }) : /* @__PURE__ */ jsxRuntimeExports.jsxs(jsxRuntimeExports.Fragment, { children: [
          /* @__PURE__ */ jsxRuntimeExports.jsxs("header", { className: "mt-3 max-w-2xl pb-4", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("h1", { id: "add-custom-extension-title", className: "text-2xl font-semibold tracking-tight text-brand-dark", children: "Add a custom extension" }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-2 text-sm leading-6 text-slate-500", children: dialogIntro(
              rememberedProjects.length > 0,
              recognized?.surface ?? null,
              props.discovering === true && recognized === null,
              !showMcpRetry,
              observedMcp
            ) })
          ] }),
          !observedMcp && !showingPackageCatalog ? /* @__PURE__ */ jsxRuntimeExports.jsxs(jsxRuntimeExports.Fragment, { children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("label", { htmlFor: "custom-extension-command", className: "mt-4 block text-sm font-semibold text-brand-dark", children: recognized === null ? "Find an extension" : commandFieldLabel(recognized.surface) }),
            /* @__PURE__ */ jsxRuntimeExports.jsx(
              "input",
              {
                id: "custom-extension-command",
                value: command,
                onChange: handleCommand,
                spellCheck: false,
                autoComplete: "off",
                placeholder: "Project folder, npm run, server name, or launch command",
                className: "mt-2 min-h-11 w-full max-w-xl rounded-xl border border-slate-300 bg-white px-3 text-sm text-brand-dark placeholder:text-brand-dark/70 focus:border-brand-blue focus:outline-none focus:ring-2 focus:ring-brand-blue/30"
              }
            )
          ] }) : null,
          recognized ? /* @__PURE__ */ jsxRuntimeExports.jsxs(jsxRuntimeExports.Fragment, { children: [
            showingPackageCatalog ? /* @__PURE__ */ jsxRuntimeExports.jsx(
              SelectedProject,
              {
                item: recognized,
                projects: rememberedProjects,
                disabled: busy,
                onSelect: switchProject,
                onFindAnother: findAnotherProject
              }
            ) : /* @__PURE__ */ jsxRuntimeExports.jsxs("section", { className: "mt-5 max-w-3xl", "aria-labelledby": "custom-extension-selected", children: [
              /* @__PURE__ */ jsxRuntimeExports.jsx("h2", { id: "custom-extension-selected", className: "text-xl font-semibold tracking-tight text-brand-dark", children: recognized.name }),
              /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: `mt-1 text-xs text-brand-dark/70${observedMcp ? "" : " font-mono"}`, children: observedMcp ? recognized.source_label : recognized.source_label ? `${recognized.source_label} · ${recognized.example_label}` : recognized.example_label }),
              blockedSummary ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-2 max-w-2xl text-sm leading-6 text-brand-dark/70", children: blockedSummary }) : null,
              showMcpRetry ? /* @__PURE__ */ jsxRuntimeExports.jsx(McpListingStatus, { name: recognized.name, busy, onRetry: retryMcpListing }) : null
            ] }),
            !showMcpRetry ? /* @__PURE__ */ jsxRuntimeExports.jsxs("section", { className: "mt-2 max-w-4xl", "aria-label": `${recognized.name} ${browserCopy.units}`, children: [
              /* @__PURE__ */ jsxRuntimeExports.jsx(
                CustomExtensionCommandBrowser,
                {
                  commands: enrollable,
                  savedCommands: baseline,
                  surface: recognized.surface,
                  disabled: busy,
                  bulkEligible,
                  bulkGroupLabel: bulkCopy.groupLabel,
                  bulkMixedCopy: bulkCopy.mixedCopy,
                  initialQuery: showingPackageCatalog ? packageScriptQueryFrom(command, enrollable) : void 0,
                  changedLabel: "Changed",
                  onChange: handleCommandState,
                  onBulkChange: applyBulk
                },
                recognized.cli_id
              ),
              observedMcp ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-3 text-xs leading-5 text-brand-dark/70", children: "Only tools your app has used are listed. More appear as it uses them." }) : null
            ] }) : null
          ] }) : /* @__PURE__ */ jsxRuntimeExports.jsxs(jsxRuntimeExports.Fragment, { children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx(
              SuggestionPanel,
              {
                query: command,
                discovering: props.discovering === true,
                hasSuggestions,
                packageScriptSuggestions,
                harnessSuggestions,
                seenSuggestions,
                onSelect: selectSuggestion
              }
            ),
            /* @__PURE__ */ jsxRuntimeExports.jsx(
              McpRegistrySearch,
              {
                items: props.items,
                approvalGate: resolvedApprovalGate,
                onOpenChange: setRegistryOpen,
                onConfigured: props.onConfigured
              }
            )
          ] })
        ] }),
        error ? /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-4 max-w-xl", children: /* @__PURE__ */ jsxRuntimeExports.jsx(InlineError, { message: error }) }) : null,
        /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: `${registryOpen && !recognized ? "relative" : "sticky bottom-[calc(var(--guard-shell-mobile-nav-height,0px)+env(safe-area-inset-bottom))] z-20 md:bottom-0"} mt-auto border-t border-slate-200 bg-white py-4`, children: /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap items-center gap-3", children: [
          recognized && !confirming && enrollable.length > 0 && !showMcpRetry ? /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "mr-auto text-sm text-brand-dark/75", "data-testid": "custom-extension-add-summary", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { className: "font-semibold text-brand-dark", children: [
              enrollable.length,
              " ",
              browserCopy.unit(enrollable.length)
            ] }),
            " · ",
            groupStateSummary(savedPreview)
          ] }) : null,
          /* @__PURE__ */ jsxRuntimeExports.jsx("button", { type: "submit", disabled: submitDisabled, className: "min-h-11 rounded-xl bg-brand-blue px-5 text-sm font-semibold text-white disabled:opacity-60", children: addDialogSubmitLabel({ recognized, busy, pending, step: recognized ? step : "pick" }) }),
          recognized && confirming && pending === "allowed" ? /* @__PURE__ */ jsxRuntimeExports.jsx("button", { type: "button", onClick: requestBlock, className: "min-h-11 rounded-xl px-4 text-sm font-semibold text-brand-dark", children: blockActionLabel(recognized.surface) }) : null,
          recognized && confirming && pending === "blocked" ? /* @__PURE__ */ jsxRuntimeExports.jsx("button", { type: "button", onClick: requestAllow, className: "min-h-11 rounded-xl px-4 text-sm font-semibold text-brand-dark", children: allowActionLabel(recognized.surface) }) : null
        ] }) })
      ]
    }
  );
}
async function fetchLocalCliDiscover() {
  const response = await fetchLocalCliApi("/v1/local-clis/discover", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: "{}"
  });
  const payload = await response.json().catch(() => null);
  if (!response.ok) {
    throw new LocalCliApiError("local_cli_request_failed", "Guard could not refresh custom extensions.");
  }
  return normalizeLocalCliList(payload);
}
function discoveryIssueMessage(issue) {
  switch (issue) {
    case "catalog_limit_reached":
      return "Some connectors have more tools than Guard can catalog safely. Existing choices were kept.";
    case "configured_host_scan_failed":
      return "Guard could not read configured host connections. Check the host app and retry.";
    case "configured_host_persist_failed":
      return "Guard read your host connections but could not save them. Existing choices were kept; retry discovery, and restart Guard if it keeps failing.";
    case "observed_provider_scan_failed":
      return "Guard could not merge observed provider tools. Existing choices were kept; retry discovery.";
    case "package_catalog_refresh_failed":
      return "Guard could not refresh project scripts. Existing custom extensions were kept; retry discovery.";
    default:
      return null;
  }
}
function useLocalCliCatalog() {
  const [data, setData] = reactExports.useState(null);
  const [error, setError] = reactExports.useState(null);
  const [discoveryNotice, setDiscoveryNotice] = reactExports.useState(null);
  const [discovering, setDiscovering] = reactExports.useState(false);
  const [catalogReady, setCatalogReady] = reactExports.useState(false);
  const loadGeneration = reactExports.useRef(0);
  const publicationPoll = reactExports.useRef({ revision: -1, attempts: 0 });
  const load = reactExports.useCallback(async (preserveDiscoveryNotice = false) => {
    const generation = loadGeneration.current + 1;
    loadGeneration.current = generation;
    try {
      const next = await fetchLocalCliList();
      if (loadGeneration.current !== generation) return;
      setData(next);
      setError(null);
      if (!preserveDiscoveryNotice) setDiscoveryNotice(null);
    } catch (caught) {
      if (loadGeneration.current !== generation) return;
      setError(caught instanceof Error ? caught.message : "Guard could not load custom extensions.");
    }
  }, []);
  const discover = reactExports.useCallback(async () => {
    const generation = loadGeneration.current + 1;
    loadGeneration.current = generation;
    setDiscovering(true);
    setCatalogReady(false);
    try {
      const next = await fetchLocalCliDiscover();
      if (loadGeneration.current !== generation) return "superseded";
      setData(next);
      setError(null);
      setDiscoveryNotice(discoveryIssueMessage(next.discovery_issue));
      return next.discovery_issue ? "partial" : "refreshed";
    } catch (error2) {
      try {
        const next = await fetchLocalCliList();
        if (loadGeneration.current !== generation) return "superseded";
        setData(next);
        setError(null);
        setDiscoveryNotice(error2 instanceof Error ? error2.message : "Guard could not refresh custom extensions.");
        return "partial";
      } catch (caught) {
        if (loadGeneration.current !== generation) return "superseded";
        setError(caught instanceof Error ? caught.message : "Guard could not load custom extensions.");
        return "partial";
      }
    } finally {
      if (loadGeneration.current === generation) {
        setDiscovering(false);
        setCatalogReady(true);
      }
    }
  }, []);
  reactExports.useEffect(() => {
    void load();
  }, [load]);
  reactExports.useEffect(() => {
    if (discovering || data?.native_publication?.state !== "pending") return;
    if (publicationPoll.current.revision !== data.revision) {
      publicationPoll.current = { revision: data.revision, attempts: 0 };
    }
    if (publicationPoll.current.attempts >= 20) return;
    const timer = window.setTimeout(() => {
      publicationPoll.current.attempts += 1;
      void load(true);
    }, 1500);
    return () => window.clearTimeout(timer);
  }, [data, discovering, load]);
  return { data, error, discoveryNotice, load, discover, discovering, catalogReady };
}
function AddCustomExtensionButton(props) {
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("button", { type: "button", onClick: props.onClick, className: "inline-flex min-h-11 items-center gap-2 rounded-xl border border-slate-300 px-4 text-sm font-semibold text-brand-dark", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniPlus, { className: "size-4", "aria-hidden": "true" }),
    "Add custom extension"
  ] });
}
function LocalCliDetail(props) {
  const { resolvedApprovalGate, resolveApprovalGate, refreshApprovalGate } = useResolvedApprovalGate(null);
  const [pending, setPending] = reactExports.useState(null);
  const [commands, setCommands] = reactExports.useState(() => prefillSuggestedStates(props.item));
  const [providerDrafts, setProviderDrafts] = reactExports.useState({});
  const previousItem = reactExports.useRef(props.item);
  const [busy, setBusy] = reactExports.useState(false);
  const [catalogBusy, setCatalogBusy] = reactExports.useState(false);
  const [catalogError, setCatalogError] = reactExports.useState(null);
  const catalogController = reactExports.useRef(null);
  reactExports.useEffect(() => () => catalogController.current?.abort(), []);
  const [error, setError] = reactExports.useState(null);
  const [freshTotpRequired, setFreshTotpRequired] = reactExports.useState(false);
  const added = props.item.state !== "unset";
  const commandChanges = commandPermissionChanges(props.item.commands, commands);
  const commandsDirty = commandChanges.length > 0;
  const [recommended, setRecommended] = reactExports.useState(false);
  const [setupOutcome, setSetupOutcome] = reactExports.useState(null);
  reactExports.useEffect(() => {
    const previous = previousItem.current;
    if (previous.cli_id !== props.item.cli_id || previous.identity_hash !== props.item.identity_hash) {
      setPending(null);
      setSetupOutcome(null);
      setProviderDrafts({});
      setCatalogError(null);
      setError(previous.cli_id === props.item.cli_id ? "This extension changed. Review its permissions again." : null);
    }
    setCommands((current) => {
      if (previous.cli_id !== props.item.cli_id || previous.identity_hash !== props.item.identity_hash) {
        return prefillSuggestedStates(props.item);
      }
      const changed = previous.mcp_catalog?.revision !== props.item.mcp_catalog?.revision ? props.item.mcp_catalog?.changes?.changed : [];
      return rebaseCommandDraft(current, previous.commands, props.item.commands, changed);
    });
    previousItem.current = props.item;
  }, [props.item]);
  const setupMatch = props.setupLink ? connectorSetupMatch(props.item, props.setupLink) : null;
  const openPending = reactExports.useCallback(async (state, fromSetupLink = false) => {
    setFreshTotpRequired(false);
    await refreshApprovalGate();
    setRecommended(fromSetupLink);
    setPending(state);
  }, [refreshApprovalGate]);
  const requestRecommended = reactExports.useCallback(() => {
    setCommands(prefillSuggestedStates(props.item));
    return openPending("allowed", true);
  }, [openPending, props.item]);
  const requestAdd = reactExports.useCallback(() => openPending("allowed"), [openPending]);
  const requestAllow = reactExports.useCallback(() => openPending("allowed"), [openPending]);
  const requestBlock = reactExports.useCallback(() => openPending("blocked"), [openPending]);
  const requestRemove = reactExports.useCallback(() => openPending("unset"), [openPending]);
  const requestSaveCommands = reactExports.useCallback(() => {
    openPending(props.item.state === "blocked" ? "blocked" : "allowed");
  }, [openPending, props.item.state]);
  const handleCommandState = reactExports.useCallback((commandId, state) => {
    setCommands((current) => withCommandState(current, commandId, state));
  }, []);
  const bulkEligible = reactExports.useCallback((command) => {
    if (props.item.surface === "package-scripts") return command.command_id !== "root" && command.command_id !== "other";
    if (props.item.surface === "mcp") return mcpToolCanReceiveDirectAllow(command);
    return true;
  }, [props.item.surface]);
  const applyBulk = reactExports.useCallback((commandIds, state) => {
    setCommands((current) => current.map((command) => commandIds.has(command.command_id) && bulkEligible(command) ? { ...command, state } : command));
  }, [bulkEligible]);
  const resetCommands = reactExports.useCallback(() => setCommands(prefillSuggestedStates(props.item)), [props.item]);
  const bulkTargetCount = commands.filter(bulkEligible).length;
  const bulkCopy = bulkPolicyCopy(props.item.surface);
  const continuity = customExtensionContinuityView("local-only");
  const catalog = mcpCatalogCopy(props.item);
  const refreshCatalog = reactExports.useCallback(async () => {
    const controller = new AbortController();
    catalogController.current = controller;
    setCatalogBusy(true);
    setCatalogError(null);
    try {
      await refreshMcpInventory(props.item.cli_id, controller.signal);
      if (!controller.signal.aborted) await props.onRefresh();
    } catch (caught) {
      if (!controller.signal.aborted) setCatalogError(caught instanceof Error ? caught.message : "Guard could not refresh this connector. Try again.");
    } finally {
      setCatalogBusy(false);
      if (catalogController.current === controller) catalogController.current = null;
    }
  }, [props.item.cli_id, props.onRefresh]);
  const clearPending = reactExports.useCallback(() => {
    if (!busy) setPending(null);
  }, [busy]);
  const confirmChange = reactExports.useCallback(async (credentials) => {
    if (pending === null) return;
    setBusy(true);
    setError(null);
    try {
      const payload = {
        cli_id: props.item.cli_id,
        identity_hash: props.item.identity_hash,
        name: props.item.name,
        kind: props.item.kind,
        example_label: props.item.example_label,
        interpreter_name: props.item.interpreter_name,
        state: pending,
        previous_revision: props.revision,
        session_nonce: randomToken$2(),
        commands: commandStatesPayload(recommended ? prefillSuggestedStates(props.item) : commands),
        ...pending !== "unset" && Object.keys(providerDrafts).length > 0 ? { provider_actions: Object.values(providerDrafts) } : {},
        // Same endpoint and proof as any other change; the daemon re-checks the request belongs to this connector.
        ...recommended && pending === "allowed" && props.setupLink && setupMatch === "ready" ? { connector_group_request_id: props.setupLink.requestId } : {},
        ...credentials
      };
      await previewLocalCliMutation(payload);
      const outcome = connectorGroupOutcome(await applyLocalCliMutation(payload));
      setSetupOutcome(outcome ? connectorGroupOutcomeCopy(outcome) : null);
      setProviderDrafts({});
      await props.onRefresh();
      await refreshApprovalGate();
      setPending(null);
    } catch (caught) {
      if (isFreshTotpRequired(caught)) {
        setFreshTotpRequired(true);
        await refreshApprovalGate().catch(() => void 0);
        setError(FRESH_TOTP_REQUIRED_MESSAGE);
      } else {
        setError(caught instanceof LocalCliApiError ? caught.message : "Guard could not update this custom extension.");
      }
    } finally {
      setBusy(false);
    }
  }, [commands, providerDrafts, pending, props, recommended, refreshApprovalGate, setupMatch]);
  reactExports.useEffect(() => {
    void resolveApprovalGate({ failClosed: true }).catch(() => {
      setError("Guard could not load the local approval settings yet.");
    });
  }, [resolveApprovalGate]);
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { "data-testid": "local-cli-detail", className: "w-full", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("button", { type: "button", onClick: props.onBack, className: "inline-flex min-h-11 items-center gap-2 rounded-lg px-1 text-sm font-semibold text-brand-dark/80 hover:text-brand-dark", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniArrowLeft, { className: "size-4", "aria-hidden": "true" }),
      "Extensions"
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("header", { className: "mt-4 border-b border-slate-200 pb-6", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("h1", { className: "text-2xl font-semibold tracking-tight text-brand-dark", children: customExtensionDisplayName(props.item) }),
      props.item.surface === "mcp" && props.item.source_label ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-2 text-sm text-slate-600", children: props.item.source_label }) : null,
      /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "mt-2 flex max-w-2xl flex-wrap items-center gap-x-2 gap-y-1 text-sm leading-6 text-slate-600", children: [
        props.item.surface !== "mcp" ? /* @__PURE__ */ jsxRuntimeExports.jsx("code", { className: "rounded-md bg-slate-100 px-1.5 py-0.5 font-mono text-xs font-semibold text-brand-dark", children: props.item.example_label }) : null,
        /* @__PURE__ */ jsxRuntimeExports.jsx("span", { children: customExtensionStateLabel(props.item) }),
        lastSeenCopy(props.item.last_seen_at) ? /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-xs text-slate-500", children: lastSeenCopy(props.item.last_seen_at) }) : null
      ] }),
      props.setupLink && setupMatch ? /* @__PURE__ */ jsxRuntimeExports.jsx(
        ConnectorSetupBanner,
        {
          name: customExtensionDisplayName(props.item),
          heldIdentityHash: props.setupLink.identityHash,
          currentIdentityHash: props.item.identity_hash,
          match: setupMatch,
          busy,
          outcome: setupOutcome,
          onSetUp: requestRecommended
        }
      ) : null,
      continuityCopy(props.item) ? /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-3 max-w-2xl rounded-xl border border-slate-200 bg-slate-50 p-3", "data-testid": "custom-extension-continuity", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm font-semibold text-brand-dark", children: continuityCopy(props.item)?.title }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1 text-sm leading-6 text-slate-600", children: continuityCopy(props.item)?.description })
      ] }) : null,
      props.item.surface === "mcp" || !(added || hasSuggestedRules(props.item)) ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-3 max-w-2xl text-sm leading-6 text-brand-dark/75", children: detailPolicyCopy(props.item.surface) }) : null,
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-5 flex flex-wrap gap-3", children: [
        added ? /* @__PURE__ */ jsxRuntimeExports.jsxs(jsxRuntimeExports.Fragment, { children: [
          props.item.state === "allowed" ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "inline-flex min-h-11 items-center rounded-xl bg-slate-100 px-4 text-sm font-semibold text-brand-dark", children: props.item.surface === "mcp" ? mcpPermissionStatusLabel(props.nativePublication, props.item.permission_scope) : "Allowed on this device" }) : /* @__PURE__ */ jsxRuntimeExports.jsx("button", { type: "button", className: "min-h-11 rounded-xl bg-brand-blue px-4 text-sm font-semibold text-white", onClick: requestAllow, children: props.item.surface === "mcp" ? "Enable tool permissions" : "Allow this extension's commands" }),
          props.item.state === "blocked" ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "inline-flex min-h-11 items-center rounded-xl bg-slate-100 px-4 text-sm font-semibold text-brand-dark", children: "Blocked" }) : /* @__PURE__ */ jsxRuntimeExports.jsx("button", { type: "button", className: "min-h-11 rounded-xl border border-slate-300 px-4 text-sm font-semibold text-brand-dark", onClick: requestBlock, children: "Block this extension" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("button", { type: "button", className: "min-h-11 rounded-xl px-4 text-sm font-semibold text-brand-dark/70 hover:text-brand-dark", onClick: requestRemove, children: "Remove custom extension" })
        ] }) : /* @__PURE__ */ jsxRuntimeExports.jsx(jsxRuntimeExports.Fragment, { children: /* @__PURE__ */ jsxRuntimeExports.jsx("button", { type: "button", className: "min-h-11 rounded-xl bg-brand-blue px-4 text-sm font-semibold text-white", onClick: requestAdd, children: "Add custom extension" }) }),
        canForgetLocalCli(props.item) && /* @__PURE__ */ jsxRuntimeExports.jsx(
          ForgetLocalCliButton,
          {
            item: props.item,
            disabled: busy,
            onForgotten: async () => {
              props.onBack();
              await props.onRefresh();
            }
          }
        )
      ] })
    ] }),
    props.item.surface === "cli" && props.item.state === "allowed" ? /* @__PURE__ */ jsxRuntimeExports.jsx(LocalCliCapabilities, { item: props.item, revision: props.revision, onRefresh: props.onRefresh }) : null,
    props.item.surface === "mcp" && added ? /* @__PURE__ */ jsxRuntimeExports.jsxs("section", { className: "mt-5 rounded-xl border border-slate-200 p-4", "aria-labelledby": "mcp-publication-heading", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("h2", { id: "mcp-publication-heading", className: "text-sm font-semibold text-brand-dark", children: props.item.permission_scope === "configured-connection" ? "Policy status" : "Enforcement status" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { role: "status", className: "mt-2 text-sm leading-6 text-brand-dark/75", children: nativePublicationMessage(props.nativePublication, props.item.permission_scope) }),
      props.nativePublication?.state !== "acknowledged" ? /* @__PURE__ */ jsxRuntimeExports.jsx(
        "button",
        {
          type: "button",
          className: "mt-3 min-h-11 rounded-xl border border-slate-300 px-4 text-sm font-semibold text-brand-dark",
          disabled: busy || catalogBusy,
          onClick: () => void props.onRefresh(),
          children: "Check enforcement status"
        }
      ) : null
    ] }) : null,
    catalog ? /* @__PURE__ */ jsxRuntimeExports.jsxs("section", { className: "mt-6 border-b border-slate-200 pb-5", "aria-labelledby": "mcp-inventory-heading", "aria-busy": catalogBusy, children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("h2", { id: "mcp-inventory-heading", className: "text-sm font-semibold text-brand-dark", children: catalog.title }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-2 max-w-2xl text-sm leading-6 text-brand-dark/75", children: catalog.description }),
      props.item.remote_origin && !catalogBusy ? null : /* @__PURE__ */ jsxRuntimeExports.jsxs(jsxRuntimeExports.Fragment, { children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-2 text-xs leading-5 text-brand-dark/75", children: "Refresh starts this connection’s configured server to list tools. It does not grant execution permission." }),
        /* @__PURE__ */ jsxRuntimeExports.jsx(
          "button",
          {
            type: "button",
            onClick: refreshCatalog,
            disabled: busy || catalogBusy || pending !== null,
            className: "mt-3 inline-flex min-h-11 items-center rounded-xl border border-slate-300 px-4 text-sm font-semibold text-brand-dark disabled:cursor-wait disabled:opacity-50",
            children: catalogBusy ? "Refreshing inventory…" : "Refresh inventory"
          }
        ),
        catalogBusy ? /* @__PURE__ */ jsxRuntimeExports.jsx(
          "button",
          {
            type: "button",
            onClick: () => catalogController.current?.abort(),
            className: "ml-3 min-h-11 rounded-xl border border-slate-300 px-4 text-sm font-semibold text-brand-dark",
            children: "Cancel refresh"
          }
        ) : null
      ] }),
      catalogError ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { role: "alert", className: "mt-3 max-w-2xl text-sm leading-6 text-red-700", children: catalogError }) : null,
      props.item.mcp_catalog ? /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "mt-2 text-xs leading-5 text-brand-dark/75", children: [
        "Last discovery attempt: ",
        /* @__PURE__ */ jsxRuntimeExports.jsx("time", { dateTime: props.item.mcp_catalog.updated_at, children: new Date(props.item.mcp_catalog.updated_at).toLocaleString() })
      ] }) : null,
      props.item.mcp_catalog?.changes && Object.values(props.item.mcp_catalog.changes).some((names) => names.length > 0) ? /* @__PURE__ */ jsxRuntimeExports.jsxs("details", { className: "mt-3 text-sm text-brand-dark/75", open: true, children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("summary", { className: "min-h-11 cursor-pointer py-3 font-semibold", children: "Changes from the last inventory" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "max-w-2xl leading-6", children: "New and changed tools need review. Removed tools lose Allow; their Deny choices remain. Stale tools have not been confirmed by this discovery attempt." }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("dl", { className: "mt-3 grid gap-3 sm:grid-cols-2", children: [
          ["added", "New tools"],
          ["changed", "Changed authority"],
          ["removed", "Removed tools"],
          ["stale", "Not confirmed"]
        ].map(([key, label]) => {
          const names = props.item.mcp_catalog?.changes?.[key] ?? [];
          return names.length > 0 ? /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
            /* @__PURE__ */ jsxRuntimeExports.jsxs("dt", { className: "font-semibold", children: [
              label,
              " · ",
              names.length
            ] }),
            /* @__PURE__ */ jsxRuntimeExports.jsxs("dd", { className: "mt-1 break-words leading-6", children: [
              names.slice(0, 10).join(", "),
              names.length > 10 ? ` and ${names.length - 10} more` : ""
            ] })
          ] }, key) : null;
        }) })
      ] }) : null,
      /* @__PURE__ */ jsxRuntimeExports.jsxs("details", { className: "mt-3 text-sm text-brand-dark/75", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("summary", { className: "min-h-11 cursor-pointer py-3 font-semibold", children: "Connection details" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "break-all font-mono text-xs leading-6", children: props.item.example_label }),
        props.item.remote_origin ? /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "mt-2 break-all", children: [
          "Last seen remote origin: ",
          /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "font-mono text-xs", children: props.item.remote_origin })
        ] }) : null,
        /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "mt-2", children: [
          "Protocol: ",
          props.item.mcp_catalog?.protocol_version ?? "Not verified"
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "mt-2", children: [
          "Permission scope: ",
          props.item.permission_scope === "configured-connection" ? "This configured host connection. Provider account and native host-hook binding are not verified." : props.item.permission_scope === "host-namespace" ? "This connector namespace in its host. Account changes cannot currently be verified." : props.item.permission_scope === "legacy-device" ? "This server identity across this device. This is a legacy setting." : "Not verified. Prefer Ask while the connection is unresolved."
        ] })
      ] })
    ] }) : null,
    props.item.mcp_catalog?.skills_catalog?.declared ? /* @__PURE__ */ jsxRuntimeExports.jsx(
      McpDeclaredSkills,
      {
        cliId: props.item.cli_id,
        identityHash: props.item.identity_hash,
        revision: props.item.mcp_catalog.revision,
        knownCount: props.item.mcp_catalog.skills_catalog.known_count,
        complete: props.item.mcp_catalog.skills_catalog.complete
      }
    ) : null,
    props.item.provider_catalog ? /* @__PURE__ */ jsxRuntimeExports.jsxs(jsxRuntimeExports.Fragment, { children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(
        McpProviderActions,
        {
          cliId: props.item.cli_id,
          knownCount: props.item.provider_catalog.known_count,
          disabled: busy,
          authorityRevision: props.revision,
          drafts: providerDrafts,
          onChange: (action, state) => {
            if (!(action.tool_slug in providerDrafts) && Object.keys(providerDrafts).length >= 100) {
              setError("Review and save these 100 action changes before changing more.");
              return;
            }
            setProviderDrafts((current) => ({
              ...current,
              [action.tool_slug]: { tool_slug: action.tool_slug, state, revision: action.revision }
            }));
          }
        },
        props.item.cli_id + props.item.identity_hash
      ),
      /* @__PURE__ */ jsxRuntimeExports.jsx(
        ProviderWorkflows,
        {
          cliId: props.item.cli_id
        },
        `workflow-${props.item.cli_id}-${props.item.identity_hash}`
      ),
      Object.keys(providerDrafts).length > 0 ? /* @__PURE__ */ jsxRuntimeExports.jsxs(
        "button",
        {
          type: "button",
          disabled: busy,
          className: "mt-4 min-h-11 rounded-xl bg-brand-blue px-4 text-sm font-semibold text-white",
          onClick: requestSaveCommands,
          children: [
            "Review ",
            Object.keys(providerDrafts).length,
            " action changes"
          ]
        }
      ) : null
    ] }) : null,
    added || hasSuggestedRules(props.item) ? /* @__PURE__ */ jsxRuntimeExports.jsxs("section", { className: "mt-8", "aria-labelledby": "custom-extension-commands-heading", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("h2", { id: "custom-extension-commands-heading", className: "text-lg font-semibold text-brand-dark", children: detailCatalogHeading(props.item.surface) }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1 max-w-2xl text-sm leading-6 text-slate-500", children: detailCatalogHelper(props.item.surface) }),
      commandsDirty && hasSuggestedRules(props.item) && !added ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { role: "note", className: "mt-2 max-w-2xl text-sm leading-6 text-brand-dark/75", children: SUGGESTED_RULES_NOTICE }) : null,
      /* @__PURE__ */ jsxRuntimeExports.jsx(
        CustomExtensionCommandBrowser,
        {
          commands,
          savedCommands: props.item.commands,
          surface: props.item.surface,
          disabled: busy,
          bulkEligible,
          bulkGroupLabel: bulkCopy.groupLabel,
          bulkMixedCopy: bulkCopy.mixedCopy,
          onChange: handleCommandState,
          onBulkChange: applyBulk
        },
        props.item.cli_id
      ),
      props.item.surface === "mcp" && bulkTargetCount > 0 ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-2 text-xs leading-5 text-brand-dark/75", children: "Bulk choices apply to listed tools with direct permissions. Execution wrappers and unlisted tools keep their separate review settings." }) : null,
      commandsDirty ? /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "guard-review-bar", "data-testid": "custom-extension-review-bar", children: /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "text-sm text-brand-dark", children: [
          commandChanges.length,
          " unsaved ",
          props.item.surface === "mcp" ? "tool" : "command",
          " ",
          commandChanges.length === 1 ? "change" : "changes",
          "."
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap gap-2", children: [
          added ? /* @__PURE__ */ jsxRuntimeExports.jsx(
            "button",
            {
              type: "button",
              disabled: busy,
              onClick: resetCommands,
              className: "min-h-11 rounded-xl border border-slate-300 px-4 text-sm font-semibold text-brand-dark",
              children: "Reset changes"
            }
          ) : null,
          /* @__PURE__ */ jsxRuntimeExports.jsxs("button", { type: "button", disabled: busy, className: "min-h-11 rounded-xl bg-brand-blue px-4 text-sm font-semibold text-white", onClick: requestSaveCommands, children: [
            "Review ",
            commandChanges.length,
            " ",
            props.item.surface === "mcp" ? "tool" : "command",
            " changes"
          ] })
        ] })
      ] }) }) : null
    ] }) : null,
    /* @__PURE__ */ jsxRuntimeExports.jsxs("section", { className: "mt-10 max-w-2xl border-t border-slate-200 pt-5", "aria-labelledby": "custom-extension-continuity-heading", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("h2", { id: "custom-extension-continuity-heading", className: "text-sm font-semibold text-brand-dark", children: continuity.title }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1 text-sm leading-6 text-brand-dark/75", children: props.continuity.summary || continuity.description }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1 text-xs leading-5 text-brand-dark/60", children: continuity.privacyDisclosure })
    ] }),
    error && !pending ? /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-4", children: /* @__PURE__ */ jsxRuntimeExports.jsx(InlineError, { message: error }) }) : null,
    pending ? /* @__PURE__ */ jsxRuntimeExports.jsx(
      CustomExtensionReviewModal,
      {
        item: props.item,
        nextState: pending,
        commandChanges: pending === "unset" ? [] : commandChanges,
        providerUpdates: pending === "unset" ? [] : Object.values(providerDrafts),
        busy,
        error,
        approvalGate: resolvedApprovalGate,
        requireFreshTotp: freshTotpRequired,
        onCancel: clearPending,
        onConfirm: confirmChange
      }
    ) : null
  ] });
}
function effectiveStatusKey(effective, options = {}) {
  const managed = effective.managed_controls;
  const approvalGate = options.approvalGate;
  return JSON.stringify({
    schema_version: effective.schema_version,
    health: effective.health,
    revision: effective.revision,
    catalog_digest: effective.catalog_digest,
    global_lockdown: effective.global_lockdown,
    cloud_policy_sync_error: options.runtime?.cloud_policy_sync_error ?? null,
    approval_gate: approvalGate ? {
      configured: approvalGate.configured,
      enabled: approvalGate.enabled,
      fail_closed: approvalGate.fail_closed,
      strict_all_decisions: approvalGate.strict_all_decisions,
      totp_enabled: approvalGate.totp_enabled ?? false,
      totp_pending: approvalGate.totp_pending ?? false
    } : null,
    failure_codes: effective.failures.map((failure) => `${failure.layer_kind ?? ""}:${failure.code}`).sort(),
    managed_controls: managed ? {
      control_set_id: managed.control_set_id,
      control_set_name: managed.control_set_name,
      bundle_version: managed.bundle_version,
      workspace_id: managed.workspace_id,
      authority_mode: managed.authority_mode,
      catalog_digest: managed.catalog_digest,
      acknowledgement: {
        extension_authority_revision: managed.acknowledgement.extension_authority_revision,
        policy_revision: managed.acknowledgement.policy_revision,
        effective_projection_digest: managed.acknowledgement.effective_projection_digest,
        status: managed.acknowledgement.status
      }
    } : null
  });
}
function safeCloudSignInHref(value) {
  if (!value) return null;
  try {
    const url = new URL(value);
    return url.protocol === "https:" || url.protocol === "http:" ? url.toString() : null;
  } catch {
    return null;
  }
}
function ManagedControlsPrimaryAction(props) {
  if (!props.action) return null;
  if (props.action.href) {
    return /* @__PURE__ */ jsxRuntimeExports.jsxs("a", { href: props.action.href, target: "_blank", rel: "noopener noreferrer", className: "inline-flex min-h-11 items-center gap-2 rounded-xl bg-brand-blue px-4 text-sm font-semibold text-white", children: [
      props.action.label,
      /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniArrowTopRightOnSquare, { className: "size-4", "aria-hidden": "true" })
    ] });
  }
  if (props.action.action === "refresh") {
    return /* @__PURE__ */ jsxRuntimeExports.jsx(
      "button",
      {
        type: "button",
        onClick: props.onRefresh,
        disabled: props.checking,
        "aria-busy": props.checking,
        className: "min-h-11 rounded-xl bg-brand-blue px-4 text-sm font-semibold text-white disabled:opacity-60",
        children: props.checking ? "Checking…" : props.action.label
      }
    );
  }
  if (props.action.action === "connect-cloud") {
    if (props.connectHref) {
      return /* @__PURE__ */ jsxRuntimeExports.jsxs("a", { href: props.connectHref, className: "inline-flex min-h-11 items-center gap-2 rounded-xl border border-slate-300 px-4 text-sm font-semibold text-brand-dark", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniCloud, { className: "size-4", "aria-hidden": "true" }),
        "Open Guard Cloud sign-in"
      ] });
    }
    return /* @__PURE__ */ jsxRuntimeExports.jsxs("button", { type: "button", onClick: props.onConnect, disabled: props.connecting, className: "inline-flex min-h-11 items-center gap-2 rounded-xl border border-slate-300 px-4 text-sm font-semibold text-brand-dark disabled:opacity-50", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniCloud, { className: "size-4", "aria-hidden": "true" }),
      props.connecting ? "Starting sign-in..." : props.action.label
    ] });
  }
  return null;
}
function extensionPermissionIds(effective, extension) {
  const ids = new Set(
    (effective.projection?.permissions ?? []).filter((item) => item.extension_id === extension.extension_id).map((item) => item.permission_id)
  );
  if ("permissions" in extension) for (const permission of extension.permissions) ids.add(permission.permission_id);
  return ids;
}
function layerTargetsExtension(effective, extension, permissionIds, kind) {
  return effective.layers.some(
    (layer) => layer.kind === kind && layer.controls.some(
      (control) => control.target_kind === "extension" && control.target_id === extension.extension_id || control.target_kind === "permission" && permissionIds.has(control.target_id)
    )
  );
}
function managedSource(effective) {
  const managed = effective.managed_controls;
  return managed?.authority_mode === "managed-restrictive" ? `Managed by ${managed.workspace_id}` : "Synced from Guard Cloud";
}
function extensionProtectionAuthority(effective, extension) {
  if (effective.global_lockdown) {
    return { effectiveState: "lockdown", source: "Emergency Lockdown", sources: ["Emergency Lockdown"] };
  }
  const permissionIds = extensionPermissionIds(effective, extension);
  const extensionProjection = effective.projection?.extensions.find(
    (item) => item.extension_id === extension.extension_id
  );
  const permissionProjections = effective.projection?.permissions.filter(
    (item) => item.extension_id === extension.extension_id || permissionIds.has(item.permission_id)
  ) ?? [];
  const projections = extensionProjection ? [extensionProjection, ...permissionProjections] : permissionProjections;
  const managed = managedSource(effective);
  const hasManaged = projections.some((item) => item.managed_state !== "inherited") || layerTargetsExtension(effective, extension, permissionIds, "signed-cloud");
  const hasLocal = projections.some((item) => item.local_state !== "inherited") || layerTargetsExtension(effective, extension, permissionIds, "local-admin");
  const sources = [];
  if (hasManaged) sources.push(managed);
  if (hasLocal) sources.push("Set on this device");
  if (sources.length === 0) sources.push(extension.required ? "Required by Guard" : "Recommended by Guard");
  const managedBlocks = projections.some(
    (item) => item.effective_state === "blocked" && item.managed_state === "disabled"
  ) || effective.layers.some((layer) => layer.kind === "signed-cloud" && layer.controls.some(
    (control) => control.state === "disabled" && (control.target_kind === "extension" && control.target_id === extension.extension_id || control.target_kind === "permission" && permissionIds.has(control.target_id))
  ));
  const localBlocks = projections.some(
    (item) => item.effective_state === "blocked" && item.local_state === "disabled"
  ) || effective.layers.some((layer) => layer.kind === "local-admin" && layer.controls.some(
    (control) => control.state === "disabled" && (control.target_kind === "extension" && control.target_id === extension.extension_id || control.target_kind === "permission" && permissionIds.has(control.target_id))
  ));
  const extensionBlocked = extensionProjection?.effective_state === "blocked" || extensionEffectiveState(effective, extension) === "disabled";
  const permissionStates = "permissions" in extension ? extension.permissions.map((permission) => permissionEffectiveState(effective, extension, permission)) : permissionProjections.map((item) => item.effective_state === "allowed" ? "enabled" : "disabled");
  const blockedPermissionCount = permissionStates.filter((state) => state === "disabled").length;
  let effectiveState;
  if (extensionBlocked) effectiveState = "blocked";
  else if (blockedPermissionCount > 0 && blockedPermissionCount < permissionStates.length) effectiveState = "partial";
  else if (blockedPermissionCount > 0 || localBlocks || managedBlocks) effectiveState = "blocked";
  else if (extension.required) effectiveState = "required";
  else effectiveState = extensionEffectiveState(effective, extension) === "enabled" ? "allowed" : "blocked";
  let source = sources.at(-1) ?? "Recommended by Guard";
  if (localBlocks) source = "Set on this device";
  if (managedBlocks) source = managed;
  return { effectiveState, source, sources };
}
function extensionProtectionSource(effective, extension) {
  return extensionProtectionAuthority(effective, extension).source;
}
function cloudBase(runtime) {
  const candidate = runtime?.dashboard_url?.trim() || runtime?.connect_url?.trim();
  return candidate || void 0;
}
function recoveryNotice(recovery) {
  if (recovery === "unsupported-version") {
    return "This Control Set uses a newer control schema. Update Guard before applying it; the last verified authority remains in force.";
  }
  if (recovery === "catalog-mismatch") {
    return "The Control Set and local Extension catalog do not match. Guard keeps the last verified authority fail-safe until compatibility is restored.";
  }
  if (recovery === "degraded") {
    return "Local control authority needs recovery. Guard keeps the last verified authority fail-safe while you refresh or repair it.";
  }
  return "Guard Cloud data is stale. Local protection continues with the last verified authority; check again to see whether a newer Control Set is available.";
}
function extensionLocalProtectionInput(extension, effective, runtime) {
  const managed = effective.managed_controls;
  const authority = extensionProtectionAuthority(effective, extension);
  const failureCodes = new Set(effective.failures.map((failure) => failure.code.toLowerCase()));
  let recovery;
  if (failureCodes.has("unsupported-control-schema")) recovery = "unsupported-version";
  else if (failureCodes.has("catalog-digest-mismatch") || failureCodes.has("catalog-unavailable")) recovery = "catalog-mismatch";
  else if (runtime?.cloud_policy_sync_error || [...failureCodes].some((code) => code.includes("stale"))) recovery = "stale";
  else if (effective.health !== "protected") recovery = "degraded";
  return {
    extensionName: extension.name,
    extensionId: extension.extension_id,
    effectiveState: authority.effectiveState,
    source: authority.source,
    sources: authority.sources,
    catalogDigest: effective.catalog_digest,
    recovery,
    cloudControlsUrl: cloudBase(runtime),
    controlSetName: managed?.control_set_name ?? managed?.control_set_id,
    controlSetVersion: managed?.bundle_version,
    workspace: managed?.workspace_id,
    authorityMode: managed?.authority_mode,
    acknowledgementRevision: managed?.acknowledgement.extension_authority_revision,
    acknowledgementStatus: managed?.acknowledgement.status,
    lastAcknowledgedAt: runtime?.cloud_policy_last_ack_at ?? void 0,
    effectiveProjectionDigest: managed?.acknowledgement.effective_projection_digest
  };
}
function ExtensionManagedControlsPanel(props) {
  const [connecting, setConnecting] = reactExports.useState(false);
  const [connectHref, setConnectHref] = reactExports.useState(null);
  const [connectMessage, setConnectMessage] = reactExports.useState(null);
  const [refreshState, setRefreshState] = reactExports.useState("idle");
  const [refreshError, setRefreshError] = reactExports.useState(null);
  const refreshBaselineRef = reactExports.useRef(null);
  const input = extensionLocalProtectionInput(props.extension, props.effective, props.runtime);
  const view = buildLocalProtectionView(input);
  const connected = props.runtime?.cloud_state === "paired_active" || props.runtime?.cloud_state === "paired_waiting";
  const hasManagedControl = layerTargetsExtension(props.effective, props.extension, extensionPermissionIds(props.effective, props.extension), "signed-cloud");
  const refresh = reactExports.useCallback(async () => {
    if (refreshState === "checking") return;
    refreshBaselineRef.current = effectiveStatusKey(props.effective, { runtime: props.runtime });
    setRefreshState("checking");
    setRefreshError(null);
    try {
      await props.onRefresh();
      setRefreshState("complete");
    } catch {
      setRefreshState("error");
      setRefreshError("Guard could not refresh this status. The last verified local authority remains in force; try again.");
    }
  }, [props.effective, props.onRefresh, props.runtime, refreshState]);
  const connect = reactExports.useCallback(() => {
    setConnecting(true);
    setConnectMessage(null);
    void startGuardCloudConnect().then((status) => {
      if (!status.connect_required) {
        setConnectMessage("Guard Cloud is connected.");
        return;
      }
      const href = safeCloudSignInHref(status.connect_flow?.authorize_url) ?? safeCloudSignInHref(status.connect_flow?.connect_url);
      setConnectHref(href);
      setConnectMessage(href ? "Complete sign-in to resume synced Control Sets." : "Guard could not start sign-in. Try again.");
    }).catch((error) => {
      setConnectMessage(error instanceof Error ? error.message : "Guard could not start sign-in. Try again.");
    }).finally(() => setConnecting(false));
  }, []);
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("section", { "aria-labelledby": "managed-controls-heading", className: "space-y-4", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "rounded-3xl border border-slate-200 bg-white p-5 shadow-sm", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs font-bold uppercase tracking-[0.18em] text-brand-blue", children: "Source and authority" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("h2", { id: "managed-controls-heading", className: "mt-1 text-lg font-semibold text-brand-dark", children: hasManagedControl ? "Active managed control" : "No Control Set targets this Extension" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-2 max-w-2xl text-sm leading-6 text-brand-dark/75", children: view.summary })
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "inline-flex self-start rounded-full border border-slate-200 bg-slate-50 px-3 py-1 text-xs font-semibold text-brand-dark", children: view.source })
      ] }),
      view.status === "needs-attention" || view.status === "unsupported" ? /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { role: "alert", className: "mt-4 flex gap-2 rounded-xl border border-amber-200 bg-amber-50 p-3 text-sm text-amber-950", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniExclamationTriangle, { className: "mt-0.5 size-4 shrink-0" }),
        recoveryNotice(input.recovery)
      ] }) : null,
      /* @__PURE__ */ jsxRuntimeExports.jsx("dl", { className: "mt-5 grid gap-4 sm:grid-cols-2 lg:grid-cols-3", children: view.technicalDetails.map((detail) => /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("dt", { className: "text-xs font-semibold uppercase tracking-wide text-brand-dark/55", children: detail.label }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("dd", { className: "mt-1 break-all text-sm text-brand-dark", children: detail.value })
      ] }, detail.label)) }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-5 flex flex-wrap gap-2", children: /* @__PURE__ */ jsxRuntimeExports.jsx(
        ManagedControlsPrimaryAction,
        {
          action: view.primaryAction,
          connecting,
          checking: refreshState === "checking",
          connectHref,
          onConnect: connect,
          onRefresh: refresh
        }
      ) }),
      connectMessage ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { role: "status", className: "mt-3 text-sm text-brand-dark/75", children: connectMessage }) : null,
      refreshState === "checking" ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { role: "status", "aria-live": "polite", className: "mt-3 text-sm text-brand-dark/75", children: "Checking current protection status…" }) : null,
      refreshState === "complete" ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { role: "status", "aria-live": "polite", className: "mt-3 text-sm text-brand-dark/75", children: effectiveStatusKey(props.effective, { runtime: props.runtime }) === refreshBaselineRef.current ? "Check complete. No change detected; the current verified authority is still in use." : "Check complete. Protection status updated." }) : null,
      refreshState === "error" && refreshError ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { role: "alert", className: "mt-3 text-sm text-rose-800", children: refreshError }) : null
    ] }),
    !connected ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "rounded-2xl border border-slate-200 bg-slate-50 p-4 text-sm leading-6 text-brand-dark/75", children: "Guard Cloud is disconnected. Local protection and local tightening remain available on this device; cross-device Control Sets resume after reconnecting." }) : null,
    hasManagedControl && input.authorityMode === "managed-restrictive" ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "rounded-2xl border border-indigo-200 bg-indigo-50 p-4 text-sm leading-6 text-indigo-950", children: "This is a managed-restrictive Control Set. Local settings can add stricter blocks, but they cannot weaken this workspace restriction." }) : null
  ] });
}
function receiptMatchesExtension(receipt, extension) {
  const identities = /* @__PURE__ */ new Set([
    extension.extension_id,
    ...extension.permissions.map((permission) => permission.permission_id),
    ...extension.rules.map((rule) => rule.rule_id)
  ]);
  if (identities.has(receipt.artifact_id)) return true;
  if (receipt.changed_capabilities.some((capability) => identities.has(capability))) return true;
  const envelope = receipt.action_envelope_json;
  if (!envelope) return false;
  if (envelope.command_category === extension.extension_id) return true;
  const toolName = envelope.tool_name?.trim().toLowerCase();
  return Boolean(toolName && extension.executables.some((executable) => executable.toLowerCase() === toolName));
}
function recentExtensionReceipts(receipts, extension, limit = 8) {
  return receipts.filter((receipt) => receiptMatchesExtension(receipt, extension)).sort((left, right) => Date.parse(right.timestamp) - Date.parse(left.timestamp)).slice(0, limit);
}
function receiptDecisionLabel(receipt) {
  if (receipt.policy_decision === "allow") return "Allowed";
  if (receipt.policy_decision === "block") return "Blocked";
  return "Reviewed";
}
function ExtensionActivity(props) {
  const receipts = recentExtensionReceipts(props.receipts, props.extension);
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("article", { className: "rounded-3xl border border-slate-200 bg-white p-5 shadow-sm", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx("h2", { className: "text-lg font-semibold text-brand-dark", children: "Recent Extension decisions" }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-2 text-sm leading-6 text-brand-dark/75", children: "Receipt-backed decisions mapped to this canonical Extension. Guard does not synthesize activity." }),
    receipts.length ? /* @__PURE__ */ jsxRuntimeExports.jsx("ul", { className: "mt-4 divide-y divide-slate-100", "aria-label": "Recent Extension receipts", children: receipts.map((receipt) => /* @__PURE__ */ jsxRuntimeExports.jsxs("li", { className: "flex flex-col gap-2 py-3 sm:flex-row sm:items-center sm:justify-between", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "text-sm font-semibold text-brand-dark", children: [
          receiptDecisionLabel(receipt),
          " · ",
          receipt.harness
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "mt-1 text-xs text-brand-dark/60", children: [
          receipt.capabilities_summary,
          " · ",
          new Date(receipt.timestamp).toLocaleString()
        ] })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("a", { href: `/evidence?view=actions&selected=${encodeURIComponent(receipt.receipt_id)}&search=${encodeURIComponent(receipt.receipt_id)}`, className: "inline-flex min-h-11 items-center gap-2 text-sm font-semibold text-brand-blue hover:underline", children: [
        "Open receipt ",
        /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniArrowTopRightOnSquare, { className: "size-4", "aria-hidden": "true" })
      ] })
    ] }, receipt.receipt_id)) }) : /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-4 rounded-2xl bg-slate-50 p-4 text-sm text-brand-dark/70", children: "No matching receipts are available on this device yet." }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("a", { href: `/evidence?view=actions&search=${encodeURIComponent(props.extension.extension_id)}`, className: "mt-4 inline-flex min-h-11 items-center gap-2 rounded-xl border border-slate-300 px-4 text-sm font-semibold text-brand-dark", children: [
      "View matching Evidence ",
      /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniArrowTopRightOnSquare, { className: "size-4", "aria-hidden": "true" })
    ] })
  ] });
}
function toolStateLabel(state) {
  if (state === "allow") return "Allow";
  if (state === "review") return "Review";
  if (state === "block") return "Block";
  return "Recommended";
}
function McpServerDefaults({ extension }) {
  if (extension.surface !== "mcp") return null;
  const launch = extension.mcp_launch;
  const tools = extension.mcp_tools ?? [];
  const remoteLaunch = launch?.kind === "remote-http" ? launch : null;
  const packageLaunch = launch?.kind === "package-launcher" ? launch : null;
  const directLaunch = launch?.kind === "direct-command" ? launch : null;
  const unsupportedLaunch = launch?.kind === "unsupported";
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("article", { className: "rounded-3xl border border-slate-200 bg-white p-5 shadow-sm lg:col-span-2", "data-testid": "mcp-server-defaults", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx("h2", { className: "text-lg font-semibold text-brand-dark", children: "MCP server defaults" }),
    unsupportedLaunch ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-2 text-sm leading-6 text-brand-dark/75", "data-testid": "mcp-launch-unsupported", children: "This server uses a launch type this version of Guard does not recognize, so its launch details are unavailable. Update Guard to see them." }) : /* @__PURE__ */ jsxRuntimeExports.jsxs(jsxRuntimeExports.Fragment, { children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-2 text-sm leading-6 text-brand-dark/75", children: remoteLaunch ? "Matching hosted endpoints use these defaults after you turn the server on. A custom extension on this device still wins." : directLaunch ? "Matching launches use this command. Defaults apply only after you turn the server on. A custom extension on this device still wins." : "Matching launches use this package name. Defaults apply only after you turn the server on. A custom extension on this device still wins." }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("dl", { className: "mt-5 grid gap-4 sm:grid-cols-2", children: remoteLaunch ? /* @__PURE__ */ jsxRuntimeExports.jsxs(jsxRuntimeExports.Fragment, { children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("dt", { className: "text-xs font-semibold uppercase text-brand-dark/55", children: "Endpoint" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("dd", { className: "mt-1 break-all font-mono text-sm text-brand-dark", children: remoteLaunch.url })
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("dt", { className: "text-xs font-semibold uppercase text-brand-dark/55", children: "Server names" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("dd", { className: "mt-1 text-sm text-brand-dark", children: remoteLaunch.serverNames.join(", ") })
        ] })
      ] }) : directLaunch ? /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("dt", { className: "text-xs font-semibold uppercase text-brand-dark/55", children: "Launcher" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("dd", { className: "mt-1 break-all font-mono text-sm text-brand-dark", children: directLaunch.command })
      ] }) : /* @__PURE__ */ jsxRuntimeExports.jsxs(jsxRuntimeExports.Fragment, { children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("dt", { className: "text-xs font-semibold uppercase text-brand-dark/55", children: "Launcher" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("dd", { className: "mt-1 text-sm text-brand-dark", children: packageLaunch?.command ?? "Package launcher" })
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("dt", { className: "text-xs font-semibold uppercase text-brand-dark/55", children: "Package" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("dd", { className: "mt-1 break-all font-mono text-sm text-brand-dark", children: packageLaunch?.package ?? "Unknown package" })
        ] })
      ] }) })
    ] }),
    tools.length ? /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-5 overflow-x-auto", children: /* @__PURE__ */ jsxRuntimeExports.jsxs("table", { className: "min-w-full text-left text-sm", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("thead", { className: "text-xs uppercase tracking-wide text-brand-dark/55", children: /* @__PURE__ */ jsxRuntimeExports.jsxs("tr", { children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("th", { className: "pb-2 pr-4 font-semibold", children: "Tool" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("th", { className: "pb-2 font-semibold", children: "Default" })
      ] }) }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("tbody", { children: tools.map((tool) => /* @__PURE__ */ jsxRuntimeExports.jsxs("tr", { className: "border-t border-slate-100", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("td", { className: "py-2 pr-4 font-mono text-xs text-brand-dark", children: tool.name }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("td", { className: "py-2 text-sm text-brand-dark", children: toolStateLabel(tool.state) })
      ] }, tool.name)) })
    ] }) }) : null
  ] });
}
const DECISIONS = /* @__PURE__ */ new Set(["allowed", "ask-first", "blocked"]);
const MINIMUM_ACTIONS = /* @__PURE__ */ new Set(["allow", "monitor", "review", "block"]);
const SEVERITIES = /* @__PURE__ */ new Set(["low", "medium", "high", "critical"]);
function record$1(value) {
  if (typeof value !== "object" || value === null || Array.isArray(value)) throw new Error("Guard returned an invalid Test Lab response");
  return value;
}
function boundedString(value, field, limit = 512) {
  if (typeof value !== "string" || !value.trim() || value.length > limit) throw new Error(`Guard returned an invalid ${field}`);
  return value;
}
function stringList(value, field, limit) {
  if (!Array.isArray(value) || value.length > limit || !value.every((item) => typeof item === "string" && item.length <= 320)) {
    throw new Error(`Guard returned an invalid ${field}`);
  }
  return [...value];
}
function normalizeProtectionTestResult(value) {
  const raw = record$1(value);
  if (raw.schema_version !== "guard.daemon.extension-control-test.v1") throw new Error("Guard returned an unsupported Test Lab response");
  if (typeof raw.decision !== "string" || !DECISIONS.has(raw.decision)) throw new Error("Guard returned an invalid Test Lab decision");
  if (typeof raw.minimum_action !== "string" || !MINIMUM_ACTIONS.has(raw.minimum_action)) throw new Error("Guard returned an invalid Test Lab action");
  if (typeof raw.matched !== "boolean" || typeof raw.module_matched !== "boolean" || typeof raw.other_protection_matched !== "boolean") {
    throw new Error("Guard returned invalid Test Lab match state");
  }
  if (!Array.isArray(raw.matches) || raw.matches.length > 32) throw new Error("Guard returned too many Test Lab matches");
  const matches = raw.matches.map((item) => {
    const match = record$1(item);
    if (typeof match.severity !== "string" || !SEVERITIES.has(match.severity)) throw new Error("Guard returned an invalid Test Lab severity");
    return {
      extension_id: boundedString(match.extension_id, "extension ID", 256),
      extension_name: boundedString(match.extension_name, "extension name", 120),
      rule_id: boundedString(match.rule_id, "rule ID", 256),
      permission_id: typeof match.permission_id === "string" && match.permission_id.trim() ? match.permission_id : null,
      rule_title: boundedString(match.rule_title, "rule title", 160),
      description: boundedString(match.description, "rule description", 320),
      severity: match.severity,
      risk_classes: stringList(match.risk_classes, "risk classes", 16)
    };
  });
  if (typeof raw.revision !== "number" || !Number.isSafeInteger(raw.revision) || raw.revision < 0) throw new Error("Guard returned an invalid Test Lab revision");
  return {
    schema_version: "guard.daemon.extension-control-test.v1",
    decision: raw.decision,
    minimum_action: raw.minimum_action,
    matched: raw.matched,
    module_matched: raw.module_matched,
    other_protection_matched: raw.other_protection_matched,
    explanation: boundedString(raw.explanation, "Test Lab explanation", 320),
    matches,
    safer_alternatives: stringList(raw.safer_alternatives, "safer alternatives", 8),
    authority_health: boundedString(raw.authority_health, "authority health", 64),
    revision: raw.revision,
    catalog_digest: boundedString(raw.catalog_digest, "catalog digest", 128)
  };
}
async function testProtectionCommand(extensionId, command) {
  const response = await fetchExtensionControlApi("/v1/extension-controls/test", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ extension_id: extensionId, command })
  });
  let payload;
  try {
    payload = await response.json();
  } catch {
    throw new Error(`Guard returned invalid JSON (${response.status})`);
  }
  if (!response.ok) {
    const raw = typeof payload === "object" && payload !== null && !Array.isArray(payload) ? payload : {};
    throw new Error(typeof raw.error === "string" ? raw.error.replaceAll("_", " ") : `Test Lab request failed (${response.status})`);
  }
  return normalizeProtectionTestResult(payload);
}
function safeExamples(extension) {
  const executable = extension.executables[0];
  const examples = extension.extension_id === "command.git" ? ["git status", "git reset --hard HEAD~1", "git push --force-with-lease"] : executable ? [`${executable} --help`] : [];
  return examples.slice(0, 3);
}
function resultTitle(result) {
  if (result.decision === "blocked") return "Guard would block this";
  if (result.decision === "ask-first") return "Guard would ask first";
  return "Guard would allow this";
}
function ProtectionTestLab({ extension }) {
  const [command, setCommand] = reactExports.useState("");
  const [result, setResult] = reactExports.useState(null);
  const [busy, setBusy] = reactExports.useState(false);
  const [error, setError] = reactExports.useState(null);
  const examples = reactExports.useMemo(() => safeExamples(extension), [extension]);
  const run = async () => {
    const candidate = command.trim();
    if (!candidate || busy) return;
    setBusy(true);
    setError(null);
    setResult(null);
    try {
      setResult(await testProtectionCommand(extension.extension_id, candidate));
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Test Lab could not evaluate this command.");
    } finally {
      setBusy(false);
    }
  };
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("section", { "aria-labelledby": "protection-test-lab-heading", className: "mt-10 rounded-2xl border border-slate-200 bg-white p-5 sm:p-6", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap items-baseline justify-between gap-2", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("h2", { id: "protection-test-lab-heading", className: "text-lg font-semibold tracking-tight text-brand-dark", children: "Test Lab" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs text-slate-500", children: "Nothing is executed. The check runs locally and is not saved." })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "mt-1 text-sm text-slate-500", children: [
      "See how Guard would handle a ",
      extension.name,
      " command without running it."
    ] }),
    examples.length ? /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-4 flex flex-wrap gap-2", children: examples.map((example) => /* @__PURE__ */ jsxRuntimeExports.jsx("button", { type: "button", disabled: busy, onClick: () => {
      setCommand(example);
      setResult(null);
      setError(null);
    }, className: `${EXTENSION_CHIP_CLASS} disabled:cursor-not-allowed disabled:opacity-50`, children: example }, example)) }) : null,
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-3 flex flex-col gap-2 sm:flex-row", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(
        "input",
        {
          value: command,
          disabled: busy,
          onChange: (event) => {
            setCommand(event.target.value.slice(0, 4096));
            setResult(null);
            setError(null);
          },
          onKeyDown: (event) => {
            if (event.key === "Enter") {
              event.preventDefault();
              void run();
            }
          },
          maxLength: 4096,
          spellCheck: false,
          autoComplete: "off",
          "aria-label": "Command to check",
          placeholder: "Paste a command Guard stopped, like git reset --hard HEAD~1",
          className: "min-h-11 w-full flex-1 rounded-xl border border-slate-200 bg-white px-3 font-mono text-sm text-brand-dark placeholder:font-sans placeholder:text-slate-400 focus:border-brand-blue focus:outline-none focus:ring-2 focus:ring-blue-100"
        }
      ),
      /* @__PURE__ */ jsxRuntimeExports.jsx("button", { type: "button", onClick: () => {
        void run();
      }, disabled: busy || !command.trim(), className: "min-h-11 shrink-0 rounded-xl bg-brand-blue px-4 text-sm font-semibold text-white disabled:cursor-not-allowed disabled:opacity-50", children: busy ? "Checking…" : "Check safely" })
    ] }),
    error ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { role: "alert", className: "mt-4 rounded-xl border border-red-200 bg-red-50 p-3 text-sm text-red-800", children: error }) : null,
    result ? /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { role: "status", className: "mt-5 rounded-xl bg-slate-50 p-4", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap items-center gap-3", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(ProtectionDecisionBadge, { result: result.decision }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("strong", { className: "text-sm text-brand-dark", children: resultTitle(result) }),
        result.decision === "allowed" ? /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniCheckCircle, { className: "size-5 text-emerald-700", "aria-hidden": "true" }) : /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniExclamationTriangle, { className: "size-5 text-amber-700", "aria-hidden": "true" })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-3 text-sm leading-6 text-brand-dark/80", children: result.explanation }),
      result.matches.length ? /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-4", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs font-semibold uppercase tracking-[0.14em] text-slate-400", children: "Protection rules involved" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-3 space-y-2", children: result.matches.slice(0, 6).map((match) => /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "rounded-xl bg-white p-3", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap items-center justify-between gap-2", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("strong", { className: "text-sm text-brand-dark", children: match.rule_title }),
            /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { className: "text-xs font-semibold capitalize text-brand-dark/55", children: [
              match.severity,
              " risk"
            ] })
          ] }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1 text-xs leading-5 text-brand-dark/70", children: match.description })
        ] }, `${match.extension_id}:${match.rule_id}`)) })
      ] }) : null,
      result.safer_alternatives.length ? /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-4", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs font-semibold uppercase tracking-[0.14em] text-slate-400", children: "Safer alternatives" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("ul", { className: "mt-2 list-disc space-y-1 pl-5 text-sm text-brand-dark/80", children: result.safer_alternatives.map((alternative) => /* @__PURE__ */ jsxRuntimeExports.jsx("li", { children: alternative }, alternative)) })
      ] }) : null,
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-4 text-xs text-slate-500", children: "This result uses the current local protection state. It is a read-only evaluation and does not create an approval or receipt." })
    ] }) : null
  ] });
}
const DRAFT_EXIT_MESSAGE = "Discard your unreviewed protection setting changes?";
const DETAIL_TABS = [
  { id: "overview", label: "Overview" },
  { id: "permissions", label: "Permissions" },
  { id: "managed-controls", label: "Managed controls" },
  { id: "activity", label: "Activity" },
  { id: "technical", label: "Technical details" }
];
function canonicalProtectionDetailTab(tab) {
  if (tab === "commands" || tab === "policy") return "permissions";
  if (tab === "test-lab") return "activity";
  if (tab === "managed-controls" || tab === "permissions" || tab === "technical") return tab;
  return tab === "activity" ? "activity" : "overview";
}
function availabilityTitle(extension) {
  if (extension.surface === "mcp") return "MCP tools available";
  if (extension.surface === "unsupported") return "Protection available";
  return "Commands available";
}
function requiredLine(extension) {
  if (!extension.required) return null;
  return "Required by Guard — this protection stays on. The command patterns below can still follow recommended settings or be blocked on this device.";
}
function availabilityCopy(extension, enabled) {
  if (extension.surface === "unsupported") {
    return enabled ? "This protection follows the settings below. Update Guard to see what it covers." : "This protection is off on this device. Update Guard to see what it covers.";
  }
  if (extension.surface === "mcp" && extension.trust_class === "external") {
    if (enabled) {
      return "Matching MCP tools follow the protection settings below. Turn off to leave this community server inactive.";
    }
    return "This community MCP server stays off until you turn it on.";
  }
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
function protectionStateLabel(state) {
  return state.charAt(0).toUpperCase() + state.slice(1);
}
function DeveloperModuleDetails(props) {
  return /* @__PURE__ */ jsxRuntimeExports.jsx(TechnicalDetails, { title: "Developer details", testId: "protection-more-detail", children: /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "grid gap-5", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("section", { children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("h3", { className: "font-semibold text-brand-dark", children: "Canonical module" }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("dl", { className: "mt-3 grid gap-3 sm:grid-cols-2", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("dt", { className: "text-xs text-brand-dark/80", children: "Extension ID" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("dd", { children: /* @__PURE__ */ jsxRuntimeExports.jsx("code", { className: "break-all text-xs", children: props.extension.extension_id }) })
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("dt", { className: "text-xs text-brand-dark/80", children: "Version" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("dd", { className: "text-sm", children: props.extension.version })
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("dt", { className: "text-xs text-brand-dark/80", children: "Catalog digest" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("dd", { children: /* @__PURE__ */ jsxRuntimeExports.jsx("code", { className: "break-all text-xs", children: props.catalogDigest }) })
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("dt", { className: "text-xs text-brand-dark/80", children: "Provenance" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("dd", { className: "text-sm", children: controlProvenance(props.effective, "extension", props.extension.extension_id).join(" · ") })
        ] })
      ] })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("section", { children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("h3", { className: "font-semibold text-brand-dark", children: "Detections" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-3 max-h-96 overflow-auto", children: /* @__PURE__ */ jsxRuntimeExports.jsxs("table", { className: "min-w-full text-left text-xs", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("thead", { className: "sticky top-0 bg-[var(--surface-1)] text-brand-dark/80", children: /* @__PURE__ */ jsxRuntimeExports.jsxs("tr", { children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("th", { className: "px-3 py-2", children: "Detection" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("th", { className: "px-3 py-2", children: "Severity" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("th", { className: "px-3 py-2", children: "Matcher" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("th", { className: "px-3 py-2", children: "Default" })
        ] }) }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("tbody", { children: props.extension.rules.map((rule) => /* @__PURE__ */ jsxRuntimeExports.jsxs("tr", { className: "border-t border-[rgba(63,65,116,0.08)]", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsxs("td", { className: "px-3 py-2", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "font-medium text-brand-dark/80", children: rule.title }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("code", { className: "break-all text-[10px] text-brand-dark/80", children: rule.rule_id })
          ] }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("td", { className: "px-3 py-2", children: rule.severity }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("td", { className: "px-3 py-2", children: rule.matcher_kind }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("td", { className: "px-3 py-2", children: treatmentLabel(rule.default_mode) })
        ] }, rule.rule_id)) })
      ] }) })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("section", { children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("h3", { className: "font-semibold text-brand-dark", children: "Protection setting identifiers" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-2 space-y-2", children: props.extension.permissions.map((permission) => /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "py-2", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "text-sm font-medium text-brand-dark/80", children: permission.label }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("code", { className: "mt-1 block break-all text-[11px] text-brand-dark/80", children: permission.permission_id }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-1 text-xs text-brand-dark/80", children: permission.action_classes.join(", ") || "No action classes" })
      ] }, permission.permission_id)) })
    ] })
  ] }) });
}
function ProtectionModuleDetail(props) {
  const [policyDirty, setPolicyDirty] = reactExports.useState(false);
  const { confirm: requestConfirmation, dialog: confirmDialog } = useConfirmDialog();
  const urlStateRef = reactExports.useRef(props.urlState);
  urlStateRef.current = props.urlState;
  const onUrlStateRef = reactExports.useRef(props.onUrlState);
  onUrlStateRef.current = props.onUrlState;
  reactExports.useEffect(() => {
    let highlightTimer = 0;
    let highlighted = null;
    const clearHighlight = () => {
      if (highlightTimer) window.clearTimeout(highlightTimer);
      highlightTimer = 0;
      highlighted?.classList.remove("guard-pattern-row-highlight");
      highlighted = null;
    };
    const highlight = () => {
      const anchor = window.location.hash;
      let rowId = null;
      let ruleId = null;
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
  const requestExtensionChange = props.extension.required ? void 0 : props.onRequestExtensionChange;
  const activeTab = canonicalProtectionDetailTab(props.urlState?.tab ?? "overview");
  const protectionView = buildLocalProtectionView(
    extensionLocalProtectionInput(props.extension, props.effective, props.runtime)
  );
  const orgManaged = protectionView.sources.some(
    (source) => source === "Synced from Guard Cloud" || source.startsWith("Managed by ")
  );
  const cloudControlsUrl = props.runtime?.dashboard_url?.trim() || props.runtime?.connect_url?.trim() || void 0;
  const setActiveTab = reactExports.useCallback(async (tab) => {
    if (!props.onUrlState) return false;
    const needsConfirmation = tab !== activeTab && policyDirty;
    if (needsConfirmation && !await requestConfirmation({
      title: "Discard unreviewed changes?",
      description: DRAFT_EXIT_MESSAGE,
      confirmLabel: "Discard changes",
      cancelLabel: "Keep editing",
      tone: "destructive"
    })) {
      return false;
    }
    const latestUrlState = urlStateRef.current;
    const latestOnUrlState = onUrlStateRef.current;
    if (!latestOnUrlState) return false;
    if (needsConfirmation && canonicalProtectionDetailTab(latestUrlState?.tab ?? "overview") !== activeTab) {
      return false;
    }
    latestOnUrlState({
      ...latestUrlState ?? {
        tab: "overview",
        query: "",
        risk: "all",
        state: "all",
        configurable: "all",
        source: "all",
        deprecated: "all",
        type: "all",
        sort: "name",
        ruleId: null
      },
      tab,
      ruleId: null
    });
    return true;
  }, [activeTab, policyDirty, props.onUrlState, requestConfirmation]);
  const handleTabKeyDown = async (event, tab) => {
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
    if (!await setActiveTab(next.id)) return;
    window.requestAnimationFrame(() => document.getElementById(`protection-tab-${next.id}`)?.focus());
  };
  const handleBack = async () => {
    if (policyDirty && !await requestConfirmation({
      title: "Discard unreviewed changes?",
      description: DRAFT_EXIT_MESSAGE,
      confirmLabel: "Discard changes",
      cancelLabel: "Keep editing",
      tone: "destructive"
    })) return;
    props.onBack();
  };
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { "data-testid": "protection-module-detail", className: "w-full", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("button", { type: "button", onClick: () => void handleBack(), className: "inline-flex min-h-11 items-center gap-2 rounded-lg px-1 text-sm font-semibold text-brand-dark/80 hover:text-brand-dark", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniArrowLeft, { className: "size-4", "aria-hidden": "true" }),
      "Extensions"
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("header", { className: "mt-4 border-b border-slate-200 pb-6", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-start gap-4", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(
          ExtensionBrandMark,
          {
            extension_id: props.extension.extension_id,
            name: props.extension.name,
            executables: props.extension.executables,
            ecosystem_ids: props.extension.ecosystem_ids,
            size: "lg"
          }
        ),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "min-w-0 flex-1", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "font-mono text-xs font-semibold tracking-[0.14em] text-slate-400", children: props.extension.executables.join(" · ") }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("h1", { className: "mt-2 text-2xl font-semibold tracking-tight text-brand-dark", children: props.extension.name }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-2 max-w-2xl text-sm leading-6 text-slate-500", children: props.extension.description }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "mt-3 inline-flex rounded-full border border-slate-200 bg-slate-50 px-3 py-1 text-xs font-semibold text-brand-dark", children: protectionView.source })
        ] })
      ] }),
      requiredNote ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-3 max-w-2xl text-sm leading-6 text-brand-dark/80", children: requiredNote }) : null,
      requestExtensionChange ? /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-4 flex flex-wrap items-center gap-3", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(
          "button",
          {
            type: "button",
            role: "switch",
            "aria-checked": extensionEnabled,
            disabled: props.effective.health !== "protected",
            onClick: () => requestExtensionChange(props.extension, !extensionEnabled),
            className: "guard-tool-switch",
            "data-testid": "extension-availability-switch",
            children: /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "guard-tool-switch-knob" })
          }
        ),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm font-semibold text-brand-dark", children: availabilityTitle(props.extension) }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs leading-5 text-brand-dark/75", children: availabilityCopy(props.extension, extensionEnabled) })
        ] })
      ] }) : null,
      orgManaged ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-3 text-sm text-brand-dark/80", children: "Your organization controls part of this protection. Local changes cannot weaken organization policy." }) : null,
      props.effective.global_lockdown ? /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { role: "status", className: "mt-4 flex gap-2 text-sm text-brand-dark", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniLockClosed, { className: "mt-0.5 size-4 shrink-0" }),
        "Emergency Lockdown currently controls this module. Matching optional actions remain blocked."
      ] }) : null
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("nav", { className: "mt-5 flex gap-5 overflow-x-auto border-b border-slate-200", role: "tablist", "aria-label": "Extension detail sections", children: DETAIL_TABS.map((tab) => /* @__PURE__ */ jsxRuntimeExports.jsx(
      "button",
      {
        id: `protection-tab-${tab.id}`,
        type: "button",
        role: "tab",
        "aria-selected": activeTab === tab.id,
        "aria-controls": `protection-panel-${tab.id}`,
        tabIndex: activeTab === tab.id ? 0 : -1,
        onClick: () => void setActiveTab(tab.id),
        onKeyDown: (event) => void handleTabKeyDown(event, tab.id),
        className: `-mb-px min-h-11 shrink-0 whitespace-nowrap border-b-2 px-1 pb-3 text-sm font-semibold focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-brand-blue ${activeTab === tab.id ? "border-brand-blue text-brand-blue" : "border-transparent text-brand-dark/60 hover:text-brand-dark"}`,
        children: tab.label
      },
      tab.id
    )) }),
    activeTab === "overview" ? /* @__PURE__ */ jsxRuntimeExports.jsxs("section", { id: "protection-panel-overview", role: "tabpanel", "aria-labelledby": "protection-tab-overview", className: "mt-6 grid gap-4 lg:grid-cols-2", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("article", { className: "rounded-3xl border border-slate-200 bg-white p-5 shadow-sm", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("h2", { className: "text-lg font-semibold text-brand-dark", children: "Effective protection" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-2 text-sm leading-6 text-brand-dark/75", children: protectionView.summary }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("dl", { className: "mt-5 grid gap-4 sm:grid-cols-2", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("dt", { className: "text-xs font-semibold uppercase text-brand-dark/55", children: "State" }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("dd", { className: "mt-1 text-sm font-semibold text-brand-dark", children: protectionStateLabel(protectionView.effectiveState) })
          ] }),
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("dt", { className: "text-xs font-semibold uppercase text-brand-dark/55", children: "Source" }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("dd", { className: "mt-1 text-sm font-semibold text-brand-dark", children: protectionView.source })
          ] }),
          protectionView.sources.length > 1 ? /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("dt", { className: "text-xs font-semibold uppercase text-brand-dark/55", children: "Contributors" }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("dd", { className: "mt-1 text-sm text-brand-dark", children: protectionView.sources.join(" · ") })
          ] }) : null,
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("dt", { className: "text-xs font-semibold uppercase text-brand-dark/55", children: "Required" }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("dd", { className: "mt-1 text-sm text-brand-dark", children: props.extension.required ? "Yes" : "No" })
          ] }),
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("dt", { className: "text-xs font-semibold uppercase text-brand-dark/55", children: "Delegated protection" }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("dd", { className: "mt-1 text-sm text-brand-dark", children: props.extension.delegated_protection === "package-firewall" ? "Package Firewall" : props.extension.delegated_protection ?? "None" })
          ] })
        ] }),
        props.extension.delegated_protection === "package-firewall" ? /* @__PURE__ */ jsxRuntimeExports.jsxs("a", { href: "/supply-chain", className: "mt-4 inline-flex min-h-11 items-center gap-2 text-sm font-semibold text-brand-blue hover:underline", children: [
          "Open Package Firewall enforcement ",
          /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniArrowTopRightOnSquare, { className: "size-4", "aria-hidden": "true" })
        ] }) : null
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("article", { className: "rounded-3xl border border-slate-200 bg-white p-5 shadow-sm", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("h2", { className: "text-lg font-semibold text-brand-dark", children: "What this Extension protects" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-2 text-sm leading-6 text-brand-dark/75", children: "Choose Permissions to review effective behavior, built-in floors, and settings you may tighten locally." }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("dl", { className: "mt-5 grid gap-4 sm:grid-cols-2", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("dt", { className: "text-xs font-semibold uppercase text-brand-dark/55", children: "Permissions" }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("dd", { className: "mt-1 text-sm text-brand-dark", children: props.extension.permission_count })
          ] }),
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("dt", { className: "text-xs font-semibold uppercase text-brand-dark/55", children: "Detection rules" }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("dd", { className: "mt-1 text-sm text-brand-dark", children: props.extension.rule_count })
          ] }),
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("dt", { className: "text-xs font-semibold uppercase text-brand-dark/55", children: "Baseline floors" }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("dd", { className: "mt-1 text-sm text-brand-dark", children: [...new Set(props.extension.permissions.map((permission) => treatmentLabel(permission.baseline_floor)))].join(", ") || "Built-in" })
          ] }),
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("dt", { className: "text-xs font-semibold uppercase text-brand-dark/55", children: "Configurable" }),
            /* @__PURE__ */ jsxRuntimeExports.jsxs("dd", { className: "mt-1 text-sm text-brand-dark", children: [
              props.extension.permissions.filter((permission) => permission.configurable).length,
              " of ",
              props.extension.permission_count
            ] })
          ] })
        ] })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsx(McpServerDefaults, { extension: props.extension })
    ] }) : null,
    activeTab === "permissions" ? /* @__PURE__ */ jsxRuntimeExports.jsx("div", { id: "protection-panel-permissions", role: "tabpanel", "aria-labelledby": "protection-tab-permissions", className: "mt-6", children: /* @__PURE__ */ jsxRuntimeExports.jsx(
      ExtensionPolicyPanel,
      {
        extension: props.extension,
        effective: props.effective,
        catalogDigest: props.catalogDigest,
        onRefresh: props.onRefresh,
        onDirtyChange: setPolicyDirty,
        cloudControlsUrl
      }
    ) }) : null,
    activeTab === "managed-controls" ? /* @__PURE__ */ jsxRuntimeExports.jsx("div", { id: "protection-panel-managed-controls", role: "tabpanel", "aria-labelledby": "protection-tab-managed-controls", className: "mt-6", children: /* @__PURE__ */ jsxRuntimeExports.jsx(
      ExtensionManagedControlsPanel,
      {
        extension: props.extension,
        effective: props.effective,
        runtime: props.runtime,
        onRefresh: props.onRefresh
      }
    ) }) : null,
    activeTab === "activity" ? /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { id: "protection-panel-activity", role: "tabpanel", "aria-labelledby": "protection-tab-activity", className: "mt-6 space-y-6", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(ExtensionActivity, { extension: props.extension, receipts: props.runtime?.latest_receipts ?? [] }),
      /* @__PURE__ */ jsxRuntimeExports.jsx(ProtectionTestLab, { extension: props.extension })
    ] }) : null,
    activeTab === "technical" ? /* @__PURE__ */ jsxRuntimeExports.jsx("div", { id: "protection-panel-technical", role: "tabpanel", "aria-labelledby": "protection-tab-technical", className: "mt-6", children: /* @__PURE__ */ jsxRuntimeExports.jsx(DeveloperModuleDetails, { extension: props.extension, effective: props.effective, catalogDigest: props.catalogDigest }) }) : null,
    confirmDialog
  ] });
}
function ExtensionsLoadingState(props) {
  return /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "grid min-h-[60vh] place-items-center", "aria-busy": "true", children: /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-col items-center gap-3", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "guard-skeleton h-8 w-48" }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm text-brand-dark/70", children: props.label }),
    /* @__PURE__ */ jsxRuntimeExports.jsx(
      HiMiniArrowPath,
      {
        className: "size-7 animate-spin text-brand-blue motion-reduce:animate-none",
        "aria-hidden": "true"
      }
    )
  ] }) });
}
function ExtensionsLoadError(props) {
  return /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mx-auto max-w-4xl", children: /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: `${EXTENSION_PANEL_CLASS} guard-extensions-tone-danger`, children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx("h1", { className: "text-xl font-semibold text-red-950", children: props.title }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("p", { role: "alert", className: "mt-2 text-sm text-red-800", children: props.detail }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-3 text-xs font-medium text-red-900", children: "Local protection continues on this device." }),
    props.reference ? /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "mt-2 text-xs text-red-900", children: [
      "Reference: ",
      /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "font-mono break-all", children: props.reference })
    ] }) : null,
    /* @__PURE__ */ jsxRuntimeExports.jsx(
      "button",
      {
        type: "button",
        onClick: props.onRetry,
        className: "mt-4 min-h-11 rounded-xl bg-red-800 px-4 text-sm font-semibold text-white",
        children: "Try again"
      }
    )
  ] }) });
}
function ExtensionsNotFound(props) {
  return /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mx-auto max-w-4xl", children: /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: `${EXTENSION_PANEL_CLASS} guard-extensions-tone-attention`, children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx("h1", { className: "font-semibold text-amber-950", children: props.title }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-2 text-sm text-amber-900", children: props.detail }),
    /* @__PURE__ */ jsxRuntimeExports.jsx(
      "button",
      {
        type: "button",
        onClick: props.onBack,
        className: "mt-4 min-h-11 rounded-xl bg-brand-blue px-4 text-sm font-semibold text-white",
        children: "Back to Extensions"
      }
    )
  ] }) });
}
function CatalogExtensionDetail(props) {
  const { readModel, summary, ...detailProps } = props;
  const key = `${readModel.catalog_digest}|${summary.extension_id}|${summary.content_revision ?? ""}`;
  const [state, setState] = reactExports.useState({ kind: "loading", key });
  const [attempt, setAttempt] = reactExports.useState(0);
  reactExports.useEffect(() => {
    let cancelled = false;
    setState({ kind: "loading", key });
    readModel.detail(summary.extension_id).then(
      (extension) => {
        if (!cancelled) setState({ kind: "ready", key, extension });
      },
      (error) => {
        if (cancelled) return;
        const stale2 = error instanceof ExtensionControlApiError && error.code === CATALOG_SNAPSHOT_EXPIRED;
        setState({ kind: "error", key, stale: stale2, message: error instanceof Error ? error.message : "Extension details are unavailable" });
      }
    );
    return () => {
      cancelled = true;
    };
  }, [attempt, key, readModel, summary.extension_id]);
  const { onRefresh } = detailProps;
  const stale = state.kind === "error" && state.stale;
  const retry = reactExports.useCallback(async () => {
    if (stale) await onRefresh();
    setAttempt((value) => value + 1);
  }, [onRefresh, stale]);
  if (state.key !== key || state.kind === "loading") return /* @__PURE__ */ jsxRuntimeExports.jsx(ExtensionsLoadingState, { label: "Loading extension" });
  if (state.kind === "error") {
    return /* @__PURE__ */ jsxRuntimeExports.jsx(ExtensionsLoadError, { title: "Extension details unavailable", detail: state.message, onRetry: () => {
      void retry();
    } });
  }
  return /* @__PURE__ */ jsxRuntimeExports.jsx(ProtectionModuleDetail, { ...detailProps, extension: state.extension });
}
const PROTECTION_DATA_UNSETTLED_MESSAGE = "Guard is still settling a protection update, so a few extensions may read as out of date and changes cannot be saved yet. Reload this page in a few seconds.";
const CATALOG_PREPARATION_DEGRADED_MESSAGE = "Guard could not rebuild its extension list, so this page is showing the list Guard already had. It may not have every extension, and a policy change can still be refused until Guard rebuilds. Updating HOL Guard restores the rebuilt list; Guard writes the reason to its log at ~/.hol-guard/logs/daemon.log.";
const PROTECTION_SAVE_UNSETTLED_MESSAGE = "Guard could not save this protection change, so your current protection is unchanged. Guard is still settling a protection update; reload this page in a few seconds, then make the change again.";
function reusableCatalogModel(previous, fresh) {
  if (previous && previous.catalog_digest === fresh.catalog_digest && previous.protocol === fresh.protocol && previous.degraded === fresh.degraded) {
    return previous;
  }
  return fresh;
}
const CONSISTENT_LOAD_RETRY_DELAYS_MS = [250, 1e3, 2e3, 4e3];
const defaultSleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
async function loadConsistentProtectionData(loadCatalog, loadEffective, options = {}) {
  const delays = options.delays ?? CONSISTENT_LOAD_RETRY_DELAYS_MS;
  const sleep = options.sleep ?? defaultSleep;
  const repair = options.repair ?? refreshEffectiveExtensionControls;
  for (let attempt = 0; ; attempt += 1) {
    const [catalog, effective] = await Promise.all([loadCatalog(), loadEffective()]);
    if (catalog.catalog_digest === effective.catalog_digest) {
      return { catalog, effective, consistent: true };
    }
    const delay = delays[attempt];
    if (delay === void 0) return { catalog, effective, consistent: false };
    await repair().catch(() => void 0);
    await sleep(delay);
  }
}
function randomToken() {
  return crypto.randomUUID().replaceAll("-", "");
}
function buildExtensionMutation(state, change) {
  const layers = structuredClone(state.effective.layers);
  let local = layers.find((layer) => layer.kind === "local-admin");
  if (!local) {
    local = {
      schema_version: "1.0.0",
      kind: "local-admin",
      catalog_digest: state.catalog.catalog_digest,
      global_lockdown: false,
      controls: []
    };
    layers.push(local);
  }
  if ("globalLockdown" in change) {
    local.global_lockdown = change.globalLockdown;
  } else {
    local.controls = local.controls.filter(
      (control) => control.target_kind !== "extension" || control.target_id !== change.extension.extension_id
    );
    local.controls.push({
      target_kind: "extension",
      target_id: change.extension.extension_id,
      state: change.enabled ? "enabled" : "disabled"
    });
    local.controls.sort(
      (left, right) => `${left.target_kind}:${left.target_id}`.localeCompare(`${right.target_kind}:${right.target_id}`)
    );
  }
  return {
    previous_revision: state.effective.revision,
    catalog_digest: state.catalog.catalog_digest,
    layers,
    actor_id: "dashboard-admin",
    idempotency_key: randomToken(),
    nonce: randomToken()
  };
}
const PROTECTION_TERMS = {
  pageTitle: "Extensions"
};
function looksLikeUnauthorizedSession(message) {
  const lower = message.trim().toLowerCase();
  if (!lower || lower === "unauthorized" || lower.includes("unauthorized") || lower.includes("session")) return true;
  return /(^|[^0-9])401([^0-9]|$)/.test(lower);
}
const LOAD_ERROR_COPY = {
  catalog_read_model_unavailable: {
    title: "Guard cannot open your extension list",
    detail: "Guard is running on this device but could not open the extension list it keeps locally. Quit HOL Guard and open it again. If the page still cannot load, install the latest version."
  },
  catalog_read_transport_failed: {
    title: "Guard stopped answering while the list loaded",
    detail: "The connection to Guard on this device ended before the extension list finished loading."
  },
  catalog_snapshot_expired: {
    title: "The extension list changed while it loaded",
    detail: "Guard rebuilt the extension list while this page was reading it, so this page never finished loading. Load it again to read the rebuilt list."
  },
  catalog_read_preparation_failed: {
    title: "Guard cannot rebuild your extension list",
    detail: "Guard on this device has failed to rebuild its extension list on every recent attempt, so waiting or loading the page again will not clear it. Install the latest version of HOL Guard. Guard writes the reason to its log file at ~/.hol-guard/logs/daemon.log."
  },
  catalog_snapshot_mismatch: {
    title: "Guard's parts are on different versions",
    detail: "The background service and the protection runtime on this device come from different versions of Guard, so neither can answer for the other's extension list. Install the latest version of HOL Guard to put them back in step."
  }
};
function looksLikeReasonCode(message) {
  return /^[a-z0-9]+(?:_[a-z0-9]+)+$/.test(message);
}
function protectionCenterLoadError(message) {
  const trimmed = message.trim();
  if (looksLikeUnauthorizedSession(trimmed)) {
    return {
      title: "This view needs a signed local session",
      detail: "Open Extensions from the local Guard dashboard and try again after Guard signs this session."
    };
  }
  const known = LOAD_ERROR_COPY[trimmed];
  if (known) return { ...known, reference: trimmed };
  if (looksLikeReasonCode(trimmed)) {
    return {
      title: "Extensions unavailable",
      detail: "Guard could not load your extension settings on this device. If trying again does not help, quit HOL Guard and open it again.",
      reference: trimmed
    };
  }
  return {
    title: "Extensions unavailable",
    detail: trimmed || "Guard could not load your extension settings on this device."
  };
}
const DEFAULT_TERMINAL_COMMANDS = {
  enroll: "hol-guard command controls enroll",
  recover_authority: "hol-guard command controls recover-authority"
};
const GATE_SETUP_SUFFIX = " Enable Ask for proof and set an Approval password in Settings > Approval gate, then return here.";
function authorityNoticeView(health, approvalGateReady, terminalCommands, approvalConfigured) {
  const commands = terminalCommands ?? DEFAULT_TERMINAL_COMMANDS;
  const terminalName = terminalCommands?.shell === "powershell" ? "PowerShell" : "your terminal";
  switch (health) {
    case "tampered":
    case "recovery-required": {
      const gateBlocked = approvalGateReady === false;
      return {
        tone: "warning",
        title: "Protection needs repair",
        body: `Guard found a problem with this device's trusted protection settings and is staying fail-safe. Protection changes stay locked until the settings are rebuilt with your approval. Commands keep being checked in the meantime.${gateBlocked ? ` Rebuilding needs your approval password, and local approval is not ready on this device.${GATE_SETUP_SUFFIX}` : ""}`,
        action: gateBlocked ? { kind: "configure-approval" } : { kind: "repair" },
        actionLabel: gateBlocked ? "Set up approval" : "Repair protection",
        actionDetail: "Rebuilding the trusted settings needs your approval password. Guard verifies the repair before protection changes unlock again.",
        command: commands.recover_authority,
        commandLabel: "Repair from the terminal",
        copyButtonLabel: "Copy repair command",
        terminalSummary: `Run this in ${terminalName} if the button above cannot reach the approval gate.`
      };
    }
    case "degraded-unacknowledged": {
      const gateBlocked = approvalGateReady === false;
      return {
        tone: "warning",
        title: "Protection is limited",
        body: `Guard cannot fully verify the trusted protection settings and is staying fail-safe until that is resolved. Acknowledging records the limited state honestly — it does not restore full protection.${gateBlocked ? ` Acknowledging needs your approval password, and local approval is not ready on this device.${GATE_SETUP_SUFFIX}` : ""}`,
        action: gateBlocked ? { kind: "configure-approval" } : { kind: "acknowledge" },
        actionLabel: gateBlocked ? "Set up approval" : "Acknowledge limited state",
        actionDetail: "Acknowledging the limited state needs your approval password. Guard keeps protecting fail-safe afterwards.",
        command: commands.recover_authority,
        commandLabel: "Repair from the terminal",
        copyButtonLabel: "Copy repair command",
        terminalSummary: `A full repair runs from ${terminalName}.`
      };
    }
    case "degraded-acknowledged": {
      const gateBlocked = approvalGateReady === false;
      return {
        tone: "warning",
        title: "Protection is limited",
        body: `The limited state is acknowledged. Guard keeps protection changes locked until the trusted settings are rebuilt from this device's terminal. Commands keep being checked in the meantime.${gateBlocked ? ` The rebuild needs your approval password, and local approval is not ready on this device.${GATE_SETUP_SUFFIX}` : ""}`,
        action: gateBlocked ? { kind: "configure-approval" } : { kind: "none" },
        actionLabel: gateBlocked ? "Set up approval" : null,
        actionDetail: null,
        command: commands.recover_authority,
        commandLabel: "Repair from the terminal",
        copyButtonLabel: "Copy repair command",
        terminalSummary: `Run this in ${terminalName} to rebuild the trusted settings.`
      };
    }
    default:
      if (approvalGateReady === null) {
        return {
          tone: "info",
          title: "Checking approval setup",
          body: "Guard is checking whether this device is ready to enroll trusted protection settings. Enrollment steps will appear when the check finishes. If this takes too long, check again.",
          action: { kind: "none" },
          actionLabel: null,
          actionDetail: null,
          command: "",
          commandLabel: "",
          copyButtonLabel: "",
          terminalSummary: ""
        };
      }
      if (!approvalGateReady) {
        return {
          tone: "info",
          title: approvalConfigured ? "Local approval is off" : "Set up local approval",
          body: approvalConfigured ? "Enable local approval to change extension permissions. Your password stays on this device; Guard Cloud is not required." : "Choose a password to protect changes to extension permissions. It stays on this device; Guard Cloud is not required.",
          action: { kind: "configure-approval" },
          actionLabel: "Open approval settings",
          actionDetail: null,
          command: "",
          commandLabel: "",
          copyButtonLabel: "",
          terminalSummary: ""
        };
      }
      return {
        tone: "info",
        title: "Finish extension setup",
        body: "Run this command to save this device's trusted extension settings. Guard is already checking commands locally.",
        action: { kind: "none" },
        actionLabel: null,
        actionDetail: null,
        command: commands.enroll,
        commandLabel: "Enroll from the terminal",
        copyButtonLabel: "Copy setup command",
        terminalSummary: `Run this in ${terminalName} to create the trusted settings.`
      };
  }
}
function ProtectionAuthorityNotice(props) {
  const health = props.effective.health;
  const approvalGateReady = props.approvalGate === null ? null : props.approvalGate.configured && props.approvalGate.enabled;
  const view = authorityNoticeView(health, approvalGateReady, props.effective.terminal_commands, props.approvalGate?.configured === true);
  const [proofOpen, setProofOpen] = reactExports.useState(false);
  const [pendingAction, setPendingAction] = reactExports.useState(null);
  const [copyState, setCopyState] = reactExports.useState("idle");
  const [checkPending, setCheckPending] = reactExports.useState(false);
  const [checkComplete, setCheckComplete] = reactExports.useState(false);
  const [checkError, setCheckError] = reactExports.useState(null);
  const checkBaselineRef = reactExports.useRef(null);
  reactExports.useEffect(() => {
    if (props.status) setProofOpen(false);
  }, [props.status]);
  if (health === "protected") return null;
  const gatePending = props.approvalGate === null;
  const copyCommand = async () => {
    try {
      await navigator.clipboard.writeText(view.command);
      setCopyState("copied");
    } catch {
      setCopyState("failed");
    }
  };
  const checkAgain = async () => {
    if (checkPending || props.busy) return;
    checkBaselineRef.current = effectiveStatusKey(props.effective, { approvalGate: props.approvalGate });
    setCheckPending(true);
    setCheckComplete(false);
    setCheckError(null);
    try {
      await props.onCheckAgain();
      setCheckComplete(true);
    } catch {
      setCheckError("Guard could not refresh the current protection status. The displayed state remains in force; try again.");
    } finally {
      setCheckPending(false);
    }
  };
  const warning = view.tone === "warning";
  const panelClass = warning ? "border border-amber-200 bg-amber-50" : "border border-brand-blue/25 bg-[rgba(85,153,254,0.06)]";
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("section", { "aria-labelledby": "protection-authority-notice-heading", className: `mt-4 rounded-2xl p-5 sm:p-6 ${panelClass}`, children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-start gap-3", children: [
      warning ? /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniExclamationTriangle, { className: "mt-0.5 size-5 shrink-0 text-amber-600", "aria-hidden": "true" }) : /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniInformationCircle, { className: "mt-0.5 size-5 shrink-0 text-brand-blue", "aria-hidden": "true" }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "min-w-0 flex-1", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("h2", { id: "protection-authority-notice-heading", className: `text-base font-semibold ${warning ? "text-amber-950" : "text-brand-dark"}`, children: view.title }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: `mt-1 max-w-3xl text-sm leading-6 ${warning ? "text-amber-950/90" : "text-brand-dark/80"}`, children: view.body }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-4 flex flex-wrap items-center gap-2", children: [
          view.actionLabel && view.action.kind !== "none" ? /* @__PURE__ */ jsxRuntimeExports.jsx(
            "button",
            {
              type: "button",
              "aria-busy": props.busy || checkPending,
              disabled: props.busy || checkPending || gatePending,
              onClick: () => {
                if (view.action.kind === "configure-approval") {
                  props.onOpenApprovalSettings();
                  return;
                }
                setPendingAction(view.action.kind === "repair" ? "repair" : "acknowledge");
                setProofOpen(true);
              },
              className: "inline-flex min-h-11 items-center rounded-xl bg-brand-blue px-4 text-sm font-semibold text-white hover:bg-brand-dark disabled:opacity-60",
              children: gatePending && !props.error ? "Loading approval settings…" : view.actionLabel
            }
          ) : null,
          view.action.kind === "none" && view.command ? /* @__PURE__ */ jsxRuntimeExports.jsxs(
            "button",
            {
              type: "button",
              onClick: () => {
                void copyCommand();
              },
              className: "inline-flex min-h-11 items-center gap-2 rounded-xl bg-brand-blue px-4 text-sm font-semibold text-white hover:bg-brand-dark",
              children: [
                copyState === "copied" ? /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniClipboardDocumentCheck, { className: "size-4", "aria-hidden": "true" }) : /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniClipboard, { className: "size-4", "aria-hidden": "true" }),
                copyState === "copied" ? "Command copied" : view.copyButtonLabel
              ]
            }
          ) : null,
          view.action.kind !== "configure-approval" ? /* @__PURE__ */ jsxRuntimeExports.jsx(
            "button",
            {
              type: "button",
              disabled: props.busy || checkPending,
              "aria-busy": checkPending,
              onClick: () => {
                void checkAgain();
              },
              className: "inline-flex min-h-11 items-center rounded-xl border border-slate-200 bg-white px-4 text-sm font-semibold text-brand-dark hover:border-brand-blue/40 disabled:opacity-60",
              children: checkPending ? "Checking…" : "Check again"
            }
          ) : null
        ] }),
        props.busy ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { role: "status", className: `mt-3 text-sm font-medium ${warning ? "text-amber-950" : "text-brand-dark"}`, children: pendingAction === "acknowledge" ? "Confirming the limited state…" : "Repairing local protection…" }) : null,
        checkPending ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { role: "status", "aria-live": "polite", className: `mt-3 text-sm font-medium ${warning ? "text-amber-950" : "text-brand-dark"}`, children: "Checking current protection status…" }) : null,
        checkComplete ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { role: "status", "aria-live": "polite", className: `mt-3 text-sm font-medium ${warning ? "text-amber-950" : "text-brand-dark"}`, children: effectiveStatusKey(props.effective, { approvalGate: props.approvalGate }) === checkBaselineRef.current ? "Check complete. No change detected; local protection remains in its current fail-safe state." : "Check complete. Protection status updated." }) : null,
        checkError ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { role: "alert", className: "mt-3 rounded-xl border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-800", children: checkError }) : null,
        props.error ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { role: "alert", className: "mt-3 rounded-xl border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-800", children: props.error }) : null,
        props.status ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { role: "status", className: "mt-3 text-sm font-medium text-brand-dark", children: props.status }) : null,
        view.command ? /* @__PURE__ */ jsxRuntimeExports.jsxs("details", { className: "mt-4", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("summary", { className: `cursor-pointer text-sm font-semibold ${warning ? "text-amber-950" : "text-brand-dark"}`, children: view.commandLabel }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: `mt-2 text-sm leading-6 ${warning ? "text-amber-950/80" : "text-brand-dark/70"}`, children: view.terminalSummary }),
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-2 flex flex-col gap-2 sm:flex-row sm:items-center", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("code", { className: "min-w-0 flex-1 overflow-x-auto rounded-lg border border-slate-200 bg-white px-3 py-2 font-mono text-xs text-brand-dark", children: view.command }),
            /* @__PURE__ */ jsxRuntimeExports.jsxs(
              "button",
              {
                type: "button",
                onClick: () => {
                  void copyCommand();
                },
                className: "inline-flex min-h-11 shrink-0 items-center justify-center gap-2 rounded-xl border border-slate-200 bg-white px-4 text-sm font-semibold text-brand-blue hover:border-brand-blue/40",
                children: [
                  copyState === "copied" ? /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniClipboardDocumentCheck, { className: "size-4", "aria-hidden": "true" }) : /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniClipboard, { className: "size-4", "aria-hidden": "true" }),
                  copyState === "copied" ? "Copied" : "Copy command"
                ]
              }
            )
          ] })
        ] }) : null
      ] })
    ] }),
    proofOpen && (view.action.kind === "repair" || view.action.kind === "acknowledge") ? /* @__PURE__ */ jsxRuntimeExports.jsx(
      ApprovalProofModal,
      {
        title: view.action.kind === "repair" ? "Repair protection" : "Acknowledge limited state",
        detail: view.actionDetail ?? "",
        confirmLabel: view.actionLabel ?? "Confirm",
        approvalGate: props.approvalGate,
        busy: props.busy,
        error: props.error,
        onCancel: () => {
          if (!props.busy) setProofOpen(false);
        },
        onConfirm: (credentials) => {
          props.onAction(view.action.kind === "repair" ? "repair" : "acknowledge", credentials);
        }
      }
    ) : null
  ] });
}
const GUARD_DISCOVERY_CLOUD_ORIGIN = "https://hol.org";
const GUARD_DISCOVERY_ADVERTISE_PATH = "/guard/extensions/advertise?source=guard_local&intent=extension-promotion";
const MIN_ORGANIC_ROWS_BEFORE_IN_FEED = 8;
const IN_FEED_SLOT_INTERVAL = 10;
const FIRST_IN_FEED_SLOT_INDEX = 6;
function integerOrNull(value) {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0 ? value : null;
}
function parseDiscoveryOffers(value) {
  if (!Array.isArray(value)) return [];
  const offers = [];
  for (const entry of value) {
    if (typeof entry !== "object" || entry === null) continue;
    const candidate = entry;
    if (candidate.product !== "always" && candidate.product !== "time_slot" && candidate.product !== "sponsored") continue;
    if (candidate.availability !== "open" && candidate.availability !== "sold_out" && candidate.availability !== "unknown") continue;
    if (candidate.quoteRequired !== true) continue;
    const open = integerOrNull(candidate.openSlots);
    const total = integerOrNull(candidate.totalSlots);
    const paired = open !== null && total !== null && total >= 1 && open <= total && candidate.availability !== "unknown" && (candidate.availability === "open" ? open >= 1 : open === 0);
    offers.push({
      product: candidate.product,
      availability: candidate.availability,
      indicativeAmountCents: typeof candidate.indicativeAmountCents === "number" && Number.isFinite(candidate.indicativeAmountCents) ? candidate.indicativeAmountCents : null,
      currency: typeof candidate.currency === "string" ? candidate.currency : null,
      checkedAt: typeof candidate.checkedAt === "string" ? candidate.checkedAt : null,
      quoteRequired: true,
      openSlots: paired ? open : null,
      totalSlots: paired ? total : null
    });
  }
  return offers;
}
function parseDiscoveryProjection(value) {
  if (typeof value !== "object" || value === null) return null;
  const record2 = value;
  const snapshot = record2.snapshot;
  if (typeof record2.remainingLeaseMs !== "number" || typeof record2.policyAllowed !== "boolean") return null;
  if (typeof snapshot !== "object" || snapshot === null) return null;
  if (snapshot.state !== "ready" && snapshot.state !== "unavailable") return null;
  if (!Array.isArray(snapshot.placements)) return null;
  for (const placement of snapshot.placements) {
    const candidate = placement;
    if (typeof candidate.publicPlacementId !== "string" || typeof candidate.extensionId !== "string" || candidate.product !== "always" && candidate.product !== "time_slot" && candidate.product !== "sponsored" || typeof candidate.endsAt !== "string" || typeof candidate.creativeVersion !== "string" || typeof candidate.creative?.headline !== "string" || typeof candidate.creative?.body !== "string") {
      return null;
    }
  }
  return {
    snapshot: {
      schemaVersion: String(snapshot.schemaVersion ?? ""),
      snapshotId: String(snapshot.snapshotId ?? ""),
      state: snapshot.state,
      enabled: snapshot.enabled === true,
      reasonCode: typeof snapshot.reasonCode === "string" ? snapshot.reasonCode : null,
      generatedAt: String(snapshot.generatedAt ?? ""),
      leaseExpiresAt: String(snapshot.leaseExpiresAt ?? ""),
      placements: snapshot.placements,
      offers: parseDiscoveryOffers(snapshot.offers)
    },
    remainingLeaseMs: record2.remainingLeaseMs,
    policyAllowed: record2.policyAllowed
  };
}
function advertiseUrl(placement, extensionId, action) {
  const url = new URL(GUARD_DISCOVERY_CLOUD_ORIGIN + GUARD_DISCOVERY_ADVERTISE_PATH);
  url.searchParams.set("placement", placement);
  if (action) {
    url.searchParams.set("action", action);
  }
  return url.toString();
}
function joinDiscoveryPlacements(placements, catalogExtensions, nowMs) {
  const catalogById = new Map(catalogExtensions.map((extension) => [extension.extension_id, extension]));
  const featured = [];
  const sponsored = [];
  for (const placement of placements) {
    if (Date.parse(placement.endsAt) <= nowMs) continue;
    const catalog = catalogById.get(placement.extensionId);
    if (!catalog) continue;
    if (placement.product === "sponsored") {
      if (!sponsored.some((entry) => entry.placement.extensionId === placement.extensionId)) {
        sponsored.push({ placement, catalog });
      }
    } else if (!featured.some((entry) => entry.placement.extensionId === placement.extensionId)) {
      featured.push({ placement, catalog });
    }
  }
  return { featured, sponsored };
}
function sponsoredCardLabel(featured) {
  return featured ? "Sponsored · Featured" : "Sponsored";
}
function featuredWindowLabel(placement) {
  if (placement.product !== "time_slot") return null;
  const ends = Date.parse(placement.endsAt);
  if (!Number.isFinite(ends)) return null;
  return `Featured until ${new Date(ends).toLocaleTimeString(void 0, { hour: "numeric", minute: "2-digit" })}`;
}
function inFeedSlotIndexes(rowCount) {
  if (rowCount < 2) return [];
  const indexes = [];
  for (let index = Math.min(FIRST_IN_FEED_SLOT_INDEX, rowCount - 1); index < rowCount; index += IN_FEED_SLOT_INTERVAL) {
    indexes.push(index);
  }
  return indexes;
}
function orderFeaturedFirst(extensions, featuredIds) {
  if (featuredIds.size === 0) return [...extensions];
  return [
    ...extensions.filter((extension) => featuredIds.has(extension.extension_id)),
    ...extensions.filter((extension) => !featuredIds.has(extension.extension_id))
  ];
}
const DISCOVERY_REFRESH_MS = 1e4;
function useDiscoveryFeed(active, fetchPlacements) {
  const [status, setStatus] = reactExports.useState("loading");
  const [projection, setProjection] = reactExports.useState(null);
  const requestGeneration = reactExports.useRef(0);
  const fetchRef = reactExports.useRef(fetchPlacements);
  fetchRef.current = fetchPlacements;
  const load = reactExports.useCallback(async () => {
    const generation = requestGeneration.current + 1;
    requestGeneration.current = generation;
    const current = () => generation === requestGeneration.current;
    const fail = (next) => {
      setStatus(next);
      setProjection(null);
    };
    try {
      const response = await fetchRef.current();
      if (!current()) return;
      if (response.status === 403) return fail("opt-out");
      if (response.status === 501 || response.status === 503 || response.status === 429) {
        const body = await response.json().catch(() => null);
        if (!current()) return;
        const code = body && typeof body.error === "string" ? body.error : null;
        return fail(code === "rate_limited" || response.status === 429 ? "rate-limited" : "unavailable");
      }
      if (!response.ok) return fail("unavailable");
      const parsed = parseDiscoveryProjection(await response.json().catch(() => null));
      if (!current()) return;
      if (!parsed) return fail("unavailable");
      if (!parsed.policyAllowed) return fail("opt-out");
      if (parsed.snapshot.state !== "ready" || !parsed.snapshot.enabled) return fail("unavailable");
      setProjection(parsed);
      setStatus("ready");
    } catch {
      if (current()) fail("offline");
    }
  }, []);
  reactExports.useEffect(() => {
    if (!active) return;
    let stopped = false;
    const tick = () => {
      if (stopped || document.hidden) return;
      void load();
    };
    const onVisibility = () => {
      if (!document.hidden) tick();
    };
    tick();
    const timer = window.setInterval(tick, DISCOVERY_REFRESH_MS);
    document.addEventListener("visibilitychange", onVisibility);
    return () => {
      stopped = true;
      requestGeneration.current += 1;
      window.clearInterval(timer);
      document.removeEventListener("visibilitychange", onVisibility);
    };
  }, [active, load]);
  return { status, projection };
}
function useJoinedDiscovery(feed, catalogExtensions) {
  return reactExports.useMemo(
    () => joinDiscoveryPlacements(
      feed.status === "ready" && feed.projection ? feed.projection.snapshot.placements : [],
      catalogExtensions,
      Date.now()
    ),
    [catalogExtensions, feed.projection, feed.status]
  );
}
const VIEWABLE_RATIO = 0.5;
const VIEWABLE_DWELL_MS = 1e3;
let measurementRefused = false;
const tokens = /* @__PURE__ */ new Map();
const recorded = /* @__PURE__ */ new WeakMap();
function postJson(path, body) {
  return fetchExtensionDiscoveryApi(path, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body)
  });
}
function renderToken(placement, surface, snapshotId) {
  const key = `${placement.publicPlacementId}:${placement.creativeVersion}:${surface}`;
  const existing = tokens.get(key);
  if (existing) return existing;
  const pending = (async () => {
    if (measurementRefused || typeof crypto?.randomUUID !== "function") return null;
    try {
      const response = await postJson("/v1/discovery/extensions/renders", {
        snapshotId,
        publicPlacementId: placement.publicPlacementId,
        creativeVersion: placement.creativeVersion,
        surface,
        renderNonce: crypto.randomUUID()
      });
      if (!response.ok) {
        measurementRefused = true;
        return null;
      }
      const body = await response.json().catch(() => null);
      return typeof body?.token === "string" ? body.token : null;
    } catch {
      measurementRefused = true;
      return null;
    }
  })();
  tokens.set(key, pending);
  return pending;
}
async function sendEvent(token, kind) {
  const kinds = recorded.get(token) ?? /* @__PURE__ */ new Set();
  recorded.set(token, kinds);
  if (kind !== "detail_open" && kinds.has(kind)) return;
  kinds.add(kind);
  const value = await token;
  if (!value || measurementRefused) return;
  try {
    await postJson("/v1/discovery/extensions/events", { events: [{ token: value, kind }] });
  } catch {
  }
}
function useDiscoveryMeasurement(target, snapshotId, placement, surface) {
  const tokenRef = reactExports.useRef(null);
  const latest = reactExports.useRef({ snapshotId, placement });
  latest.current = { snapshotId, placement };
  const measurable = snapshotId !== null;
  reactExports.useEffect(() => {
    const { snapshotId: snapshot, placement: current } = latest.current;
    if (!snapshot) return;
    const token = renderToken(current, surface, snapshot);
    tokenRef.current = token;
    void sendEvent(token, "served");
    const element = target.current;
    if (!element || typeof IntersectionObserver !== "function") return;
    let dwell = 0;
    const observer = new IntersectionObserver((entries) => {
      const visible = entries.some((entry) => entry.intersectionRatio >= VIEWABLE_RATIO);
      if (visible && !dwell) {
        dwell = window.setTimeout(() => {
          void sendEvent(token, "viewable");
          observer.disconnect();
        }, VIEWABLE_DWELL_MS);
      } else if (!visible && dwell) {
        window.clearTimeout(dwell);
        dwell = 0;
      }
    }, { threshold: [0, VIEWABLE_RATIO] });
    observer.observe(element);
    return () => {
      observer.disconnect();
      if (dwell) window.clearTimeout(dwell);
    };
  }, [measurable, placement.publicPlacementId, placement.creativeVersion, surface, target]);
  return () => {
    if (tokenRef.current) void sendEvent(tokenRef.current, "detail_open");
  };
}
const SPOTLIGHT_CELL_COUNT = 3;
const SPOTLIGHT_ACTIVITY_DAYS = 30;
const STARTER_SPOTLIGHT_IDS = [
  "command.git",
  "command.container-runtime",
  "command.cloud.aws",
  "command.package.node",
  "command.kubernetes-operations",
  "command.remote.ssh",
  "command.github",
  "command.package.python",
  "command.database.postgresql",
  "command.filesystem"
];
const RISK_CLASS_PHRASES = {
  destructive_shell: "irreversible deletes and overwrites",
  network_egress: "commands that send data off this machine",
  execution: "running code that was fetched or generated",
  dynamic_execution: "code assembled at run time",
  encoded_execution: "code hidden behind encoding",
  remote_execution: "commands run on another host",
  local_secret_read: "reads of local secrets and keys",
  credential_access: "credential lookups",
  credential_exfiltration: "credentials being sent somewhere",
  security_credential_provisioning: "new credentials being issued",
  data_flow_exfiltration: "data leaving on an unexpected path",
  data_export: "bulk exports",
  database_mutation: "writes against live databases",
  supply_chain: "untrusted installs and lockfile edits",
  financial_transaction: "transfers and payments",
  permission_change: "permission and access changes",
  policy_bypass: "attempts to work around your own policy",
  destructive: "irreversible changes"
};
function protectionLine(catalog) {
  const phrases = [];
  for (const riskClass of catalog.risk_classes ?? []) {
    const phrase = RISK_CLASS_PHRASES[riskClass];
    if (phrase && !phrases.includes(phrase)) phrases.push(phrase);
    if (phrases.length === 2) break;
  }
  if (phrases.length === 0) return null;
  return `Watches for ${phrases.join(" and ")}.`;
}
function ruleCountLabel(catalog) {
  const count = catalog.rule_count;
  if (!Number.isFinite(count) || count <= 0) return null;
  return `${count.toLocaleString()} ${count === 1 ? "rule" : "rules"}`;
}
function commandsCheckedLabel(count) {
  return `${count.toLocaleString()} ${count === 1 ? "command" : "commands"} checked here`;
}
function buildSpotlight(input) {
  const cards = [];
  const taken = /* @__PURE__ */ new Set();
  const add = (card) => {
    if (cards.length >= SPOTLIGHT_CELL_COUNT) return;
    if (taken.has(card.catalog.extension_id)) return;
    taken.add(card.catalog.extension_id);
    cards.push(card);
  };
  for (const entry of input.featured) {
    add({ catalog: entry.catalog, placement: entry.placement, featured: true, basis: "paid", reason: null });
  }
  for (const entry of input.sponsored) {
    add({ catalog: entry.catalog, placement: entry.placement, featured: false, basis: "paid", reason: null });
  }
  const paidCount = cards.length;
  const catalogById = new Map(input.catalog.map((extension) => [extension.extension_id, extension]));
  const ranked = [...input.activity].filter((bucket) => bucket.count > 0 && catalogById.has(bucket.extensionId)).sort((left, right) => right.count - left.count || left.extensionId.localeCompare(right.extensionId));
  for (const bucket of ranked) {
    const catalog = catalogById.get(bucket.extensionId);
    if (!catalog) continue;
    add({ catalog, placement: null, featured: false, basis: "activity", reason: commandsCheckedLabel(bucket.count) });
  }
  const isActive = input.isActive ?? (() => false);
  const starters = STARTER_SPOTLIGHT_IDS.map((extensionId) => catalogById.get(extensionId)).filter((catalog) => catalog !== void 0);
  for (const catalog of [...starters.filter((c) => !isActive(c)), ...starters.filter((c) => isActive(c))]) {
    add({ catalog, placement: null, featured: false, basis: "starter", reason: null });
  }
  for (const catalog of input.catalog) {
    add({ catalog, placement: null, featured: false, basis: "starter", reason: null });
  }
  return {
    cards,
    lead: paidCount > 0 ? "paid" : cards.some((card) => card.basis === "activity") ? "activity" : "starter",
    vacant: paidCount === 0
  };
}
function allCardsActive(cards, isActive) {
  const organic = cards.filter((card) => card.basis !== "paid");
  return organic.length > 0 && organic.every((card) => isActive(card.catalog));
}
function spotlightHeading(lead, allActive = false) {
  if (lead === "paid") {
    return {
      title: "Featured by their makers",
      basis: "Paid placements are labeled. They change position here, never your protection."
    };
  }
  if (lead === "activity") {
    return {
      title: "Busiest tools on this device",
      basis: `Counted from Guard's own decisions over the last ${SPOTLIGHT_ACTIVITY_DAYS} days.`
    };
  }
  if (allActive) {
    return {
      title: "Already covering the basics",
      basis: "These are on, and Guard checks them on every command. Not a ranking or a popularity measure."
    };
  }
  return {
    title: "Good places to start",
    basis: "A starting selection from the built-in catalog. Not a ranking or a popularity measure."
  };
}
const SHELF_SLOT_PRODUCTS = ["always", "time_slot"];
const CATALOG_SLOT_PRODUCTS = ["sponsored"];
function forProducts(offers, products) {
  return offers.filter((offer) => products.includes(offer.product));
}
function slotState(input) {
  if (input.status === "loading" || input.status === "opt-out") return "hidden";
  const known = forProducts(input.offers, input.products).filter((offer) => offer.availability !== "unknown");
  if (known.length === 0) return "unconfirmed";
  return known.some((offer) => offer.availability === "open") ? "open" : "sold-out";
}
function quotedSlotOffer(offers, products) {
  const rank = (offer) => products.indexOf(offer.product);
  const priced = (offer) => offer.indicativeAmountCents !== null && !!offer.currency;
  const candidates = forProducts(offers, products).filter((offer) => offer.availability === "open").sort((left, right) => {
    if (priced(left) !== priced(right)) return priced(left) ? -1 : 1;
    if (priced(left) && priced(right)) {
      const difference = left.indicativeAmountCents - right.indicativeAmountCents;
      if (difference !== 0) return difference;
    }
    return rank(left) - rank(right);
  });
  return candidates[0] ?? null;
}
function slotStartingPrice(offers, products) {
  const quoted = quotedSlotOffer(offers, products);
  if (!quoted || quoted.indicativeAmountCents === null || !quoted.currency) return null;
  const cents = quoted.indicativeAmountCents;
  try {
    return new Intl.NumberFormat("en-US", {
      style: "currency",
      currency: quoted.currency.toUpperCase(),
      maximumFractionDigits: cents % 100 === 0 ? 0 : 2
    }).format(cents / 100);
  } catch {
    return null;
  }
}
function slotInventory(offers, products) {
  const soldOut = forProducts(offers, products).filter((offer) => offer.availability === "sold_out").sort((left, right) => products.indexOf(left.product) - products.indexOf(right.product));
  const quoted = quotedSlotOffer(offers, products) ?? soldOut[0] ?? null;
  if (!quoted || quoted.openSlots === null || quoted.totalSlots === null) return null;
  if (quoted.totalSlots < 1) return null;
  return { open: quoted.openSlots, total: quoted.totalSlots };
}
function slotInventoryLabel(offers, products) {
  const inventory = slotInventory(offers, products);
  if (!inventory) return null;
  return `${inventory.open} of ${inventory.total} open.`;
}
function spotlightActivityFromDimensions(buckets) {
  return buckets.filter((bucket) => typeof bucket.value === "string" && Number.isFinite(bucket.count)).map((bucket) => ({ extensionId: bucket.value, count: Math.max(0, Math.trunc(bucket.count)) }));
}
function SponsorLine(props) {
  const brand = props.placement.creative.brandName?.trim();
  const window2 = featuredWindowLabel(props.placement);
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap items-center gap-x-2 gap-y-1", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "guard-sponsor-label guard-sponsor-label-inverse", "data-sponsored-label": true, children: sponsoredCardLabel(props.featured) }),
    brand ? /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { className: "text-xs text-white/70", children: [
      "Paid for by ",
      /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "font-semibold text-white", children: brand })
    ] }) : null,
    window2 ? /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { className: "inline-flex items-center gap-1 text-xs text-white/70", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniClock, { className: "size-3.5", "aria-hidden": "true" }),
      window2
    ] }) : null
  ] });
}
function PaidSpotlightCard(props) {
  const ref = reactExports.useRef(null);
  const recordOpen = useDiscoveryMeasurement(
    ref,
    props.snapshotId,
    props.placement,
    props.card.featured ? "extensions_featured" : "extensions_feed"
  );
  const { catalog } = props.card;
  const headline = props.placement.creative.headline?.trim() || catalog.name;
  return /* @__PURE__ */ jsxRuntimeExports.jsxs(
    "article",
    {
      ref,
      className: "guard-spotlight-card guard-spotlight-card-paid",
      "data-testid": props.card.featured ? "discovery-featured-card" : "discovery-sponsored-card",
      "data-sponsored-placement-id": props.placement.publicPlacementId,
      children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-start gap-3", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx(
            ExtensionBrandMark,
            {
              extension_id: catalog.extension_id,
              name: catalog.name,
              executables: catalog.executables,
              ecosystem_ids: catalog.ecosystem_ids,
              size: "md"
            }
          ),
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "min-w-0 flex-1", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx(SponsorLine, { placement: props.placement, featured: props.card.featured }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("h3", { className: "mt-2 text-balance text-lg font-semibold leading-snug tracking-tight text-white", children: headline }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-0.5 text-xs font-medium text-white/60", children: catalog.name })
          ] })
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "line-clamp-3 text-sm leading-5 text-white/85", children: props.placement.creative.body }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-auto", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsxs(
            "button",
            {
              type: "button",
              className: "guard-discover-cta guard-discover-cta-inverse",
              onClick: () => {
                recordOpen();
                props.onOpen(catalog);
              },
              children: [
                "View extension",
                /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniArrowRight, { className: "size-4", "aria-hidden": "true" })
              ]
            }
          ),
          /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-2 text-xs text-white/55", children: "Paid placement. Your protection settings are unchanged." })
        ] })
      ]
    }
  );
}
function OrganicSpotlightCard(props) {
  const { catalog, reason, basis } = props.card;
  const protection = protectionLine(catalog);
  const rules = ruleCountLabel(catalog);
  return /* @__PURE__ */ jsxRuntimeExports.jsxs(
    "article",
    {
      className: "guard-spotlight-card",
      "data-testid": "spotlight-organic-card",
      "data-basis": basis,
      "data-active": props.active ? "true" : "false",
      children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-start gap-3", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx(
            ExtensionBrandMark,
            {
              extension_id: catalog.extension_id,
              name: catalog.name,
              executables: catalog.executables,
              ecosystem_ids: catalog.ecosystem_ids,
              size: "md"
            }
          ),
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "min-w-0 flex-1", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-start justify-between gap-2", children: [
              /* @__PURE__ */ jsxRuntimeExports.jsx("h3", { className: "text-base font-semibold leading-snug tracking-tight text-brand-dark", children: catalog.name }),
              /* @__PURE__ */ jsxRuntimeExports.jsx(
                "span",
                {
                  className: props.active ? "guard-spotlight-state guard-spotlight-state-on" : "guard-spotlight-state",
                  "data-testid": "spotlight-organic-state",
                  children: props.active ? "On" : "Off"
                }
              )
            ] }),
            reason ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1 font-mono text-xs tabular-nums text-brand-dark/55", children: reason }) : rules ? /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "mt-1 text-xs text-brand-dark/55", children: [
              rules,
              " in the built-in catalog"
            ] }) : /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1 text-xs text-brand-dark/55", children: "Built-in coverage, ready to review" })
          ] })
        ] }),
        protection ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm leading-5 text-brand-dark/85", "data-testid": "spotlight-organic-protection", children: protection }) : /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "line-clamp-2 text-sm leading-5 text-brand-dark/65", children: catalog.description }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-auto", children: /* @__PURE__ */ jsxRuntimeExports.jsxs("button", { type: "button", className: "guard-discover-cta guard-discover-cta-quiet", onClick: () => props.onOpen(catalog), children: [
          props.active ? "Review protection" : "Set it up",
          /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniArrowRight, { className: "size-4", "aria-hidden": "true" })
        ] }) })
      ]
    }
  );
}
function VacantSlotCard(props) {
  return /* @__PURE__ */ jsxRuntimeExports.jsxs(
    "article",
    {
      className: "guard-spotlight-card guard-spotlight-slot",
      "data-testid": "spotlight-slot-card",
      "data-state": props.state,
      "data-full": props.full ? "true" : void 0,
      "aria-labelledby": "spotlight-slot-heading",
      children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-center gap-2", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "guard-spotlight-slot-mark guard-spotlight-slot-mark-sm", "aria-hidden": "true", children: /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniPlus, { className: "size-4" }) }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs font-semibold uppercase tracking-[0.14em] text-brand-blue", children: props.state === "open" ? "This slot is open" : "Promote your extension" })
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("h3", { id: "spotlight-slot-heading", className: "text-base font-semibold leading-snug tracking-tight text-brand-dark", children: "Put your extension on this shelf." }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "text-sm leading-5 text-brand-dark/75", children: [
          "Labeled Sponsored. Never changes anyone’s protection.",
          props.inventory ? /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { className: "font-semibold text-brand-dark", children: [
            " ",
            props.inventory
          ] }) : null
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-auto", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsxs(
            "a",
            {
              className: "guard-discover-cta",
              href: advertiseUrl("extensions_header"),
              target: "_blank",
              rel: "noopener noreferrer",
              referrerPolicy: "no-referrer",
              children: [
                props.price ? `Take this slot · from ${props.price}/mo` : "Take this slot",
                /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniArrowTopRightOnSquare, { className: "size-4", "aria-hidden": "true" })
              ]
            }
          ),
          /* @__PURE__ */ jsxRuntimeExports.jsx(SlotFreePath, { placement: "extensions_header" })
        ] })
      ]
    }
  );
}
function SlotFreePath(props) {
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "mt-2 text-xs text-brand-dark/50", children: [
    "Already listed?",
    " ",
    /* @__PURE__ */ jsxRuntimeExports.jsx(
      "a",
      {
        className: "font-semibold text-brand-blue hover:underline",
        href: advertiseUrl(props.placement, void 0, "claim"),
        target: "_blank",
        rel: "noopener noreferrer",
        referrerPolicy: "no-referrer",
        children: "Claim it free"
      }
    ),
    ". Not listed yet?",
    " ",
    /* @__PURE__ */ jsxRuntimeExports.jsx(
      "a",
      {
        className: "font-semibold text-brand-blue hover:underline",
        href: "https://github.com/hashgraph-online/hol-guard/blob/main/CONTRIBUTING.md",
        target: "_blank",
        rel: "noopener noreferrer",
        referrerPolicy: "no-referrer",
        children: "Submit it free"
      }
    ),
    "."
  ] });
}
function SpotlightSkeleton() {
  return /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "guard-spotlight-grid mt-5", "aria-hidden": "true", children: [0, 1, 2].map((cell) => /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "guard-spotlight-card guard-spotlight-skeleton min-h-40" }, cell)) });
}
function withoutWeakestOrganic(cards) {
  if (cards.length < SPOTLIGHT_CELL_COUNT) return cards;
  let weakest = -1;
  cards.forEach((card, index) => {
    if (!card.placement) weakest = index;
  });
  if (weakest < 0) return cards;
  return [...cards.slice(0, weakest), ...cards.slice(weakest + 1)];
}
function ExtensionsSpotlight(props) {
  const { isExtensionActive } = props;
  const spotlight = reactExports.useMemo(
    () => buildSpotlight({
      featured: props.featured,
      sponsored: props.sponsored,
      activity: props.activity,
      catalog: props.catalogExtensions,
      isActive: isExtensionActive
    }),
    [isExtensionActive, props.activity, props.catalogExtensions, props.featured, props.sponsored]
  );
  const slot = slotState({ status: props.status, offers: props.offers, products: SHELF_SLOT_PRODUCTS });
  const price = reactExports.useMemo(() => slotStartingPrice(props.offers, SHELF_SLOT_PRODUCTS), [props.offers]);
  const inventory = reactExports.useMemo(() => slotInventoryLabel(props.offers, SHELF_SLOT_PRODUCTS), [props.offers]);
  const waiting = !props.settled || props.status === "loading";
  const showSlot = slot === "open" || slot === "unconfirmed";
  const cards = showSlot ? withoutWeakestOrganic(spotlight.cards) : spotlight.cards;
  const heading = spotlightHeading(spotlight.lead, allCardsActive(cards, isExtensionActive));
  if (props.catalogExtensions.length === 0) return null;
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("section", { className: "mt-6", "aria-labelledby": "extensions-spotlight-heading", "data-testid": "extensions-spotlight", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-col gap-1", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("h2", { id: "extensions-spotlight-heading", className: "text-xl font-semibold tracking-tight text-brand-dark", children: waiting ? "Extensions to look at" : heading.title }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "max-w-[72ch] text-sm leading-6 text-brand-dark/60", "data-testid": "spotlight-basis", children: waiting ? " " : heading.basis })
    ] }),
    waiting ? /* @__PURE__ */ jsxRuntimeExports.jsx(SpotlightSkeleton, {}) : /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "guard-spotlight-grid mt-5", children: [
      cards.map((card) => card.placement ? /* @__PURE__ */ jsxRuntimeExports.jsx(
        PaidSpotlightCard,
        {
          card,
          placement: card.placement,
          snapshotId: props.snapshotId,
          onOpen: props.onOpenExtension
        },
        card.catalog.extension_id
      ) : /* @__PURE__ */ jsxRuntimeExports.jsx(
        OrganicSpotlightCard,
        {
          card,
          active: isExtensionActive(card.catalog),
          onOpen: props.onOpenExtension
        },
        card.catalog.extension_id
      )),
      showSlot ? /* @__PURE__ */ jsxRuntimeExports.jsx(
        VacantSlotCard,
        {
          state: slot === "open" ? "open" : "unconfirmed",
          price,
          inventory,
          full: cards.length >= SPOTLIGHT_CELL_COUNT
        }
      ) : null
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsx(SpotlightStatusLine, { status: props.status })
  ] });
}
function SpotlightStatusLine(props) {
  if (props.status === "loading") return null;
  if (props.status === "ready") {
    return /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-4 text-xs text-brand-dark/45", "data-testid": "discovery-status-ready", children: "Sponsored placements, when present, are labeled and never change protection." });
  }
  if (props.status === "opt-out") {
    return /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-4 text-xs text-brand-dark/45", "data-testid": "discovery-status-optout", children: "Sponsored discovery is turned off for this device. Extension management is unaffected." });
  }
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "mt-4 text-xs text-brand-dark/45", "data-testid": `discovery-status-${props.status}`, children: [
    "Paid placements could not be loaded right now.",
    " ",
    /* @__PURE__ */ jsxRuntimeExports.jsx(
      "a",
      {
        className: "font-semibold text-brand-blue hover:underline",
        href: advertiseUrl("extensions_header"),
        target: "_blank",
        rel: "noopener noreferrer",
        referrerPolicy: "no-referrer",
        children: "About sponsorships"
      }
    )
  ] });
}
function CatalogSlotRow(props) {
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "guard-catalog-slot-row", "data-testid": "catalog-slot-row", "data-state": props.state, children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "guard-spotlight-slot-mark", "aria-hidden": "true", children: /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniPlus, { className: "size-5" }) }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "min-w-0 max-w-[62ch] flex-[1_1_16rem]", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm font-semibold text-brand-dark", children: "Put your extension in this list." }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "mt-0.5 text-sm leading-6 text-brand-dark/65", children: [
        "Sponsored listings sit inside the catalog, keep their real protection state and their Sponsored label. Position is all they buy.",
        props.inventory ? /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { className: "font-semibold text-brand-dark", children: [
          " ",
          props.inventory
        ] }) : null
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsx(SlotFreePath, { placement: "extensions_feed" })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs(
      "a",
      {
        className: "guard-discover-cta shrink-0 sm:ml-auto",
        href: advertiseUrl("extensions_feed"),
        target: "_blank",
        rel: "noopener noreferrer",
        referrerPolicy: "no-referrer",
        children: [
          props.price ? `Get this spot · from ${props.price}/mo` : "Get this spot",
          /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniArrowTopRightOnSquare, { className: "size-4", "aria-hidden": "true" })
        ]
      }
    )
  ] });
}
const TOP_LIMIT = 12;
function useExtensionPopularity(active) {
  const [state, setState] = reactExports.useState({ counts: [], settled: false });
  reactExports.useEffect(() => {
    if (!active) return;
    const controller = new AbortController();
    const client = createCommandActivityClient(fetchCommandActivityApi);
    void client.fetchAnalytics(
      { days: SPOTLIGHT_ACTIVITY_DAYS, top_limit: TOP_LIMIT, dimension: null, dimension_value: null },
      controller.signal
    ).then((analytics) => {
      if (controller.signal.aborted) return;
      setState({ counts: spotlightActivityFromDimensions(analytics.dimensions.extension), settled: true });
    }).catch(() => {
      if (!controller.signal.aborted) setState({ counts: [], settled: true });
    });
    return () => controller.abort();
  }, [active]);
  return state;
}
const digest = (value) => typeof value === "string" && /^[a-f0-9]{64}$/.test(value);
const record = (value) => Boolean(value) && typeof value === "object" && !Array.isArray(value);
const integer = (value) => typeof value === "number" && Number.isSafeInteger(value) && value >= 0;
async function request(payload, signal) {
  const response = await fetchLocalCliApi("/v1/local-clis/skills", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
    signal
  });
  const body = await response.json();
  if (!response.ok) throw new Error(record(body) && typeof body.message === "string" ? body.message : "Could not read skill metadata.");
  if (!record(body)) throw new Error("Invalid skill metadata response");
  return body;
}
async function fetchLocalSkillRoots(signal) {
  const body = await request({ operation: "roots" }, signal);
  if (!Array.isArray(body.roots) || body.roots.length > 16 || body.permissions_granted !== false) throw new Error("Invalid skill roots");
  return body.roots.map((root) => {
    if (!record(root) || !digest(root.root_id) || typeof root.path !== "string" || root.path.length > 4096 || typeof root.available !== "boolean") throw new Error("Invalid skill root");
    return { root_id: root.root_id, path: root.path, available: root.available };
  });
}
async function scanLocalSkillMetadata(rootIds, signal) {
  if (signal.aborted) return;
  const job = await startCancelableDiscoveryJob(signal, (clientJobId) => request(
    { operation: "scan", confirm_metadata_read: true, approved_root_ids: rootIds, client_job_id: clientJobId },
    signal
  ));
  if (job === null) return;
  await waitForMcpDiscoveryJob("inventory:skills", job, signal);
}
async function fetchLocalSkillPage(options) {
  const body = await request({
    operation: "list",
    offset: options.offset,
    search: options.search,
    ...options.revision === void 0 ? {} : { revision: options.revision }
  }, options.signal);
  if (!Array.isArray(body.skills) || body.skills.length > 50 || body.permissions_granted !== false || !integer(body.known_count) || body.known_count > 1e3 || !integer(body.matched_count) || body.matched_count > body.known_count || !integer(body.revision) || !integer(body.issue_count) || typeof body.complete !== "boolean" || body.next_offset !== null && body.next_offset !== options.offset + 50) {
    throw new Error("Invalid skill inventory");
  }
  const skills = body.skills.map((skill) => {
    if (!record(skill) || !digest(skill.skill_id) || !digest(skill.root_id) || !digest(skill.metadata_digest) || skill.origin !== "local-agent-skill" || skill.permission_state !== "not-granted" || skill.requirements_complete !== false || skill.instruction_content_loaded !== false || typeof skill.name !== "string" || skill.name.length > 64 || !/^[a-z0-9]+(?:-[a-z0-9]+)*$/.test(skill.name) || typeof skill.description !== "string" || skill.description.length > 1024 || typeof skill.uri !== "string" || !skill.uri.startsWith("file://") || skill.uri.length > 8192 || typeof skill.compatibility !== "string" || skill.compatibility.length > 500 || typeof skill.requested_tools !== "string" || skill.requested_tools.length > 2048 || typeof skill.duplicate_name !== "boolean") throw new Error("Invalid local skill evidence");
    return {
      skill_id: skill.skill_id,
      root_id: skill.root_id,
      metadata_digest: skill.metadata_digest,
      name: skill.name,
      description: skill.description,
      uri: skill.uri,
      compatibility: skill.compatibility,
      requested_tools: skill.requested_tools,
      duplicate_name: skill.duplicate_name
    };
  });
  return {
    skills,
    known_count: body.known_count,
    matched_count: body.matched_count,
    revision: body.revision,
    next_offset: body.next_offset,
    complete: body.complete,
    issue_count: body.issue_count
  };
}
async function prepareSkillWorkflow(skillId, signal) {
  if (signal.aborted) return null;
  const job = await startCancelableDiscoveryJob(signal, (clientJobId) => request(
    { operation: "preflight", skill_id: skillId, confirm_directory_read: true, client_job_id: clientJobId },
    signal
  ));
  if (job === null) return null;
  await waitForMcpDiscoveryJob(`skill:${skillId}`, job, signal);
  if (signal.aborted) return null;
  const body = await request({ operation: "preflight-result", skill_id: skillId }, signal);
  if (body.skill_id !== skillId || body.schema_version !== "guard.workflow-preflight.v1" || body.dependency_source !== "guard-extension" || !["absent", "invalid", "declared"].includes(String(body.dependency_status)) || !integer(body.authority_revision) || !integer(body.expires_in_seconds) || body.expires_in_seconds > 30 || body.requirements_complete !== false || body.permissions_granted !== false || body.runtime_checks_required !== true || !Array.isArray(body.requirements) || body.requirements.length > 50 || !record(body.inspection) || !["complete", "incomplete"].includes(String(body.inspection.status)) || !integer(body.inspection.entry_count) || body.inspection.permissions_granted !== false || body.inspection.status === "complete" && (typeof body.inspection.manifest_digest !== "string" || !/^sha256:[a-f0-9]{64}$/.test(body.inspection.manifest_digest))) throw new Error("Invalid workflow preflight");
  const requirements = body.requirements.map((entry) => {
    if (!record(entry) || typeof entry.connection_id !== "string" || !isLocalCliId(entry.connection_id) || typeof entry.tool_name !== "string" || !/^[A-Za-z0-9][A-Za-z0-9_.:-]{0,255}$/.test(entry.tool_name) || !["saved-allow", "deny", "ask", "unresolved"].includes(String(entry.state))) throw new Error("Invalid workflow requirement");
    return {
      connection_id: entry.connection_id,
      tool_name: entry.tool_name,
      state: entry.state
    };
  });
  const native = normalizeLocalCliList({
    schema_version: "guard.daemon.local-clis.v1",
    revision: body.authority_revision,
    items: [],
    native_publication: body.native_publication
  }).native_publication;
  return {
    skill_id: skillId,
    dependency_status: body.dependency_status,
    authority_revision: body.authority_revision,
    requirements,
    native_state: native?.state ?? "unavailable",
    inspection: {
      status: body.inspection.status,
      entry_count: body.inspection.entry_count,
      manifest_digest: typeof body.inspection.manifest_digest === "string" ? body.inspection.manifest_digest : null
    },
    expires_at: performance.now() + body.expires_in_seconds * 1e3
  };
}
function LocalSkillsWorkspace() {
  const [open, setOpen] = reactExports.useState(false);
  const [roots, setRoots] = reactExports.useState([]);
  const [selected, setSelected] = reactExports.useState([]);
  const [page, setPage] = reactExports.useState(null);
  const [offset, setOffset] = reactExports.useState(0);
  const [input, setInput] = reactExports.useState("");
  const [search, setSearch] = reactExports.useState("");
  const [reload, setReload] = reactExports.useState(0);
  const [busy, setBusy] = reactExports.useState(false);
  const [loading, setLoading] = reactExports.useState(false);
  const [error, setError] = reactExports.useState(null);
  const [preparing, setPreparing] = reactExports.useState(null);
  const [preflights, setPreflights] = reactExports.useState({});
  const revision = reactExports.useRef(void 0);
  const scan = reactExports.useRef(null);
  reactExports.useEffect(() => () => scan.current?.abort(), []);
  reactExports.useEffect(() => {
    if (input === search) return;
    const timer = window.setTimeout(() => {
      setSearch(input);
      setOffset(0);
    }, 250);
    return () => window.clearTimeout(timer);
  }, [input, search]);
  reactExports.useEffect(() => {
    if (!open) return;
    const controller = new AbortController();
    setLoading(true);
    setError(null);
    void Promise.all([
      fetchLocalSkillRoots(controller.signal),
      fetchLocalSkillPage({ offset, search, revision: offset > 0 ? revision.current : void 0, signal: controller.signal })
    ]).then(([nextRoots, nextPage]) => {
      if (!controller.signal.aborted) {
        setRoots(nextRoots);
        setPage(nextPage);
        revision.current = nextPage.revision;
      }
    }).catch((caught) => {
      if (!controller.signal.aborted) setError(caught instanceof Error ? caught.message : "Could not load skill metadata.");
    }).finally(() => {
      if (!controller.signal.aborted) setLoading(false);
    });
    return () => controller.abort();
  }, [open, offset, search, reload]);
  const readMetadata = async () => {
    const controller = new AbortController();
    scan.current = controller;
    setBusy(true);
    setError(null);
    try {
      await scanLocalSkillMetadata(selected, controller.signal);
      if (!controller.signal.aborted) {
        setOffset(0);
        setPreflights({});
        setReload((value) => value + 1);
      }
    } catch (caught) {
      if (!controller.signal.aborted) setError(caught instanceof Error ? caught.message : "Skill discovery did not finish.");
    } finally {
      setBusy(false);
      if (scan.current === controller) scan.current = null;
    }
  };
  const prepareWorkflow = async (skillId) => {
    const controller = new AbortController();
    scan.current = controller;
    setPreparing(skillId);
    setError(null);
    try {
      const result = await prepareSkillWorkflow(skillId, controller.signal);
      if (result) setPreflights((current) => ({ ...current, [skillId]: result }));
    } catch (caught) {
      if (!controller.signal.aborted) setError(caught instanceof Error ? caught.message : "Could not prepare this workflow.");
    } finally {
      setPreparing(null);
      if (scan.current === controller) scan.current = null;
    }
  };
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("details", { className: "mt-8 border-b border-slate-200 pb-5", onToggle: (event) => setOpen(event.currentTarget.open), children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx("summary", { className: "min-h-11 cursor-pointer py-3 text-base font-semibold text-brand-dark", children: "Local skills and workflows" }),
    open ? /* @__PURE__ */ jsxRuntimeExports.jsxs("section", { "aria-label": "Local skill metadata", "aria-busy": busy || loading || preparing !== null, children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "max-w-2xl text-sm leading-6 text-brand-dark/75", children: "Choose the skill folders Guard may inspect. This reads bounded names and descriptions. Instructions and scripts stay unloaded; declared tools remain requests for permission." }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("fieldset", { disabled: busy || loading || preparing !== null, className: "mt-4", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("legend", { className: "text-sm font-semibold text-brand-dark", children: "Folders to read" }),
        roots.map((root) => /* @__PURE__ */ jsxRuntimeExports.jsxs("label", { className: "mt-2 flex min-h-11 items-center gap-3 text-sm text-brand-dark/75", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx(
            "input",
            {
              type: "checkbox",
              checked: selected.includes(root.root_id),
              disabled: !root.available,
              onChange: (event) => setSelected((current) => event.target.checked ? [...current, root.root_id] : current.filter((id) => id !== root.root_id))
            }
          ),
          /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { className: "break-all", children: [
            root.path,
            root.available ? "" : " · Not available"
          ] })
        ] }, root.root_id))
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-3 flex flex-wrap gap-3", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(
          "button",
          {
            type: "button",
            disabled: busy || loading || preparing !== null || selected.length === 0,
            onClick: () => void readMetadata(),
            className: "min-h-11 rounded-xl border border-slate-300 px-4 text-sm font-semibold text-brand-dark disabled:opacity-50",
            children: busy ? "Reading skill metadata…" : "Read selected skill metadata"
          }
        ),
        busy ? /* @__PURE__ */ jsxRuntimeExports.jsx(
          "button",
          {
            type: "button",
            onClick: () => scan.current?.abort(),
            className: "min-h-11 rounded-xl border border-slate-300 px-4 text-sm font-semibold text-brand-dark",
            children: "Cancel skill scan"
          }
        ) : null
      ] }),
      error ? /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { role: "alert", className: "mt-3 text-sm leading-6 text-red-700", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { children: error }),
        /* @__PURE__ */ jsxRuntimeExports.jsx(
          "button",
          {
            type: "button",
            onClick: () => {
              setOffset(0);
              setReload((value) => value + 1);
            },
            className: "mt-2 min-h-11 rounded-xl border border-slate-300 px-4 font-semibold text-brand-dark",
            children: "Reload skill metadata"
          }
        )
      ] }) : null,
      page && page.revision > 0 ? /* @__PURE__ */ jsxRuntimeExports.jsxs(jsxRuntimeExports.Fragment, { children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { role: "status", className: "mt-4 text-sm leading-6 text-brand-dark/75", children: [
          page.known_count,
          " skills indexed.",
          page.complete ? "" : ` ${page.issue_count} discovery gaps; some metadata could not be indexed.`,
          " No permissions granted."
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("label", { className: "mt-4 block max-w-xl text-sm font-semibold text-brand-dark", children: [
          "Find a local skill",
          /* @__PURE__ */ jsxRuntimeExports.jsx(
            "input",
            {
              type: "search",
              value: input,
              onChange: (event) => setInput(event.target.value),
              className: "mt-2 min-h-11 w-full rounded-xl border border-slate-300 bg-white px-3 font-normal"
            }
          )
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("ul", { className: "mt-4 divide-y divide-slate-200", children: page.skills.map((skill) => /* @__PURE__ */ jsxRuntimeExports.jsxs("li", { className: "py-4", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("h3", { className: "text-sm font-semibold text-brand-dark", children: skill.name }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1 max-w-2xl text-sm leading-6 text-brand-dark/75", children: skill.description }),
          skill.duplicate_name ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-2 text-xs font-semibold text-brand-dark/75", children: "Same name found in another origin. Each copy keeps its own identity and review." }) : null,
          /* @__PURE__ */ jsxRuntimeExports.jsxs("details", { className: "mt-2 text-xs leading-5 text-brand-dark/75", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("summary", { className: "min-h-11 cursor-pointer py-3 font-semibold", children: "Origin and requirements" }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "break-all", children: skill.uri }),
            skill.compatibility ? /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "mt-2", children: [
              "Declared compatibility: ",
              skill.compatibility
            ] }) : null,
            skill.requested_tools ? /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "mt-2 break-words", children: [
              "Requested tools: ",
              skill.requested_tools
            ] }) : null,
            /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-2", children: "Requirements are incomplete. Loading this skill cannot allow its tools." })
          ] }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-2 max-w-2xl text-xs leading-5 text-brand-dark/75", children: "Prepare inspects files in this skill directory to identify its revision and check declared dependencies. It does not run scripts or activate the skill." }),
          /* @__PURE__ */ jsxRuntimeExports.jsx(
            "button",
            {
              type: "button",
              disabled: busy || preparing !== null,
              onClick: () => void prepareWorkflow(skill.skill_id),
              className: "mt-2 min-h-11 rounded-xl border border-slate-300 px-4 text-sm font-semibold text-brand-dark disabled:opacity-50",
              children: preparing === skill.skill_id ? "Preparing workflow…" : `Prepare ${skill.name}`
            }
          ),
          preparing === skill.skill_id ? /* @__PURE__ */ jsxRuntimeExports.jsx(
            "button",
            {
              type: "button",
              onClick: () => scan.current?.abort(),
              className: "ml-3 min-h-11 rounded-xl border border-slate-300 px-4 text-sm font-semibold text-brand-dark",
              children: "Cancel preparation"
            }
          ) : null,
          preflights[skill.skill_id] ? /* @__PURE__ */ jsxRuntimeExports.jsx(SkillPreflightPreview, { plan: preflights[skill.skill_id] }) : null
        ] }, skill.skill_id)) }),
        page.matched_count === 0 ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-3 text-sm text-brand-dark/75", children: "No skills match this search." }) : null,
        page.matched_count > 50 ? /* @__PURE__ */ jsxRuntimeExports.jsxs("nav", { "aria-label": "Local skill pages", className: "mt-4 flex flex-wrap items-center gap-3", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx(
            "button",
            {
              type: "button",
              disabled: offset === 0 || loading,
              onClick: () => setOffset(Math.max(0, offset - 50)),
              className: "min-h-11 rounded-xl border border-slate-300 px-4 text-sm font-semibold disabled:opacity-50",
              children: "Previous"
            }
          ),
          /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { className: "text-sm text-brand-dark/75", children: [
            "Page ",
            offset / 50 + 1
          ] }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("button", { type: "button", disabled: page.next_offset === null || loading, onClick: () => {
            if (page.next_offset !== null) setOffset(page.next_offset);
          }, className: "min-h-11 rounded-xl border border-slate-300 px-4 text-sm font-semibold disabled:opacity-50", children: "Next" })
        ] }) : null
      ] }) : null
    ] }) : null
  ] });
}
function SkillPreflightPreview({ plan }) {
  const [expired, setExpired] = reactExports.useState(false);
  reactExports.useEffect(() => {
    const remaining = plan.expires_at - performance.now();
    setExpired(remaining <= 0);
    const timer = window.setTimeout(() => setExpired(true), Math.max(0, remaining));
    return () => window.clearTimeout(timer);
  }, [plan.expires_at]);
  if (expired) return /* @__PURE__ */ jsxRuntimeExports.jsx("p", { role: "status", className: "mt-4 text-xs leading-5 text-brand-dark/75", children: "This workflow preview expired. Prepare it again to check current evidence." });
  const stateLabel = { "saved-allow": "Saved Allow · runtime checks required", deny: "Denied", ask: "Needs review", unresolved: "Not resolved" };
  const dependencyLabel = {
    declared: "Guard dependency manifest (nonstandard extension)",
    invalid: "Invalid Guard dependency manifest; review the skill's metadata.",
    absent: "No Guard dependency manifest. Requirements remain unresolved."
  }[plan.dependency_status];
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("section", { "aria-label": "Workflow preflight", className: "mt-4 border-l-2 border-brand-blue pl-4 text-xs leading-5 text-brand-dark/75", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "font-semibold", children: plan.inspection.status === "complete" ? "Skill revision inspected" : "Skill revision could not be fully inspected" }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "mt-2", children: [
      "Dependencies: ",
      dependencyLabel
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "mt-2", children: [
      "Permissions checked at revision ",
      plan.authority_revision,
      ". Native publication: ",
      plan.native_state,
      "."
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("ul", { className: "mt-3 divide-y divide-slate-200", children: plan.requirements.map((requirement) => /* @__PURE__ */ jsxRuntimeExports.jsxs("li", { className: "py-3", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "break-all font-mono", children: requirement.tool_name }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1 font-semibold", children: stateLabel[requirement.state] }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("a", { href: guardAwareHref(localCliHref(requirement.connection_id)), className: "mt-2 inline-flex min-h-11 items-center font-semibold text-brand-blue", children: "Review connection permissions" })
    ] }, `${requirement.connection_id}:${requirement.tool_name}`)) }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-2", children: "This is a preview of current evidence. Preparing grants nothing; every runtime call still checks its permissions." })
  ] });
}
const PAGE_SIZE = 25;
function HostAppTools({ app }) {
  const [shown, setShown] = reactExports.useState(PAGE_SIZE);
  if (!app.metadata_available) {
    return /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-2 text-sm text-brand-dark/80", children: "Tool summaries are unavailable for this app." });
  }
  if (app.tools.length === 0) {
    return /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-2 text-sm text-brand-dark/80", children: "Codex provided no tool summaries." });
  }
  return /* @__PURE__ */ jsxRuntimeExports.jsxs(jsxRuntimeExports.Fragment, { children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx("ul", { className: "mt-2 divide-y divide-brand-dark/10", children: app.tools.slice(0, shown).map((tool) => /* @__PURE__ */ jsxRuntimeExports.jsxs("li", { className: "py-2 text-sm text-brand-dark", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "break-words font-medium", children: tool.title ?? tool.name }),
      tool.description ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1 max-w-prose break-words leading-6 text-brand-dark/80", children: tool.description }) : null
    ] }, tool.name)) }),
    shown < app.tools.length ? /* @__PURE__ */ jsxRuntimeExports.jsxs("button", { type: "button", className: "guard-extensions-chip mt-2", onClick: () => setShown((value) => value + PAGE_SIZE), children: [
      "Show more tools for ",
      app.name
    ] }) : null
  ] });
}
function HostAppRow({ app }) {
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("details", { className: "border-b border-brand-dark/10 py-3", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("summary", { className: "cursor-pointer rounded-lg px-1 py-1 text-sm text-brand-dark focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-brand-blue", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "break-words font-semibold", children: app.name }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "ml-2 text-xs text-brand-dark/70", children: app.enabled ? "Enabled in Codex" : "Disabled in Codex" })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-2 pl-4", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "text-xs leading-5 text-brand-dark/80", children: [
        app.callable ? "Codex reports tools available." : "Codex does not report callable tools.",
        " ",
        "Permissions in Guard are unchanged."
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsx(HostAppTools, { app })
    ] })
  ] });
}
function HostInventoryApps({ inventory }) {
  const searchId = reactExports.useId();
  const [query, setQuery] = reactExports.useState("");
  const [shown, setShown] = reactExports.useState(PAGE_SIZE);
  if (inventory.apps.length === 0) {
    return /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-3 text-sm text-brand-dark/80", children: "Codex did not report any apps. Check host connections again after using an app in Codex." });
  }
  const matches = filterCodexHostApps(inventory.apps, query);
  return /* @__PURE__ */ jsxRuntimeExports.jsxs(jsxRuntimeExports.Fragment, { children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx("label", { htmlFor: searchId, className: "mt-4 block text-sm font-medium text-brand-dark", children: "Search Codex apps and tool summaries" }),
    /* @__PURE__ */ jsxRuntimeExports.jsx(
      "input",
      {
        id: searchId,
        type: "search",
        value: query,
        maxLength: 128,
        onChange: (event) => {
          setQuery(event.target.value);
          setShown(PAGE_SIZE);
        },
        className: "mt-1 w-full rounded-xl border border-brand-dark/20 bg-white px-3 py-2 text-sm text-brand-dark focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-brand-blue"
      }
    ),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "mt-2 text-xs text-brand-dark/80", role: "status", children: [
      matches.length,
      " ",
      matches.length === 1 ? "app" : "apps",
      query.trim() ? " match this search" : " in the host snapshot",
      " · Tool summaries only"
    ] }),
    matches.slice(0, shown).map((app) => /* @__PURE__ */ jsxRuntimeExports.jsx(HostAppRow, { app }, `${inventory.connection_id}:${app.app_id}`)),
    matches.length === 0 ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-3 text-sm text-brand-dark/80", children: "No Codex apps or tool summaries match this search." }) : null,
    shown < matches.length ? /* @__PURE__ */ jsxRuntimeExports.jsx("button", { type: "button", className: "guard-extensions-chip mt-3", onClick: () => setShown((value) => value + PAGE_SIZE), children: "Show more Codex apps" }) : null
  ] });
}
function CodexHostConnectors({ inventory }) {
  const headingId = reactExports.useId();
  const [reported, setReported] = reactExports.useState(Boolean(inventory));
  const [now, setNow] = reactExports.useState(Date.now);
  reactExports.useEffect(() => {
    if (!inventory) return;
    setReported(true);
    setNow(Date.now());
    const remaining = Math.max(0, Math.min(3e4, inventory.expires_at_ms - Date.now()));
    const timer = window.setTimeout(() => setNow(inventory.expires_at_ms), remaining);
    return () => window.clearTimeout(timer);
  }, [inventory?.expires_at_ms]);
  if (!inventory && !reported) return null;
  let content;
  if (!inventory || inventory.expires_at_ms <= now) {
    content = /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-3 text-sm text-brand-dark/80", role: "status", children: "Host summaries expired or are unavailable. Check host connections again." });
  } else {
    content = /* @__PURE__ */ jsxRuntimeExports.jsx(HostInventoryApps, { inventory });
  }
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("section", { className: "mt-8", "aria-labelledby": headingId, children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx("h2", { id: headingId, className: "text-xl font-semibold tracking-tight text-brand-dark", children: "Apps reported by Codex" }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1 max-w-prose text-sm leading-6 text-brand-dark/80", children: "Inspect apps and tool summaries from your existing Codex host. Guard has not verified their accounts or tool permissions. Manage tools Guard has observed under Custom extensions." }),
    content
  ] });
}
const CUSTOM_EXTENSION_PREVIEW_COUNT = 8;
const CUSTOM_EXTENSION_PAGE_SIZE = 25;
function CustomExtensionRow(props) {
  const { item, onOpen, onSetUp } = props;
  const handleOpen = reactExports.useCallback(() => {
    const setup = item.seeded === true ? profileSetupCommand(item) : null;
    if (setup !== null && onSetUp) onSetUp(setup);
    else onOpen(item.cli_id);
  }, [item, onOpen, onSetUp]);
  const action = customExtensionActionLabel(item);
  const catalog = mcpCatalogCopy(props.item);
  return /* @__PURE__ */ jsxRuntimeExports.jsx(
    ProtectionModuleRow,
    {
      extensionId: props.item.cli_id,
      name: customExtensionDisplayName(props.item),
      description: customExtensionRowDescription(props.item, catalog?.title ?? null),
      behavior: customExtensionRowBehavior(props.item),
      source: customExtensionRowSource(props.item),
      brand: props.item.brand,
      badge: customExtensionBadge(props.item) ?? void 0,
      actionLabel: action ?? void 0,
      custom: true,
      executables: [props.item.name],
      onOpen: handleOpen
    }
  );
}
function CustomExtensionEmptyState(props) {
  let title = "No custom extensions yet.";
  let detail = "Add a tool you run yourself or connect an MCP server. Connectors in your host apps appear here automatically.";
  if (props.search) {
    title = "No custom extensions match this search.";
    detail = "No connectors or custom tools match this search.";
  }
  if (props.filteredOut) {
    title = "No custom extensions match these filters.";
    detail = "Remove a filter or start over to see all custom extensions again.";
  }
  return /* @__PURE__ */ jsxRuntimeExports.jsxs(
    "div",
    {
      className: "mt-4 rounded-2xl border border-dashed border-[rgba(63,65,116,0.2)] px-4 py-5",
      "data-testid": props.filteredOut ? "custom-extensions-filter-empty" : "custom-extensions-empty",
      children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm font-semibold text-brand-dark", children: title }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1 max-w-xl text-sm leading-6 text-brand-dark/70", children: detail }),
        props.filteredOut ? props.onClearFilters ? /* @__PURE__ */ jsxRuntimeExports.jsxs("button", { type: "button", onClick: props.onClearFilters, className: "guard-extensions-chip mt-3", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniXMark, { className: "size-4", "aria-hidden": "true" }),
          "Clear filters"
        ] }) : null : props.search ? /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-3 flex flex-wrap items-center gap-3", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsxs("button", { type: "button", onClick: props.onClearSearch, className: "guard-extensions-chip", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniXMark, { className: "size-4", "aria-hidden": "true" }),
            "Clear search"
          ] }),
          props.addWithSearch ? /* @__PURE__ */ jsxRuntimeExports.jsxs("button", { type: "button", onClick: props.onAdd, className: "inline-flex min-h-11 items-center gap-2 rounded-xl border border-slate-300 bg-white px-4 text-sm font-semibold text-brand-dark", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniPlus, { className: "size-4", "aria-hidden": "true" }),
            "Add custom extension"
          ] }) : null
        ] }) : /* @__PURE__ */ jsxRuntimeExports.jsxs(jsxRuntimeExports.Fragment, { children: [
          /* @__PURE__ */ jsxRuntimeExports.jsxs("button", { type: "button", onClick: props.onAdd, className: "mt-3 inline-flex min-h-11 items-center gap-2 rounded-xl border border-slate-300 bg-white px-4 text-sm font-semibold text-brand-dark", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniPlus, { className: "size-4", "aria-hidden": "true" }),
            "Add custom extension"
          ] }),
          props.discovering ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { role: "status", className: "mt-3 text-sm text-brand-dark/75", children: "Checking host configuration for connectors…" }) : null
        ] })
      ]
    }
  );
}
function CustomExtensionsSection(props) {
  const [search, setSearch] = reactExports.useState("");
  const [showAll, setShowAll] = reactExports.useState(false);
  const [page, setPage] = reactExports.useState(0);
  const rowsId = reactExports.useId();
  const all = reactExports.useMemo(() => connectorWorkspaceItems(props.items, "", props.seededItems), [props.items, props.seededItems]);
  const added = reactExports.useMemo(
    () => search ? connectorWorkspaceItems(props.items, search, props.seededItems) : all,
    [props.items, props.seededItems, search, all]
  );
  const searchable = all.length > CUSTOM_EXTENSION_PREVIEW_COUNT || search !== "";
  const filteredOut = props.filteredOut === true && search === "";
  const needsReview = added.filter(customExtensionNeedsReview);
  const reviewed = added.filter((item) => !customExtensionNeedsReview(item));
  const grouped = needsReview.length > 0 && reviewed.length > 0;
  const pageCount = Math.max(1, Math.ceil(added.length / CUSTOM_EXTENSION_PAGE_SIZE));
  const currentPage = Math.min(page, pageCount - 1);
  const handleSearchChange = reactExports.useCallback((event) => {
    setSearch(event.target.value);
    setShowAll(false);
    setPage(0);
  }, []);
  const handleClearSearch = reactExports.useCallback(() => {
    setSearch("");
    setPage(0);
  }, []);
  const handleExpand = reactExports.useCallback(() => {
    setShowAll(true);
    setPage(0);
  }, []);
  const handleCollapse = reactExports.useCallback(() => {
    setShowAll(false);
    setPage(0);
  }, []);
  const handlePrevious = reactExports.useCallback(() => {
    if (currentPage > 0) setPage(currentPage - 1);
  }, [currentPage]);
  const handleNext = reactExports.useCallback(() => {
    if (currentPage < pageCount - 1) setPage(currentPage + 1);
  }, [currentPage, pageCount]);
  const start = showAll ? currentPage * CUSTOM_EXTENSION_PAGE_SIZE : 0;
  const visible = added.slice(start, start + (showAll ? CUSTOM_EXTENSION_PAGE_SIZE : CUSTOM_EXTENSION_PREVIEW_COUNT));
  const visibleNeedsReview = grouped ? visible.filter(customExtensionNeedsReview) : visible;
  const visibleReviewed = grouped ? visible.filter((item) => !customExtensionNeedsReview(item)) : [];
  const unit = added.length === 1 ? "extension" : "extensions";
  const firstRun = all.length === 0 && search === "" && !filteredOut;
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("section", { className: props.embedded ? "mt-4" : "mt-10", "aria-labelledby": "custom-extensions-heading", "data-testid": "custom-extensions-section", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-col gap-3 sm:flex-row sm:items-end sm:justify-between", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(
          "h2",
          {
            id: "custom-extensions-heading",
            className: props.embedded ? "sr-only" : "text-xl font-semibold tracking-tight text-brand-dark",
            children: "Custom extensions"
          }
        ),
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: props.embedded ? "max-w-xl text-sm text-slate-500" : "mt-1 max-w-xl text-sm text-slate-500", children: "Connectors Guard detected in your apps, plus tools you add yourself. Open one to choose its permissions." })
      ] }),
      firstRun || props.embedded ? null : /* @__PURE__ */ jsxRuntimeExports.jsxs("button", { type: "button", onClick: props.onAdd, className: "inline-flex min-h-11 shrink-0 items-center gap-2 self-start rounded-xl px-3 text-sm font-semibold text-brand-blue sm:self-end", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniPlus, { className: "size-4", "aria-hidden": "true" }),
        "Add custom extension"
      ] })
    ] }),
    props.discoveryControl ? /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-2", children: props.discoveryControl }) : null,
    searchable ? /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-4", children: /* @__PURE__ */ jsxRuntimeExports.jsxs("label", { className: "relative block w-full max-w-sm", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "sr-only", children: "Search custom extensions" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniMagnifyingGlass, { className: "pointer-events-none absolute left-3 top-1/2 size-4 -translate-y-1/2 text-brand-dark/55", "aria-hidden": "true" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx(
        "input",
        {
          type: "search",
          value: search,
          onChange: handleSearchChange,
          placeholder: "Search connectors",
          className: "min-h-11 w-full rounded-xl border border-slate-300 bg-white pl-9 pr-3 text-sm font-normal text-brand-dark"
        }
      )
    ] }) }) : null,
    added.length === 0 ? /* @__PURE__ */ jsxRuntimeExports.jsx(
      CustomExtensionEmptyState,
      {
        search,
        filteredOut,
        discovering: props.discovering,
        onAdd: props.onAdd,
        onClearFilters: props.onClearFilters,
        onClearSearch: handleClearSearch,
        addWithSearch: props.embedded === true && props.addInEmptyState === true
      }
    ) : /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-4", id: rowsId, children: [
      grouped && visibleNeedsReview.length > 0 ? /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "text-xs font-semibold text-brand-dark/55", children: [
        "Needs review · ",
        needsReview.length
      ] }) : null,
      visibleNeedsReview.map((item) => /* @__PURE__ */ jsxRuntimeExports.jsx(CustomExtensionRow, { item, onOpen: props.onOpen, onSetUp: props.onSetUp }, item.cli_id)),
      grouped && visibleReviewed.length > 0 ? /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "mt-6 text-xs font-semibold text-brand-dark/55", children: [
        "Reviewed · ",
        reviewed.length
      ] }) : null,
      visibleReviewed.map((item) => /* @__PURE__ */ jsxRuntimeExports.jsx(CustomExtensionRow, { item, onOpen: props.onOpen, onSetUp: props.onSetUp }, item.cli_id)),
      !showAll && added.length > visible.length ? /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-4 flex flex-wrap items-center gap-3", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(
          "button",
          {
            type: "button",
            onClick: handleExpand,
            "aria-controls": rowsId,
            className: "min-h-11 rounded-xl border border-slate-300 bg-white px-4 text-sm font-semibold text-brand-dark",
            children: added.length > CUSTOM_EXTENSION_PAGE_SIZE ? `Browse all ${added.length} ${unit}` : `Show all ${added.length} ${unit}`
          }
        ),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "text-sm text-brand-dark/70", children: [
          "Showing ",
          visible.length,
          " of ",
          added.length,
          ". Search to narrow the list."
        ] })
      ] }) : null,
      showAll && added.length > CUSTOM_EXTENSION_PREVIEW_COUNT ? /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-4 flex flex-wrap items-center gap-3", children: [
        pageCount > 1 ? /* @__PURE__ */ jsxRuntimeExports.jsxs("nav", { "aria-label": "Custom extension pages", className: "flex flex-wrap items-center gap-3", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx(
            "button",
            {
              type: "button",
              "aria-disabled": currentPage === 0,
              "aria-controls": rowsId,
              onClick: handlePrevious,
              className: "min-h-11 rounded-xl border border-slate-300 bg-white px-4 text-sm font-semibold text-brand-dark aria-disabled:opacity-50",
              children: "Previous page"
            }
          ),
          /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { role: "status", className: "text-sm text-brand-dark/70 tabular-nums", children: [
            "Page ",
            currentPage + 1,
            " of ",
            pageCount,
            " · Showing ",
            start + 1,
            "–",
            start + visible.length,
            " of ",
            added.length
          ] }),
          /* @__PURE__ */ jsxRuntimeExports.jsx(
            "button",
            {
              type: "button",
              "aria-disabled": currentPage === pageCount - 1,
              "aria-controls": rowsId,
              onClick: handleNext,
              className: "min-h-11 rounded-xl border border-slate-300 bg-white px-4 text-sm font-semibold text-brand-dark aria-disabled:opacity-50",
              children: "Next page"
            }
          )
        ] }) : null,
        /* @__PURE__ */ jsxRuntimeExports.jsx(
          "button",
          {
            type: "button",
            onClick: handleCollapse,
            "aria-controls": rowsId,
            className: "min-h-11 rounded-xl border border-slate-300 bg-white px-4 text-sm font-semibold text-brand-dark",
            children: "Show fewer"
          }
        )
      ] }) : null
    ] })
  ] });
}
function ExtensionListSwitch(props) {
  const options = [
    { view: "builtin", label: "All tools", count: props.builtinCount, panelId: props.builtinPanelId, attention: 0 },
    {
      view: "custom",
      label: "Custom extensions",
      count: props.customCount,
      panelId: props.customPanelId,
      attention: props.customNeedsReviewCount
    }
  ];
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "guard-list-switch", "data-testid": "extension-list-switch", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "guard-list-switch-track", role: "group", "aria-label": "Extension list", children: options.map((option) => /* @__PURE__ */ jsxRuntimeExports.jsxs(
      "button",
      {
        type: "button",
        className: "guard-list-switch-option",
        "aria-pressed": props.view === option.view,
        "aria-controls": option.panelId,
        "data-view": option.view,
        onClick: () => props.onViewChange(option.view),
        children: [
          option.label,
          /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "guard-list-switch-count", children: option.count.toLocaleString() }),
          option.attention > 0 ? /* @__PURE__ */ jsxRuntimeExports.jsxs(jsxRuntimeExports.Fragment, { children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "guard-list-switch-dot", "aria-hidden": "true" }),
            /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { className: "sr-only", children: [
              option.attention.toLocaleString(),
              " need review"
            ] })
          ] }) : null
        ]
      },
      option.view
    )) }),
    props.onAddCustom ? /* @__PURE__ */ jsxRuntimeExports.jsxs(
      "button",
      {
        type: "button",
        onClick: props.onAddCustom,
        className: "guard-list-switch-add",
        children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniPlus, { className: "size-4", "aria-hidden": "true" }),
          "Add custom extension"
        ]
      }
    ) : null
  ] });
}
const PROTECTION_CATEGORIES = [
  { id: "source-control", label: "Source control", description: "Protect repository history, branches, and source-control operations.", searchAliases: ["git", "github", "repository", "source"] },
  { id: "packages", label: "Packages and dependencies", description: "Protect dependency installs, package managers, and supply-chain changes.", searchAliases: ["npm", "pnpm", "yarn", "pip", "package", "dependency"] },
  { id: "files-secrets", label: "Files and secrets", description: "Protect sensitive files, credentials, and secret-bearing operations.", searchAliases: ["file", "secret", "credential", "environment"] },
  { id: "cloud-infrastructure", label: "Cloud and infrastructure", description: "Protect infrastructure, cloud resources, and administrative actions.", searchAliases: ["aws", "gcp", "azure", "terraform", "cloud", "infrastructure"] },
  { id: "network-downloads", label: "Network and downloads", description: "Protect downloads, remote access, and network-facing operations.", searchAliases: ["curl", "wget", "ssh", "network", "download", "remote"] },
  { id: "data-databases", label: "Data and databases", description: "Protect databases, storage, backups, and destructive data operations.", searchAliases: ["database", "sql", "postgres", "mysql", "redis", "data", "backup"] },
  { id: "deployments-ci", label: "Deployments and CI", description: "Protect deployment, build, release, and CI/CD operations.", searchAliases: ["deploy", "release", "ci", "cd", "workflow", "pipeline"] },
  { id: "messaging-collaboration", label: "Messaging and collaboration", description: "Protect actions in messaging, search, and collaboration tools.", searchAliases: ["slack", "message", "collaboration", "search"] },
  { id: "system-shell", label: "System and shell actions", description: "Protect high-impact local shell, process, and system operations.", searchAliases: ["shell", "system", "bash", "terminal", "process"] },
  { id: "ai-workflows", label: "AI tools and agent workflows", description: "Protect AI-agent, tool, and automated workflow actions.", searchAliases: ["ai", "agent", "mcp", "tool", "workflow"] }
];
new Map(PROTECTION_CATEGORIES.map((category) => [category.id, category]));
function searchableExtensionText(extension) {
  return [
    extension.extension_id,
    extension.name,
    extension.description,
    ...extension.ecosystem_ids,
    ...extension.executables,
    ...extension.action_classes,
    ...extension.risk_classes
  ].join(" ").toLowerCase();
}
function protectionCategoryIdForExtension(extension) {
  const text = searchableExtensionText(extension);
  if (/\bgit\b|github|source.?control|repository|branch|commit/.test(text)) return "source-control";
  if (/package|dependency|npm|pnpm|yarn|pip|poetry|cargo|composer|gem|supply.?chain/.test(text)) return "packages";
  if (/secret|credential|\.env|filesystem|sensitive.?file|keychain/.test(text)) return "files-secrets";
  if (/aws|azure|gcp|cloud|terraform|kubectl|kubernetes|infrastructure|platform/.test(text)) return "cloud-infrastructure";
  if (/network|egress|download|curl|wget|ssh|remote|http|ftp/.test(text)) return "network-downloads";
  if (/database|sql|postgres|mysql|sqlite|redis|mongo|storage|backup|data/.test(text)) return "data-databases";
  if (/deploy|release|ci.?cd|pipeline|workflow|build|artifact/.test(text)) return "deployments-ci";
  if (/slack|discord|message|collaboration|search|email/.test(text)) return "messaging-collaboration";
  if (/agent|\bmcp\b|assistant|model|prompt|ai.?tool/.test(text)) return "ai-workflows";
  return "system-shell";
}
const EMPTY_CATALOG_FILTERS = {
  trusts: [],
  kinds: [],
  areas: []
};
const CATALOG_TRUST_FILTERS = [
  "first-party",
  "trusted-library",
  "external"
];
const CATALOG_KIND_FILTERS = ["commands", "mcp"];
function catalogFiltersActive(filters) {
  return filters.trusts.length > 0 || filters.kinds.length > 0 || filters.areas.length > 0;
}
function catalogTrustLabel(trust) {
  if (trust === "first-party") return "Built in";
  if (trust === "trusted-library") return "Trusted";
  return "External";
}
function catalogKindLabel(kind) {
  if (kind === "mcp") return "MCP";
  return "Commands";
}
function catalogItemKind(extension) {
  if (extension.surface === "mcp") return "mcp";
  if (extension.surface === "unsupported") return null;
  return "commands";
}
function toggleCatalogFilterValue(selected, value) {
  if (selected.includes(value)) return selected.filter((item) => item !== value);
  return [...selected, value];
}
function catalogItemMatchesFilters(extension, filters) {
  if (filters.trusts.length > 0 && !filters.trusts.includes(extension.trust_class)) return false;
  if (filters.kinds.length > 0) {
    const kind = catalogItemKind(extension);
    if (kind === null || !filters.kinds.includes(kind)) return false;
  }
  if (filters.areas.length > 0) {
    const area = protectionCategoryIdForExtension(extension);
    if (!filters.areas.includes(area)) return false;
  }
  return true;
}
function filterCatalogExtensions(extensions, filters) {
  if (!catalogFiltersActive(filters)) return [...extensions];
  return extensions.filter((extension) => catalogItemMatchesFilters(extension, filters));
}
function customItemMatchesKind(item, kinds) {
  if (kinds.length === 0) return true;
  if (item.surface === "mcp") return kinds.includes("mcp");
  return kinds.includes("commands");
}
function customItemMatchesFilters(item, filters) {
  if (filters.trusts.length > 0 || filters.areas.length > 0) return false;
  return customItemMatchesKind(item, filters.kinds);
}
function sameFilterValues(left, right) {
  if (left.length !== right.length) return false;
  return left.every((item, index) => item === right[index]);
}
function catalogFiltersEqual(left, right) {
  return sameFilterValues(left.trusts, right.trusts) && sameFilterValues(left.kinds, right.kinds) && sameFilterValues(left.areas, right.areas);
}
function pruneCatalogFilters(filters, extensions) {
  const presentTrusts = new Set(extensions.map((item) => item.trust_class));
  const presentKinds = new Set(extensions.map((item) => catalogItemKind(item)));
  const presentAreas = new Set(populatedCatalogAreas(extensions));
  return {
    trusts: filters.trusts.filter((trust) => presentTrusts.has(trust)),
    kinds: filters.kinds.filter((kind) => presentKinds.has(kind)),
    areas: filters.areas.filter((area) => presentAreas.has(area))
  };
}
function catalogToolUnit(count) {
  if (count === 1) return "tool";
  return "tools";
}
function catalogFilterCountCopy(visible, total, filtering) {
  if (!filtering) return `${total} ${catalogToolUnit(total)}`;
  return `${visible} of ${total} ${catalogToolUnit(total)}`;
}
function catalogFilterChipAriaLabel(label, count) {
  return `${label}, ${count} ${catalogToolUnit(count)}`;
}
function populatedCatalogAreas(extensions) {
  const present = /* @__PURE__ */ new Set();
  for (const extension of extensions) {
    present.add(protectionCategoryIdForExtension(extension));
  }
  return PROTECTION_CATEGORIES.map((category) => category.id).filter((id) => present.has(id));
}
function populatedCatalogAreaOptions(extensions) {
  const present = new Set(populatedCatalogAreas(extensions));
  return PROTECTION_CATEGORIES.filter((category) => present.has(category.id)).map((category) => ({ id: category.id, label: category.label }));
}
function catalogFilterChipCount(extensions, filters, patch) {
  return filterCatalogExtensions(extensions, { ...filters, ...patch }).length;
}
function CatalogFilterOption(props) {
  return /* @__PURE__ */ jsxRuntimeExports.jsxs(
    "button",
    {
      type: "button",
      "aria-pressed": props.pressed,
      "aria-label": catalogFilterChipAriaLabel(props.label, props.count),
      disabled: props.disabled,
      onClick: props.onToggle,
      className: "group flex min-h-10 w-full items-center justify-between gap-3 rounded-lg border border-[rgba(63,65,116,0.16)] bg-white px-2.5 text-[0.8125rem] font-semibold text-brand-dark/80 transition-colors hover:border-brand-blue/45 hover:text-brand-dark focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-brand-blue disabled:cursor-not-allowed disabled:opacity-45 aria-pressed:border-brand-blue/55 aria-pressed:bg-brand-blue/10 aria-pressed:text-brand-dark motion-reduce:transition-none",
      children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { className: "flex min-w-0 items-center gap-2", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "grid size-4 shrink-0 place-items-center text-brand-blue", children: props.pressed ? /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniCheck, { className: "size-4", "aria-hidden": "true" }) : null }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "truncate", children: props.label })
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "tabular-nums text-xs font-medium text-brand-dark/50 group-aria-pressed:text-brand-dark/65", children: props.count })
      ]
    }
  );
}
function ActiveFilterToken(props) {
  return /* @__PURE__ */ jsxRuntimeExports.jsxs(
    "button",
    {
      type: "button",
      "aria-label": `Remove ${props.valueLabel} ${props.groupLabel.toLowerCase()} filter`,
      onClick: props.onRemove,
      className: "group inline-flex min-h-8 items-center gap-1.5 rounded-full border border-brand-blue/45 bg-brand-blue/10 py-1 pl-2.5 pr-2 text-xs font-semibold text-brand-dark transition-colors hover:border-brand-blue hover:bg-brand-blue/15 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-brand-blue motion-reduce:transition-none",
      children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { className: "text-brand-dark/65", children: [
          props.groupLabel,
          ":"
        ] }),
        props.valueLabel,
        /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniXMark, { className: "size-3.5 shrink-0 text-brand-dark/55 group-hover:text-brand-dark", "aria-hidden": "true" })
      ]
    }
  );
}
function CatalogFilterGroup(props) {
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("fieldset", { className: `min-w-0 ${props.className ?? ""}`, children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx("legend", { className: "text-xs font-semibold text-brand-dark/55", children: props.legend }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-2 flex flex-col gap-1.5", children: props.children })
  ] });
}
function TrustFilterOption(props) {
  const handleToggle = reactExports.useCallback(() => {
    props.onToggle(props.value);
  }, [props]);
  return /* @__PURE__ */ jsxRuntimeExports.jsx(
    CatalogFilterOption,
    {
      label: catalogTrustLabel(props.value),
      count: props.count,
      pressed: props.pressed,
      disabled: props.count === 0 && !props.pressed,
      onToggle: handleToggle
    }
  );
}
function KindFilterOption(props) {
  const handleToggle = reactExports.useCallback(() => {
    props.onToggle(props.value);
  }, [props]);
  return /* @__PURE__ */ jsxRuntimeExports.jsx(
    CatalogFilterOption,
    {
      label: catalogKindLabel(props.value),
      count: props.count,
      pressed: props.pressed,
      disabled: props.count === 0 && !props.pressed,
      onToggle: handleToggle
    }
  );
}
function AreaFilterOption(props) {
  const handleToggle = reactExports.useCallback(() => {
    props.onToggle(props.value);
  }, [props]);
  return /* @__PURE__ */ jsxRuntimeExports.jsx(
    CatalogFilterOption,
    {
      label: props.label,
      count: props.count,
      pressed: props.pressed,
      disabled: props.count === 0 && !props.pressed,
      onToggle: handleToggle
    }
  );
}
function CatalogFilterTrigger(props) {
  return /* @__PURE__ */ jsxRuntimeExports.jsxs(
    "button",
    {
      type: "button",
      ref: props.buttonRef,
      "aria-expanded": props.open,
      "aria-controls": props.panelId,
      title: "Filters (press f)",
      onClick: props.onToggle,
      className: "inline-flex min-h-11 items-center gap-2 rounded-xl border border-[rgba(63,65,116,0.18)] bg-white px-3.5 text-sm font-semibold text-brand-dark shadow-sm transition-colors hover:border-brand-blue hover:text-brand-blue focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-brand-blue aria-expanded:border-brand-blue aria-expanded:text-brand-blue motion-reduce:transition-none",
      children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniAdjustmentsHorizontal, { className: "size-4", "aria-hidden": "true" }),
        "Filters",
        props.activeCount > 0 ? /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "grid min-w-5 place-items-center rounded-full bg-brand-blue px-1 text-[0.6875rem] font-semibold leading-5 text-white tabular-nums", children: props.activeCount }) : null,
        /* @__PURE__ */ jsxRuntimeExports.jsx(
          HiMiniChevronDown,
          {
            className: `size-4 transition-transform duration-200 motion-reduce:transition-none ${props.open ? "rotate-180" : ""}`,
            "aria-hidden": "true"
          }
        )
      ]
    }
  );
}
function CatalogFilterBar(props) {
  const areas = reactExports.useMemo(() => populatedCatalogAreaOptions(props.catalog), [props.catalog]);
  const filtering = catalogFiltersActive(props.filters);
  const activeCount = props.filters.trusts.length + props.filters.kinds.length + props.filters.areas.length;
  const visibleCount = reactExports.useMemo(
    () => filterCatalogExtensions(props.catalog, props.filters).length,
    [props.catalog, props.filters]
  );
  const handleToggleTrust = reactExports.useCallback((value) => {
    props.onChange({
      ...props.filters,
      trusts: toggleCatalogFilterValue(props.filters.trusts, value)
    });
  }, [props]);
  const handleToggleKind = reactExports.useCallback((value) => {
    props.onChange({
      ...props.filters,
      kinds: toggleCatalogFilterValue(props.filters.kinds, value)
    });
  }, [props]);
  const handleToggleArea = reactExports.useCallback((value) => {
    props.onChange({
      ...props.filters,
      areas: toggleCatalogFilterValue(props.filters.areas, value)
    });
  }, [props]);
  const handleClear = reactExports.useCallback(() => {
    props.onChange(EMPTY_CATALOG_FILTERS);
    props.onAfterClear?.();
  }, [props]);
  return /* @__PURE__ */ jsxRuntimeExports.jsxs(jsxRuntimeExports.Fragment, { children: [
    filtering ? /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-2 flex flex-wrap items-center gap-2", "data-testid": "catalog-filter-tokens", children: [
      props.filters.trusts.map((trust) => /* @__PURE__ */ jsxRuntimeExports.jsx(
        ActiveFilterToken,
        {
          groupLabel: "Trust",
          valueLabel: catalogTrustLabel(trust),
          onRemove: () => handleToggleTrust(trust)
        },
        `trust-${trust}`
      )),
      props.filters.kinds.map((kind) => /* @__PURE__ */ jsxRuntimeExports.jsx(
        ActiveFilterToken,
        {
          groupLabel: "Kind",
          valueLabel: catalogKindLabel(kind),
          onRemove: () => handleToggleKind(kind)
        },
        `kind-${kind}`
      )),
      props.filters.areas.map((areaId) => {
        const area = areas.find((option) => option.id === areaId);
        return /* @__PURE__ */ jsxRuntimeExports.jsx(
          ActiveFilterToken,
          {
            groupLabel: "Area",
            valueLabel: area?.label ?? areaId,
            onRemove: () => handleToggleArea(areaId)
          },
          `area-${areaId}`
        );
      }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("button", { type: "button", className: "guard-extensions-chip", onClick: handleClear, children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniXMark, { className: "size-4", "aria-hidden": "true" }),
        "Clear filters"
      ] })
    ] }) : null,
    /* @__PURE__ */ jsxRuntimeExports.jsxs(
      "div",
      {
        id: props.panelId,
        hidden: !props.open,
        "data-testid": "catalog-filter-panel",
        className: "mt-2 max-h-[min(70vh,32rem)] overflow-y-auto overscroll-contain rounded-2xl border border-[rgba(63,65,116,0.12)] bg-white p-4 shadow-[0_12px_32px_rgba(63,65,116,0.16)] sm:absolute sm:inset-x-0 sm:top-full sm:z-30 sm:mt-2 sm:p-5",
        children: [
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "grid gap-x-8 gap-y-5 sm:grid-cols-2 lg:grid-cols-[minmax(0,14rem)_minmax(0,12rem)_minmax(0,1fr)]", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx(CatalogFilterGroup, { legend: "Trust", children: CATALOG_TRUST_FILTERS.map((trust) => /* @__PURE__ */ jsxRuntimeExports.jsx(
              TrustFilterOption,
              {
                value: trust,
                count: catalogFilterChipCount(props.catalog, props.filters, { trusts: [trust] }),
                pressed: props.filters.trusts.includes(trust),
                onToggle: handleToggleTrust
              },
              trust
            )) }),
            /* @__PURE__ */ jsxRuntimeExports.jsx(CatalogFilterGroup, { legend: "Kind", children: CATALOG_KIND_FILTERS.map((kind) => /* @__PURE__ */ jsxRuntimeExports.jsx(
              KindFilterOption,
              {
                value: kind,
                count: catalogFilterChipCount(props.catalog, props.filters, { kinds: [kind] }),
                pressed: props.filters.kinds.includes(kind),
                onToggle: handleToggleKind
              },
              kind
            )) }),
            /* @__PURE__ */ jsxRuntimeExports.jsx(CatalogFilterGroup, { legend: "Area", className: "sm:col-span-2 lg:col-span-1", children: /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "grid gap-x-6 gap-y-1.5 sm:grid-cols-2", children: areas.map((area) => /* @__PURE__ */ jsxRuntimeExports.jsx(
              AreaFilterOption,
              {
                value: area.id,
                label: area.label,
                count: catalogFilterChipCount(props.catalog, props.filters, { areas: [area.id] }),
                pressed: props.filters.areas.includes(area.id),
                onToggle: handleToggleArea
              },
              area.id
            )) }) })
          ] }),
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-4 flex flex-wrap items-center justify-between gap-2 border-t border-[rgba(63,65,116,0.12)] pt-3", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs text-brand-dark/65", "data-testid": "catalog-filter-count", children: catalogFilterCountCopy(visibleCount, props.catalog.length, filtering) }),
            filtering ? /* @__PURE__ */ jsxRuntimeExports.jsxs("button", { type: "button", className: "guard-extensions-chip", onClick: handleClear, children: [
              /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniXMark, { className: "size-4", "aria-hidden": "true" }),
              "Clear all ",
              activeCount,
              " ",
              activeCount === 1 ? "filter" : "filters"
            ] }) : null
          ] })
        ]
      }
    )
  ] });
}
const PROTECTION_CENTER_PERFORMANCE_BUDGETS = Object.freeze({
  simpleRuleRenderCap: 500,
  recentDecisionCap: 20,
  humanSearchCharacterCap: 160,
  humanSearchTermCap: 8,
  developerRelationshipCap: 1024
});
const COMMAND_PATTERN_DISPLAY_LIMIT = 24;
const IDENTITY_MATCH = 0;
const CONTEXT_MATCH = 2;
const RISK_TIER_SEVERITY = { critical: 3, high: 2, medium: 1, low: 0 };
function catalogOriginRank(extension) {
  return extension.source === "local-admin" ? 1 : 0;
}
function patternSearchBands(extension, permission) {
  return [
    [permission.label, extension.name, extension.extension_id, ...extension.executables].join(" "),
    [permission.example_command ?? "", permission.permission_id].join(" "),
    [permission.description, permission.family ?? ""].join(" ")
  ];
}
const WORD_CHAR = /[\p{L}\p{N}]/u;
const LOWER = new RegExp("\\p{Ll}", "u");
const UPPER = new RegExp("\\p{Lu}", "u");
function startsWord(text, index) {
  if (index === 0) return true;
  const previous = text[index - 1];
  return !WORD_CHAR.test(previous) || LOWER.test(previous) && UPPER.test(text[index]);
}
function endsWord(text, end) {
  return end >= text.length || !WORD_CHAR.test(text[end]);
}
function wordMatch(text, term) {
  const { folded, origin } = foldCase(text);
  const anchored = WORD_CHAR.test(term[0] ?? "");
  const closes = WORD_CHAR.test(term[term.length - 1] ?? "");
  let found = null;
  for (let index = folded.indexOf(term); index !== -1; index = folded.indexOf(term, index + 1)) {
    if (anchored && (splitsCharacter(origin, index) || !startsWord(text, origin?.[index] ?? index))) continue;
    const end = index + term.length;
    if (!closes || !splitsCharacter(origin, end) && endsWord(text, origin?.[end] ?? end)) return "exact";
    found = "prefix";
  }
  return found;
}
function foldCase(text) {
  const lower = text.toLowerCase();
  if (lower.length === text.length) return { folded: lower, origin: null };
  let folded = "";
  const origin = [];
  for (let index = 0; index < text.length; ) {
    const character = String.fromCodePoint(text.codePointAt(index));
    const lowered = character.toLowerCase();
    folded += lowered;
    for (let unit = 0; unit < lowered.length; unit += 1) origin.push(index);
    index += character.length;
  }
  origin.push(text.length);
  return { folded, origin };
}
function splitsCharacter(origin, index) {
  return origin !== null && index > 0 && index < origin.length - 1 && origin[index] === origin[index - 1];
}
function termMatch(term, bands) {
  for (let band = IDENTITY_MATCH; band <= CONTEXT_MATCH; band += 1) {
    const match = wordMatch(bands[band], term);
    if (match) return { band, exact: match === "exact" };
  }
  return null;
}
function commandPatternQuery(rawQuery) {
  const normalized = rawQuery.trim().toLowerCase().slice(0, PROTECTION_CENTER_PERFORMANCE_BUDGETS.humanSearchCharacterCap);
  return normalized.split(/\s+/).filter(Boolean).slice(0, PROTECTION_CENTER_PERFORMANCE_BUDGETS.humanSearchTermCap).join(" ");
}
function searchCommandPatterns(candidates, rawQuery, limit = COMMAND_PATTERN_DISPLAY_LIMIT) {
  const query = commandPatternQuery(rawQuery);
  if (!query) return [];
  const terms = query.split(" ");
  const matches = [];
  for (const { extension, permission } of candidates) {
    const bands = patternSearchBands(extension, permission);
    const termMatches = terms.map((term) => termMatch(term, bands));
    if (termMatches.some((match) => match === null)) continue;
    const found = termMatches;
    const score = Math.max(...found.map((match) => match.band));
    const partial = found.filter((match) => !match.exact).length;
    matches.push({ extension, permission, score, partial });
  }
  return matches.sort(
    (left, right) => left.score - right.score || left.partial - right.partial || catalogOriginRank(left.extension) - catalogOriginRank(right.extension) || (RISK_TIER_SEVERITY[right.permission.risk_tier] ?? 0) - (RISK_TIER_SEVERITY[left.permission.risk_tier] ?? 0) || left.permission.label.localeCompare(right.permission.label) || left.extension.name.localeCompare(right.extension.name)
  ).slice(0, limit).map(({ partial: _partial, ...match }) => match);
}
function useDebounce(value, delay) {
  const [debouncedValue, setDebouncedValue] = reactExports.useState(value);
  reactExports.useEffect(() => {
    const timer = setTimeout(() => setDebouncedValue(value), delay);
    return () => clearTimeout(timer);
  }, [value, delay]);
  return debouncedValue;
}
const SEARCH_DEBOUNCE_MS = 150;
function useCatalogPermissionSearch(catalog, rawQuery) {
  const current = commandPatternQuery(rawQuery);
  const query = useDebounce(current, SEARCH_DEBOUNCE_MS);
  const [state, setState] = reactExports.useState({ query: "", hits: [], error: null });
  const local = reactExports.useMemo(
    () => catalog.localSearch ? { query: current, hits: catalog.localSearch(current), error: null } : null,
    [catalog, current]
  );
  reactExports.useEffect(() => {
    if (local) return;
    if (!query) {
      setState({ query, hits: [], error: null });
      return;
    }
    const controller = new AbortController();
    catalog.searchPermissions(query, controller.signal).then(
      (hits) => {
        if (!controller.signal.aborted) setState({ query, hits, error: null });
      },
      (error) => {
        if (controller.signal.aborted) return;
        setState({ query, hits: [], error: error instanceof Error ? error.message : "Guard could not search command patterns." });
      }
    );
    return () => controller.abort();
  }, [catalog, local, query]);
  if (local) return { ...local, pending: false };
  return { ...state, pending: current !== "" && state.query !== current };
}
function CatalogSearchRow(props) {
  const handleOpen = reactExports.useCallback(() => {
    props.onOpen(props.extension);
  }, [props]);
  return /* @__PURE__ */ jsxRuntimeExports.jsx(
    ProtectionModuleRow,
    {
      extensionId: props.extension.extension_id,
      name: extensionDisplayName(props.extension.name),
      description: props.extension.description,
      behavior: catalogRowSecondLine(props.extension, extensionStateLabel(props.effective, props.extension)),
      required: props.extension.required,
      mcp: props.extension.surface === "mcp",
      external: props.extension.trust_class === "external",
      executables: props.extension.executables,
      ecosystemIds: props.extension.ecosystem_ids,
      onOpen: handleOpen
    }
  );
}
function PatternSearchConsole(props) {
  const [internalQuery, setInternalQuery] = reactExports.useState("");
  const query = props.query ?? internalQuery;
  const setQuery = props.onQueryChange ?? setInternalQuery;
  const [focused, setFocused] = reactExports.useState(false);
  const inputRef = reactExports.useRef(null);
  const searchActive = props.active ?? true;
  const draft = useExtensionPolicyDraft({ effective: props.effective, onRefresh: props.onRefresh });
  const { resolvedApprovalGate, resolveApprovalGate } = useResolvedApprovalGate(null);
  const {
    baseEffective,
    dirty,
    preview,
    previewBusy,
    applyBusy,
    reviewOpen,
    error,
    stale,
    pendingRebase,
    refreshRequired,
    lastApplied,
    undoLastApplied,
    changedPermissionCount,
    setReviewOpen,
    setPermissionState,
    setPermissionStates,
    resetDraft,
    runPreview,
    apply,
    permissionState,
    rebaseDraft,
    keepConflicts,
    useCurrent
  } = draft;
  const touchedExtensionIds = reactExports.useRef(/* @__PURE__ */ new Set());
  const rememberTouched = reactExports.useCallback((extensionIds) => {
    for (const extensionId of extensionIds) touchedExtensionIds.current.add(extensionId);
  }, []);
  reactExports.useEffect(() => {
    if (!searchActive) return;
    const onKeyDown = (event) => {
      if (event.key !== "/" || event.defaultPrevented) return;
      const target = event.target;
      if (target && (target.tagName === "INPUT" || target.tagName === "TEXTAREA" || target.isContentEditable)) return;
      event.preventDefault();
      inputRef.current?.focus();
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [searchActive]);
  const totalPermissionCount = reactExports.useMemo(
    () => props.catalog.reduce((total, extension) => total + extension.permission_count, 0),
    [props.catalog]
  );
  const search = useCatalogPermissionSearch(props.readModel, query);
  const allMatches = reactExports.useMemo(() => {
    const visible = new Set(props.catalog.map((extension) => extension.extension_id));
    const candidates = search.hits.filter((hit) => visible.has(hit.extension.extension_id));
    return searchCommandPatterns(candidates, query, totalPermissionCount);
  }, [props.catalog, search.hits, query, totalPermissionCount]);
  const matches = reactExports.useMemo(() => allMatches.slice(0, COMMAND_PATTERN_DISPLAY_LIMIT), [allMatches]);
  const toolMatches = reactExports.useMemo(() => {
    const terms = query.trim().toLowerCase().split(/\s+/).filter(Boolean);
    if (!terms.length) return [];
    return props.catalog.filter((extension) => {
      const text = [extension.name, extension.extension_id, ...extension.executables, ...extension.aliases].join(" ");
      return terms.every((term) => wordMatch(text, term) !== null);
    });
  }, [props.catalog, query]);
  const grouped = reactExports.useMemo(() => {
    const groups = /* @__PURE__ */ new Map();
    for (const match of matches) {
      const group = groups.get(match.extension.extension_id) ?? { extension: match.extension, permissions: [] };
      group.permissions.push(match.permission);
      groups.set(match.extension.extension_id, group);
    }
    return [...groups.values()];
  }, [matches]);
  const involvedPermissions = reactExports.useMemo(() => allMatches.map((match) => match.permission), [allMatches]);
  const handleRebase = reactExports.useCallback(async () => {
    const extensionIds = touchedExtensionIds.current.size ? [...touchedExtensionIds.current] : grouped.map((group) => group.extension.extension_id);
    await rebaseDraft(() => Promise.all(extensionIds.map((extensionId) => props.readModel.detail(extensionId))));
  }, [grouped, props.readModel, rebaseDraft]);
  const changeCount = changedPermissionCount;
  const showResults = query.trim().length > 0;
  reactExports.useEffect(() => {
    if (!reviewOpen) return;
    void resolveApprovalGate({ failClosed: true }).catch(() => {
    });
  }, [reviewOpen, resolveApprovalGate]);
  const managedCount = involvedPermissions.filter(
    (permission) => managedPermissionState(baseEffective, permission.permission_id) !== null
  ).length;
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("section", { "aria-labelledby": "pattern-search-heading", className: "mt-6", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx("h2", { id: "pattern-search-heading", className: "sr-only", children: "Search command patterns" }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "relative", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-col gap-2 sm:flex-row sm:flex-wrap sm:items-center", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs("label", { className: "relative block min-w-0 flex-1 sm:min-w-60", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "sr-only", children: "Search command patterns" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniMagnifyingGlass, { className: "pointer-events-none absolute left-3 top-1/2 size-4 -translate-y-1/2 text-brand-dark/55", "aria-hidden": "true" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx(
            "input",
            {
              ref: inputRef,
              type: "text",
              role: "searchbox",
              enterKeyHint: "search",
              value: query,
              onFocus: () => setFocused(true),
              onChange: (event) => setQuery(event.target.value.slice(0, 160)),
              placeholder: 'Search any command Guard watches — "squash", "git push --force", "kubectl"…',
              "aria-describedby": "pattern-search-hint",
              className: "min-h-11 w-full rounded-xl border border-[rgba(63,65,116,0.14)] bg-white/85 py-2.5 pl-9 pr-10 text-sm text-brand-dark shadow-sm focus:border-brand-blue focus:outline-none focus:ring-2 focus:ring-blue-100"
            }
          ),
          showResults ? /* @__PURE__ */ jsxRuntimeExports.jsx(
            "button",
            {
              type: "button",
              onClick: () => {
                setQuery("");
                inputRef.current?.focus();
              },
              "aria-label": "Clear search",
              className: "absolute right-2 top-1/2 grid size-8 -translate-y-1/2 place-items-center rounded-lg text-brand-dark/55 hover:bg-[rgba(63,65,116,0.06)] hover:text-brand-dark",
              children: /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniXMark, { className: "size-4", "aria-hidden": "true" })
            }
          ) : null
        ] }),
        props.toolbarSlot ? /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "flex shrink-0 flex-wrap items-center gap-2", children: props.toolbarSlot }) : null
      ] }),
      props.subtoolbarSlot
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("p", { id: "pattern-search-hint", className: `mt-2 text-xs text-brand-dark/60 ${focused || showResults ? "" : "sr-only"}`, children: "Matches patterns across every tool. Press / to focus search from anywhere on this page." }),
    props.actionSlot ? /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-3", children: props.actionSlot }) : null,
    showResults ? /* @__PURE__ */ jsxRuntimeExports.jsx(
      PolicyEditingLocks,
      {
        health: baseEffective.health,
        globalLockdown: baseEffective.global_lockdown,
        refreshRequired
      }
    ) : null,
    showResults && search.error ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { role: "alert", className: "mt-3 text-sm font-medium text-rose-800", children: search.error }) : null,
    showResults ? matches.length || toolMatches.length ? /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-3", children: [
      matches.length ? /* @__PURE__ */ jsxRuntimeExports.jsxs(jsxRuntimeExports.Fragment, { children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(
          QuickApplyToolbar,
          {
            permissions: involvedPermissions,
            effective: baseEffective,
            disabled: refreshRequired || previewBusy || applyBusy || baseEffective.health !== "protected",
            permissionState,
            onApply: (permissionIds, state) => {
              rememberTouched(allMatches.map((match) => match.extension.extension_id));
              setPermissionStates(permissionIds, state);
            }
          }
        ),
        allMatches.length > matches.length ? /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { role: "status", className: "mt-3 text-xs text-brand-dark/65", children: [
          "Showing ",
          matches.length,
          " of ",
          allMatches.length,
          " matching capabilities. Quick actions apply to all ",
          allMatches.length,
          "."
        ] }) : null
      ] }) : null,
      grouped.map((group) => /* @__PURE__ */ jsxRuntimeExports.jsxs("section", { "aria-label": `${group.extension.name} patterns`, className: "guard-pattern-family", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs("h3", { className: "guard-pattern-family-heading", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx(
            ExtensionBrandMark,
            {
              extension_id: group.extension.extension_id,
              name: group.extension.name,
              executables: group.extension.executables,
              ecosystem_ids: group.extension.ecosystem_ids,
              size: "sm"
            }
          ),
          group.extension.executables.length ? /* @__PURE__ */ jsxRuntimeExports.jsx("code", { children: group.extension.executables[0] }) : null,
          /* @__PURE__ */ jsxRuntimeExports.jsx("span", { children: extensionDisplayName(group.extension.name) })
        ] }),
        group.permissions.map((permission) => {
          return /* @__PURE__ */ jsxRuntimeExports.jsx(
            PermissionPolicyRow,
            {
              permission,
              extension: group.extension,
              effective: baseEffective,
              draftState: permissionState(permission.permission_id),
              disabled: refreshRequired,
              onChange: (state) => {
                rememberTouched([group.extension.extension_id]);
                setPermissionState(permission.permission_id, state);
              }
            },
            permission.permission_id
          );
        })
      ] }, group.extension.extension_id)),
      toolMatches.length ? /* @__PURE__ */ jsxRuntimeExports.jsxs("section", { "aria-label": "Matching tools", className: "guard-pattern-family", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("h3", { className: "guard-pattern-family-heading", children: /* @__PURE__ */ jsxRuntimeExports.jsx("span", { children: "Tools" }) }),
        toolMatches.map((extension) => /* @__PURE__ */ jsxRuntimeExports.jsx(
          CatalogSearchRow,
          {
            extension,
            effective: props.effective,
            onOpen: props.onOpenExtension
          },
          extension.extension_id
        ))
      ] }) : null,
      managedCount ? /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "mt-3 text-xs text-indigo-950", children: [
        managedCount,
        " matched setting",
        managedCount === 1 ? "" : "s are",
        " managed by your organization and cannot be weakened on this device."
      ] }) : null
    ] }) : /* @__PURE__ */ jsxRuntimeExports.jsx("p", { role: "status", className: "mt-3 text-sm text-brand-dark/75", children: search.pending ? "Searching command patterns…" : "No command patterns or tools match this search." }) : null,
    dirty ? /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "guard-review-bar", children: /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "text-sm text-brand-dark", children: [
        changeCount,
        " unsaved setting change",
        changeCount === 1 ? "" : "s",
        "."
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap gap-2", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("button", { type: "button", disabled: previewBusy || applyBusy, onClick: resetDraft, className: "min-h-11 rounded-xl border border-[rgba(63,65,116,0.2)] px-4 text-sm font-semibold text-brand-dark", children: "Reset changes" }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("button", { type: "button", disabled: previewBusy || applyBusy || baseEffective.health !== "protected" || stale, onClick: () => {
          void runPreview();
        }, className: "inline-flex min-h-11 items-center gap-2 rounded-xl bg-brand-blue px-4 text-sm font-semibold text-[#f4f7fb] disabled:opacity-40", children: [
          previewBusy ? /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniArrowPath, { className: "size-4 animate-spin motion-reduce:animate-none" }) : /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniShieldCheck, { className: "size-4" }),
          "Review ",
          changeCount,
          " change",
          changeCount === 1 ? "" : "s"
        ] })
      ] })
    ] }) }) : null,
    lastApplied ? /* @__PURE__ */ jsxRuntimeExports.jsx(
      AppliedPolicyToast,
      {
        revision: lastApplied.revision,
        onUndo: () => {
          undoLastApplied();
        },
        onViewHistory: () => {
          document.getElementById("pattern-search-heading")?.scrollIntoView({ behavior: "smooth", block: "start" });
        }
      }
    ) : null,
    error ? /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { role: "alert", className: "mt-4 text-sm text-red-950", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-start gap-2", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniExclamationTriangle, { className: "mt-0.5 size-5 shrink-0" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("span", { children: error })
      ] }),
      stale && !pendingRebase ? /* @__PURE__ */ jsxRuntimeExports.jsx("button", { type: "button", disabled: previewBusy, onClick: () => {
        void handleRebase();
      }, className: "mt-3 min-h-11 rounded-xl bg-red-800 px-4 text-sm font-semibold text-[#f4f7fb] disabled:opacity-40", children: "Update draft with latest protection" }) : null,
      pendingRebase ? /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-4", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("ul", { className: "space-y-2", children: pendingRebase.result.conflicts.map((conflict) => /* @__PURE__ */ jsxRuntimeExports.jsxs("li", { className: "text-xs text-brand-dark", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("code", { className: "break-all", children: conflict.original_permission_id }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-1", children: conflict.kind === "removed" ? "Target removed from the current catalog." : `Current ${conflict.latest_state}; your draft requests ${conflict.requested_state}.` })
        ] }, conflict.original_permission_id)) }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-3 flex flex-wrap gap-2", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("button", { type: "button", onClick: keepConflicts, className: "min-h-11 rounded-xl bg-red-800 px-4 text-sm font-semibold text-[#f4f7fb]", children: "Keep my compatible changes" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("button", { type: "button", onClick: useCurrent, className: "min-h-11 rounded-xl border border-red-300 px-4 text-sm font-semibold text-red-950", children: "Use current protection" })
        ] })
      ] }) : null
    ] }) : dirty && !preview ? /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-4 flex items-start gap-3 text-sm text-brand-dark", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniInformationCircle, { className: "mt-0.5 size-5 shrink-0" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { children: "Review is required before approval. Guard calculates the real outcome from current protections, dependencies, organization settings, and Emergency Lockdown before anything can change." })
    ] }) : null,
    reviewOpen && preview ? /* @__PURE__ */ jsxRuntimeExports.jsx(
      PolicyReviewSheet,
      {
        preview,
        approvalGate: resolvedApprovalGate,
        busy: applyBusy,
        error,
        onClose: () => {
          if (!applyBusy) setReviewOpen(false);
        },
        onApply: (credentials) => {
          void apply(credentials);
        }
      }
    ) : null
  ] });
}
function sourceIsManaged(effective, extensionId) {
  return effective.layers.some((layer) => layer.kind === "signed-cloud" && layer.controls.some(
    (control) => control.target_kind === "extension" && control.target_id === extensionId
  ));
}
function CatalogExtensionRow(props) {
  const handleOpen = reactExports.useCallback(() => {
    props.onOpen(props.extension);
  }, [props]);
  const source = extensionProtectionSource(props.effective, props.extension);
  const cloudSource = source === "Synced from Guard Cloud" || source.startsWith("Managed by ");
  const state = extensionStateLabel(props.effective, props.extension);
  return /* @__PURE__ */ jsxRuntimeExports.jsx(
    ProtectionModuleRow,
    {
      extensionId: props.extension.extension_id,
      name: extensionDisplayName(props.extension.name),
      description: props.extension.description,
      behavior: catalogRowSecondLine(props.extension, state),
      state,
      ruleCount: props.extension.rule_count,
      permissionCount: props.extension.permission_count,
      publisher: props.extension.publisher?.displayName,
      required: props.extension.required,
      mcp: props.extension.surface === "mcp",
      external: props.extension.trust_class === "external",
      managed: cloudSource || sourceIsManaged(props.effective, props.extension.extension_id),
      managedLabel: cloudSource ? source : void 0,
      executables: props.extension.executables,
      ecosystemIds: props.extension.ecosystem_ids,
      onOpen: handleOpen
    }
  );
}
function PaidCatalogRow(props) {
  const ref = reactExports.useRef(null);
  const featured = props.entry.placement.product !== "sponsored";
  const recordOpen = useDiscoveryMeasurement(
    ref,
    props.snapshotId,
    props.entry.placement,
    featured ? "extensions_featured" : "extensions_feed"
  );
  const { onOpen } = props;
  const open = reactExports.useCallback((extension) => {
    recordOpen();
    onOpen(extension);
  }, [onOpen, recordOpen]);
  const { placement } = props.entry;
  const brand = placement.creative.brandName?.trim();
  const headline = placement.creative.headline?.trim();
  const window2 = featuredWindowLabel(placement);
  return /* @__PURE__ */ jsxRuntimeExports.jsxs(
    "div",
    {
      ref,
      className: "guard-featured-row",
      "data-testid": "catalog-featured-row",
      "data-sponsored-placement-id": placement.publicPlacementId,
      children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap items-center gap-x-2 gap-y-1 px-4 pt-3", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "guard-sponsor-label", "data-sponsored-label": true, children: sponsoredCardLabel(featured) }),
          brand ? /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { className: "text-xs text-brand-dark/60", children: [
            "Paid for by ",
            /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "font-semibold text-brand-dark", children: brand })
          ] }) : null,
          window2 ? /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-xs text-brand-dark/60", children: window2 }) : null,
          headline ? /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "basis-full text-sm font-medium text-brand-dark/80", children: headline }) : null
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsx(CatalogExtensionRow, { extension: props.entry.catalog, effective: props.effective, onOpen: open })
      ]
    }
  );
}
function ConnectorDiscoveryControl(props) {
  const message = props.discovering ? props.showProgress ? "Checking host connections…" : "" : props.error ?? "";
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap items-center gap-x-3 gap-y-1", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx("p", { "aria-live": "polite", "aria-atomic": "true", className: "text-sm text-brand-dark/70", children: message }),
    props.discovering ? null : /* @__PURE__ */ jsxRuntimeExports.jsx(
      "button",
      {
        type: "button",
        className: "inline-flex min-h-11 items-center rounded-lg text-sm font-semibold text-brand-blue hover:text-brand-dark focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-brand-blue",
        onClick: props.onRetry,
        children: props.error ? "Check for connectors again" : "Check host connections"
      }
    )
  ] });
}
function CatalogFilterEmpty(props) {
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-6 flex flex-col items-start gap-1 rounded-2xl border border-dashed border-[rgba(63,65,116,0.2)] bg-white px-5 py-8 sm:items-center sm:text-center", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "mb-2 grid size-10 place-items-center rounded-full bg-brand-blue/10 text-brand-blue", "aria-hidden": "true", children: /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniFunnel, { className: "size-5" }) }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm font-semibold text-brand-dark", children: "No extensions match these filters." }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "max-w-[46ch] text-sm leading-6 text-brand-dark/70", children: "Remove a filter or start over to see the full catalog again." }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("button", { type: "button", className: "guard-extensions-chip mt-1", onClick: props.onClear, children: "Clear filters" })
  ] });
}
const POSTURE_ORDER = ["Allowed", "Required", "Managed", "Blocked", "Lockdown", "Unavailable"];
function CatalogPostureSummary(props) {
  const { counts, external } = reactExports.useMemo(() => {
    const tally = /* @__PURE__ */ new Map();
    let externalCount = 0;
    for (const extension of props.extensions) {
      const state = extensionStateLabel(props.effective, extension);
      tally.set(state, (tally.get(state) ?? 0) + 1);
      if (extension.trust_class === "external") externalCount += 1;
    }
    return { counts: POSTURE_ORDER.flatMap((state) => tally.get(state) ? [{ state, count: tally.get(state) ?? 0 }] : []), external: externalCount };
  }, [props.effective, props.extensions]);
  const total = props.extensions.length;
  if (total === 0) return null;
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-4 rounded-2xl border border-[rgba(63,65,116,0.1)] bg-white px-4 py-3", "data-testid": "catalog-posture-summary", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "guard-posture-bar", role: "img", "aria-label": counts.map(({ state, count }) => `${count} ${extensionStatePillLabel(state).toLowerCase()}`).join(", "), children: counts.map(({ state, count }) => /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "guard-posture-segment", "data-state": state, style: { flexGrow: count } }, state)) }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("ul", { className: "mt-3 flex flex-wrap items-center gap-x-4 gap-y-2", "aria-label": "Catalog status", children: [
      counts.map(({ state, count }) => /* @__PURE__ */ jsxRuntimeExports.jsxs("li", { className: "inline-flex items-center gap-1.5 text-sm text-brand-dark/75", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(ExtensionStatePill, { state }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "font-semibold tabular-nums text-brand-dark", children: count })
      ] }, state)),
      external > 0 ? /* @__PURE__ */ jsxRuntimeExports.jsxs("li", { className: "inline-flex items-center gap-1.5 text-sm text-brand-dark/70 sm:ml-auto", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniGlobeAlt, { className: "size-4 text-brand-dark/45", "aria-hidden": "true" }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "font-semibold tabular-nums text-brand-dark", children: external }),
          " from outside the built-ins"
        ] })
      ] }) : null
    ] })
  ] });
}
function ConnectorDiscoveryNotice(props) {
  return /* @__PURE__ */ jsxRuntimeExports.jsx("div", { role: "status", className: props.error ? "mt-3 flex flex-wrap items-center gap-x-3 gap-y-1" : void 0, children: props.error ? /* @__PURE__ */ jsxRuntimeExports.jsxs(jsxRuntimeExports.Fragment, { children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm text-brand-dark/70", children: props.error }),
    /* @__PURE__ */ jsxRuntimeExports.jsx(
      "button",
      {
        type: "button",
        className: "inline-flex min-h-11 items-center rounded-lg text-sm font-semibold text-brand-blue hover:text-brand-dark focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-brand-blue",
        onClick: props.onRetry,
        children: "Check for connectors again"
      }
    )
  ] }) : null });
}
function ExtensionsOverview(props) {
  const fetchPlacements = reactExports.useCallback(
    () => fetchExtensionDiscoveryApi("/v1/discovery/extensions/placements"),
    []
  );
  const discoveryFeed = useDiscoveryFeed(props.active, fetchPlacements);
  const joinedDiscovery = useJoinedDiscovery(discoveryFeed, props.catalogExtensions);
  const discoverySnapshotId = discoveryFeed.projection?.snapshot.snapshotId || null;
  const discoveryOffers = discoveryFeed.projection?.snapshot.offers ?? [];
  const popularity = useExtensionPopularity(props.active);
  const [query, setQuery] = reactExports.useState("");
  const discoveryStarted = reactExports.useRef(false);
  const reloadConnections = reactExports.useRef(props.onReloadConnections);
  reloadConnections.current = props.onReloadConnections;
  const [discoveryError, setDiscoveryError] = reactExports.useState(null);
  const [hostDiscoveryError, setHostDiscoveryError] = reactExports.useState(null);
  const [discovering, setDiscovering] = reactExports.useState(false);
  const [discoveryAttempt, setDiscoveryAttempt] = reactExports.useState(0);
  reactExports.useEffect(() => {
    if (!props.active || discoveryStarted.current) return;
    discoveryStarted.current = true;
    const controller = new AbortController();
    setDiscovering(true);
    setDiscoveryError(null);
    setHostDiscoveryError(null);
    const reload = async () => {
      if (!controller.signal.aborted) await reloadConnections.current();
    };
    const configured = refreshMcpInventory("inventory:configured", controller.signal, true, discoveryAttempt > 0).then(reload).catch((error) => {
      if (!controller.signal.aborted) setDiscoveryError(discoveryFailureMessage(error, CONFIGURED_CONNECTIONS_FALLBACK));
    });
    let hostRunning = false;
    const refreshHost = async (force) => {
      if (hostRunning || controller.signal.aborted) return;
      hostRunning = true;
      try {
        await refreshCodexHostInventory(controller.signal, force);
        if (!controller.signal.aborted) setHostDiscoveryError(null);
      } catch (error) {
        if (!controller.signal.aborted) setHostDiscoveryError(discoveryFailureMessage(error, CODEX_HOST_FALLBACK));
      } finally {
        await reload();
        hostRunning = false;
      }
    };
    const host = refreshHost(discoveryAttempt > 0);
    const hostTimer = window.setInterval(() => {
      if (!document.hidden) void refreshHost(true);
    }, 25e3);
    void Promise.all([configured, host]).finally(() => {
      if (!controller.signal.aborted) setDiscovering(false);
    });
    return () => {
      window.clearInterval(hostTimer);
      controller.abort();
      discoveryStarted.current = false;
    };
  }, [props.active, discoveryAttempt]);
  const [filters, setFilters] = reactExports.useState(EMPTY_CATALOG_FILTERS);
  const [filterPanelOpen, setFilterPanelOpen] = reactExports.useState(false);
  const [listView, setListView] = reactExports.useState("builtin");
  const filterPanelId = reactExports.useId();
  const builtinPanelId = reactExports.useId();
  const customPanelId = reactExports.useId();
  const filterTriggerRef = reactExports.useRef(null);
  const filterToolbarRef = reactExports.useRef(null);
  reactExports.useEffect(() => {
    setFilters((current) => {
      const next = pruneCatalogFilters(current, props.catalogExtensions);
      if (catalogFiltersEqual(current, next)) return current;
      return next;
    });
  }, [props.catalogExtensions]);
  reactExports.useEffect(() => {
    if (!filterPanelOpen) return;
    const onPointerDown = (event) => {
      if (filterToolbarRef.current?.contains(event.target)) return;
      setFilterPanelOpen(false);
    };
    const onKeyDown = (event) => {
      if (event.key !== "Escape") return;
      if (document.querySelector('[role="dialog"][aria-modal="true"]')) return;
      setFilterPanelOpen(false);
      filterTriggerRef.current?.focus();
    };
    document.addEventListener("pointerdown", onPointerDown);
    document.addEventListener("keydown", onKeyDown);
    return () => {
      document.removeEventListener("pointerdown", onPointerDown);
      document.removeEventListener("keydown", onKeyDown);
    };
  }, [filterPanelOpen]);
  reactExports.useEffect(() => {
    if (!props.active) return;
    const onKeyDown = (event) => {
      if (event.key !== "f" || event.defaultPrevented || event.metaKey || event.ctrlKey || event.altKey) return;
      if (document.querySelector('[role="dialog"][aria-modal="true"]')) return;
      const target = event.target;
      if (target && (target.tagName === "INPUT" || target.tagName === "TEXTAREA" || target.isContentEditable)) return;
      event.preventDefault();
      setFilterPanelOpen(true);
      filterTriggerRef.current?.focus();
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [props.active]);
  const searching = query.trim().length > 0;
  const filtering = catalogFiltersActive(filters);
  const visibleCatalog = reactExports.useMemo(
    () => filterCatalogExtensions(props.catalogExtensions, filters),
    [filters, props.catalogExtensions]
  );
  const paidById = reactExports.useMemo(
    () => new Map(
      // Featured last so it wins a collision: one extension can hold both a
      // featured and a sponsored placement, and the row must disclose and
      // measure the stronger one it is actually ranked for.
      [...joinedDiscovery.sponsored, ...joinedDiscovery.featured].map((entry) => [entry.placement.extensionId, entry])
    ),
    [joinedDiscovery.featured, joinedDiscovery.sponsored]
  );
  const orderedCatalog = reactExports.useMemo(() => {
    const visibleIds = new Set(visibleCatalog.map((extension) => extension.extension_id));
    const featuredVisible = joinedDiscovery.featured.map((entry) => entry.catalog).filter((extension) => visibleIds.has(extension.extension_id));
    const featuredIds = new Set(joinedDiscovery.featured.map((entry) => entry.placement.extensionId));
    const sponsoredIds = new Set(
      joinedDiscovery.sponsored.map((entry) => entry.placement.extensionId).filter((extensionId) => !featuredIds.has(extensionId))
    );
    const rest = orderFeaturedFirst(
      visibleCatalog.filter((extension) => !featuredIds.has(extension.extension_id)),
      sponsoredIds
    );
    return [...featuredVisible, ...rest];
  }, [joinedDiscovery.featured, joinedDiscovery.sponsored, visibleCatalog]);
  const catalogSlot = slotState({
    status: discoveryFeed.status,
    offers: discoveryOffers,
    products: CATALOG_SLOT_PRODUCTS
  });
  const catalogSlotOpen = !searching && !filtering && visibleCatalog.length >= MIN_ORGANIC_ROWS_BEFORE_IN_FEED && (catalogSlot === "open" || catalogSlot === "unconfirmed");
  const catalogSlotPrice = reactExports.useMemo(
    () => slotStartingPrice(discoveryOffers, CATALOG_SLOT_PRODUCTS),
    [discoveryOffers]
  );
  const catalogSlotInventory = reactExports.useMemo(
    () => slotInventoryLabel(discoveryOffers, CATALOG_SLOT_PRODUCTS),
    [discoveryOffers]
  );
  const catalogSlotIndexes = reactExports.useMemo(() => new Set(inFeedSlotIndexes(orderedCatalog.length)), [orderedCatalog.length]);
  const effective = props.effective;
  const isExtensionActive = reactExports.useCallback(
    (extension) => extensionEffectiveState(effective, extension) === "enabled",
    [effective]
  );
  const handleClearFilters = reactExports.useCallback(() => {
    setFilters(EMPTY_CATALOG_FILTERS);
  }, []);
  const onAddCustom = props.onAddCustom;
  const handleAddCustom = reactExports.useCallback(() => {
    setListView("custom");
    onAddCustom();
  }, [onAddCustom]);
  const handleSetUpCustom = reactExports.useCallback((command) => {
    setListView("custom");
    onAddCustom(command);
  }, [onAddCustom]);
  const allCustomItems = connectorWorkspaceItems(props.localCliItems, "", props.seededItems);
  const addedCustomItems = allCustomItems.filter(
    (item) => customItemMatchesFilters(item, filters)
  );
  const customItemsFilteredOut = filtering && allCustomItems.length > 0 && addedCustomItems.length === 0;
  const customNeedsReviewCount = allCustomItems.filter(customExtensionNeedsReview).length;
  const customEmptyOwnsAdd = listView === "custom" && allCustomItems.length === 0;
  const switchOffersAdd = !searching && !customEmptyOwnsAdd;
  const searchOffersAdd = searching && !customEmptyOwnsAdd;
  const discoveryMessage = [discoveryError, hostDiscoveryError].filter(Boolean).join(" ") || null;
  const retryDiscovery = reactExports.useCallback(() => setDiscoveryAttempt((attempt) => attempt + 1), []);
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { hidden: !props.active, inert: !props.active || void 0, children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx(
      WorkspacePageHeader,
      {
        eyebrow: "On this device",
        title: PROTECTION_TERMS.pageTitle,
        description: "Choose an Extension to review its permissions and effective protection.",
        actions: /* @__PURE__ */ jsxRuntimeExports.jsx(
          "a",
          {
            className: "guard-extensions-chip",
            "data-testid": "sponsor-extension-action",
            href: "https://hol.org/guard/extensions/advertise?source=guard_local&intent=extension-promotion&placement=extensions_header",
            target: "_blank",
            rel: "noopener noreferrer",
            referrerPolicy: "no-referrer",
            children: "Sponsor an extension"
          }
        )
      }
    ),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { "data-testid": "extensions-surface", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-6", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(
          ProtectionStatusHero,
          {
            status: props.status,
            onPrimaryAction: props.status.primaryAction === "review-lockdown" ? props.onPrimaryStatusAction : void 0
          }
        ),
        props.recoveryStatus && !props.healthBroken ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { role: "status", className: "mt-3 text-sm font-medium text-emerald-800", children: props.recoveryStatus }) : null
      ] }),
      props.mutationError ? /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-4", children: /* @__PURE__ */ jsxRuntimeExports.jsx(InlineError, { message: props.mutationError }) }) : null,
      props.localCliError ? /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-4", children: /* @__PURE__ */ jsxRuntimeExports.jsx(InlineError, { message: props.localCliError }) }) : null,
      props.localCliNotice ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { role: "status", className: "mt-4 rounded-xl border border-brand-blue/20 bg-brand-blue/5 p-3 text-sm text-brand-dark", children: props.localCliNotice }) : null,
      searching ? null : /* @__PURE__ */ jsxRuntimeExports.jsx(
        ExtensionsSpotlight,
        {
          catalogExtensions: props.catalogExtensions,
          featured: joinedDiscovery.featured,
          sponsored: joinedDiscovery.sponsored,
          activity: popularity.counts,
          offers: discoveryOffers,
          status: discoveryFeed.status,
          snapshotId: discoverySnapshotId,
          settled: popularity.settled,
          isExtensionActive,
          onOpenExtension: props.onOpenExtension
        }
      ),
      /* @__PURE__ */ jsxRuntimeExports.jsx(
        "div",
        {
          ref: filterToolbarRef,
          "data-testid": "catalog-filters",
          children: /* @__PURE__ */ jsxRuntimeExports.jsx(
            PatternSearchConsole,
            {
              catalog: visibleCatalog,
              readModel: props.readModel,
              effective: props.effective,
              active: props.active,
              query,
              onQueryChange: setQuery,
              onRefresh: props.onRefresh,
              onOpenExtension: props.onOpenExtension,
              actionSlot: searchOffersAdd ? /* @__PURE__ */ jsxRuntimeExports.jsx(AddCustomExtensionButton, { onClick: handleAddCustom }) : null,
              toolbarSlot: /* @__PURE__ */ jsxRuntimeExports.jsx(
                CatalogFilterTrigger,
                {
                  open: filterPanelOpen,
                  activeCount: filters.trusts.length + filters.kinds.length + filters.areas.length,
                  panelId: filterPanelId,
                  buttonRef: filterTriggerRef,
                  onToggle: () => setFilterPanelOpen((open) => !open)
                }
              ),
              subtoolbarSlot: /* @__PURE__ */ jsxRuntimeExports.jsx(
                CatalogFilterBar,
                {
                  catalog: props.catalogExtensions,
                  filters,
                  onChange: setFilters,
                  open: filterPanelOpen,
                  onOpenChange: setFilterPanelOpen,
                  panelId: filterPanelId,
                  onAfterClear: () => filterTriggerRef.current?.focus()
                }
              )
            }
          )
        }
      ),
      /* @__PURE__ */ jsxRuntimeExports.jsx(
        ExtensionListSwitch,
        {
          view: listView,
          onViewChange: setListView,
          builtinCount: visibleCatalog.length,
          customCount: addedCustomItems.length,
          customNeedsReviewCount,
          builtinPanelId: searching ? void 0 : builtinPanelId,
          customPanelId,
          onAddCustom: switchOffersAdd ? handleAddCustom : void 0
        }
      ),
      props.active && listView === "builtin" ? /* @__PURE__ */ jsxRuntimeExports.jsx(ConnectorDiscoveryNotice, { error: discoveryMessage, onRetry: retryDiscovery }) : null,
      /* @__PURE__ */ jsxRuntimeExports.jsx("div", { id: customPanelId, hidden: listView !== "custom", children: /* @__PURE__ */ jsxRuntimeExports.jsx(
        CustomExtensionsSection,
        {
          embedded: true,
          addInEmptyState: customEmptyOwnsAdd,
          items: addedCustomItems,
          onOpen: props.onOpenLocalCli,
          seededItems: addedCustomItems.filter((item) => item.seeded === true),
          onSetUp: handleSetUpCustom,
          onAdd: handleAddCustom,
          discovering,
          filteredOut: customItemsFilteredOut,
          onClearFilters: handleClearFilters,
          discoveryControl: props.active && listView === "custom" ? /* @__PURE__ */ jsxRuntimeExports.jsx(
            ConnectorDiscoveryControl,
            {
              discovering,
              showProgress: addedCustomItems.length > 0 || customItemsFilteredOut,
              error: discoveryMessage,
              onRetry: retryDiscovery
            }
          ) : null
        }
      ) }),
      searching ? null : /* @__PURE__ */ jsxRuntimeExports.jsxs(jsxRuntimeExports.Fragment, { children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs("section", { id: builtinPanelId, hidden: listView !== "builtin", className: "mt-4", "aria-labelledby": "all-tools-heading", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-col gap-1 sm:flex-row sm:items-end sm:justify-between", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
              /* @__PURE__ */ jsxRuntimeExports.jsx("h2", { id: "all-tools-heading", className: "sr-only", children: "All tools" }),
              /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm text-slate-500", children: filtering ? "Built-in tools that match the selected trust, kind, and area filters." : "Every built-in tool Guard can watch on this device. Open one to adjust its command patterns." })
            ] }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "flex flex-wrap items-center gap-3", children: /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-sm text-brand-dark/70", "data-testid": "catalog-tool-count", "aria-live": "polite", children: catalogFilterCountCopy(visibleCatalog.length, props.catalogExtensions.length, filtering) }) })
          ] }),
          !filtering ? /* @__PURE__ */ jsxRuntimeExports.jsx(CatalogPostureSummary, { extensions: props.catalogExtensions, effective: props.effective }) : null,
          visibleCatalog.length ? /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-4", children: orderedCatalog.map((extension, index) => {
            const paid = paidById.get(extension.extension_id);
            const row = paid ? /* @__PURE__ */ jsxRuntimeExports.jsx(
              PaidCatalogRow,
              {
                entry: paid,
                snapshotId: discoverySnapshotId,
                effective: props.effective,
                onOpen: props.onOpenExtension
              },
              extension.extension_id
            ) : /* @__PURE__ */ jsxRuntimeExports.jsx(
              CatalogExtensionRow,
              {
                extension,
                effective: props.effective,
                onOpen: props.onOpenExtension
              },
              extension.extension_id
            );
            if (!catalogSlotOpen || !catalogSlotIndexes.has(index)) return row;
            return /* @__PURE__ */ jsxRuntimeExports.jsxs(reactExports.Fragment, { children: [
              /* @__PURE__ */ jsxRuntimeExports.jsx(
                CatalogSlotRow,
                {
                  state: catalogSlot === "open" ? "open" : "unconfirmed",
                  price: catalogSlotPrice,
                  inventory: catalogSlotInventory
                }
              ),
              row
            ] }, extension.extension_id);
          }) }) : /* @__PURE__ */ jsxRuntimeExports.jsx(CatalogFilterEmpty, { onClear: handleClearFilters })
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsx(CodexHostConnectors, { inventory: props.hostInventory }),
        /* @__PURE__ */ jsxRuntimeExports.jsx(LocalSkillsWorkspace, {})
      ] })
    ] })
  ] });
}
function pushExtensionHistory(href) {
  const target = guardAwareHref(href);
  if (loadCurrentDashboardBuild(target)) return;
  window.history.pushState({}, "", target);
}
function replaceExtensionHistory(href) {
  window.history.replaceState({}, "", guardAwareHref(href));
}
function deriveProtectionStatus(effective) {
  if (effective.global_lockdown) {
    return {
      status: "lockdown",
      title: "Emergency Lockdown active",
      summary: "Guard is blocking matching optional actions until you review and end lockdown.",
      tone: "danger",
      primaryAction: "review-lockdown",
      primaryActionLabel: "Review lockdown"
    };
  }
  switch (effective.health) {
    case "protected":
      return {
        status: "protected",
        title: "Protected",
        summary: "Guard is actively applying the trusted protection settings on this device.",
        tone: "safe",
        primaryAction: "none",
        primaryActionLabel: null
      };
    case "unenrolled":
      return {
        status: "finish-setup",
        title: "Finish setup",
        summary: "Complete local setup so Guard can protect and verify settings on this device.",
        tone: "attention",
        primaryAction: "finish-setup",
        primaryActionLabel: "Show setup steps"
      };
    case "tampered":
    case "recovery-required":
      return {
        status: "needs-repair",
        title: "Needs repair",
        summary: "Guard detected a problem with trusted protection settings and is staying fail-safe until they are repaired.",
        tone: "danger",
        primaryAction: "repair",
        primaryActionLabel: "Repair protection"
      };
    case "degraded-unacknowledged":
      return {
        status: "limited",
        title: "Protection limited",
        summary: "Guard is staying fail-safe because it cannot fully verify protection settings. Repair is recommended.",
        tone: "attention",
        primaryAction: "repair",
        primaryActionLabel: "Restore protection"
      };
    case "degraded-acknowledged":
      return {
        status: "limited",
        title: "Protection limited",
        summary: "Guard is still staying fail-safe. The earlier acknowledgement did not restore trusted protection.",
        tone: "attention",
        primaryAction: "retry-repair",
        primaryActionLabel: "Try repair again"
      };
    default:
      return {
        status: "unavailable",
        title: "Protection status unavailable",
        summary: "Guard could not verify the current protection state. Refresh before making any protection changes.",
        tone: "neutral",
        primaryAction: "refresh",
        primaryActionLabel: "Check again"
      };
  }
}
function summarizeProtectionChange(change) {
  if ("globalLockdown" in change) {
    if (change.globalLockdown) {
      return { current: "Off", requested: "Active", title: "Enable Emergency Lockdown" };
    }
    return { current: "Active", requested: "Off", title: "Disable Emergency Lockdown" };
  }
  if (change.enabled) {
    return {
      current: "Blocked",
      requested: "Allowed within Guard safety rules",
      title: `Permit ${change.extension.name}`
    };
  }
  return {
    current: "Allowed",
    requested: "Blocked",
    title: `Block ${change.extension.name}`
  };
}
function ReviewModal(props) {
  const [password, setPassword] = reactExports.useState("");
  const [totp, setTotp] = reactExports.useState("");
  const dialogRef = useModalDialog(props.onCancel, !props.busy);
  const { current, requested, title } = summarizeProtectionChange(props.change);
  const handlePassword = reactExports.useCallback((event) => {
    setPassword(event.target.value);
  }, []);
  const handleTotp = reactExports.useCallback((event) => {
    setTotp(event.target.value);
  }, []);
  const handleSubmit = reactExports.useCallback((event) => {
    event.preventDefault();
    props.onConfirm(buildApprovalProofCredentials(props.approvalGate, { approvalPassword: password, approvalTotpCode: totp }));
  }, [password, props, totp]);
  const submitDisabled = isApprovalProofSubmitDisabled(props.approvalGate, { approvalPassword: password, approvalTotpCode: totp }, props.busy, false, true);
  return /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "fixed inset-0 z-50 grid place-items-center bg-slate-950/45 p-4 backdrop-blur-sm", children: /* @__PURE__ */ jsxRuntimeExports.jsxs("form", { ref: dialogRef, tabIndex: -1, role: "dialog", "aria-modal": "true", "aria-labelledby": "protection-review-title", onSubmit: handleSubmit, className: "w-full max-w-lg rounded-3xl bg-white p-6 shadow-2xl focus:outline-none", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-start justify-between gap-4", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs font-bold uppercase tracking-[0.18em] text-brand-blue", children: "Review protection change" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("h2", { id: "protection-review-title", className: "mt-2 text-xl font-semibold text-brand-dark", children: title })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("button", { type: "button", disabled: props.busy, onClick: props.onCancel, "aria-label": "Close review", className: "grid size-11 place-items-center rounded-full text-brand-dark hover:bg-white/70 disabled:opacity-50", children: /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniXMark, { className: "size-5" }) })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-5 grid grid-cols-[1fr_auto_1fr] items-center gap-3 rounded-2xl bg-[rgba(85,153,254,0.08)] p-4 text-sm text-brand-dark", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("span", { children: "Current" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("span", { "aria-hidden": "true", children: "→" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("strong", { children: "Requested" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("span", { children: current }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("span", {}),
      /* @__PURE__ */ jsxRuntimeExports.jsx("span", { children: requested })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-4 text-sm leading-6 text-brand-dark", children: "Guard's built-in minimum safety rules and organization policy remain active. This change does not disable detection." }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-5", children: /* @__PURE__ */ jsxRuntimeExports.jsx(ApprovalProofFieldInputs, { approvalGate: props.approvalGate, approvalPassword: password, approvalTotpCode: totp, requireGate: true, onApprovalPasswordChange: handlePassword, onApprovalTotpCodeChange: handleTotp }) }),
    props.error ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { role: "alert", className: "mt-4 rounded-xl border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-800", children: props.error }) : null,
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-6 flex justify-end gap-3", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("button", { type: "button", disabled: props.busy, onClick: props.onCancel, className: "min-h-11 rounded-xl px-4 text-sm font-semibold text-brand-dark hover:bg-white/70 disabled:opacity-50", children: "Cancel" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("button", { type: "submit", disabled: submitDisabled, className: "min-h-11 rounded-xl bg-brand-blue px-5 text-sm font-semibold text-white hover:bg-brand-dark disabled:opacity-60", children: props.busy ? "Verifying…" : "Confirm change" })
    ] })
  ] }) });
}
const KEPT = "Guard could not save this protection change, so your current protection is unchanged.";
const UNCERTAIN = "Guard could not confirm this protection change, so it may or may not have been saved. Reload the page to see the settings Guard is holding now.";
function preparationSentence(cause, recovery) {
  switch (cause) {
    case "offline":
      return `${KEPT} It could not reach the protection release service. Check this machine's connection and try again.`;
    case "release_unavailable":
      return `${KEPT} The protection release it needs is not available yet. Try again shortly.`;
    case "pack_authority_unavailable":
      return `${KEPT} This install has no protection release it can verify yet. Update Guard, or reconnect this machine so it can fetch one, then try again.`;
    case "installed_runtime_incomplete":
      return `${KEPT} This Guard installation is missing part of its runtime, so it cannot read its own protection bundle. Reinstall or update Guard, then try again.`;
    case "installed_runtime_unresponsive":
      return `${KEPT} Guard's packaged compiler did not answer in time. Try again; if it keeps failing, restart Guard.`;
    case "pack_revoked":
      return `${KEPT} A protection pack it needs was withdrawn. Reload this page to pick up the current catalog, then try again.`;
    case "local_storage":
      return `${KEPT} Guard could not read its local protection cache. Try again; if it keeps failing, run \`${recovery.command}\` in ${recovery.terminal}.`;
    // Not a broken install and not transient: the request is rebuilt from the
    // same local data every time, so neither reinstalling nor retrying moves
    // it. Saying "try again" here is what left operators in a loop, and so
    // would naming a recovery command, because none of them prune the state
    // the request is built from. The log is the one place that says what grew.
    case "native_request_too_large":
      return `${KEPT} Guard's local protection data has grown past what its runtime accepts in one request. Retrying sends the same request again and reinstalling Guard will not change it; the Guard daemon log records the request that grew and how far past the bound it got.`;
    default:
      return `${KEPT} Try again; if it keeps failing, the Guard daemon log records the exact cause.`;
  }
}
function codeSentence(code, recovery) {
  const repairAuthority = `Run \`${recovery.command}\` in ${recovery.terminal}, then try again.`;
  switch (code) {
    case "approval_required":
      return `${KEPT} It needs your approval password before it can apply.`;
    case "authority_apply_failed":
      return `${UNCERTAIN} If the change is not there, ${repairAuthority}`;
    case "authority_conflict":
    case "revision_conflict":
    case "invalid_previous_revision":
      return `${KEPT} Your protection settings changed while this page was open. ${recovery.reloaded ? "This page now shows the current settings; make the change again." : "Reload the page and make the change again."}`;
    case "authority_unavailable":
    case "authority_unread":
    case "authority_history_unavailable":
      return `${KEPT} Guard could not open its local protection authority. ${repairAuthority}`;
    case "authority_not_degraded":
      return "This Guard install's protection authority is healthy, so there is nothing to recover.";
    case "authority_not_recoverable":
      return `Guard cannot recover this protection authority automatically. ${repairAuthority}`;
    case "authority_recovery_failed":
    case "authority_recovery_incomplete":
      return `Guard could not finish recovering the protection authority. ${repairAuthority}`;
    case "catalog_conflict":
    case "catalog_payload_limit_exceeded":
      return `${KEPT} Guard's protection catalog moved underneath this page. ${recovery.reloaded ? "This page now shows the current catalog; make the change again." : "Reload the page and make the change again."}`;
    case "control_limit_exceeded":
    case "layer_control_limit_exceeded":
    case "layer_limit_exceeded":
      return `${KEPT} It would take this install past the number of custom protection settings Guard keeps. Return some settings to Recommended, then try again.`;
    case "duplicate_control_target":
      return `${KEPT} The same setting was changed twice in one save. Reload the page and make the change once.`;
    case "extension_control_stopped":
      return `${KEPT} Guard is shutting down. Start Guard again, then make the change.`;
    case "immutable_extension":
    case "immutable_permission":
    case "managed_layer_mutation":
    case "managed_layer_conflict":
      return `${KEPT} This setting is managed for you by your organization and cannot be changed here.`;
    case "invalid_extension":
    case "unknown_extension":
    case "unknown_permission":
      return `${KEPT} Guard no longer recognizes the setting this page asked to change. ${recovery.reloaded ? "This page now shows what Guard recognizes; try again." : "Reload the page and try again."}`;
    case "invalid_layers":
    case "invalid_mutation":
      return `${KEPT} Guard rejected the change as malformed. Reload the page and make the change again; if it keeps failing, the Guard daemon log records the exact cause.`;
    case "invalid_inspection_command":
    case "invalid_test_command":
      return "Guard could not read that command. Enter the command exactly as you would run it, then check it again.";
    case "pack_preparation_unavailable":
      return void 0;
    // Refined by cause below.
    case "prepared_preview_expired":
      return `${KEPT} The review you approved has expired. Make the change again and apply it straight away.`;
    case "proof_invalid":
    case "proof_mismatch":
    case "proof_not_found":
      return `${KEPT} The approval for this change was no longer valid. Make the change again and re-enter your approval password.`;
    default:
      return void 0;
  }
}
const RETRYABLE_PREPARATION_CAUSES = /* @__PURE__ */ new Set([
  "installed_runtime_unresponsive",
  "local_storage",
  "offline",
  "release_unavailable"
]);
const STALE_DATA_CODES = /* @__PURE__ */ new Set([
  "authority_conflict",
  "catalog_conflict",
  "invalid_extension",
  "invalid_previous_revision",
  "revision_conflict",
  "unknown_extension",
  "unknown_permission"
]);
function isStaleProtectionDataError(error) {
  return error instanceof ExtensionControlApiError && STALE_DATA_CODES.has(error.code ?? "");
}
function isRetryableProtectionChangeError(error) {
  return error instanceof ExtensionControlApiError && error.code === "pack_preparation_unavailable" && RETRYABLE_PREPARATION_CAUSES.has(error.cause ?? "");
}
function protectionChangeErrorMessage(error, recoveryCommand, recoveryShell, options = {}) {
  const recovery = {
    command: recoveryCommand ?? "hol-guard command controls recover-authority",
    terminal: recoveryShell === "powershell" ? "PowerShell" : "your terminal",
    reloaded: options.reloaded === true
  };
  if (error instanceof ExtensionControlApiError) {
    if (error.code === "pack_preparation_unavailable") return preparationSentence(error.cause, recovery);
    const sentence = error.code ? codeSentence(error.code, recovery) : void 0;
    if (sentence) return sentence;
    return `${UNCERTAIN} If it is not there, try again; the Guard daemon log records the exact cause.`;
  }
  return error instanceof Error && error.message ? error.message : "Protection change failed";
}
const RETRY_PREPARATION_DELAY_MS = 1200;
const DEFAULT_AUTHORITY_RECOVERY_COMMAND = "hol-guard command controls recover-authority";
function currentExtensionRouteState() {
  return {
    route: parseProtectionRoute(window.location.pathname),
    detail: readExtensionDetailUrlState(window.location.search)
  };
}
function requiresExtensionRecoveryApproval(error) {
  return error instanceof ExtensionControlApiError && (error.code === "approval_required" || error.code?.startsWith("approval_gate_") === true);
}
function authorityActionErrorMessage(error, recoveryCommand, recoveryShell) {
  const command = recoveryCommand ?? DEFAULT_AUTHORITY_RECOVERY_COMMAND;
  const terminalName = recoveryShell === "powershell" ? "PowerShell" : "your terminal";
  if (error instanceof ExtensionControlApiError) {
    if (error.code === "authority_not_recoverable") {
      return `Guard could not start this repair because the protection state changed underneath it. Guard reloaded the latest status. If protection still needs attention, run \`${command}\` in ${terminalName}.`;
    }
    if (error.code === "authority_recovery_failed" || error.code === "authority_recovery_incomplete") {
      return `Guard started the repair but could not verify a fully protected state. Protection stays fail-safe. Try again, or run \`${command}\` in ${terminalName}.`;
    }
    if (error.code === "authority_not_degraded") {
      return "The limited state already changed. Guard reloaded the latest status.";
    }
    if (requiresExtensionRecoveryApproval(error)) {
      return "Guard needs your approval password to continue. Enter it and try again.";
    }
  }
  return error instanceof Error && error.message && !/^authority_|^approval_/.test(error.message) ? error.message : `Guard could not complete this action. Local protection continues. Try again, or run \`${command}\` in ${terminalName}.`;
}
function ProtectionCenterWorkspace(props) {
  const [state, setState] = reactExports.useState({ kind: "loading" });
  const [routeState, setRouteState] = reactExports.useState(() => currentExtensionRouteState());
  const [pending, setPending] = reactExports.useState(null);
  const [busy, setBusy] = reactExports.useState(false);
  const [mutationError, setMutationError] = reactExports.useState(null);
  const [recoveryBusy, setRecoveryBusy] = reactExports.useState(false);
  const [recoveryError, setRecoveryError] = reactExports.useState(null);
  const [recoveryStatus, setRecoveryStatus] = reactExports.useState(null);
  const recoveryCommand = state.kind === "ready" ? state.effective.terminal_commands?.recover_authority : void 0;
  const recoveryShell = state.kind === "ready" ? state.effective.terminal_commands?.shell : void 0;
  const recoveryTerminal = recoveryShell === "powershell" ? "PowerShell" : "your terminal";
  const { resolvedApprovalGate, resolveApprovalGate, refreshApprovalGate } = useResolvedApprovalGate(null);
  const aliasRedirected = reactExports.useRef(null);
  const overviewKeepAlive = reactExports.useRef(false);
  const loadInFlightRef = reactExports.useRef(null);
  const unsettledRef = reactExports.useRef(false);
  const catalogRef = reactExports.useRef(null);
  const refreshInFlightRef = reactExports.useRef(null);
  const localClis = useLocalCliCatalog();
  const startLoad = reactExports.useCallback(() => {
    const request2 = (async () => {
      setState((current) => current.kind === "ready" ? current : { kind: "loading" });
      try {
        const { catalog: fresh, effective, consistent } = await loadConsistentProtectionData(loadCatalogReadModel, fetchEffectiveExtensionControls);
        const previous = catalogRef.current;
        const catalog = reusableCatalogModel(previous, fresh);
        catalogRef.current = catalog;
        unsettledRef.current = !consistent;
        setState({ kind: "ready", catalog, effective, unsettled: !consistent });
        return effective;
      } catch (error) {
        setState((current) => current.kind === "ready" ? current : { kind: "error", message: error instanceof Error ? error.message : "Extensions are unavailable" });
        return null;
      }
    })();
    loadInFlightRef.current = request2;
    void request2.then(
      () => {
        if (loadInFlightRef.current === request2) loadInFlightRef.current = null;
      },
      () => {
        if (loadInFlightRef.current === request2) loadInFlightRef.current = null;
      }
    );
    return request2;
  }, []);
  const load = reactExports.useCallback(async (options = {}) => {
    const inFlight = loadInFlightRef.current;
    if (inFlight === null) return startLoad();
    if (!options.fresh) return inFlight;
    await inFlight;
    return loadInFlightRef.current ?? startLoad();
  }, [startLoad]);
  reactExports.useEffect(() => {
    void load();
  }, [load]);
  reactExports.useEffect(() => {
    const onPopState = () => {
      const next = currentExtensionRouteState();
      if (next.route.kind === "add-custom") void localClis.discover();
      setRouteState(next);
    };
    window.addEventListener("popstate", onPopState);
    return () => window.removeEventListener("popstate", onPopState);
  }, [localClis.discover]);
  reactExports.useEffect(() => {
    if (routeState.route.kind !== "add-custom") return;
    void localClis.discover();
  }, [localClis.discover, routeState.route.kind]);
  const catalogExtensions = reactExports.useMemo(() => state.kind === "ready" ? state.catalog.extensions : [], [state]);
  const requestedExtensionId = routeState.route.kind === "detail" ? routeState.route.extensionId : null;
  const canonicalSelected = reactExports.useMemo(() => canonicalExtensionId(catalogExtensions, requestedExtensionId), [catalogExtensions, requestedExtensionId]);
  const selectedExtension = reactExports.useMemo(() => catalogExtensions.find((item) => item.extension_id === canonicalSelected) ?? null, [catalogExtensions, canonicalSelected]);
  reactExports.useEffect(() => {
    if (state.kind !== "ready" || routeState.route.kind !== "detail" || !canonicalSelected) return;
    if (routeState.route.extensionId === canonicalSelected) return;
    const key = `${routeState.route.extensionId}->${canonicalSelected}`;
    if (aliasRedirected.current === key) return;
    aliasRedirected.current = key;
    replaceExtensionHistory(extensionDetailHref(canonicalSelected, routeState.detail));
    setRouteState({ route: { kind: "detail", extensionId: canonicalSelected }, detail: routeState.detail });
  }, [canonicalSelected, routeState, state]);
  const openExtension = reactExports.useCallback((extension) => {
    pushExtensionHistory(extensionDetailHref(extension.extension_id, DEFAULT_EXTENSION_DETAIL_URL_STATE));
    setRouteState({ route: { kind: "detail", extensionId: extension.extension_id }, detail: DEFAULT_EXTENSION_DETAIL_URL_STATE });
    window.scrollTo({ top: 0, behavior: "auto" });
  }, []);
  const closeExtension = reactExports.useCallback(() => {
    pushExtensionHistory("/extensions");
    setRouteState({ route: { kind: "overview" }, detail: DEFAULT_EXTENSION_DETAIL_URL_STATE });
    window.scrollTo({ top: 0, behavior: "auto" });
  }, []);
  const updateExtensionDetailState = reactExports.useCallback((detail) => {
    if (!canonicalSelected) return;
    pushExtensionHistory(extensionDetailHref(canonicalSelected, detail));
    setRouteState({ route: { kind: "detail", extensionId: canonicalSelected }, detail });
  }, [canonicalSelected]);
  const openLocalCliDetail = reactExports.useCallback((cliId) => {
    pushExtensionHistory(localCliHref(cliId));
    setRouteState({ route: { kind: "local-cli", cliId }, detail: DEFAULT_EXTENSION_DETAIL_URL_STATE });
    window.scrollTo({ top: 0, behavior: "auto" });
  }, []);
  const openAddCustom = reactExports.useCallback((command) => {
    void localClis.discover();
    pushExtensionHistory(addCustomExtensionPrefillHref(addCustomExtensionHref(), typeof command === "string" ? command : void 0));
    setRouteState({ route: { kind: "add-custom" }, detail: DEFAULT_EXTENSION_DETAIL_URL_STATE });
    window.scrollTo({ top: 0, behavior: "auto" });
  }, [localClis.discover]);
  const handleCustomExtensionAdded = reactExports.useCallback((cliId) => {
    void localClis.load();
    openLocalCliDetail(cliId);
  }, [localClis.load, openLocalCliDetail]);
  const retryLocalClis = reactExports.useCallback(() => {
    void localClis.load();
  }, [localClis.load]);
  const retryLoad = reactExports.useCallback(() => {
    void load();
  }, [load]);
  const refreshProtection = reactExports.useCallback(() => {
    if (refreshInFlightRef.current !== null) return refreshInFlightRef.current;
    const request2 = (async () => {
      const [refreshed] = await Promise.all([load(), props.onRefreshRuntime()]);
      if (refreshed === null) {
        throw new Error("Protection status could not be refreshed.");
      }
    })();
    refreshInFlightRef.current = request2;
    void request2.then(
      () => {
        if (refreshInFlightRef.current === request2) refreshInFlightRef.current = null;
      },
      () => {
        if (refreshInFlightRef.current === request2) refreshInFlightRef.current = null;
      }
    );
    return request2;
  }, [load, props.onRefreshRuntime]);
  const handleCancelPending = reactExports.useCallback(() => {
    if (!busy) setPending(null);
  }, [busy]);
  const requestChange = reactExports.useCallback((change) => {
    setMutationError(null);
    void resolveApprovalGate({ failClosed: true }).then(() => setPending(change)).catch(() => setMutationError("Guard could not load local approval settings. Check the local connection and try again."));
  }, [resolveApprovalGate]);
  const handleRequestExtensionChange = reactExports.useCallback((extension, enabled) => {
    requestChange({ extension: { extension_id: extension.extension_id, name: extension.name }, enabled });
  }, [requestChange]);
  const confirm = reactExports.useCallback(async (credentials) => {
    if (state.kind !== "ready" || !pending) return;
    if (state.unsettled) {
      setMutationError(PROTECTION_SAVE_UNSETTLED_MESSAGE);
      return;
    }
    setBusy(true);
    setMutationError(null);
    const submit = async () => {
      const payload = buildExtensionMutation(state, pending);
      Object.assign(payload, credentials);
      payload.session_nonce = randomToken();
      const preview = await previewExtensionMutation(payload);
      if (typeof preview.proof_id !== "string") throw new Error("Guard did not issue a one-use proof for this protection change.");
      payload.proof_id = preview.proof_id;
      await applyExtensionMutation(payload);
    };
    try {
      try {
        await submit();
      } catch (error) {
        if (!isRetryableProtectionChangeError(error)) throw error;
        await new Promise((resolve) => setTimeout(resolve, RETRY_PREPARATION_DELAY_MS));
        await submit();
      }
      setPending(null);
      await load();
    } catch (error) {
      if (isStaleProtectionDataError(error)) {
        const reloaded = await load({ fresh: true }) !== null;
        setMutationError(
          reloaded && unsettledRef.current ? PROTECTION_SAVE_UNSETTLED_MESSAGE : protectionChangeErrorMessage(error, recoveryCommand, recoveryShell, { reloaded })
        );
        return;
      }
      setMutationError(protectionChangeErrorMessage(error, recoveryCommand, recoveryShell));
    } finally {
      setBusy(false);
    }
  }, [load, pending, recoveryCommand, recoveryShell, state]);
  const runAuthorityAction = reactExports.useCallback(async (kind, credentials) => {
    const startHealth = state.kind === "ready" ? state.effective.health : null;
    setRecoveryBusy(true);
    setRecoveryError(null);
    setRecoveryStatus(null);
    try {
      const effective = kind === "acknowledge" ? await acknowledgeDegradedExtensionControlAuthority(credentials) : await recoverExtensionControlAuthority(credentials);
      if (kind === "acknowledge") {
        if (effective.health !== "degraded-acknowledged") throw new Error("Guard could not confirm the limited state.");
        setRecoveryStatus("The limited state is acknowledged. Guard remains fail-safe until trusted protection can be restored.");
      } else {
        if (effective.health !== "protected") throw new Error("Guard could not verify repaired protection.");
        setRecoveryStatus("Local protection repaired and verified.");
      }
      if (state.kind === "ready") setState({ ...state, effective });
    } catch (error) {
      const fresh = await load();
      const wanted = kind === "acknowledge" ? "degraded-acknowledged" : "protected";
      if (fresh && fresh.health === wanted) {
        setRecoveryError(null);
        setRecoveryStatus(kind === "acknowledge" ? "The limited state is acknowledged. Guard remains fail-safe until trusted protection can be restored." : "Local protection repaired and verified.");
      } else if (fresh && startHealth !== null && fresh.health !== startHealth) {
        setRecoveryError(null);
        setRecoveryStatus("The protection state changed during the attempt. This page now shows the latest status.");
      } else {
        setRecoveryStatus(null);
        setRecoveryError(authorityActionErrorMessage(
          error,
          recoveryCommand,
          recoveryShell
        ));
      }
    } finally {
      setRecoveryBusy(false);
    }
  }, [load, state]);
  const handleAuthorityAction = reactExports.useCallback((kind, credentials) => {
    void runAuthorityAction(kind, credentials);
  }, [runAuthorityAction]);
  const handleCheckAgain = reactExports.useCallback(async () => {
    setRecoveryError(null);
    const [protectionResult, approvalResult] = await Promise.allSettled([
      refreshProtection(),
      refreshApprovalGate({ failClosed: true })
    ]);
    if (approvalResult.status === "rejected") {
      setRecoveryError(`Guard could not load the local approval settings yet. Check the connection and try again, or run \`${recoveryCommand ?? DEFAULT_AUTHORITY_RECOVERY_COMMAND}\` in ${recoveryTerminal}.`);
    }
    if (protectionResult.status === "rejected") throw protectionResult.reason;
  }, [refreshApprovalGate, refreshProtection, recoveryCommand, recoveryTerminal]);
  const handleOpenApprovalSettings = reactExports.useCallback(() => {
    props.onNavigate("/settings?section=approval&returnTo=extensions");
  }, [props.onNavigate]);
  const authorityNeedsAttention = state.kind === "ready" && state.effective.health !== "protected";
  reactExports.useEffect(() => {
    if (!authorityNeedsAttention) return;
    void resolveApprovalGate({ failClosed: true }).catch(() => {
      setRecoveryError(`Guard could not load the local approval settings yet. Check the connection and try again, or run \`${recoveryCommand ?? DEFAULT_AUTHORITY_RECOVERY_COMMAND}\` in ${recoveryTerminal}.`);
    });
  }, [authorityNeedsAttention, recoveryCommand, recoveryTerminal, resolveApprovalGate]);
  const showOverview = state.kind === "ready" && routeState.route.kind === "overview";
  if (showOverview) overviewKeepAlive.current = true;
  const keepOverviewMounted = state.kind === "ready" && (showOverview || overviewKeepAlive.current);
  const localCliRoute = routeState.route.kind === "local-cli" ? routeState.route : null;
  const selectedLocalCli = localCliRoute ? localClis.data?.items.find((item) => item.cli_id === localCliRoute.cliId) ?? null : null;
  const showLocalCli = localCliRoute !== null;
  const setupLink = reactExports.useMemo(
    () => localCliRoute ? connectorSetupLinkFromSearch(window.location.search) : null,
    [localCliRoute]
  );
  const showDetail = routeState.route.kind === "detail" && selectedExtension !== null;
  const showNotFound = routeState.route.kind === "invalid" || routeState.route.kind === "detail" && selectedExtension === null && state.kind === "ready" || showLocalCli && localClis.data !== null && selectedLocalCli === null;
  const handlePrimaryStatusAction = reactExports.useCallback(() => {
    requestChange({ globalLockdown: false });
  }, [requestChange]);
  const loadError = state.kind === "error" ? protectionCenterLoadError(state.message) : null;
  const status = state.kind === "ready" ? deriveProtectionStatus(state.effective) : null;
  const healthBroken = state.kind === "ready" && state.effective.health !== "protected";
  const dataUnsettled = state.kind === "ready" && state.unsettled;
  const catalogDegraded = state.kind === "ready" && state.catalog.degraded === CATALOG_PREPARATION_FAILED;
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "w-full", "data-testid": "extensions-workspace", children: [
    state.kind === "loading" ? /* @__PURE__ */ jsxRuntimeExports.jsx(ExtensionsLoadingState, { label: "Loading Extensions" }) : null,
    state.kind === "error" && loadError ? /* @__PURE__ */ jsxRuntimeExports.jsx(
      ExtensionsLoadError,
      {
        title: loadError.title,
        detail: loadError.detail,
        reference: loadError.reference,
        onRetry: retryLoad
      }
    ) : null,
    state.kind === "ready" && healthBroken ? /* @__PURE__ */ jsxRuntimeExports.jsx(
      ProtectionAuthorityNotice,
      {
        effective: state.effective,
        busy: recoveryBusy,
        error: recoveryError,
        status: recoveryStatus,
        approvalGate: resolvedApprovalGate,
        onAction: handleAuthorityAction,
        onCheckAgain: handleCheckAgain,
        onOpenApprovalSettings: handleOpenApprovalSettings
      }
    ) : null,
    catalogDegraded ? /* @__PURE__ */ jsxRuntimeExports.jsx(
      "p",
      {
        role: "status",
        "data-testid": "catalog-preparation-degraded",
        className: "mb-3 rounded-md border border-amber-300 bg-amber-50 px-3 py-2 text-sm text-amber-900",
        children: CATALOG_PREPARATION_DEGRADED_MESSAGE
      }
    ) : null,
    dataUnsettled ? /* @__PURE__ */ jsxRuntimeExports.jsx(
      "p",
      {
        role: "status",
        "data-testid": "protection-data-unsettled",
        className: "mb-3 rounded-md border border-amber-300 bg-amber-50 px-3 py-2 text-sm text-amber-900",
        children: PROTECTION_DATA_UNSETTLED_MESSAGE
      }
    ) : null,
    state.kind === "ready" && recoveryStatus && !healthBroken && !showOverview ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { role: "status", className: "mb-3 text-sm font-medium text-emerald-800", children: recoveryStatus }) : null,
    keepOverviewMounted && state.kind === "ready" && status ? /* @__PURE__ */ jsxRuntimeExports.jsx(
      ExtensionsOverview,
      {
        catalogExtensions,
        readModel: state.catalog,
        effective: state.effective,
        localCliItems: localClis.data?.items ?? [],
        seededItems: localClis.data?.seeded_items ?? [],
        hostInventory: localClis.data?.host_inventory,
        localCliError: localClis.error,
        localCliNotice: localClis.discoveryNotice,
        mutationError: mutationError && !pending ? mutationError : null,
        recoveryStatus,
        healthBroken,
        status,
        active: showOverview,
        onPrimaryStatusAction: handlePrimaryStatusAction,
        onRefresh: refreshProtection,
        onReloadConnections: localClis.load,
        onOpenExtension: openExtension,
        onOpenLocalCli: openLocalCliDetail,
        onAddCustom: openAddCustom
      }
    ) : null,
    showLocalCli && localClis.error && !localClis.data ? /* @__PURE__ */ jsxRuntimeExports.jsx(
      ExtensionsLoadError,
      {
        title: "Custom extension unavailable",
        detail: localClis.error,
        onRetry: retryLocalClis
      }
    ) : null,
    showLocalCli && localClis.error && localClis.data ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { role: "alert", className: "mb-3 text-sm font-medium text-rose-800", children: localClis.error }) : null,
    (showLocalCli || routeState.route.kind === "add-custom") && localClis.discoveryNotice && localClis.data ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { role: "status", className: "mb-3 rounded-xl border border-brand-blue/20 bg-brand-blue/5 p-3 text-sm text-brand-dark", children: localClis.discoveryNotice }) : null,
    showLocalCli && !localClis.data && !localClis.error ? /* @__PURE__ */ jsxRuntimeExports.jsx(ExtensionsLoadingState, { label: "Loading custom extension" }) : null,
    routeState.route.kind === "add-custom" && state.kind === "ready" ? /* @__PURE__ */ jsxRuntimeExports.jsx(
      AddCustomExtensionWorkspace,
      {
        items: localClis.data?.items ?? [],
        revision: localClis.data?.revision ?? 0,
        discovering: localClis.discovering || !localClis.catalogReady,
        onBack: closeExtension,
        onAdded: handleCustomExtensionAdded,
        onConfigured: localClis.discover
      }
    ) : null,
    showLocalCli && selectedLocalCli && localClis.data ? /* @__PURE__ */ jsxRuntimeExports.jsx(
      LocalCliDetail,
      {
        item: selectedLocalCli,
        revision: localClis.data.revision,
        continuity: localClis.data.cloud,
        nativePublication: localClis.data.native_publication,
        setupLink,
        onBack: closeExtension,
        onRefresh: localClis.load
      }
    ) : null,
    showDetail && selectedExtension && state.kind === "ready" ? /* @__PURE__ */ jsxRuntimeExports.jsx(
      CatalogExtensionDetail,
      {
        readModel: state.catalog,
        summary: selectedExtension,
        effective: state.effective,
        catalogDigest: state.catalog.catalog_digest,
        runtime: props.runtime,
        urlState: routeState.detail,
        onUrlState: updateExtensionDetailState,
        onBack: closeExtension,
        onRefresh: refreshProtection,
        onRequestExtensionChange: handleRequestExtensionChange
      }
    ) : null,
    showNotFound ? /* @__PURE__ */ jsxRuntimeExports.jsx(
      ExtensionsNotFound,
      {
        title: showLocalCli ? "Custom extension not found" : "Extension not found",
        detail: showLocalCli ? "This link does not match a CLI Guard has seen on this device." : "This link does not match an extension in the current Guard catalog.",
        onBack: closeExtension
      }
    ) : null,
    pending ? /* @__PURE__ */ jsxRuntimeExports.jsx(
      ReviewModal,
      {
        change: pending,
        busy,
        error: mutationError,
        approvalGate: resolvedApprovalGate,
        onCancel: handleCancelPending,
        onConfirm: confirm
      }
    ) : null
  ] });
}
export {
  ProtectionCenterWorkspace as ExtensionsWorkspace,
  ProtectionAuthorityNotice,
  ReviewModal,
  authorityActionErrorMessage,
  buildExtensionMutation,
  currentExtensionRouteState,
  requiresExtensionRecoveryApproval
};
