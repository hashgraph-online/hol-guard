import { useCallback, useMemo, useRef, useState, type ChangeEvent } from "react";
import type { BulkGateCredentials } from "./approval-gate-utils";
import { requestResolutionBlockReason } from "./approval-center-utils";
import { BulkBlockError } from "./bulk-block-requests";
import { countRetryBlockedActions } from "./approval-retry-guidance";
import type { GuardApprovalGatePublicConfig, GuardApprovalRequest } from "./guard-types";
import {
  bulkApproveActionCount,
  bulkApprovePrimaryIds,
  bulkApprovalRiskTier,
  countDuplicateActionsInGroups,
  countSensitiveFileReadGroups,
  groupDuplicates,
  isBulkApprovableGroup,
  summarizeSensitiveFileReadGroups,
  type QueueGroup,
} from "./queue-state";
import {
  buildBulkGateCredentials,
  isBulkApproveGateReady,
  validateBulkApproveCredentials,
} from "./queue-bulk-approve-flow";
import {
  buildBulkRiskDisclosure,
  bulkConfirmMatches,
  type BulkRiskDisclosure,
  type BulkRiskTier,
  type BulkSelectionStats,
} from "./queue-bulk-risk-disclosure";

export function resolveBulkSelectionGroupId(
  item: GuardApprovalRequest,
  groups: QueueGroup[],
): string {
  for (const group of groups) {
    if (group.primary.request_id === item.request_id) {
      return group.primary.request_id;
    }
    if (group.duplicateIds.includes(item.request_id)) {
      return group.primary.request_id;
    }
  }
  return item.request_id;
}

export function isBulkSelectableRequest(
  item: GuardApprovalRequest,
  groups: QueueGroup[],
): boolean {
  for (const group of groups) {
    if (
      group.primary.request_id === item.request_id ||
      group.duplicateIds.includes(item.request_id)
    ) {
      return isBulkApprovableGroup(group);
    }
  }
  return isBulkApprovableGroup({ primary: item, duplicateCount: 0, duplicateIds: [] });
}

/**
 * Any pending request Guard can resolve can be refused, the same rule that
 * shows Keep blocked on a single request; only eligible reads can be approved
 * at once. Queue pages hold only pending requests and leave `status` out, so
 * only a request that says it is no longer pending is excluded.
 */
export function isBulkBlockableGroup(group: QueueGroup): boolean {
  const status = group.primary.status as string | undefined;
  return (status === undefined || status === "pending") && requestResolutionBlockReason(group.primary) === null;
}

/** The groups a "Block selected" answers. */
export function bulkBlockGroups(groups: QueueGroup[], selectedIds: ReadonlySet<string>): QueueGroup[] {
  return groups.filter((group) => isBulkBlockableGroup(group) && selectedIds.has(group.primary.request_id));
}

export type QueueBulkDrawerStep = "review" | "submitting" | "completed";

export type QueueBulkBlockStep = "idle" | "confirming" | "blocking";

export type QueueBulkStickyBarProps = {
  visible: boolean;
  selectedGroupCount: number;
  selectedActionCount: number;
  /** Every selected request, including ones that can only be blocked. */
  selectedRequestCount: number;
  /** Whether the selection holds reads that can be approved at once. */
  canApprove: boolean;
  riskTier: BulkRiskTier;
  riskTone: BulkRiskDisclosure["tone"];
  gateReady: boolean;
  blockAvailable: boolean;
  blockStep: QueueBulkBlockStep;
  blockError: string | null;
  onStartReview: () => void;
  onRequestBlock: () => void;
  onConfirmBlock: () => void;
  onCancelBlock: () => void;
  onClearSelection: () => void;
};

export type QueueBulkDrawerProps = {
  open: boolean;
  step: QueueBulkDrawerStep;
  selectedGroups: QueueGroup[];
  selectedActionCount: number;
  retryBlockedActionCount?: number;
  sensitiveFileReadCount: number;
  riskDisclosure: BulkRiskDisclosure;
  approvalGate: GuardApprovalGatePublicConfig | null;
  settingsHref: string;
  bulkApprovePassword: string;
  bulkApproveTotpCode: string;
  typedConfirm: string;
  confirmMatches: boolean;
  canConfirm: boolean;
  completedActionCount: number | null;
  errorMessage: string | null;
  onBulkApprovePasswordChange: (event: ChangeEvent<HTMLInputElement>) => void;
  onBulkApproveTotpCodeChange: (event: ChangeEvent<HTMLInputElement>) => void;
  onTypedConfirmChange: (event: ChangeEvent<HTMLInputElement>) => void;
  onConfirmApprove: () => void;
  onCancel: () => void;
};

export type QueueBulkStatusProps = {
  visible: boolean;
  sensitiveFileReadCount: number;
};

export type QueueBulkGatePromptProps = {
  /** True when eligible reads exist but the approval gate is not configured. */
  visible: boolean;
  eligibleActionCount: number;
  settingsHref: string;
};

export type QueueBulkSelectionApi = {
  /** Ambient selection mode — checkboxes render whenever eligible reads exist. */
  selectionMode: boolean;
  isSelectable: (item: GuardApprovalRequest) => boolean;
  isSelected: (item: GuardApprovalRequest) => boolean;
  onToggle: (item: GuardApprovalRequest) => void;
  onToggleMany: (items: GuardApprovalRequest[], selectAll: boolean) => void;
  selectedActionCount: number;
  selectedGroupCount: number;
};

export type UseQueueBulkApproveResult = {
  groups: QueueGroup[];
  showBulkApprove: boolean;
  bulkSelection: QueueBulkSelectionApi;
  stickyBar: QueueBulkStickyBarProps;
  drawer: QueueBulkDrawerProps;
  status: QueueBulkStatusProps;
  gatePrompt: QueueBulkGatePromptProps;
};

export function useQueueBulkApprove(props: {
  items: GuardApprovalRequest[];
  approvalGate?: GuardApprovalGatePublicConfig | null;
  onBulkApprove?: (ids: string[], gateCredentials?: BulkGateCredentials) => void | Promise<void>;
  onBulkBlock?: (groups: QueueGroup[]) => Promise<void>;
  settingsHref: string;
}): UseQueueBulkApproveResult {
  const [drawerOpen, setDrawerOpen] = useState(false);
  const [drawerStep, setDrawerStep] = useState<QueueBulkDrawerStep>("review");
  const [selectedBulkIds, setSelectedBulkIds] = useState<Set<string>>(() => new Set());
  const [bulkApprovePassword, setBulkApprovePassword] = useState("");
  const [bulkApproveTotpCode, setBulkApproveTotpCode] = useState("");
  const [typedConfirm, setTypedConfirm] = useState("");
  const [bulkApproveError, setBulkApproveError] = useState<string | null>(null);
  const [bulkCompletedActionCount, setBulkCompletedActionCount] = useState<number | null>(null);
  const [blockStep, setBlockStep] = useState<QueueBulkBlockStep>("idle");
  const [blockError, setBlockError] = useState<string | null>(null);
  // The selection is what a running block was confirmed for; hold it still.
  const blocking = useRef(false);

  const groups = useMemo(() => groupDuplicates(props.items), [props.items]);

  const bulkEligibleGroups = useMemo(
    () => groups.filter((group) => isBulkApprovableGroup(group)),
    [groups],
  );

  const sensitiveFileReadCount = useMemo(
    () => countSensitiveFileReadGroups(groups),
    [groups],
  );

  const sensitiveSummary = useMemo(() => summarizeSensitiveFileReadGroups(groups), [groups]);

  const bulkGateReady = isBulkApproveGateReady(props.approvalGate);
  const hasBulkHandler = props.onBulkApprove !== undefined;
  const hasEligibleGroups = bulkEligibleGroups.length >= 1;
  const showBulkApprove = hasBulkHandler && bulkGateReady && hasEligibleGroups;
  // A gate that asks for proof on every decision would refuse each bulk block.
  const hasBlockHandler = props.onBulkBlock !== undefined && props.approvalGate?.strict_all_decisions !== true;
  // With a block handler every pending request is selectable; approval still
  // acts only on the eligible reads within the selection.
  const selectableGroups = useMemo(
    () => (hasBlockHandler ? groups.filter((group) => isBulkBlockableGroup(group)) : bulkEligibleGroups),
    [bulkEligibleGroups, groups, hasBlockHandler],
  );
  const selectionMode = showBulkApprove || (hasBlockHandler && selectableGroups.length > 0);

  const selectedBulkGroups = useMemo(
    () => bulkEligibleGroups.filter((group) => selectedBulkIds.has(group.primary.request_id)),
    [bulkEligibleGroups, selectedBulkIds],
  );

  const selectedActionCount = useMemo(
    () => bulkApproveActionCount(selectedBulkGroups),
    [selectedBulkGroups],
  );
  const selectedGroupCount = selectedBulkGroups.length;
  const selectedBlockGroups = useMemo(
    () => (hasBlockHandler ? bulkBlockGroups(groups, selectedBulkIds) : []),
    [groups, hasBlockHandler, selectedBulkIds],
  );
  const selectedSelectableGroups = useMemo(
    () => selectableGroups.filter((group) => selectedBulkIds.has(group.primary.request_id)),
    [selectableGroups, selectedBulkIds],
  );
  const selectedRequestCount = bulkApproveActionCount(selectedSelectableGroups);

  const selectionStats: BulkSelectionStats = useMemo(() => {
    let highActionCount = 0;
    let elevatedActionCount = 0;
    let lowActionCount = 0;
    const retryBlockedActionCount = countRetryBlockedActions(selectedBulkGroups, props.items);
    for (const group of selectedBulkGroups) {
      const tier = bulkApprovalRiskTier(group);
      const count = 1 + group.duplicateCount;
      if (tier === "high") highActionCount += count;
      else if (tier === "elevated") elevatedActionCount += count;
      else if (tier === "low") lowActionCount += count;
    }
    return {
      actionCount: selectedActionCount,
      groupCount: selectedGroupCount,
      duplicateActionCount: countDuplicateActionsInGroups(selectedBulkGroups),
      sensitiveCount: sensitiveSummary.count,
      sensitiveSamplePaths: sensitiveSummary.samplePaths,
      highActionCount,
      elevatedActionCount,
      lowActionCount,
      retryBlockedActionCount,
    };
  }, [props.items, selectedActionCount, selectedGroupCount, selectedBulkGroups, sensitiveSummary]);

  const riskDisclosure = useMemo(
    () => buildBulkRiskDisclosure(selectionStats),
    [selectionStats],
  );

  const credentialError = useMemo(
    () =>
      validateBulkApproveCredentials(props.approvalGate, {
        password: bulkApprovePassword,
        totpCode: bulkApproveTotpCode,
      }),
    [props.approvalGate, bulkApprovePassword, bulkApproveTotpCode],
  );

  const confirmMatches = useMemo(
    () =>
      !riskDisclosure.requiresTypedConfirm ||
      bulkConfirmMatches(typedConfirm, riskDisclosure.confirmPhrase),
    [riskDisclosure, typedConfirm],
  );

  const canConfirm = useMemo(
    () => credentialError === null && confirmMatches && selectedGroupCount > 0 &&
      (selectionStats.retryBlockedActionCount ?? 0) === 0,
    [credentialError, confirmMatches, selectedGroupCount, selectionStats.retryBlockedActionCount],
  );

  const resetBulkFlow = useCallback(() => {
    setDrawerOpen(false);
    setDrawerStep("review");
    setSelectedBulkIds(new Set());
    setBulkApprovePassword("");
    setBulkApproveTotpCode("");
    setTypedConfirm("");
    setBulkApproveError(null);
    setBulkCompletedActionCount(null);
    setBlockStep("idle");
    setBlockError(null);
  }, []);

  const handleClearSelection = useCallback(() => {
    if (blocking.current) return;
    setSelectedBulkIds(new Set());
    setTypedConfirm("");
    setBulkApproveError(null);
    setBlockStep("idle");
    setBlockError(null);
  }, []);

  const handleRequestBlock = useCallback(() => {
    if (selectedBlockGroups.length === 0) return;
    setBlockStep("confirming");
    setBlockError(null);
  }, [selectedBlockGroups.length]);

  const handleCancelBlock = useCallback(() => {
    if (blockStep === "blocking") return;
    setBlockStep("idle");
  }, [blockStep]);

  const handleConfirmBlock = useCallback(async () => {
    if (blockStep === "blocking" || selectedBlockGroups.length === 0 || !hasBlockHandler || props.onBulkBlock === undefined) {
      return;
    }
    blocking.current = true;
    setBlockStep("blocking");
    setBlockError(null);
    try {
      await props.onBulkBlock(selectedBlockGroups);
      setSelectedBulkIds(new Set());
    } catch (error) {
      // Blocked requests leave the queue. A failed duplicate can become its
      // group's new primary, so select exactly the requests that failed.
      if (error instanceof BulkBlockError) setSelectedBulkIds(new Set(error.failedIds));
      setBlockError(error instanceof Error ? error.message : "Blocking the selected requests failed.");
    } finally {
      blocking.current = false;
      setBlockStep("idle");
    }
  }, [blockStep, hasBlockHandler, props.onBulkBlock, selectedBlockGroups]);

  const handleStartReview = useCallback(() => {
    if (selectedBulkGroups.length === 0) {
      return;
    }
    setDrawerOpen(true);
    setDrawerStep("review");
    setBulkApproveError(null);
  }, [selectedBulkGroups.length]);

  const handleCancelDrawer = useCallback(() => {
    if (drawerStep === "submitting") return;
    // Closing the completed drawer means the batch is done — clear the
    // already-approved selection so it doesn't linger in the background.
    if (drawerStep === "completed") {
      resetBulkFlow();
      return;
    }
    setDrawerOpen(false);
    setDrawerStep("review");
    setBulkApproveError(null);
    setTypedConfirm("");
    setBulkApprovePassword("");
    setBulkApproveTotpCode("");
  }, [drawerStep, resetBulkFlow]);

  const handleBulkToggleSelect = useCallback((requestId: string) => {
    if (blocking.current) return;
    setSelectedBulkIds((current) => {
      const next = new Set(current);
      if (next.has(requestId)) {
        next.delete(requestId);
      } else {
        next.add(requestId);
      }
      return next;
    });
    setTypedConfirm("");
    setBulkApproveError(null);
    setBlockStep("idle");
    setBlockError(null);
  }, []);

  const handleBulkToggleMany = useCallback(
    (items: GuardApprovalRequest[], selectAll: boolean) => {
      if (blocking.current) return;
      setSelectedBulkIds(() => {
        if (!selectAll) return new Set();
        const eligibleIds = new Set<string>(bulkApprovePrimaryIds(selectableGroups));
        const targetIds = new Set<string>();
        for (const item of items) {
          if (eligibleIds.has(item.request_id)) {
            targetIds.add(item.request_id);
          } else {
            // Items that belong to an eligible group via duplicate id mapping.
            for (const group of selectableGroups) {
              if (group.duplicateIds.includes(item.request_id)) {
                targetIds.add(group.primary.request_id);
                break;
              }
            }
          }
        }
        return targetIds;
      });
      setTypedConfirm("");
      setBulkApproveError(null);
      setBlockStep("idle");
      setBlockError(null);
    },
    [selectableGroups],
  );

  const handleBulkApprovePasswordChange = useCallback((event: ChangeEvent<HTMLInputElement>) => {
    setBulkApprovePassword(event.target.value);
  }, []);

  const handleBulkApproveTotpCodeChange = useCallback((event: ChangeEvent<HTMLInputElement>) => {
    setBulkApproveTotpCode(event.target.value);
  }, []);

  const handleTypedConfirmChange = useCallback((event: ChangeEvent<HTMLInputElement>) => {
    setTypedConfirm(event.target.value);
  }, []);

  const handleBulkConfirmApprove = useCallback(async () => {
    if (drawerStep === "submitting" || drawerStep === "completed" || selectedBulkGroups.length === 0) {
      return;
    }
    if ((selectionStats.retryBlockedActionCount ?? 0) > 0) {
      setBulkApproveError("Run once is unavailable for part of this selection. Open those requests individually.");
      return;
    }
    const ids = bulkApprovePrimaryIds(selectedBulkGroups);
    const approvedActionCount = bulkApproveActionCount(selectedBulkGroups);
    const credentialErrorCheck = validateBulkApproveCredentials(props.approvalGate, {
      password: bulkApprovePassword,
      totpCode: bulkApproveTotpCode,
    });
    if (credentialErrorCheck !== null) {
      setBulkApproveError(credentialErrorCheck);
      return;
    }
    if (riskDisclosure.requiresTypedConfirm && !bulkConfirmMatches(typedConfirm, riskDisclosure.confirmPhrase)) {
      setBulkApproveError(`Type "${riskDisclosure.confirmPhrase}" to confirm this high-impact approval.`);
      return;
    }
    const gateCredentials = buildBulkGateCredentials(
      props.approvalGate,
      bulkApprovePassword,
      bulkApproveTotpCode,
    );
    setDrawerStep("submitting");
    setBulkApproveError(null);
    try {
      await props.onBulkApprove?.(ids, gateCredentials);
      setBulkCompletedActionCount(approvedActionCount);
      setDrawerStep("completed");
      setBulkApprovePassword("");
      setBulkApproveTotpCode("");
      setTypedConfirm("");
    } catch (error) {
      setDrawerStep("review");
      setBulkApproveError(error instanceof Error ? error.message : "Bulk approval failed.");
    }
  }, [
    bulkApprovePassword,
    bulkApproveTotpCode,
    typedConfirm,
    drawerStep,
    props.approvalGate,
    props.onBulkApprove,
    riskDisclosure,
    selectedBulkGroups,
    selectionStats.retryBlockedActionCount,
  ]);

  const bulkSelectableMap = useMemo(() => {
    const map = new Map<string, boolean>();
    for (const group of groups) {
      const selectable = hasBlockHandler ? isBulkBlockableGroup(group) : isBulkApprovableGroup(group);
      map.set(group.primary.request_id, selectable);
      for (const id of group.duplicateIds) {
        map.set(id, selectable);
      }
    }
    return map;
  }, [groups, hasBlockHandler]);

  const groupIdMap = useMemo(() => {
    const map = new Map<string, string>();
    for (const group of groups) {
      map.set(group.primary.request_id, group.primary.request_id);
      for (const id of group.duplicateIds) {
        map.set(id, group.primary.request_id);
      }
    }
    return map;
  }, [groups]);

  const isSelectable = useCallback(
    (item: GuardApprovalRequest) =>
      bulkSelectableMap.get(item.request_id) ??
      (hasBlockHandler
        ? isBulkBlockableGroup({ primary: item, duplicateCount: 0, duplicateIds: [] })
        : isBulkApprovableGroup({ primary: item, duplicateCount: 0, duplicateIds: [] })),
    [bulkSelectableMap, hasBlockHandler],
  );

  const isSelected = useCallback(
    (item: GuardApprovalRequest) =>
      selectedBulkIds.has(groupIdMap.get(item.request_id) ?? item.request_id),
    [groupIdMap, selectedBulkIds],
  );

  const onToggle = useCallback(
    (item: GuardApprovalRequest) => {
      handleBulkToggleSelect(groupIdMap.get(item.request_id) ?? item.request_id);
    },
    [groupIdMap, handleBulkToggleSelect],
  );

  const onToggleMany = useCallback(
    (items: GuardApprovalRequest[], selectAll: boolean) => {
      const resolved = items.map((item) => ({
        ...item,
        request_id: groupIdMap.get(item.request_id) ?? item.request_id,
      }));
      handleBulkToggleMany(resolved, selectAll);
    },
    [groupIdMap, handleBulkToggleMany],
  );

  const canApprove = showBulkApprove && selectedGroupCount > 0;
  const stickyBarVisible = (canApprove || selectedBlockGroups.length > 0) && drawerStep !== "completed";

  // Discovery path: when eligible reads exist but the approval gate is not
  // configured, surface a prompt to set one up. Without this, the ambient
  // selection mode (which requires bulkGateReady) would never appear, hiding
  // bulk approval entirely from users who haven't configured the gate yet.
  const gatePromptVisible =
    hasBulkHandler && hasEligibleGroups && !bulkGateReady;
  const eligibleActionCount = useMemo(
    () => bulkApproveActionCount(bulkEligibleGroups),
    [bulkEligibleGroups],
  );

  return {
    groups,
    showBulkApprove,
    bulkSelection: {
      selectionMode,
      isSelectable,
      isSelected,
      onToggle,
      onToggleMany,
      selectedActionCount: hasBlockHandler ? selectedRequestCount : selectedActionCount,
      selectedGroupCount: hasBlockHandler ? selectedSelectableGroups.length : selectedGroupCount,
    },
    stickyBar: {
      visible: stickyBarVisible,
      selectedGroupCount,
      selectedActionCount,
      selectedRequestCount: hasBlockHandler ? selectedRequestCount : selectedActionCount,
      canApprove,
      riskTier: riskDisclosure.tier,
      riskTone: riskDisclosure.tone,
      gateReady: bulkGateReady,
      blockAvailable: hasBlockHandler,
      blockStep,
      blockError,
      onStartReview: handleStartReview,
      onRequestBlock: handleRequestBlock,
      onConfirmBlock: handleConfirmBlock,
      onCancelBlock: handleCancelBlock,
      onClearSelection: handleClearSelection,
    },
    drawer: {
      open: drawerOpen,
      step: drawerStep,
      selectedGroups: selectedBulkGroups,
      selectedActionCount,
      retryBlockedActionCount: selectionStats.retryBlockedActionCount ?? 0,
      sensitiveFileReadCount,
      riskDisclosure,
      approvalGate: props.approvalGate ?? null,
      settingsHref: props.settingsHref,
      bulkApprovePassword,
      bulkApproveTotpCode,
      typedConfirm,
      confirmMatches,
      canConfirm,
      completedActionCount: bulkCompletedActionCount,
      errorMessage: bulkApproveError,
      onBulkApprovePasswordChange: handleBulkApprovePasswordChange,
      onBulkApproveTotpCodeChange: handleBulkApproveTotpCodeChange,
      onTypedConfirmChange: handleTypedConfirmChange,
      onConfirmApprove: handleBulkConfirmApprove,
      onCancel: handleCancelDrawer,
    },
    status: {
      visible: !showBulkApprove && sensitiveFileReadCount > 0,
      sensitiveFileReadCount,
    },
    gatePrompt: {
      visible: gatePromptVisible,
      eligibleActionCount,
      settingsHref: props.settingsHref,
    },
  };
}
