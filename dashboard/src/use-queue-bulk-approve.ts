import { useCallback, useMemo, useState, type ChangeEvent } from "react";
import type { BulkGateCredentials } from "./approval-gate-utils";
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

export type QueueBulkDrawerStep = "review" | "submitting" | "completed";

export type QueueBulkStickyBarProps = {
  visible: boolean;
  selectedGroupCount: number;
  selectedActionCount: number;
  riskTier: BulkRiskTier;
  riskTone: BulkRiskDisclosure["tone"];
  gateReady: boolean;
  onStartReview: () => void;
  onClearSelection: () => void;
};

export type QueueBulkDrawerProps = {
  open: boolean;
  step: QueueBulkDrawerStep;
  selectedGroups: QueueGroup[];
  selectedActionCount: number;
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

  const selectedBulkGroups = useMemo(
    () => bulkEligibleGroups.filter((group) => selectedBulkIds.has(group.primary.request_id)),
    [bulkEligibleGroups, selectedBulkIds],
  );

  const selectedActionCount = useMemo(
    () => bulkApproveActionCount(selectedBulkGroups),
    [selectedBulkGroups],
  );
  const selectedGroupCount = selectedBulkGroups.length;

  const selectionStats: BulkSelectionStats = useMemo(() => {
    let elevatedActionCount = 0;
    let lowActionCount = 0;
    for (const group of selectedBulkGroups) {
      const tier = bulkApprovalRiskTier(group);
      const count = 1 + group.duplicateCount;
      if (tier === "elevated") elevatedActionCount += count;
      else if (tier === "low") lowActionCount += count;
    }
    return {
      actionCount: selectedActionCount,
      groupCount: selectedGroupCount,
      duplicateActionCount: countDuplicateActionsInGroups(selectedBulkGroups),
      sensitiveCount: sensitiveSummary.count,
      sensitiveSamplePaths: sensitiveSummary.samplePaths,
      elevatedActionCount,
      lowActionCount,
    };
  }, [selectedActionCount, selectedGroupCount, selectedBulkGroups, sensitiveSummary]);

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
    () => credentialError === null && confirmMatches && selectedGroupCount > 0,
    [credentialError, confirmMatches, selectedGroupCount],
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
  }, []);

  const handleClearSelection = useCallback(() => {
    setSelectedBulkIds(new Set());
    setTypedConfirm("");
    setBulkApproveError(null);
  }, []);

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
  }, []);

  const handleBulkToggleMany = useCallback(
    (items: GuardApprovalRequest[], selectAll: boolean) => {
      setSelectedBulkIds(() => {
        if (!selectAll) return new Set();
        const eligibleIds = new Set<string>(bulkApprovePrimaryIds(bulkEligibleGroups));
        const targetIds = new Set<string>();
        for (const item of items) {
          if (eligibleIds.has(item.request_id)) {
            targetIds.add(item.request_id);
          } else {
            // Items that belong to an eligible group via duplicate id mapping.
            for (const group of bulkEligibleGroups) {
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
    },
    [bulkEligibleGroups],
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
  ]);

  const bulkSelectableMap = useMemo(() => {
    const map = new Map<string, boolean>();
    for (const group of groups) {
      const isApprovable = isBulkApprovableGroup(group);
      map.set(group.primary.request_id, isApprovable);
      for (const id of group.duplicateIds) {
        map.set(id, isApprovable);
      }
    }
    return map;
  }, [groups]);

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
      isBulkApprovableGroup({ primary: item, duplicateCount: 0, duplicateIds: [] }),
    [bulkSelectableMap],
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

  const stickyBarVisible = showBulkApprove && selectedGroupCount > 0 && drawerStep !== "completed";

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
      selectionMode: showBulkApprove,
      isSelectable,
      isSelected,
      onToggle,
      onToggleMany,
      selectedActionCount,
      selectedGroupCount,
    },
    stickyBar: {
      visible: stickyBarVisible,
      selectedGroupCount,
      selectedActionCount,
      riskTier: riskDisclosure.tier,
      riskTone: riskDisclosure.tone,
      gateReady: bulkGateReady,
      onStartReview: handleStartReview,
      onClearSelection: handleClearSelection,
    },
    drawer: {
      open: drawerOpen,
      step: drawerStep,
      selectedGroups: selectedBulkGroups,
      selectedActionCount,
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
