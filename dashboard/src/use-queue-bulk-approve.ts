import { useCallback, useMemo, useState, type ChangeEvent } from "react";
import type { BulkGateCredentials } from "./approval-gate-utils";
import type { GuardApprovalGatePublicConfig, GuardApprovalRequest } from "./guard-types";
import {
  bulkApproveActionCount,
  bulkApprovePrimaryIds,
  countSensitiveFileReadGroups,
  groupDuplicates,
  isReadOnlyQueueGroup,
  type QueueGroup,
} from "./queue-state";
import {
  buildBulkGateCredentials,
  isBulkApproveGateReady,
  validateBulkApproveCredentials,
  type BulkApproveFlowStep,
  type QueueBulkApproveFlowProps,
} from "./queue-bulk-approve-flow";

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
      return isReadOnlyQueueGroup(group);
    }
  }
  return isReadOnlyQueueGroup({ primary: item, duplicateCount: 0, duplicateIds: [] });
}

export function useQueueBulkApprove(props: {
  items: GuardApprovalRequest[];
  approvalGate?: GuardApprovalGatePublicConfig | null;
  onBulkApprove?: (ids: string[], gateCredentials?: BulkGateCredentials) => void | Promise<void>;
  settingsHref: string;
}): {
  groups: QueueGroup[];
  showBulkApprove: boolean;
  showSensitiveOnlyWarning: boolean;
  sensitiveFileReadCount: number;
  bulkFlowProps: QueueBulkApproveFlowProps | null;
  bulkSelection: {
    selectionMode: boolean;
    isSelectable: (item: GuardApprovalRequest) => boolean;
    isSelected: (item: GuardApprovalRequest) => boolean;
    onToggle: (item: GuardApprovalRequest) => void;
  };
} {
  const [bulkFlowStep, setBulkFlowStep] = useState<BulkApproveFlowStep>("collapsed");
  const [selectedBulkIds, setSelectedBulkIds] = useState<Set<string>>(() => new Set());
  const [bulkApprovePassword, setBulkApprovePassword] = useState("");
  const [bulkApproveTotpCode, setBulkApproveTotpCode] = useState("");
  const [bulkApproveError, setBulkApproveError] = useState<string | null>(null);
  const [bulkCompletedActionCount, setBulkCompletedActionCount] = useState<number | null>(null);

  const groups = useMemo(() => groupDuplicates(props.items), [props.items]);

  const bulkEligibleGroups = useMemo(
    () => groups.filter((group) => isReadOnlyQueueGroup(group)),
    [groups],
  );

  const sensitiveFileReadCount = useMemo(
    () => countSensitiveFileReadGroups(groups),
    [groups],
  );

  const showBulkApprove =
    props.onBulkApprove !== undefined &&
    (bulkEligibleGroups.length >= 2 || bulkFlowStep === "completed");

  const showSensitiveOnlyWarning = !showBulkApprove && sensitiveFileReadCount > 0;

  const bulkGateReady = isBulkApproveGateReady(props.approvalGate);

  const selectedBulkGroups = useMemo(
    () => bulkEligibleGroups.filter((group) => selectedBulkIds.has(group.primary.request_id)),
    [bulkEligibleGroups, selectedBulkIds],
  );

  const resetBulkFlow = useCallback(() => {
    setBulkFlowStep("collapsed");
    setSelectedBulkIds(new Set());
    setBulkApprovePassword("");
    setBulkApproveTotpCode("");
    setBulkApproveError(null);
    setBulkCompletedActionCount(null);
  }, []);

  const handleBulkFlowStart = useCallback(() => {
    if (!bulkGateReady) {
      return;
    }
    setBulkFlowStep("select");
    setSelectedBulkIds(new Set());
    setBulkApproveError(null);
    setBulkCompletedActionCount(null);
  }, [bulkGateReady]);

  const handleBulkSelectAll = useCallback(() => {
    setSelectedBulkIds(new Set(bulkApprovePrimaryIds(bulkEligibleGroups)));
  }, [bulkEligibleGroups]);

  const handleBulkClearSelection = useCallback(() => {
    setSelectedBulkIds(new Set());
  }, []);

  const handleBulkContinueToReview = useCallback(() => {
    if (selectedBulkIds.size === 0) {
      return;
    }
    setBulkFlowStep("review");
    setBulkApproveError(null);
  }, [selectedBulkIds.size]);

  const handleBulkBackToSelect = useCallback(() => {
    if (bulkFlowStep === "submitting" || bulkFlowStep === "completed") {
      return;
    }
    setBulkFlowStep("select");
    setBulkApproveError(null);
  }, [bulkFlowStep]);

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
  }, []);

  const handleBulkApprovePasswordChange = useCallback((event: ChangeEvent<HTMLInputElement>) => {
    setBulkApprovePassword(event.target.value);
  }, []);

  const handleBulkApproveTotpCodeChange = useCallback((event: ChangeEvent<HTMLInputElement>) => {
    setBulkApproveTotpCode(event.target.value);
  }, []);

  const handleBulkConfirmApprove = useCallback(async () => {
    if (bulkFlowStep === "submitting" || bulkFlowStep === "completed" || selectedBulkGroups.length === 0) {
      return;
    }
    const ids = bulkApprovePrimaryIds(selectedBulkGroups);
    const approvedActionCount = bulkApproveActionCount(selectedBulkGroups);
    const credentialError = validateBulkApproveCredentials(props.approvalGate, {
      password: bulkApprovePassword,
      totpCode: bulkApproveTotpCode,
    });
    if (credentialError !== null) {
      setBulkApproveError(credentialError);
      return;
    }
    const gateCredentials = buildBulkGateCredentials(
      props.approvalGate,
      bulkApprovePassword,
      bulkApproveTotpCode,
    );
    setBulkFlowStep("submitting");
    setBulkApproveError(null);
    try {
      setBulkCompletedActionCount(approvedActionCount);
      await props.onBulkApprove?.(ids, gateCredentials);
      setBulkFlowStep("completed");
      setBulkApprovePassword("");
      setBulkApproveTotpCode("");
    } catch (error) {
      setBulkFlowStep("review");
      setBulkApproveError(error instanceof Error ? error.message : "Bulk approval failed.");
    }
  }, [
    bulkApprovePassword,
    bulkApproveTotpCode,
    bulkFlowStep,
    props.approvalGate,
    props.onBulkApprove,
    selectedBulkGroups,
  ]);

  const isSelectable = useCallback(
    (item: GuardApprovalRequest) => isBulkSelectableRequest(item, groups),
    [groups],
  );

  const isSelected = useCallback(
    (item: GuardApprovalRequest) =>
      selectedBulkIds.has(resolveBulkSelectionGroupId(item, groups)),
    [groups, selectedBulkIds],
  );

  const onToggle = useCallback(
    (item: GuardApprovalRequest) => {
      handleBulkToggleSelect(resolveBulkSelectionGroupId(item, groups));
    },
    [groups, handleBulkToggleSelect],
  );

  const bulkFlowProps = showBulkApprove
    ? {
        step: bulkFlowStep,
        eligibleGroups: bulkEligibleGroups,
        selectedGroups: selectedBulkGroups,
        completedActionCount: bulkCompletedActionCount,
        sensitiveFileReadCount,
        approvalGate: props.approvalGate ?? null,
        settingsHref: props.settingsHref,
        bulkApprovePassword,
        bulkApproveTotpCode,
        errorMessage: bulkApproveError,
        onStart: handleBulkFlowStart,
        onSelectAll: handleBulkSelectAll,
        onClearSelection: handleBulkClearSelection,
        onContinueToReview: handleBulkContinueToReview,
        onBackToSelect: handleBulkBackToSelect,
        onCancel: resetBulkFlow,
        onConfirmApprove: handleBulkConfirmApprove,
        onBulkApprovePasswordChange: handleBulkApprovePasswordChange,
        onBulkApproveTotpCodeChange: handleBulkApproveTotpCodeChange,
      }
    : null;

  return {
    groups,
    showBulkApprove,
    showSensitiveOnlyWarning,
    sensitiveFileReadCount,
    bulkFlowProps,
    bulkSelection: {
      selectionMode: bulkFlowStep === "select",
      isSelectable,
      isSelected,
      onToggle,
    },
  };
}
