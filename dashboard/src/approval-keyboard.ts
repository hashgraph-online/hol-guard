export function reviewDecisionShortcutAllowed(isComposing: boolean): boolean {
  return !isComposing;
}

export function shouldSubmitApprovalProof(
  key: string,
  isComposing: boolean,
  submitDisabled: boolean,
): boolean {
  return key === "Enter" && !isComposing && !submitDisabled;
}
