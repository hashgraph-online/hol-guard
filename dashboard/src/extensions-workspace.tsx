// Compatibility surface for existing imports and routes.
// The user-facing implementation now lives under the Protection Center feature boundary.
export {
  authorityActionErrorMessage,
  buildExtensionMutation,
  currentExtensionRouteState,
  ProtectionCenterWorkspace as ExtensionsWorkspace,
  requiresExtensionRecoveryApproval,
} from "./protection-center/protection-center-workspace";
export { ReviewModal, type ProtectionPendingChange } from "./protection-center/protection-change-review";
export { ProtectionAuthorityNotice } from "./protection-center/components/protection-authority-notice";
