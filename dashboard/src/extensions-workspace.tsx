// Compatibility surface for existing imports and routes.
// The user-facing implementation now lives under the Protection Center feature boundary.
export {
  authorityActionErrorMessage,
  buildExtensionMutation,
  currentExtensionRouteState,
  ProtectionCenterWorkspace as ExtensionsWorkspace,
  ReviewModal,
  requiresExtensionRecoveryApproval,
  type ProtectionPendingChange,
} from "./protection-center/protection-center-workspace";
export { ProtectionAuthorityNotice } from "./protection-center/components/protection-authority-notice";
