// Compatibility surface for existing imports and routes.
// The user-facing implementation now lives under the Protection Center feature boundary.
export {
  buildExtensionMutation,
  currentExtensionRouteState,
  ExtensionStatusBanner,
  extensionRecoveryAction,
  ProtectionCenterWorkspace as ExtensionsWorkspace,
  ReviewModal,
  requiresExtensionRecoveryApproval,
  type ExtensionRecoveryAction,
  type ProtectionPendingChange,
} from "./protection-center/protection-center-workspace";
