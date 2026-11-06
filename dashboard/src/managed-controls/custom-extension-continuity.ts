export type CustomExtensionContinuityState =
  | 'local-only'
  | 'identity-matched'
  | 'portable'
  | 'incompatible'
  | 'pending-observation'
  | 'changed-identity'
  | 'locally-overridden'
  | 'removed'
  | 'stale';

export interface CustomExtensionContinuityView {
  state: CustomExtensionContinuityState;
  title: string;
  description: string;
  canApplyAcrossDevices: boolean;
  privacyDisclosure: string;
}

export function customExtensionContinuityView(
  state: CustomExtensionContinuityState,
): CustomExtensionContinuityView {
  const privacyDisclosure =
    'Guard Cloud receives stable identity and compatibility metadata, not local source paths.';
  switch (state) {
    case 'local-only':
      return {
        state,
        title: 'Available on this device',
        description:
          'This custom protection remains local until portable continuity is enabled.',
        canApplyAcrossDevices: false,
        privacyDisclosure,
      };
    case 'identity-matched':
      return {
        state,
        title: 'Matched on another device',
        description:
          'Guard matched the stable identity. Each device still uses its own verified definition.',
        canApplyAcrossDevices: true,
        privacyDisclosure,
      };
    case 'portable':
      return {
        state,
        title: 'Portable continuity enabled',
        description:
          'A verified portable definition is available to compatible devices.',
        canApplyAcrossDevices: true,
        privacyDisclosure,
      };
    case 'incompatible':
      return {
        state,
        title: 'Needs a compatible definition',
        description:
          'This device cannot apply the shared custom protection safely.',
        canApplyAcrossDevices: false,
        privacyDisclosure,
      };
    case 'pending-observation':
      return {
        state,
        title: 'Waiting for this device',
        description: 'Cloud settings stay pending until Guard observes the same extension identity locally.',
        canApplyAcrossDevices: false,
        privacyDisclosure,
      };
    case 'changed-identity':
      return {
        state,
        title: 'Identity changed',
        description: 'Guard refused the Cloud settings because this device observed a different identity.',
        canApplyAcrossDevices: false,
        privacyDisclosure,
      };
    case 'locally-overridden':
      return {
        state,
        title: 'Changed on this device',
        description: 'Guard kept this device\'s local setting until a newer Cloud revision is available.',
        canApplyAcrossDevices: false,
        privacyDisclosure,
      };
    case 'removed':
      return {
        state,
        title: 'Removed on this device',
        description: 'The local setting was removed. Guard did not delete the script, executable, or MCP configuration.',
        canApplyAcrossDevices: false,
        privacyDisclosure,
      };
    case 'stale':
      return {
        state,
        title: 'Cloud observation is stale',
        description: 'Guard kept the last-known-good local setting and did not apply expired Cloud state.',
        canApplyAcrossDevices: false,
        privacyDisclosure,
      };
  }
}
