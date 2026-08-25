export type ProtectionSource =
  | 'Built-in protection'
  | 'This device'
  | 'Personal Control Set'
  | 'Organization Control Set'
  | 'Recommended by Guard'
  | 'Set on this device'
  | 'Synced from Guard Cloud'
  | `Managed by ${string}`
  | 'Required by Guard'
  | 'Emergency Lockdown';

export type LocalProtectionStatus =
  | 'protected'
  | 'needs-attention'
  | 'managed'
  | 'lockdown'
  | 'unsupported';

export interface LocalProtectionView {
  title: string;
  summary: string;
  source: ProtectionSource;
  sources: readonly ProtectionSource[];
  effectiveState: LocalProtectionInput['effectiveState'];
  status: LocalProtectionStatus;
  primaryAction: {
    label: string;
    href?: string;
    action?: 'refresh' | 'repair' | 'connect-cloud';
  } | null;
  technicalDetails: ReadonlyArray<{ label: string; value: string }>;
}

export interface LocalProtectionInput {
  extensionName: string;
  effectiveState: 'allowed' | 'blocked' | 'partial' | 'required' | 'lockdown';
  source: ProtectionSource;
  sources?: readonly ProtectionSource[];
  catalogDigest?: string;
  acknowledgementRevision?: number;
  recovery?: 'degraded' | 'stale' | 'catalog-mismatch' | 'unsupported-version';
  cloudControlsUrl?: string;
  extensionId?: string;
  permissionId?: string;
  controlSetName?: string;
  controlSetVersion?: number | string;
  workspace?: string;
  authorityMode?: 'personal-shared' | 'workspace-shared' | 'managed-restrictive';
  acknowledgementStatus?: string;
  lastAcknowledgedAt?: string;
  effectiveProjectionDigest?: string;
}

export function managedControlsHref(input: LocalProtectionInput): string | null {
  if (!input.cloudControlsUrl) {
    return null;
  }
  let target: URL;
  try {
    target = new URL('/guard/controls', input.cloudControlsUrl);
  } catch {
    return null;
  }
  if (input.extensionId) {
    target.searchParams.set('extensionId', input.extensionId);
  }
  if (input.permissionId) {
    target.searchParams.set('permissionId', input.permissionId);
  }
  return target.toString();
}

export function buildLocalProtectionView(
  input: LocalProtectionInput,
): LocalProtectionView {
  const sources = input.sources?.length ? input.sources : [input.source];
  const technicalDetails = [
    ...(sources.length > 1 ? [{ label: 'Contributors', value: sources.join(' · ') }] : []),
    ...(input.catalogDigest ? [{ label: 'Catalog digest', value: input.catalogDigest }] : []),
    ...(input.acknowledgementRevision !== undefined
      ? [{ label: 'Acknowledgement revision', value: String(input.acknowledgementRevision) }]
      : []),
    ...(input.controlSetName ? [{ label: 'Control Set', value: input.controlSetName }] : []),
    ...(input.controlSetVersion !== undefined
      ? [{ label: 'Control Set version', value: String(input.controlSetVersion) }]
      : []),
    ...(input.workspace ? [{ label: 'Workspace', value: input.workspace }] : []),
    ...(input.authorityMode ? [{ label: 'Authority mode', value: input.authorityMode }] : []),
    ...(input.acknowledgementStatus ? [{ label: 'Acknowledgement', value: input.acknowledgementStatus }] : []),
    ...(input.lastAcknowledgedAt ? [{ label: 'Last acknowledged', value: input.lastAcknowledgedAt }] : []),
    ...(input.effectiveProjectionDigest
      ? [{ label: 'Effective projection digest', value: input.effectiveProjectionDigest }]
      : []),
  ];
  if (input.recovery === 'unsupported-version') {
    return {
      title: input.extensionName,
      summary: 'Update Guard before this managed setting can be applied.',
      source: input.source,
      sources,
      effectiveState: input.effectiveState,
      status: 'unsupported',
      primaryAction: { label: 'Check for updates', action: 'refresh' },
      technicalDetails,
    };
  }
  if (input.recovery) {
    let recoverySummary = 'Guard is using the last verified setting while it checks for an update.';
    if (input.recovery === 'catalog-mismatch') {
      recoverySummary = 'Guard is using the last verified setting because this Control Set and the local Extension catalog do not match.';
    } else if (input.recovery === 'degraded') {
      recoverySummary = 'Guard is preserving the last verified authority while local control recovery is required.';
    }
    return {
      title: input.extensionName,
      summary: recoverySummary,
      source: input.source,
      sources,
      effectiveState: input.effectiveState,
      status: 'needs-attention',
      primaryAction: { label: 'Check again', action: 'refresh' },
      technicalDetails,
    };
  }
  let status: LocalProtectionStatus = 'protected';
  if (input.effectiveState === 'lockdown') {
    status = 'lockdown';
  } else if (input.source === 'Organization Control Set' || input.source.startsWith('Managed by ')) {
    status = 'managed';
  }

  let summary = 'Guard checks matching actions before they run.';
  if (input.effectiveState === 'blocked') {
    summary = 'Matching actions are blocked.';
  } else if (input.effectiveState === 'partial') {
    summary = 'Some matching actions are blocked while the remaining actions stay available.';
  } else if (input.effectiveState === 'required') {
    summary = 'This protection stays on.';
  } else if (input.effectiveState === 'lockdown') {
    summary = 'Emergency Lockdown blocks governed actions.';
  }

  const controlsHref = managedControlsHref(input);
  const hasManagedContributor = sources.some(
    (source) => source === 'Organization Control Set' || source === 'Synced from Guard Cloud' || source.startsWith('Managed by '),
  );
  const primaryAction = controlsHref
    ? {
        label: hasManagedContributor ? 'Manage in Guard Cloud' : 'Apply across my devices',
        href: controlsHref,
      }
    : { label: 'Connect Guard Cloud', action: 'connect-cloud' as const };
  return {
    title: input.extensionName,
    summary,
    source: input.source,
    sources,
    effectiveState: input.effectiveState,
    status,
    primaryAction,
    technicalDetails,
  };
}
