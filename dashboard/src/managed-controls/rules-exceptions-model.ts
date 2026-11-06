export type RuleAuthority =
  | 'Remembered on this device'
  | 'Synced contextual rule'
  | 'Cloud exception'
  | `Managed by ${string}`;

export interface RuleExceptionItem {
  id: string;
  title: string;
  authority: RuleAuthority;
  extensionId?: string;
  expiresAt?: string;
}

export interface RulesExceptionsView {
  title: 'Rules & exceptions';
  description: string;
  items: readonly RuleExceptionItem[];
  decisionOrder: readonly string[];
  governingExtensionLinks: readonly { label: string; href: string }[];
  includesExtensionEditor: false;
}

export function buildRulesExceptionsView(
  items: readonly RuleExceptionItem[],
): RulesExceptionsView {
  const links = new Map<string, { label: string; href: string }>();
  for (const item of items) {
    if (!item.extensionId) continue;
    links.set(item.extensionId, {
      label: `Open ${item.extensionId}`,
      href: `/extensions/${encodeURIComponent(item.extensionId)}`,
    });
  }
  return {
    title: 'Rules & exceptions',
    description:
      'Review remembered decisions, contextual Cloud rules, and exceptions. Extension permissions stay in Protection Center.',
    items,
    decisionOrder: [
      'Hard safety floors and Emergency Lockdown',
      'Extension and permission posture',
      'Contextual rules and remembered decisions',
    ],
    governingExtensionLinks: [...links.values()],
    includesExtensionEditor: false,
  };
}
