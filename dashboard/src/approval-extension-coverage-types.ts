/** Which extension matched which step of a paused command.
 *
 * Advisory only: the card built from this changes no setting and approves
 * nothing. It names the extension behind each step so the person reviewing can
 * go and pre-configure it, and says plainly that doing so settles that step
 * alone.
 */
export const APPROVAL_EXTENSION_COVERAGE_SCHEMA = "guard.approval-extension-coverage.v1";

export type GuardCoveredExtension = {
  readonly extension_id: string;
  readonly name: string;
  /** The rule the link should focus in the permissions tab, when one matched. */
  readonly focus_rule_id: string | null;
};

export type GuardCoveredRule = {
  readonly rule_id: string;
  /** A catalog rule may have no title; the card then names it by its description. */
  readonly title: string | null;
  readonly severity: string;
  /** The rule's catalog description, from a daemon that sends it. */
  readonly description?: string | null;
  /** At most two catalog safer alternatives, from a daemon that sends them. */
  readonly safer_alternatives?: readonly string[];
  /**
   * True when the matcher could not read this step well enough to rule the
   * rule in or out. The card must not describe such a rule as what the step does.
   */
  readonly uncertain?: boolean;
};

export type GuardCoveredPermission = {
  readonly permission_id: string;
  readonly label: string;
  readonly configurable: boolean;
};

export type GuardCoveredSegment = {
  /** 0-based position of this step in the command the agent asked to run. */
  readonly index: number;
  readonly executable: string | null;
  readonly extensions: readonly GuardCoveredExtension[];
  readonly rules: readonly GuardCoveredRule[];
  readonly permissions: readonly GuardCoveredPermission[];
};

export type GuardApprovalExtensionCoverage = {
  readonly schema: typeof APPROVAL_EXTENSION_COVERAGE_SCHEMA;
  readonly catalog_digest: string;
  readonly segments: readonly GuardCoveredSegment[];
  /** True when the command runs more than the one covered step. */
  readonly compound: boolean;
};
