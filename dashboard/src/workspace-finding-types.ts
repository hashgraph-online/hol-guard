/** The finding shapes the local workspace findings API returns, already normalized. */

export type WorkspaceFindingValidation = "confirmed" | "unvalidated" | "unknown";

export type WorkspaceFindingKind = "supply_chain" | "secret" | "runtime" | "skill" | "mcp" | "hook" | "plugin" | "workflow" | "editor_task";

/** The fixed wording of the skill content rule that matched; never text from the skill. */
export type WorkspaceSkillCheck = { title: string; reason: string; confidence: string; falsePositiveHint: string | null };

/** The MCP launch rule that matched and the server it names; never the server's command or URL. */
export type WorkspaceMcpCheck = WorkspaceSkillCheck & { server: string };

/** The hook rule that matched and the event the hook runs on; never the hook's command. */
export type WorkspaceHookCheck = WorkspaceSkillCheck & { event: string };

/** An executable a configured tool would launch that matches a runtime advisory. */
export type WorkspaceRuntime = { family: string; version: string | null; title: string | null; knownExploited: boolean };

export type WorkspaceFinding = {
  findingId: string;
  kind: WorkspaceFindingKind;
  severity: string;
  decision: string;
  /** Rule or advisory codes that raised the finding. */
  ruleIds: string[];
  ecosystem: string;
  /** Null for a secret finding, which names a file location instead of a package. */
  packageName: string | null;
  packageVersion: string | null;
  fixVersion: string | null;
  advisoryIds: string[];
  /**
   * True when the latest scan could not recheck this finding (its detector did
   * not finish), so it is still listed from the run that last observed it.
   */
  carried: boolean;
  /**
   * Whether evidence beyond the match itself backs the finding: an installed
   * version inside an advisory's range is confirmed, a pattern or rule match is
   * not. Unknown when the daemon did not say.
   */
  validation: WorkspaceFindingValidation;
  /**
   * Root-relative file path of a secret or skill finding, or the executable
   * path of a runtime finding. Guard never receives the secret itself.
   */
  path: string | null;
  line: number | null;
  /** Every line the same secret appears on in that file, first to last. */
  lines: number[];
  /** Set only for a runtime finding; observation only, so it has no fix. */
  runtime: WorkspaceRuntime | null;
  /** Set only for an agent skill finding, a warning with no fix. */
  skill: WorkspaceSkillCheck | null;
  /**
   * Set only for an MCP server configuration finding, a warning with no fix,
   * or for an agent plugin finding about a server the plugin ships.
   */
  mcp: WorkspaceMcpCheck | null;
  /**
   * Set only for a project hook configuration finding, a warning with no fix,
   * or for an agent plugin finding about a hook the plugin ships.
   */
  hook: WorkspaceHookCheck | null;
  /** Set only for a GitHub Actions workflow finding, a warning with no fix. */
  workflow: WorkspaceSkillCheck | null;
  /** Set only for an editor task or dev container finding, a warning with no fix. */
  editorTask: WorkspaceSkillCheck | null;
};
