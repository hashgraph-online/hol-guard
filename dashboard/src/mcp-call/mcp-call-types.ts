import type { McpEffectKind } from "./mcp-effects";

export type McpFact = { label: string; value: string; mono?: boolean };

/** One action a call will carry out, such as a single Gmail send inside a batch. */
export type McpStep = {
  id: string;
  app: string | null;
  action: string;
  effect: McpEffectKind;
  details: McpFact[];
  /** Fields in this step's input that the card did not list. */
  hiddenDetails: number;
};

/** Text the agent wrote about its own call. A claim, shown quoted and never used in a decision. */
export type McpAgentQuotes = { caption: string; items: string[] };

export type McpCodeBlock = { label: string; text: string };

/** What Guard shows for one MCP tool call, built only from the call's own data. */
export type McpCallExplanation = {
  /** The review page title: who wants to do what. */
  headline: string;
  /** The service the call goes to, such as Composio or GitHub. */
  connector: string;
  /** The card heading: what the call does, in a few words. */
  title: string;
  summary: string;
  effect: McpEffectKind;
  /** Where the effect label comes from, so it is never read as a safety check. */
  effectBasis: string;
  facts: McpFact[];
  steps: McpStep[];
  /** Actions past the rows the card lists. They still count toward the title and the effect. */
  hiddenSteps?: number;
  quotes: McpAgentQuotes | null;
  code: McpCodeBlock | null;
  /** The exact input Guard matches an approval against. */
  rawInput: string | null;
  /** Core cut long text in the input, so what the card shows is a shortened copy. */
  truncated: boolean;
  /** The tool's own identifier, for people who know it. */
  toolId: string;
  /** Plain reason for the pause, replacing policy setting names. */
  whyAsked: string;
  queueTitle: string;
  queueDetail: string | null;
};
