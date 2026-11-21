import type { McpEffectKind } from "./mcp-effects";

/** How a value is drawn: addresses as chips, a link with its host first, long text clamped, code in a block. */
export type McpValueKind = "text" | "email" | "url" | "long" | "code";

export type McpFact = {
  label: string;
  value: string;
  mono?: boolean;
  kind?: McpValueKind;
  /** The input field the value came from, so a field is never listed twice. */
  key?: string;
};

/** What the call will do to the world, in one line, and how much care it asks for. */
export type McpConsequence = { tone: "calm" | "care" | "danger"; text: string };

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

export type McpCodeBlock = {
  label: string;
  text: string;
  /** The card already says what the code does, so the code waits behind a toggle. */
  collapsed?: boolean;
};

/** What Guard shows for one MCP tool call, built only from the call's own data. */
export type McpCallExplanation = {
  /** The review page title: who wants to do what. */
  headline: string;
  /** The service the call goes to, such as Composio or GitHub. */
  connector: string;
  /** The tool is part of the agent app itself, not a server the user added. */
  builtIn?: boolean;
  /** The app that asked, in people's words. Set when the tool can only come from one app. */
  requester?: string;
  /** The card heading: what the call does, in a few words. */
  title: string;
  /** A sentence of context for a tool whose name says little, such as a Composio meta-tool. */
  aside: string | null;
  /** The line under the heading: what approving lets happen. */
  consequence: McpConsequence;
  effect: McpEffectKind;
  /** Where the effect label comes from, so it is never read as a safety check. */
  effectBasis: string;
  facts: McpFact[];
  steps: McpStep[];
  /** A heading over the action rows, when they were read from somewhere a person would not expect, such as code. */
  stepsCaption?: string;
  /** Actions past the rows the card lists. They still count toward the title and the effect. */
  hiddenSteps?: number;
  /** The apps whose actions carry the call's effect, read from every action, listed or not. */
  effectApps?: string[];
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
