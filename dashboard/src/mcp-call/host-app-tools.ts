import type { McpCallBody } from "./composio-calls";
import type { McpFact } from "./mcp-call-types";
import { classifyMcpEffect, type McpEffectKind } from "./mcp-effects";
import { recordList, recordOf, textOf } from "./mcp-input";
import { sentenceCase } from "./mcp-services";

/**
 * Tools an agent app builds into itself, such as the Claude desktop app's
 * `ccd_turn__wrap_up`. They are MCP calls on the wire, but the user never
 * installed them and their server names (`ccd_turn`) mean nothing to anyone.
 *
 * This is a fixed list keyed on the server and tool names, the same names the
 * rest of the card reads. Like every other effect it is a reading of the name,
 * not a check of the tool, and the card says so.
 */
export type HostAppTool = {
  /** The app the tool is part of, as people know it. */
  app: string;
  /** The app that asked, for the page title. Only that app ships these tools. */
  requester: string;
  title: string;
  /** Finishes "Claude wants to …". */
  phrase: string;
  effect: McpEffectKind;
  facts: (input: Record<string, unknown> | null) => McpFact[];
};

type CatalogEntry = Omit<HostAppTool, "app" | "requester">;

const CLAUDE_APP = "the Claude app";
const CLAUDE = "Claude";
const CLAUDE_SERVER_PREFIX = "ccd_";

const STATUS_WORDS: Record<string, string> = { completed: "Done", in_progress: "Now", pending: "Next" };

function noFacts(): McpFact[] {
  return [];
}

function fact(label: string, value: string | null, key: string, kind: McpFact["kind"] = "text"): McpFact[] {
  return value !== null && value.length > 0 ? [{ label, value, key, kind }] : [];
}

function summaryFacts(input: Record<string, unknown> | null): McpFact[] {
  const buttons = recordList(input?.actions, 4)
    .map((action) => textOf(action.label, 40))
    .filter((label): label is string => label !== null && label.length > 0);
  return [
    ...fact("Summary", textOf(input?.recap, 400), "recap", "long"),
    ...fact("Question", textOf(input?.ask, 160), "ask"),
    ...fact("Buttons", buttons.length > 0 ? buttons.join(" · ") : null, "actions"),
  ];
}

function taskFacts(input: Record<string, unknown> | null): McpFact[] {
  const tasks = recordList(input?.items, 12)
    .map((task) => {
      const content = textOf(task.content, 80);
      if (content === null || content.length === 0) return null;
      const status = STATUS_WORDS[textOf(task.status, 20) ?? ""] ?? "Next";
      return `${status}: ${content}`;
    })
    .filter((line): line is string => line !== null);
  if (tasks.length > 0) return fact("Tasks", tasks.join(" · "), "items", "long");
  return input?.advance === true ? [{ label: "Change", value: "Marks the current task done and starts the next one", key: "advance" }] : [];
}

function paneFacts(input: Record<string, unknown> | null): McpFact[] {
  return fact("Panel", textOf(input?.pane ?? input?.kind ?? input?.name, 60), "pane");
}

function chapterFacts(input: Record<string, unknown> | null): McpFact[] {
  return fact("Chapter", textOf(input?.title, 80), "title");
}

function sessionFacts(input: Record<string, unknown> | null): McpFact[] {
  return fact("Task", textOf(input?.title, 120), "title");
}

const CLAUDE_TOOLS = new Map<string, CatalogEntry>([
  ["ccd_turn/wrap_up", { title: "Show a summary and next steps", phrase: "show you a summary and next-step buttons", effect: "in-app", facts: summaryFacts }],
  ["ccd_turn/update_plan", { title: "Update its task list", phrase: "update the task list under its reply", effect: "in-app", facts: taskFacts }],
  ["ccd_view/show_pane", { title: "Open a side panel", phrase: "open a side panel", effect: "in-app", facts: paneFacts }],
  ["ccd_view/close_pane", { title: "Close a side panel", phrase: "close a side panel", effect: "in-app", facts: paneFacts }],
  ["ccd_view/get_layout", { title: "Check which panels are open", phrase: "check which panels are open", effect: "in-app", facts: noFacts }],
  ["ccd_view/set_transcript_view", { title: "Change how the chat is shown", phrase: "change how the chat is shown", effect: "in-app", facts: noFacts }],
  ["ccd_session/mark_chapter", { title: "Add a chapter to the chat", phrase: "add a chapter to the chat", effect: "in-app", facts: chapterFacts }],
  ["ccd_session/dismiss_task", { title: "Withdraw a suggested task", phrase: "withdraw a task it suggested", effect: "in-app", facts: noFacts }],
  ["ccd_session/start_session", { title: "Start another Claude session", phrase: "start another Claude session", effect: "write", facts: sessionFacts }],
]);

/**
 * What says the call came from the Claude app. A server name alone does not:
 * anyone can name a server `ccd_turn`. The hook route (`claude-code`) or the
 * environment Guard's own hook stamped (the Claude desktop app sets
 * `CLAUDE_CODE_DESKTOP_APP_VERSION`) does, and neither is the agent's to write.
 */
export type HostEvidence = { harness: string | null | undefined; raw?: Record<string, unknown> | null };

const CLAUDE_HARNESS = "claude-code";
const CLAUDE_DESKTOP_ENVIRONMENT = "CLAUDE_CODE_DESKTOP_APP_VERSION";

function fromClaudeApp(evidence: HostEvidence): boolean {
  if ((evidence.harness ?? "").trim().toLowerCase().replace(/_/g, "-") === CLAUDE_HARNESS) return true;
  const stamp = recordOf(evidence.raw?.guard_execution_environment);
  const names: unknown = stamp?.environment_names;
  return Array.isArray(names) && names.includes(CLAUDE_DESKTOP_ENVIRONMENT);
}

/**
 * The built-in tool behind `server`/`tool`, or null for any tool the user
 * added, or when nothing but the server name says the call came from Claude.
 */
export function hostAppTool(server: string, tool: string, evidence: HostEvidence): HostAppTool | null {
  const key = server.toLowerCase();
  if (!key.startsWith(CLAUDE_SERVER_PREFIX) || !fromClaudeApp(evidence)) return null;
  const entry = CLAUDE_TOOLS.get(`${key}/${tool.toLowerCase()}`);
  if (entry !== undefined) return { ...entry, app: CLAUDE_APP, requester: CLAUDE };
  // Another Claude app tool: still Claude's, and its effect is read from its name like any tool.
  const title = sentenceCase(tool);
  return {
    app: CLAUDE_APP,
    requester: CLAUDE,
    title,
    phrase: `use its “${title}” tool`,
    effect: classifyMcpEffect(tool),
    facts: noFacts,
  };
}

/** The card body for a built-in tool: its job in plain words and the parts of the input a person would look at. */
export function explainHostAppTool(host: HostAppTool, input: Record<string, unknown> | null): McpCallBody {
  return {
    headline: `${host.requester} wants to ${host.phrase}`,
    title: host.title,
    aside: null,
    effect: host.effect,
    effectBasis: "Read from the tool's name.",
    facts: host.facts(recordOf(input)),
    steps: [],
    quotes: null,
    code: null,
    queueTitle: `${host.requester} · ${host.title}`,
    queueDetail: null,
    builtIn: true,
  };
}
