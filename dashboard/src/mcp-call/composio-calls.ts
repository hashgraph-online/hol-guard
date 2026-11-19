import type { McpCallExplanation, McpStep } from "./mcp-call-types";
import { readComposioCode } from "./composio-code";
import { classifyMcpEffect, worstMcpEffect } from "./mcp-effects";
import { codeOf, joinList, recordList, recordOf, scalarFacts, textList, textOf, unique } from "./mcp-input";
import { serviceDisplayName, splitToolSlug } from "./mcp-services";

export type McpCallBody = Omit<McpCallExplanation, "connector" | "rawInput" | "truncated" | "toolId" | "whyAsked" | "consequence">;

type ComposioContext = { harness: string; input: Record<string, unknown> | null };

const NAME_BASIS = "Read from the tool's name. Guard has not checked what it does.";
const STEP_BASIS = "Read from the action names. Guard has not checked what they do.";
const SEPARATE_CALL = "Running a tool is a separate call, and Guard reviews that call too.";
export const THOUGHT_CAPTION = "What the agent said it is doing";

const TITLES = {
  search_tools: "Search for tools",
  get_tool_schemas: "Look up how tools work",
  manage_connections: "Manage connected accounts",
  multi_execute_tool: "Run actions",
  remote_workbench: "Run code in Composio's workspace",
  remote_bash_tool: "Run a command in Composio's workspace",
} as const;
const TITLES_BY_TOOL = new Map<string, string>(Object.entries(TITLES));

/** The plain title of a Composio meta-tool, for a list row that has only the tool's name. */
export function composioToolTitle(shortTool: string): string | null {
  return TITLES_BY_TOOL.get(shortTool.toLowerCase()) ?? null;
}

/**
 * Composio fronts many apps through a few fixed tools. The tool's name says
 * little (`MULTI_EXECUTE_TOOL`), so the apps and actions come from its input.
 * Returns null for a Composio tool this does not know, which then reads like
 * any other MCP tool.
 */
export function explainComposioTool(shortTool: string, context: ComposioContext): McpCallBody | null {
  switch (shortTool.toLowerCase()) {
    case "search_tools":
      return searchTools(context);
    case "get_tool_schemas":
      return toolSchemas(context);
    case "manage_connections":
      return manageConnections(context);
    case "multi_execute_tool":
      return multiExecute(context);
    case "remote_workbench":
      return workbenchCode(context) ?? remoteCode(context, TITLES.remote_workbench, "code_to_execute", "Code");
    case "remote_bash_tool":
      return remoteCode(context, TITLES.remote_bash_tool, "command", "Command");
    default:
      return null;
  }
}

function searchTools({ harness, input }: ComposioContext): McpCallBody {
  const queries = input?.queries;
  const entries = Array.isArray(queries) ? queries : [];
  const records = recordList(queries);
  const useCases = [
    ...records.map((query) => textOf(query.use_case, 200)),
    ...entries.map((query) => (typeof query === "string" ? textOf(query, 200) : null)),
  ].filter((text): text is string => text !== null);
  const apps = unique(records.flatMap((query) => appsFromKnownFields(query.known_fields)));
  const count = Math.max(entries.length, 1);
  return {
    headline: `${harness} wants to search for tools in Composio`,
    title: TITLES.search_tools,
    aside: `Composio connects the agent to other apps. This only asks which tools could do the job. ${SEPARATE_CALL}`,
    effect: "read",
    effectBasis: NAME_BASIS,
    facts: [
      ...(apps.length > 0 ? [{ label: "Apps in the search", value: apps.join(", ") }] : []),
      ...(count > 1 ? [{ label: "Searches", value: String(count) }] : []),
    ],
    steps: [],
    quotes: useCases.length > 0 ? { caption: "What the agent said it is looking for", items: useCases.slice(0, 4) } : null,
    code: null,
    queueTitle: `Composio · ${TITLES.search_tools}`,
    queueDetail: apps.length > 0 ? joinList(apps) : null,
  };
}

/** `app: gmail` and `app: gmail, toolkit: slack` inside a search's `known_fields`. */
function appsFromKnownFields(value: unknown): string[] {
  const text = textOf(value, 400);
  if (text === null) return [];
  const apps: string[] = [];
  for (const part of text.split(/[,;]/)) {
    const match = /^\s*(?:app|apps|toolkit|toolkits)\s*[:=]\s*(.{1,60})$/i.exec(part);
    if (match) apps.push(serviceDisplayName(match[1].trim()));
  }
  return apps;
}

function toolSchemas({ harness, input }: ComposioContext): McpCallBody {
  const slugs = textList(input?.tool_slugs ?? input?.tools);
  const named = slugs.map(slugLabel);
  return {
    headline: `${harness} wants to look up how Composio tools work`,
    title: TITLES.get_tool_schemas,
    aside: `This fetches the instructions the agent needs to call specific tools correctly. ${SEPARATE_CALL}`,
    effect: "read",
    effectBasis: NAME_BASIS,
    facts: named.length > 0 ? [{ label: "Tools", value: joinList(named, 6) }] : [],
    steps: [],
    quotes: null,
    code: null,
    queueTitle: `Composio · ${TITLES.get_tool_schemas}`,
    queueDetail: named.length > 0 ? joinList(named) : null,
  };
}

function manageConnections({ harness, input }: ComposioContext): McpCallBody {
  const accounts = unique(textList(input?.toolkits ?? input?.apps).map(serviceDisplayName));
  return {
    headline: `${harness} wants to manage your connected accounts in Composio`,
    title: TITLES.manage_connections,
    aside: "This checks which of your accounts are linked to Composio, and can ask to link another one.",
    effect: "connect",
    effectBasis: NAME_BASIS,
    facts: accounts.length > 0 ? [{ label: "Accounts", value: accounts.join(", ") }] : [],
    steps: [],
    quotes: null,
    code: null,
    queueTitle: `Composio · ${TITLES.manage_connections}`,
    queueDetail: accounts.length > 0 ? joinList(accounts) : null,
  };
}

const STEP_ROW_LIMIT = 10;

function multiExecute({ harness, input }: ComposioContext): McpCallBody {
  // Every entry counts toward the title, the apps and the effect. Only the rows are capped,
  // and an entry that is not an object reads as an action Guard cannot identify.
  const toolsValue: unknown = input?.tools;
  const entries: unknown[] = Array.isArray(toolsValue) ? toolsValue : [];
  const all = entries.map((entry, index) => toStep(recordOf(entry), index));
  const steps = all.slice(0, STEP_ROW_LIMIT);
  const hiddenSteps = all.length - steps.length;
  const apps = unique(all.map((step) => step.app).filter((app): app is string => app !== null));
  const where = apps.length > 0 ? joinList(apps) : "Composio";
  const effect = worstMcpEffect(all.map((step) => step.effect));
  const effectApps = unique(
    all.filter((step) => step.effect === effect).map((step) => step.app).filter((app): app is string => app !== null),
  );
  const count = all.length;
  const thought = textOf(input?.thought, 300);
  const first = all[0];
  return {
    headline: `${harness} wants to ${batchPhrase(first, count, where)}`,
    title: batchTitle(first, count, apps),
    aside: `Composio carries out ${count === 1 ? "this action" : "these actions"} in your connected ${accountPhrase(apps)}, using the inputs below.`,
    effect,
    effectBasis: STEP_BASIS,
    facts: [],
    steps,
    hiddenSteps,
    effectApps,
    quotes: thought !== null ? { caption: THOUGHT_CAPTION, items: [thought] } : null,
    code: null,
    // The row leads with the app people know (Gmail), not the service in between.
    queueTitle: `${apps.length === 1 ? apps[0] : "Composio"} · ${first?.action ?? "Run actions"}${count > 1 ? ` and ${count - 1} more` : ""}`,
    queueDetail: batchQueueDetail(first, apps),
  };
}

/** One app: the first step's main detail. Several apps: their names. None: nothing. */
function batchQueueDetail(first: McpStep | undefined, apps: string[]): string | null {
  if (apps.length === 1) return firstDetail(first);
  if (apps.length > 1) return joinList(apps);
  return null;
}

/** "send email in Gmail" for one action, "take 3 actions in Gmail and Slack" for several. */
function batchPhrase(first: McpStep | undefined, count: number, where: string): string {
  if (count === 1 && first !== undefined && first.app !== null) {
    return `${first.action.charAt(0).toLowerCase()}${first.action.slice(1)} in ${first.app}`;
  }
  if (count === 1) return `take an action in ${where}`;
  return `take ${count === 0 ? "some" : count} actions in ${where}`;
}

/** The first detail of an action, such as who an email goes to, for the list row. */
function firstDetail(step: McpStep | undefined): string | null {
  const value = step?.details[0]?.value;
  return value !== undefined && value.length > 0 ? value : null;
}

function accountPhrase(apps: string[]): string {
  if (apps.length === 1) return `${apps[0]} account`;
  return "accounts";
}

function batchTitle(first: McpStep | undefined, count: number, apps: string[]): string {
  if (count === 1 && first !== undefined) {
    return first.app !== null ? `${first.action} in ${first.app}` : first.action;
  }
  const where = apps.length > 0 ? ` in ${joinList(apps)}` : "";
  return `Run ${count === 0 ? "some" : count} actions${where}`;
}

function toStep(tool: Record<string, unknown> | null, index: number): McpStep {
  const slug = textOf(tool?.tool_slug, 120) ?? "";
  const { app, action } = slug.length > 0 ? splitToolSlug(slug) : { app: null, action: "Unnamed action" };
  const { facts, hidden } = scalarFacts(recordOf(tool?.arguments), { max: 5, tool: slug });
  return {
    id: `${index}-${slug}`,
    app,
    action,
    effect: slug.length > 0 ? classifyMcpEffect(slug) : "unknown",
    details: facts,
    hiddenDetails: hidden,
  };
}

/**
 * Code for Composio's workspace that names the actions it calls reads as those
 * actions: "Search emails in Gmail, using code". The code stays one click away,
 * and the effect stays "runs code", since code can do more than it names.
 * Returns null when the code names no action, so the code itself is the card.
 */
function workbenchCode({ harness, input }: ComposioContext): McpCallBody | null {
  const code = codeOf(input?.code_to_execute);
  if (code === null) return null;
  const { steps: all, unreadable } = readComposioCode(code);
  if (all.length === 0) return null;
  // Every call counts toward the title and the apps; only the rows are capped.
  const steps = all.slice(0, STEP_ROW_LIMIT);
  const apps = unique(all.map((step) => step.app).filter((app): app is string => app !== null));
  const first = all[0];
  const count = all.length;
  const thought = textOf(input?.thought, 300);
  const lines = code.split("\n").length;
  return {
    headline: `${harness} wants to ${batchPhrase(first, count, apps.length > 0 ? joinList(apps) : "Composio")}, using code`,
    title: batchTitle(first, count, apps),
    aside: codeAside(apps, unreadable),
    effect: "run-code",
    effectBasis: "Read from the action names in the code. Guard has not run or checked it.",
    facts: [],
    steps,
    hiddenSteps: all.length - steps.length,
    stepsCaption: count === 1 ? "What the code asks for" : "What the code asks for, in order",
    effectApps: apps,
    quotes: thought !== null ? { caption: THOUGHT_CAPTION, items: [thought] } : null,
    // When part of the code could not be read, the code itself stays in view.
    code: { label: `The code (${lines} ${lines === 1 ? "line" : "lines"})`, text: code, collapsed: unreadable === 0 },
    queueTitle: `${apps.length === 1 ? apps[0] : "Composio"} · ${first.action}${count > 1 ? ` and ${count - 1} more` : ""}`,
    queueDetail: batchQueueDetail(first, apps),
  };
}

function codeAside(apps: string[], unreadable: number): string {
  const account = apps.length > 0 ? `your connected ${accountPhrase(apps)}` : "your connected accounts";
  const rest = unreadable > 0 ? " Some of it reaches actions in ways Guard cannot read, so read the code below." : "";
  return `The agent wrote code that Composio runs with ${account}.${rest}`;
}

function remoteCode(context: ComposioContext, title: string, field: string, label: string): McpCallBody {
  const code = codeOf(context.input?.[field]);
  const thought = textOf(context.input?.thought, 300);
  return {
    headline: `${context.harness} wants to ${title.charAt(0).toLowerCase()}${title.slice(1)}`,
    title,
    aside: "Composio runs this in its remote workspace.",
    effect: "run-code",
    effectBasis: NAME_BASIS,
    facts: [],
    steps: [],
    quotes: thought !== null ? { caption: THOUGHT_CAPTION, items: [thought] } : null,
    code: code !== null ? { label, text: code } : null,
    queueTitle: `Composio · ${title}`,
    queueDetail: null,
  };
}

function slugLabel(slug: string): string {
  const { app, action } = splitToolSlug(slug);
  return app !== null ? `${app} · ${action}` : action;
}
