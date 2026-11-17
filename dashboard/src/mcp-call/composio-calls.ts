import type { McpCallExplanation, McpStep } from "./mcp-call-types";
import { classifyMcpEffect, worstMcpEffect } from "./mcp-effects";
import { codeOf, joinList, recordList, recordOf, scalarFacts, textList, textOf, unique } from "./mcp-input";
import { serviceDisplayName, splitToolSlug } from "./mcp-services";

export type McpCallBody = Omit<McpCallExplanation, "connector" | "rawInput" | "truncated" | "toolId" | "whyAsked">;

type ComposioContext = { harness: string; input: Record<string, unknown> | null };

const NAME_BASIS = "Read from the tool's name. Guard has not checked what it does.";
const STEP_BASIS = "Read from the action names. Guard has not checked what they do.";
const SEPARATE_CALL = "Running a tool is a separate call, and Guard reviews that call too.";
export const THOUGHT_CAPTION = "What the agent said it is doing";

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
      return remoteCode(context, "Run code in Composio's workspace", "code_to_execute", "Code");
    case "remote_bash_tool":
      return remoteCode(context, "Run a command in Composio's workspace", "command", "Command");
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
    title: "Search for tools",
    summary: `Composio connects the agent to other apps. This call asks it which tools could do the job. ${SEPARATE_CALL}`,
    effect: "read",
    effectBasis: NAME_BASIS,
    facts: [
      ...(apps.length > 0 ? [{ label: "Apps in the search", value: apps.join(", ") }] : []),
      ...(count > 1 ? [{ label: "Searches", value: String(count) }] : []),
    ],
    steps: [],
    quotes: useCases.length > 0 ? { caption: "What the agent said it is looking for", items: useCases.slice(0, 4) } : null,
    code: null,
    queueTitle: "Composio · Search for tools",
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
    title: "Look up how tools work",
    summary: `This call fetches the instructions for specific tools so the agent can call them correctly. ${SEPARATE_CALL}`,
    effect: "read",
    effectBasis: NAME_BASIS,
    facts: named.length > 0 ? [{ label: "Tools", value: joinList(named, 6) }] : [],
    steps: [],
    quotes: null,
    code: null,
    queueTitle: "Composio · Look up how tools work",
    queueDetail: named.length > 0 ? joinList(named) : null,
  };
}

function manageConnections({ harness, input }: ComposioContext): McpCallBody {
  const accounts = unique(textList(input?.toolkits ?? input?.apps).map(serviceDisplayName));
  return {
    headline: `${harness} wants to manage your connected accounts in Composio`,
    title: "Manage connected accounts",
    summary: "This call checks which of your accounts are linked to Composio and can ask to link another one.",
    effect: "connect",
    effectBasis: NAME_BASIS,
    facts: accounts.length > 0 ? [{ label: "Accounts", value: accounts.join(", ") }] : [],
    steps: [],
    quotes: null,
    code: null,
    queueTitle: "Composio · Manage connected accounts",
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
  const count = all.length;
  const thought = textOf(input?.thought, 300);
  const first = all[0];
  return {
    headline: `${harness} wants to run ${actionCountPhrase(count)} in ${where}`,
    title: batchTitle(first, count, apps),
    summary: `Composio will carry out ${count === 1 ? "this action" : "these actions"} in your connected ${accountPhrase(apps)}, using the inputs below.`,
    effect: worstMcpEffect(all.map((step) => step.effect)),
    effectBasis: STEP_BASIS,
    facts: [],
    steps,
    hiddenSteps,
    quotes: thought !== null ? { caption: THOUGHT_CAPTION, items: [thought] } : null,
    code: null,
    queueTitle: `Composio · ${first?.action ?? "Run actions"}${count > 1 ? ` and ${count - 1} more` : ""}`,
    queueDetail: apps.length > 0 ? joinList(apps) : null,
  };
}

function actionCountPhrase(count: number): string {
  if (count === 1) return "an action";
  if (count === 0) return "some actions";
  return `${count} actions`;
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
  const { facts, hidden } = scalarFacts(recordOf(tool?.arguments), { max: 5 });
  return {
    id: `${index}-${slug}`,
    app,
    action,
    effect: slug.length > 0 ? classifyMcpEffect(slug) : "unknown",
    details: facts,
    hiddenDetails: hidden,
  };
}

function remoteCode(context: ComposioContext, title: string, field: string, label: string): McpCallBody {
  const code = codeOf(context.input?.[field]);
  const thought = textOf(context.input?.thought, 300);
  return {
    headline: `${context.harness} wants to ${title.charAt(0).toLowerCase()}${title.slice(1)}`,
    title,
    summary: "Composio will run this in its remote workspace. Code can do anything its tools allow, so read it before you approve.",
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
