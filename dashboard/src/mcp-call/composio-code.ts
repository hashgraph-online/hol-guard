import type { McpStep } from "./mcp-call-types";
import { classifyMcpEffect } from "./mcp-effects";
import { scalarFacts } from "./mcp-input";
import { splitToolSlug } from "./mcp-services";

/**
 * Code sent to Composio's workspace usually calls Composio actions by name:
 * `run_composio_tool('GMAIL_FETCH_EMAILS', {'query': 'riverside', ...})`.
 * Those names say what the code is for in words people know, so the card can
 * show "Search emails in Gmail" instead of asking them to read Python.
 *
 * This reads the text only. It finds the action names and the plain values
 * written next to them; it does not run or fully parse the code, and code can
 * do more than the actions it names. The card says so and keeps the code one
 * click away.
 */
export type ComposioCodeReading = {
  steps: McpStep[];
  /** Calls whose action name is not written out (a variable), so the card cannot name them. */
  unnamedCalls: number;
};

const CALL = /\b(?:run_composio_tool|execute_action|tools\.execute)\s*\(\s*(?:(["'])([A-Za-z][A-Za-z0-9_]{2,119})\1)?/g;
// `'key': 'value'`, `"key": 15`, `key=True`. Strings stop at their closing quote; a string the input cut short is left out.
const PAIR = /(?:(["'])([A-Za-z_][A-Za-z0-9_]{0,59})\1\s*:|\b([A-Za-z_][A-Za-z0-9_]{0,59})\s*=(?!=))\s*(?:(["'])((?:\\.|(?!\4)[^\\\n]){0,400})\4|(-?\d+(?:\.\d+)?)\b|(True|False|None|true|false|null)\b)/g;
const STEP_LIMIT = 10;
const ARG_REACH = 1200;

export function readComposioCode(code: string): ComposioCodeReading {
  const calls = [...code.matchAll(CALL)];
  const steps: McpStep[] = [];
  let unnamedCalls = 0;
  calls.forEach((match, index) => {
    const slug = match[2];
    if (slug === undefined) {
      unnamedCalls += 1;
      return;
    }
    if (steps.length >= STEP_LIMIT) return;
    const start = (match.index ?? 0) + match[0].length;
    const args = literalArguments(code.slice(start, callEnd(code, start)));
    const { app, action } = splitToolSlug(slug.toUpperCase());
    const { facts, hidden } = scalarFacts(args, { max: 4, tool: slug.toUpperCase() });
    steps.push({
      id: `code-${index}-${slug}`,
      app,
      action,
      effect: classifyMcpEffect(slug),
      details: facts,
      hiddenDetails: hidden,
    });
  });
  return { steps, unnamedCalls };
}

/** Where the call's parentheses close, skipping quoted text, so values written after the call are not read as its inputs. */
function callEnd(code: string, start: number): number {
  const limit = Math.min(code.length, start + ARG_REACH);
  let depth = 1;
  let quote: string | null = null;
  for (let at = start; at < limit; at += 1) {
    const char = code[at];
    if (quote !== null) {
      if (char === "\\") at += 1;
      else if (char === quote) quote = null;
      continue;
    }
    if (char === "'" || char === '"') quote = char;
    else if (char === "(") depth += 1;
    else if (char === ")") {
      depth -= 1;
      if (depth === 0) return at;
    }
  }
  return limit;
}

/** The plain values written beside an action name. Yes/no switches are settings, not something a person judges, so they stay in the code. */
function literalArguments(text: string): Record<string, unknown> {
  const args: Record<string, unknown> = {};
  for (const match of text.matchAll(PAIR)) {
    const key = match[2] ?? match[3];
    if (key === undefined || key in args) continue;
    if (match[5] !== undefined) args[key] = match[5].replace(/\\(["'\\])/g, "$1");
    else if (match[6] !== undefined) args[key] = Number(match[6]);
  }
  return args;
}
