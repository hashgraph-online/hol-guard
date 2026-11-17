import type { McpConsequence } from "./mcp-call-types";
import type { McpEffectKind } from "./mcp-effects";

/**
 * What approving lets happen, in one line. It is worded as what the tool's name
 * suggests, never as a promise: Guard has read a name, not checked the tool.
 * `where` is the service or services the call acts in.
 */
export function consequenceFor(effect: McpEffectKind, where: string): McpConsequence {
  switch (effect) {
    case "in-app":
      return {
        tone: "calm",
        text: `By its name, this only changes what ${where} shows you. It does not reach your files, accounts or other apps.`,
      };
    case "read":
      return { tone: "calm", text: `By its name, this looks something up in ${where}.` };
    case "write":
      return { tone: "care", text: `By its name, this creates or changes something in ${where}.` };
    case "send":
      return {
        tone: "danger",
        text: `Sends something through ${where}. Once it goes out, it may not be possible to take back.`,
      };
    case "delete":
      return { tone: "danger", text: `Deletes something in ${where}. It may not be possible to recover.` };
    case "run-code":
      return { tone: "danger", text: "Runs code. It can do anything this tool's access allows, so read it first." };
    case "connect":
      return { tone: "care", text: `Checks or changes which accounts are linked to ${where}, and may ask you to link another.` };
    case "unknown":
      return { tone: "care", text: "Guard cannot tell what this does from the tool's name. Check the details below." };
  }
}
