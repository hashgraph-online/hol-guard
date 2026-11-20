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
        text: `By its name, this only changes what ${where} shows you. Guard has not checked what it does.`,
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
      return {
        tone: "danger",
        text: `Runs code that can use ${where}. Code can do more than it says, so open it if anything looks wrong.`,
      };
    case "connect":
      return { tone: "care", text: `Checks or changes which accounts are linked to ${where}, and may ask you to link another.` };
    case "act-as-you":
      return {
        tone: "care",
        text: `Works in ${where} as if it were you. Where you are signed in, it can do what you can, like buy, post or change settings.`,
      };
    case "unknown":
      return { tone: "care", text: "Guard cannot tell what this does from the tool's name. Check the details below." };
  }
}
