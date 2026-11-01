import type { CigarTab } from "./workspace-model";
import { CIGAR_UPDATE_TUTORIAL } from "./versions-tutorial";

export const CIGAR_FULL_NAME = "Context Intelligence Graph Agentic Runtime";
export type CigarTutorialId = "first-brief" | "ai-apps" | "execution" | "cigar-updates";
export type CigarTutorialStep = {
  title: string;
  description: string;
  instructions: string[];
  expect: string;
  target: CigarTab;
  action: string;
  tip?: string;
  question?: string;
};
export type CigarTutorial = {
  id: CigarTutorialId;
  title: string;
  level: string;
  description: string;
  outcome: string;
  steps: CigarTutorialStep[];
};

export const CIGAR_TUTORIALS: readonly CigarTutorial[] = [
  {
    id: "first-brief", title: "Prepare your first cited brief", level: "Start here",
    description: "Go from a running runtime to useful evidence for one workspace.",
    outcome: "A context brief whose sources and revisions you can inspect.",
    steps: [
      {
        title: "Turn on CIGAR", description: "One click. Guard gets Python ready, downloads the approved CIGAR copy, checks it and starts it.",
        instructions: ["Click Turn on CIGAR at the top of this page. If Guard asks for your approval password, enter it once; it covers every step.", "Watch the steps tick off. You can stop at any point and nothing stays turned on.", "Later, if you want to switch versions yourself, use Updates."],
        expect: "The status says Ready.", target: "runtime", action: "Open Settings",
        tip: "CIGAR uses its own copy of Python 3.14. Guard can keep using the Python it already has.",
      },
      {
        title: "Choose a small evidence set", description: "Pick the sources that can answer your question before granting workspace access.",
        instructions: ["Open Sources, limits and runtime details in Settings. Native policy and decision facts can be used without adding project files.", "For project documentation, turn on Allow selected workspace documents. Plan to start with one or two relevant files, such as README.md and a release guide that exists in your project.", "Save changes and start CIGAR again if its status returns to Not started. Changing preferences can end existing context access."],
        expect: "Your intended source preferences are saved and the runtime is Ready.", target: "runtime", action: "Choose source preferences",
        tip: "A document preference allows you to choose files later. It does not grant access to the whole workspace.",
      },
      {
        title: "Grant one workspace access", description: "A grant connects a workspace and a consumer to the evidence you explicitly select.",
        instructions: ["In Projects & AI apps, choose Guard dashboard as the Context consumer.", "Enter the absolute Workspace folder. Add individual files relative to that folder, one per line, if document context is enabled. Leave the file list empty for native facts only.", "Click Grant review source access. Confirm the exact workspace, consumer, and sources when Guard asks for approval proof."],
        expect: "A Context access section appears for your chosen workspace.", target: "access", action: "Open Projects & AI apps",
        tip: "Choose only relevant sources. Environment files and credential stores are not valid context sources.",
      },
      {
        title: "Ask one concrete question", description: "Tell CIGAR what evidence you need for the task in front of you.",
        instructions: ["Fill What would you like context about? with one focused question.", "For native facts only, try the example below. If you granted project docs, ask about a specific documented workflow, file, or rule.", "Click Prepare cited context in the section for the workspace you want to use."],
        expect: "Prepared context contains excerpts and citations. If relevant evidence is missing, refine the question or select better sources.", target: "access", action: "Prepare context in your workspace",
        question: "Which native Guard policy and decision facts apply to this workspace?",
        tip: "The brief is evidence prepared for your question. Your review or authorized AI app can use that evidence to reason about the task.",
      },
      {
        title: "Read the evidence behind it", description: "Use the citations to decide whether the brief supports your task.",
        instructions: ["Read the excerpts in Prepared context, then open Sources and revisions.", "Check the source names, line ranges, and document revisions. A citation identifies the evidence checked when the brief was prepared.", "For a pending command in Inbox, request its context brief when available, inspect the evidence, and make your Guard approval decision separately."],
        expect: "You can trace a useful statement back to its admitted source. A brief never grants command permission.", target: "access", action: "Inspect your prepared context",
      },
      {
        title: "Keep context current", description: "Fresh sources make the next brief useful as your work changes.",
        instructions: ["After editing a selected document, click Refresh selected files, then Prepare cited context again.", "Use Withdraw beside a file or Revoke workspace access when it is no longer needed.", "Stopping or restarting the runtime ends active access. Grant the workspace again when needed; saved evidence never restores permission."],
        expect: "You know how to prepare a fresh brief and remove its source access.", target: "access", action: "Review workspace access",
        tip: "Use Privacy to inspect or remove saved evidence. Memory is the default and ends with the runtime.",
      },
    ],
  },
  {
    id: "ai-apps", title: "Give an AI app scoped context", level: "After your first brief",
    description: "Choose sources for an app, match its real connection code, and pair it explicitly.",
    outcome: "One authorized Guard MCP connection with access to a chosen workspace.",
    steps: [
      {
        title: "Enable app context deliberately", description: "App access is a separate feature choice from review briefs.",
        instructions: ["In Settings, enable Context for AI apps. Choose source preferences before granting access.", "Keep Share context between paired AI connections off while you try a single connection.", "Save your changes. If CIGAR is off, click Turn on CIGAR. Confirm the status says Ready."],
        expect: "Context for AI apps is saved and the runtime is Ready.", target: "runtime", action: "Choose AI app preferences",
      },
      {
        title: "Grant sources for that app", description: "A dashboard grant and an app grant have different consumers.",
        instructions: ["In Projects & AI apps, choose your app in Context consumer: Codex, Claude Code, or Cursor.", "Choose the workspace and individual source files it needs. Enable document context first if you want to add files.", "Click Grant review source access and review the app and workspace in the confirmation."],
        expect: "A workspace grant names the app you chose.", target: "access", action: "Choose the app's sources",
      },
      {
        title: "Identify the real connection", description: "Use the local Guard MCP server configured in your app.",
        instructions: ["In the app's Guard MCP connection, request get_context_status to obtain its pending connection code.", "Return to AI app context connections and click Refresh app connections.", "Match the displayed Connection code to the one from that app's actual process."],
        expect: "The same code appears in your app and the pending connection shown here.", target: "access", action: "Find the pending connection",
        tip: "This screen does not install an app connection. Choosing an app label is a permission choice; matching the real code identifies the connection you are authorizing.",
      },
      {
        title: "Authorize one connection", description: "Pair the verified connection with the workspace grant you intended.",
        instructions: ["Under the matched connection, choose its Workspace and app grant.", "Click Authorize context connection and confirm the connection code, app, and workspace when prompted.", "Look for Grant assigned. A running runtime alone does not grant app access."],
        expect: "The intended connection shows Grant assigned for the chosen workspace.", target: "access", action: "Authorize the matched connection",
        tip: "Connections have short leases. If one expires or the runtime restarts, reconnect and pair its current code.",
      },
      {
        title: "Ask the app to use its context", description: "Make evidence use part of a focused task request.",
        instructions: ["Ask the authorized app to request Guard context for a specific workspace task, using the example below as a starting point.", "Check the app's cited sources and ask it to identify missing evidence rather than assume an answer.", "Use Revoke context connection when you are finished. Add sharing only when you need it, with separate reviewed-note permissions."],
        expect: "The app can request context within its grant. Missing access or evidence is reported explicitly.", target: "access", action: "Review app access",
        question: "Use your Guard context tools for this workspace to explain the relevant project rules. Cite the evidence you receive and identify anything the available context does not establish.",
      },
    ],
  },
  {
    id: "execution", title: "Understand execution context", level: "Advanced · supported routes only",
    description: "Learn the optional native preparation path for Pi and Oh My Pi captured-Bash actions.",
    outcome: "An understanding of the route requirements and how to inspect an execution-context observation.",
    steps: [
      {
        title: "Check the route first", description: "Execution context has a narrower scope than general review briefs.",
        instructions: ["Use an existing supported native captured-Bash route for Pi or Oh My Pi on macOS.", "Check the execution capability and Native execution context panel in Settings.", "This candidate has local native preparation checks. Full delivery from external apps has not yet been qualified."],
        expect: "You know whether the preparation route is available in this build.", target: "runtime", action: "Inspect execution availability",
        tip: "You can read this walkthrough even when the route is unavailable. Review briefs and paired app context have their own controls.",
      },
      {
        title: "Choose the execution preference", description: "Execution associations use native capture and policy facts.",
        instructions: ["Open Sources, limits and runtime details. Enable Native policy and decision facts.", "If the build offers it, enable Associate native context with execution.", "Save and start CIGAR. Inspect the Native execution context panel for preparation readiness."],
        expect: "The panel reports the current native preparation state.", target: "runtime", action: "Review execution preferences",
      },
      {
        title: "Scope the executor's workspace", description: "Choose the app and workspace for the native route you use.",
        instructions: ["In Projects & AI apps, choose Pi or Oh My Pi as Context consumer when offered.", "Enter the workspace, review its native facts and any separately selected documents, and grant only that scope.", "A workspace grant does not install an app adapter or approve a command."],
        expect: "The workspace grant names the intended executor consumer.", target: "access", action: "Inspect executor workspace access",
      },
      {
        title: "Inspect the native observation", description: "Keep the command decision in Guard's normal approval flow.",
        instructions: ["Use your existing supported app route. Inspect its Guard review and choose the approval scope you intend, such as Run once or Always allow this version in this project.", "Return to Native execution context observations to inspect whether preparation or association was recorded.", "For an uncertain outcome, consult Guard's native execution record before retrying."],
        expect: "You can distinguish context preparation, a dispatch acknowledgement, and a native execution record.", target: "runtime", action: "Open execution observations",
        tip: "Context is supporting information. Guard owns command authorization and the execution record.",
      },
    ],
  },
  CIGAR_UPDATE_TUTORIAL,
];

export function cigarTutorial(id: CigarTutorialId): CigarTutorial {
  return CIGAR_TUTORIALS.find((tutorial) => tutorial.id === id) ?? CIGAR_TUTORIALS[0];
}
