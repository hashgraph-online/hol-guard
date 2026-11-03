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
    id: "first-brief", title: "Your first CIGAR prompt", level: "Start here",
    description: "Turn CIGAR on, ask your AI something, and see what it was handed.",
    outcome: "A prompt that came with the right project files, and a way to check each one.",
    steps: [
      {
        title: "Turn on CIGAR", description: "One click. Guard gets everything ready, checks it and starts it.",
        instructions: ["Click Turn on CIGAR at the top of this page. If Guard asks for your approval password, enter it once; it covers every step.", "Watch the steps tick off. You can stop at any point and nothing stays turned on.", "Later, if you want to switch versions yourself, use Updates."],
        expect: "The status at the top says Ready.", target: "overview", action: "Go to Home",
        tip: "CIGAR uses its own copy of Python. The Python you already use is left alone.",
      },
      {
        title: "Let it read project files", description: "Prompts only get files once CIGAR may read them.",
        instructions: ["If the top of this page shows Let CIGAR read project files, click it.", "Secrets, keys, hidden files and anything your .gitignore leaves out stay skipped either way."],
        expect: "The top of the page no longer asks to read project files.", target: "overview", action: "Go to Home",
      },
      {
        title: "Pick exact files (optional)", description: "Skip this and CIGAR picks matching files from the project your app is open in.",
        instructions: ["In Projects, click Choose a project folder and browse to your project.", "Tick the files CIGAR should read, such as the README, then click Add project.", "Your choice counts for every AI app."],
        expect: "Your project shows up under Your projects.", target: "access", action: "Open Projects",
        tip: "Leave this step for later if you are not sure. The automatic choice works for most projects.",
      },
      {
        title: "Ask your AI something specific", description: "Use Claude Code, Codex, Pi or Oh My Pi in your project, the way you always do.",
        instructions: ["Copy the example below, or write your own about a real file, feature or word in your project.", "Send it in your AI app. CIGAR adds the parts that match before your AI starts."],
        expect: "Your AI's answer points at the right files. A vague prompt may get no files, which is expected.", target: "access", action: "Open Projects",
        question: "Where is the main page header styled, and which file sets its color?",
        tip: "Prompts that name something in your project match best.",
      },
      {
        title: "See what your AI got", description: "Check the pieces CIGAR hands over, and where each came from.",
        instructions: ["In Projects, type the same question under Try it: what would you ask your AI?", "Click Show what your AI would get under your project.", "Open Where each part came from to see the file and lines for each piece."],
        expect: "You can trace each piece back to a file and lines in your project.", target: "access", action: "Open Projects",
      },
      {
        title: "Change it or take it back", description: "You stay in charge of what CIGAR reads.",
        instructions: ["After you edit a picked file, click Read files again.", "Click Stop reading next to a file, or Remove project to drop the whole folder.", "Turn CIGAR off at the top of this page to stop everything at once."],
        expect: "You know how to refresh, narrow or remove what CIGAR reads.", target: "access", action: "Open Projects",
        tip: "Privacy shows what CIGAR keeps. By default its notes live in memory only.",
      },
    ],
  },
  {
    id: "ai-apps", title: "Connect another app, like Cursor", level: "Optional",
    description: "Claude Code, Codex, Pi and Oh My Pi need nothing extra. Other apps can ask CIGAR for files once you connect them.",
    outcome: "One app connected to one project, that you can disconnect at any time.",
    steps: [
      {
        title: "Turn on CIGAR and file reading", description: "Connections need both.",
        instructions: ["At the top of this page, click Turn on CIGAR if it is off.", "If the page shows Let CIGAR read project files, click it too."],
        expect: "The status says Ready and nothing asks to read project files.", target: "overview", action: "Go to Home",
      },
      {
        title: "Add the project", description: "Choose the folder the app will work in.",
        instructions: ["In Projects, click Choose a project folder and browse to the folder.", "Tick the files it should read, then click Add project."],
        expect: "The project shows up under Your projects.", target: "access", action: "Open Projects",
      },
      {
        title: "Get the app's code", description: "The app asks through Guard's tool server (MCP), which your app needs set up.",
        instructions: ["In your app, ask it to run Guard's get_context_status tool.", "It answers with a short code. Keep it on screen."],
        expect: "Your app shows a short connection code.", target: "access", action: "Open Projects",
        tip: "The code proves which running app is asking, so you never connect the wrong one.",
      },
      {
        title: "Connect it", description: "Match the code, then say which app and project.",
        instructions: ["Under Connect another app, click Check for apps.", "Find the entry whose code matches your app's code.", "Choose the app and the project, then click Connect."],
        expect: "The entry says Connected, with the app and project you chose.", target: "access", action: "Open Projects",
        tip: "Connections last a few minutes at a time. If one ends, ask the app for a new code and connect again.",
      },
      {
        title: "Use it, then disconnect", description: "Ask the app a question about the project.",
        instructions: ["Ask the app to use Guard's context tools, using the example below.", "Click Disconnect when you are done."],
        expect: "The app answers with pieces from your project and says where they came from.", target: "access", action: "Open Projects",
        question: "Use your Guard context tools to explain how this project is set up. Say which files each part of your answer came from.",
      },
    ],
  },
  {
    id: "execution", title: "Context for Pi commands", level: "Advanced · macOS",
    description: "When Pi or Oh My Pi runs a shell command, CIGAR can hand it Guard's safety facts for that project.",
    outcome: "You know whether this works on your computer and where to see it happen.",
    steps: [
      {
        title: "Check it works here", description: "This needs Pi or Oh My Pi on macOS.",
        instructions: ["In Settings, open More settings and look for Associate native context with execution.", "If it is missing or greyed out, this computer does not support it yet. Everything else in CIGAR still works.", "Delivery to apps other than Pi and Oh My Pi is not tested end to end yet."],
        expect: "You know whether this computer supports it.", target: "runtime", action: "Open Settings",
      },
      {
        title: "Turn it on", description: "Two switches in More settings.",
        instructions: ["In Settings, open More settings and turn on Native policy and decision facts.", "Turn on Associate native context with execution, then save."],
        expect: "Both switches stay on after saving.", target: "runtime", action: "Open Settings",
      },
      {
        title: "Use Pi as usual", description: "No project setup needed.",
        instructions: ["Open Pi or Oh My Pi in your project and ask it to do something that runs a command.", "CIGAR uses the project Pi is open in, or the files you picked for it in Projects."],
        expect: "Pi keeps working. Guard still asks before risky commands, exactly as before.", target: "access", action: "Open Projects",
      },
      {
        title: "See what happened", description: "Guard still decides every command. CIGAR only adds facts.",
        instructions: ["In Settings, find Native execution context to see what CIGAR prepared for recent commands.", "Approve or deny commands in Guard the usual way."],
        expect: "You can see what CIGAR prepared, separate from Guard's own decision.", target: "runtime", action: "Open Settings",
      },
    ],
  },
  CIGAR_UPDATE_TUTORIAL,
];

export function cigarTutorial(id: CigarTutorialId): CigarTutorial {
  return CIGAR_TUTORIALS.find((tutorial) => tutorial.id === id) ?? CIGAR_TUTORIALS[0];
}
