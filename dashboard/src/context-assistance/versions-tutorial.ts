import type { CigarTutorial } from "./tutorial-content";
export const CIGAR_UPDATE_TUTORIAL: CigarTutorial = {
  id: "cigar-updates", title: "Update CIGAR with less interruption", level: "Runtime maintenance",
  description: "Prepare a replacement beside the current build and choose when to switch.",
  outcome: "A verified selection, an understood reconnect boundary, and a path to the last good build.",
  steps: [
    {
      title: "Read the available builds", description: "Opening Updates reads metadata without starting Python or CIGAR.",
      instructions: ["Check the Guard host, catalog freshness and build ID. Different builds can have the same version label.", "A withdrawn, expired or upstream-only artifact is unavailable for preparation. A new Guard release does not qualify an SDK automatically.", "Use Check for catalog updates only when a trusted feed is configured, or import a catalog signed by an already trusted key."],
      expect: "You can identify the exact build and whether this Guard host has a qualified artifact.", target: "versions", action: "Inspect versions & updates",
    },
    {
      title: "Prepare beside your current runtime", description: "Downloading and verifying a replacement does not select or enable it.",
      instructions: ["Choose a registered Python interpreter for an available SDK build, or explicitly prepare an eligible private Python build first.", "Click Prepare this build and watch its native job. The current runtime remains selected while preparation runs.", "Cancel the job if you change your mind. For an uncertain response, refresh jobs and inspect the recorded job ID before another action."],
      expect: "The prepared installation appears in Registered installations, with your current selection intact.", target: "versions", action: "Prepare an eligible build",
    },
    {
      title: "Prepare the selection", description: "Guard checks the target and compatible data before offering a commit.",
      instructions: ["Save any pending CIGAR preference edits, then click Prepare selection beside the target installation.", "Wait for that selection job to become ready. Its preparation can be cancelled without choosing the target.", "If Guard requires a saved-data choice or recovery, follow the diagnostic. Do not clear data just to bypass a refusal."],
      expect: "A current native selection job offers Switch now, or Select & keep CIGAR off.", target: "versions", action: "Review selection readiness",
    },
    {
      title: "Choose the switch boundary", description: "A live switch briefly pauses CIGAR and ends existing context authority.",
      instructions: ["For a live runtime, finish current context work and acknowledge that sources and app connections will need fresh access.", "Click Switch now and provide Guard's settings proof when required. Refresh jobs if the response is uncertain; the browser never retries the change automatically.", "If CIGAR is off, Select & keep CIGAR off commits only the selection. It does not turn CIGAR on."],
      expect: "The selected runtime changes only after your explicit commit. Your Guard command approvals remain available.", target: "versions", action: "Review the explicit switch",
    },
    {
      title: "Reconnect the scopes you need", description: "Saved evidence does not restore source or app permission.",
      instructions: ["If you selected while off, return to Settings, choose your enabled preference, save and explicitly start CIGAR.", "Use the live runtime status to confirm readiness before granting workspace access.", "Grant only the intended workspace sources and pair the current app connection again when needed."],
      expect: "Your intended sources and apps have fresh access to the selected runtime.", target: "access", action: "Review projects & AI apps",
    },
    {
      title: "Use the last good build deliberately", description: "Rollback prepares current compatible data for the previous verified installation.",
      instructions: ["In Updates, choose Prepare last good build when you need to return to the retained installation.", "Wait for the rollback selection job, then commit it explicitly with the same reconnect acknowledgement when live.", "Use Recover job for interrupted work. Recovery does not re-grant context access. Your Guard approvals remain in place."],
      expect: "You know where to inspect a rollback or interrupted job before taking another action.", target: "versions", action: "Inspect rollback & recovery",
    },
  ],
};
