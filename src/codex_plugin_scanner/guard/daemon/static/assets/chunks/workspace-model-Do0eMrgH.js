const CIGAR_TABS = [
  { value: "overview", label: "Home" },
  { value: "access", label: "Projects" },
  { value: "runtime", label: "Settings" },
  { value: "versions", label: "Updates" },
  { value: "data", label: "Privacy" },
  { value: "guide", label: "Guide" }
];
function canStartCigar(status, dirty) {
  return !dirty && status !== null && status.requested_enabled && status.preferences.enabled && status.effective_preferences.enabled && status.verification_permitted && Boolean(status.preferences.runtime_id) && !status.effective_enabled && status.job === null;
}
function cigarTabFromSearch(search) {
  const value = new URLSearchParams(search).get("section");
  if (value === "tutorials") return "guide";
  return CIGAR_TABS.find((tab) => tab.value === value)?.value ?? "overview";
}
function cigarWaking(status) {
  if (!status || status.effective_enabled) return false;
  return status.diagnostic === "runtime_resting" || status.requested_enabled && status.job?.operation === "activate";
}
function cigarHelpsPrompts(status) {
  const effective = status?.effective_preferences;
  return effective?.features.agent_context === true && effective.sources.workspace_documents === true;
}
function cigarWillHelpPrompts(status) {
  if (!status) return false;
  if (cigarHelpsPrompts(status)) return true;
  const { sources } = status.preferences;
  return !sources.workspace_documents && !sources.source_set_id;
}
const PROMPT_PROMISE = "Every prompt you send in Claude Code, Codex, Pi or Oh My Pi gets the few project files that match it.";
const NO_FILES_YET = "Prompts get no project files yet, because reading project files is off.";
function cigarHomeCopy(status, loading, running) {
  if (running) return { headline: "Turning on CIGAR", detail: "Guard is setting it up. You can keep browsing.", setupHint: false };
  if (!status) {
    if (loading) return { headline: "Checking CIGAR", detail: "One moment.", setupHint: false };
    return { headline: "CIGAR status unavailable", detail: "Guard did not answer. Try refreshing the status.", setupHint: false };
  }
  if (status.effective_enabled) {
    if (cigarHelpsPrompts(status)) return { headline: "CIGAR is on", detail: PROMPT_PROMISE, setupHint: false };
    return { headline: "CIGAR is on", detail: NO_FILES_YET, setupHint: true };
  }
  if (cigarWaking(status)) {
    return { headline: "CIGAR is on", detail: "It rests when nothing needs it and wakes up by itself. You do not need to turn it on again.", setupHint: false };
  }
  if (status.restriction && !status.effective_preferences.enabled) {
    return { headline: "CIGAR is off", detail: "Your organization manages CIGAR on this computer.", setupHint: false };
  }
  if (status.requested_enabled) {
    return { headline: "CIGAR is not running", detail: "It is saved as on but has not started. Turn it on to start it.", setupHint: false };
  }
  if (cigarWillHelpPrompts(status)) {
    return { headline: "CIGAR is off", detail: "Turn it on and " + PROMPT_PROMISE.charAt(0).toLowerCase() + PROMPT_PROMISE.slice(1), setupHint: false };
  }
  return { headline: "CIGAR is off", detail: "Turn it on to start CIGAR. " + NO_FILES_YET, setupHint: true };
}
export {
  CIGAR_TABS as C,
  cigarWaking as a,
  canStartCigar as b,
  cigarHomeCopy as c,
  cigarTabFromSearch as d
};
