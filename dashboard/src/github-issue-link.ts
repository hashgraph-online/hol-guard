const GITHUB_ISSUE_BASE_URL = "https://github.com/hashgraph-online/hol-guard/issues/new";

const DEFAULT_ISSUE_BODY = [
  "## What happened?",
  "",
  "",
  "## Expected behavior",
  "",
  "",
  "## Steps to reproduce",
  "1.",
  "2.",
  "3.",
  "",
  "## Environment",
  "- HOL Guard version:",
  "- OS:",
  "- AI app or harness:",
  "",
  "## Anything else?",
  "",
].join("\n");

export const GITHUB_ISSUE_BUTTON_LABEL = "Report a bug";

export function buildGitHubIssueUrl(options?: {
  title?: string;
  body?: string;
  labels?: string[];
}): string {
  const url = new URL(GITHUB_ISSUE_BASE_URL);
  url.searchParams.set("title", options?.title ?? "[Bug]: ");
  url.searchParams.set("body", options?.body ?? DEFAULT_ISSUE_BODY);
  url.searchParams.set("labels", (options?.labels ?? ["bug", "needs-triage"]).join(","));
  return url.toString();
}

export const GITHUB_ISSUE_LINK = buildGitHubIssueUrl();
