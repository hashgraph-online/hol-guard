import {
  GITHUB_ISSUE_BUTTON_LABEL,
  GITHUB_ISSUE_LINK,
  buildGitHubIssueUrl,
} from "./github-issue-link";

function assert(condition: boolean, message: string): void {
  if (!condition) {
    throw new Error(message);
  }
}

const url = new URL(GITHUB_ISSUE_LINK);

assert(GITHUB_ISSUE_BUTTON_LABEL === "Report a bug", "button label is direct");
assert(url.origin === "https://github.com", "issue URL opens GitHub");
assert(url.pathname === "/hashgraph-online/hol-guard/issues/new", "issue URL opens a new HOL Guard issue");
assert(url.searchParams.get("labels") === "bug,needs-triage", "issue URL applies triage labels");
assert(url.searchParams.get("title") === "[Bug]: ", "issue URL pre-fills a bug title prefix");

const body = url.searchParams.get("body") ?? "";
assert(body.includes("## What happened?"), "issue body asks what happened");
assert(body.includes("## Expected behavior"), "issue body asks what should happen");
assert(body.includes("## Steps to reproduce"), "issue body asks for reproduction steps");
assert(body.includes("## Environment"), "issue body asks for environment");
assert(!body.includes("guard-token"), "issue body does not request Guard tokens");

const customUrl = new URL(buildGitHubIssueUrl({ title: "Crash on approvals", labels: ["bug"] }));

assert(customUrl.searchParams.get("title") === "Crash on approvals", "custom issue URL accepts a title");
assert(customUrl.searchParams.get("labels") === "bug", "custom issue URL accepts labels");

console.log("github-issue-link.test.ts: all assertions passed");
