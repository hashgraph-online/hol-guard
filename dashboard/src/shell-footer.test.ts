import {
  GITHUB_ISSUE_BUTTON_LABEL,
  GITHUB_ISSUE_LINK,
} from "./github-issue-link";
import { SHELL_FOOTER_LICENSE_HREF, SHELL_FOOTER_RESOURCE_LINKS } from "./shell-footer";

function assert(condition: boolean, message: string): void {
  if (!condition) {
    throw new Error(message);
  }
}

assert(
  SHELL_FOOTER_LICENSE_HREF.endsWith("/hol-guard/blob/main/LICENSE"),
  "footer license link points at the repository LICENSE file"
);

assert(
  SHELL_FOOTER_RESOURCE_LINKS.length >= 4,
  "footer keeps a compact set of resource links for the workspace shell"
);

const labels = SHELL_FOOTER_RESOURCE_LINKS.map((link) => link.label);

assert(labels.includes("Docs"), "footer includes Docs");
assert(labels.includes("Guard Cloud"), "footer includes Guard Cloud");
assert(labels.includes("GitHub"), "footer includes GitHub");
assert(labels.includes(GITHUB_ISSUE_BUTTON_LABEL), "footer includes report bug link");
assert(!labels.includes("Privacy"), "footer does not include Privacy link");
assert(!labels.includes("Terms"), "footer does not include Terms link");

const bugLink = SHELL_FOOTER_RESOURCE_LINKS.find((link) => link.href === GITHUB_ISSUE_LINK);
assert(bugLink !== undefined, "footer bug link uses the shared GitHub issue URL");

const hrefs = new Set(SHELL_FOOTER_RESOURCE_LINKS.map((link) => link.href));
assert(hrefs.size === SHELL_FOOTER_RESOURCE_LINKS.length, "footer links are unique by href");

const labelSet = new Set(labels);
assert(labelSet.size === SHELL_FOOTER_RESOURCE_LINKS.length, "footer links are unique by label");

console.log("shell-footer.test.ts: all tests passed");
