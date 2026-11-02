import assert from "node:assert/strict";
import { renderToStaticMarkup } from "react-dom/server";
import { AddProjectPanel, projectAppOptions, proofDetail } from "./add-project-panel";
import { folderChoiceBlock } from "./folder-picker";
import { folderCrumbs, formatFileSize, type FolderListing } from "./folders-api";

assert.deepEqual(folderCrumbs("/Users/you/code", "/").map((crumb) => crumb.path), ["/", "/Users", "/Users/you", "/Users/you/code"]);
assert.deepEqual(folderCrumbs("C:\\Users\\you", "\\"), [
  { label: "C:", path: "C:\\" }, { label: "Users", path: "C:\\Users" }, { label: "you", path: "C:\\Users\\you" },
]);
assert.equal(formatFileSize(900), "900 B");
assert.equal(formatFileSize(65536), "64 KB");

const listing = (path: string, parent: string | null): FolderListing => ({
  path, parent, name: path, project: false, home: "/Users/you", separator: "/", places: [], roots: [], entries: [], truncated: false,
});
assert.match(folderChoiceBlock(listing("/", null)) ?? "", /top of the drive/);
assert.match(folderChoiceBlock(listing("/Users/you", "/Users")) ?? "", /whole home folder/);
assert.equal(folderChoiceBlock(listing("/Users/you/my-app", "/Users/you")), null);

// The app question disappears when only this page can use the project.
assert.deepEqual(projectAppOptions(false, false).map((option) => option.value), ["dashboard"]);
assert.deepEqual(projectAppOptions(true, true).map((option) => option.value), ["dashboard", "codex", "claude-code", "cursor", "pi", "omp"]);

const detail = proofDetail({ workspace: "/Users/you/my-app", files: ["README.md"], app: "dashboard" }, false, false);
assert.equal(detail, "CIGAR can read 1 file in my-app, plus Guard's own safety facts for that folder. Nothing else in it is opened.");
assert.match(proofDetail({ workspace: "C:\\code\\site", files: [], app: "omp", notes: { read: true, propose: true } }, true, true),
  /no files in site for Oh My Pi.*does not approve any command.*Shared notes: allowed, and it may suggest/);

const props = { busy: false, dirty: false, documentsAllowed: true, agentsAllowed: false, sharingAllowed: false, executionAllowed: false,
  gate: null, error: null, onGrant: async () => true };
const idle = renderToStaticMarkup(<AddProjectPanel {...props} first />);
assert.match(idle, /Add your first project/);
assert.match(idle, /Choose a project folder/);
assert.doesNotMatch(idle, /one per line|Context consumer|Workspace folder|relative to the workspace/i);
assert.match(renderToStaticMarkup(<AddProjectPanel {...props} first={false} dirty />), /Save your preferences first/);

console.log("CIGAR folder picker, file choice and access summary passed.");
