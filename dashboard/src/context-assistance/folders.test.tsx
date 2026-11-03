import assert from "node:assert/strict";
import { renderToStaticMarkup } from "react-dom/server";
import { AddProjectPanel, proofDetail } from "./add-project-panel";
import type { CigarAllowFiles } from "./allow-files";
import { folderChoiceBlock } from "./folder-picker";
import { ContextWorkspacesPanel } from "./workspaces-panel";
import { folderCrumbs, formatFileSize, type FolderListing } from "./folders-api";

assert.deepEqual(folderCrumbs("/Users/you/code", "/").map((crumb) => crumb.path), ["/", "/Users", "/Users/you", "/Users/you/code"]);
assert.deepEqual(folderCrumbs("\\\\server\\share\\project", "\\").map((crumb) => crumb.path), ["\\\\server\\share\\", "\\\\server\\share\\project"],
  "a network folder keeps its share root so every crumb can be opened");
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

// A project picked here counts for every AI app, so the proof names no app.
const detail = proofDetail({ workspace: "/Users/you/my-app", files: ["README.md"] }, false);
assert.equal(detail, "CIGAR can read 1 file in my-app, plus Guard's own safety facts for that folder, for prompts in every AI app. Nothing else in it is opened.");
assert.match(proofDetail({ workspace: "C:\\code\\site", files: [] }, true), /no files in site.*does not approve any command\.$/);

const props = { busy: false, dirty: false, documentsAllowed: true, executionAllowed: false, gate: null, error: null, onGrant: async () => true };
const idle = renderToStaticMarkup(<AddProjectPanel {...props} first />);
assert.match(idle, /Add your first project/);
assert.match(idle, /Choose a project folder/);
assert.doesNotMatch(idle, /one per line|Context consumer|Workspace folder|relative to the workspace|Which app can use it/i);
assert.match(renderToStaticMarkup(<AddProjectPanel {...props} first={false} dirty />), /Save your preferences first/);
const allow: CigarAllowFiles = { available: true, busy: false, error: null, start: () => undefined, proofOpen: false, cancel: () => undefined, confirm: () => undefined };
assert.match(renderToStaticMarkup(<AddProjectPanel {...props} documentsAllowed={false} allowFiles={allow} first />), /Choose a project folder/,
  "reading files off still lets the person start");


// Saved folders stay on the page while CIGAR rests or starts: shown loading, read-only, never "No projects yet".
const panel = (ready: boolean, waking: boolean) => renderToStaticMarkup(<ContextWorkspacesPanel ready={ready} waking={waking} generation="1" dirty={false}
  documentsAllowed agentsAllowed={false} gate={null} />);
const starting = panel(false, true);
assert.match(starting, /Loading your folders/);
assert.match(starting, /CIGAR is starting\. You can change folders once it is running\./);
assert.doesNotMatch(starting, /No projects yet|Turn on CIGAR to pick/);
assert.doesNotMatch(starting, /Refresh list|Remove all projects/, "nothing changes folders before CIGAR runs");
assert.match(panel(false, false), /Turn on CIGAR to pick project folders\. Folders you already picked come back when it is on\./);
const running = panel(true, false);
assert.match(running, /Loading your folders/);
assert.doesNotMatch(running, /CIGAR is starting/);
assert.match(running, /Refresh list/);
console.log("CIGAR folder picker, file choice and access summary passed.");
