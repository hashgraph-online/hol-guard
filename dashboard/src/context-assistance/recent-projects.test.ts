import assert from "node:assert/strict";
import { renderToStaticMarkup } from "react-dom/server";
import { createElement } from "react";
import { RecentProjects } from "./add-project-panel";
import { forgetProject, keptFiles, MAX_RECENT_PROJECTS, readRecentProjects, RECENT_PROJECTS_KEY, rememberProject } from "./recent-projects";

const memory = () => {
  const values = new Map<string, string>();
  return { getItem: (key: string) => values.get(key) ?? null, setItem: (key: string, value: string) => void values.set(key, value), values };
};

const store = memory();
assert.deepEqual(readRecentProjects(store), [], "nothing remembered yet");
rememberProject({ workspace: "/code/app", files: ["README.md"], app: "codex" }, store);
rememberProject({ workspace: "/code/site", files: [], app: "dashboard" }, store);
rememberProject({ workspace: "/code/app", files: ["README.md", "AGENTS.md"], app: "codex" }, store);
assert.deepEqual(readRecentProjects(store).map((row) => [row.workspace, row.files.length]), [["/code/app", 2], ["/code/site", 0]],
  "adding a project again moves it to the top with its latest files");
for (let index = 0; index < 6; index += 1) rememberProject({ workspace: `/code/p${index}`, files: [], app: "dashboard" }, store);
assert.equal(readRecentProjects(store).length, MAX_RECENT_PROJECTS);
assert.deepEqual(forgetProject("/code/p5", store).map((row) => row.workspace), ["/code/p4", "/code/p3", "/code/p2"]);

const broken = memory();
for (const raw of ["not json", "{}", JSON.stringify([{ workspace: "", files: [], app: "x" }, { workspace: "/a", files: [7], app: "x" }, { workspace: "/b", app: "x" }])]) {
  broken.values.set(RECENT_PROJECTS_KEY, raw);
  assert.deepEqual(readRecentProjects(broken), [], raw);
}
const blocked = { getItem: () => { throw new Error("blocked"); }, setItem: () => { throw new Error("blocked"); } };
assert.deepEqual(rememberProject({ workspace: "/a", files: [], app: "dashboard" }, blocked).map((row) => row.workspace), ["/a"],
  "a blocked browser store never breaks adding a project");
assert.deepEqual(readRecentProjects(null), []);

assert.deepEqual(keptFiles(["README.md", "gone.md", "big.md", "docs/plan.md", "src/notes.md"], {
  files: [{ name: "README.md", relative: "README.md", size: 9, available: true, reason: null }, { name: "big.md", relative: "big.md", size: 1e6, available: false, reason: "too_large" }],
  suggested: [{ relative: "docs/plan.md", size: 4 }],
}), ["README.md", "docs/plan.md", "src/notes.md"], "files that vanished or can no longer be read are dropped");

const html = renderToStaticMarkup(createElement(RecentProjects, {
  projects: [{ workspace: "/code/app", files: ["README.md"], app: "codex" }, { workspace: "C:\\code\\site", files: [], app: "dashboard" }],
  onReuse: () => {}, onForget: () => {},
}));
assert.match(html, /Recent projects/);
assert.match(html, /app<\/span>.*1 file · for Codex/);
assert.match(html, /site<\/span>.*0 files · for this page/);
assert.match(html, /aria-label="Remove app from this list"/);
console.log("recent projects ok");
