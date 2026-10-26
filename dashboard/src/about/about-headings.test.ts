import { readFileSync, readdirSync } from "node:fs";
import { resolve } from "node:path";
import { resolveAboutHeroState } from "./components/about-hero";

function assert(condition: boolean, message: string): void {
  if (!condition) {
    throw new Error(message);
  }
}

const dir = import.meta.dirname;
const read = (name: string) => readFileSync(resolve(dir, name), "utf8");

// The hero's title is the page's title. A mono, uppercase line above it reads
// as a second heading competing with the first.
const hero = read("components/about-hero.tsx");
assert(!hero.includes("SectionLabel"), "the hero does not stack a label above its own title");
assert(hero.includes('id="about-hero-heading"'), "the hero title is the hero's label");
assert(!hero.includes('labelledBy="about-hero-heading"'), "the hero surface does not repeat the section's landmark name");

// The runtime summary carries no protection health, so About never claims protection.
const idle = resolveAboutHeroState({
  guardVersion: "1.0.0",
  cloudState: "paired_active",
  cloudStateLabel: "Connected",
  syncConfigured: true,
  syncHealth: "failed",
  pendingCount: 0,
  receiptCount: 0,
  protectedAppCount: 0,
});
assert(idle.tone !== "clear" && !/protect/i.test(idle.badge), "About does not claim protection it cannot see");
assert(idle.facts.includes("Cloud sync stalled"), "each sync state reads as its own fact");

// Every section names itself with a real heading, and the landmark points at
// it, so the page can be navigated by its sections.
const workspace = read("about-workspace.tsx");
const labelled: Array<[string, string]> = [
  ["components/about-hero.tsx", "about-hero-heading"],
  ["components/data-boundary-panel.tsx", "about-data-boundary-heading"],
  ["components/open-standards-map.tsx", "about-open-standards-heading"],
  ["components/pathway-grid.tsx", "about-pathways-heading"],
];
for (const [file, headingId] of labelled) {
  assert(
    read(file).includes(headingId),
    `${file} renders the heading ${headingId} it is labelled by`,
  );
  assert(
    workspace.includes(`labelledBy="${headingId}"`),
    `the ${headingId} section is announced by its own heading`,
  );
}

// Priority is the page author's word for its own ordering, not information a
// reader can act on.
const pathways = read("components/pathway-grid.tsx");
for (const word of ["Primary", "Secondary", "priorityLabel"]) {
  assert(!pathways.includes(`"${word}"`), `the path cards do not label themselves ${word}`);
}

// Muted body text was carrying real sentences at roughly 2.6:1 (slate-400) and
// 4.1:1 (brand-dark/70) on white, under the 4.5:1 floor. brand-dark/75 is the
// lightest tone that clears it; anything lighter is a graphic, not a sentence.
for (const file of readdirSync(resolve(dir, "components"))) {
  const source = read(`components/${file}`);
  assert(!source.includes("text-slate-400"), `${file} keeps body text above the contrast floor`);
  for (const line of source.split("\n")) {
    if (line.includes("size-")) continue; // icon sizing on the same element: a graphic, not body text
    for (const [, tone] of line.matchAll(/text-brand-dark\/(\d+)/g)) {
      assert(
        Number(tone) >= 75,
        `${file} uses text-brand-dark/${tone} for text, below the contrast floor`,
      );
    }
  }
}

console.log("about-headings.test.ts: all assertions passed");
