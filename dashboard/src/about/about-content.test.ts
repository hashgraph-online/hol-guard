import {
  ABOUT_HERO_TITLE,
  ABOUT_HERO_BODY,
  ABOUT_HERO_KICKER,
  ABOUT_LOCAL_SECTION_TITLE,
  ABOUT_LOCAL_SECTION_BODY,
  ABOUT_MISSION_SECTION_TITLE,
  ABOUT_MISSION_SECTION_BODY,
  ABOUT_OPEN_SOURCE_NOTE,
  ABOUT_PARTNER_SECTION_TITLE,
  ABOUT_PARTNER_SECTION_BODY,
  ABOUT_PARTNER_CTA,
  ABOUT_PARTNER_CTA_HREF,
  ABOUT_AFFILIATE_SECTION_TITLE,
  ABOUT_AFFILIATE_SECTION_BODY,
  ABOUT_AFFILIATE_CTA,
  ABOUT_AFFILIATE_CTA_HREF,
  ABOUT_AFFILIATE_DISCLOSURE,
  ABOUT_TRUST_CONTRACT_CLAIMS,
  ABOUT_DATA_BOUNDARY_ROWS,
  ABOUT_STANDARDS_NODES,
  ABOUT_PATH_CARDS,
  ABOUT_PARTNER_LEVELS,
  ABOUT_AFFILIATE_TERMS,
  ALLOWED_LINKS,
} from "./about-content";

function assert(condition: boolean, message: string): void {
  if (!condition) {
    throw new Error(message);
  }
}

function assertNoBannedPhrases(text: string, sourceLabel: string): void {
  const banned = [
    "score a recurring commission",
    "tamper-evident",
    "guaranteed",
    "unbreakable",
    "always secure",
    "cloud required",
  ];
  for (const phrase of banned) {
    assert(
      !text.toLowerCase().includes(phrase),
      `${sourceLabel} avoids banned phrase: ${phrase}`
    );
  }
}

function collectAllCopy(): string {
  const parts = [
    ABOUT_HERO_TITLE,
    ABOUT_HERO_BODY,
    ABOUT_HERO_KICKER,
    ABOUT_LOCAL_SECTION_TITLE,
    ABOUT_LOCAL_SECTION_BODY,
    ABOUT_MISSION_SECTION_TITLE,
    ABOUT_MISSION_SECTION_BODY,
    ABOUT_OPEN_SOURCE_NOTE,
    ABOUT_PARTNER_SECTION_TITLE,
    ABOUT_PARTNER_SECTION_BODY,
    ABOUT_PARTNER_CTA,
    ABOUT_AFFILIATE_SECTION_TITLE,
    ABOUT_AFFILIATE_SECTION_BODY,
    ABOUT_AFFILIATE_CTA,
    ABOUT_AFFILIATE_DISCLOSURE,
    ...ABOUT_TRUST_CONTRACT_CLAIMS.flatMap((c) => [c.title, c.body]),
    ...ABOUT_DATA_BOUNDARY_ROWS.flatMap((r) => [r.label, r.localDefault, r.optionalSync, r.neverFromAbout]),
    ...ABOUT_STANDARDS_NODES.flatMap((n) => [n.label, n.body]),
    ...ABOUT_PATH_CARDS.flatMap((c) => [c.title, c.description, c.ctaLabel]),
    ...ABOUT_PARTNER_LEVELS.flatMap((l) => [l.name, l.description]),
    ABOUT_AFFILIATE_TERMS.commissionRate,
    ABOUT_AFFILIATE_TERMS.commissionDuration,
    ABOUT_AFFILIATE_TERMS.cookieWindow,
    ABOUT_AFFILIATE_TERMS.qualificationNote,
  ];
  return parts.join(" ");
}

// Hero content
assert(ABOUT_HERO_TITLE.length > 0, "hero title is non-empty");
assert(ABOUT_HERO_BODY.length > 0, "hero body is non-empty");
assert(ABOUT_HERO_KICKER.length > 0, "hero kicker is non-empty");
assert(!ABOUT_HERO_BODY.includes("earn"), "hero body avoids earn language");

// Local-first section
assert(ABOUT_LOCAL_SECTION_TITLE.length > 0, "local section title is non-empty");
assert(ABOUT_LOCAL_SECTION_BODY.length > 0, "local section body is non-empty");

// Mission section
assert(ABOUT_MISSION_SECTION_TITLE.length > 0, "mission title is non-empty");
assert(ABOUT_MISSION_SECTION_BODY.length > 0, "mission body is non-empty");
assert(!ABOUT_MISSION_SECTION_BODY.includes("earn"), "mission body avoids earn language");

// Open source note
assert(ABOUT_OPEN_SOURCE_NOTE.length > 0, "open source note is non-empty");

// Partner section
assert(ABOUT_PARTNER_SECTION_TITLE.length > 0, "partner title is non-empty");
assert(ABOUT_PARTNER_SECTION_BODY.length > 0, "partner body is non-empty");
assert(ABOUT_PARTNER_CTA.length > 0, "partner CTA label is non-empty");
assert(
  ABOUT_PARTNER_CTA_HREF.startsWith("https://") || ABOUT_PARTNER_CTA_HREF.startsWith("mailto:"),
  "partner CTA uses HTTPS or mailto"
);
assert(!ABOUT_PARTNER_CTA_HREF.includes("guard-token"), "partner CTA has no guard-token");

// Affiliate section
assert(ABOUT_AFFILIATE_SECTION_TITLE.length > 0, "affiliate title is non-empty");
assert(ABOUT_AFFILIATE_SECTION_BODY.length > 0, "affiliate body is non-empty");
assert(ABOUT_AFFILIATE_CTA.length > 0, "affiliate CTA label is non-empty");
assert(ABOUT_AFFILIATE_CTA_HREF.startsWith("https://"), "affiliate CTA uses HTTPS");
assert(!ABOUT_AFFILIATE_CTA_HREF.includes("guard-token"), "affiliate CTA has no guard-token");
assert(ABOUT_AFFILIATE_DISCLOSURE.length > 0, "affiliate disclosure is non-empty");

// Trust contract claims
assert(ABOUT_TRUST_CONTRACT_CLAIMS.length === 4, "trust contract claims has exactly 4 items");
for (const claim of ABOUT_TRUST_CONTRACT_CLAIMS) {
  assert(claim.title.length > 0, "trust claim title is non-empty");
  assert(claim.body.length > 0, "trust claim body is non-empty");
  assert(claim.proofLabel.length > 0, "trust claim proofLabel is non-empty");
}

// Data boundary rows
assert(ABOUT_DATA_BOUNDARY_ROWS.length === 4, "data boundary rows has exactly 4 items");
for (const row of ABOUT_DATA_BOUNDARY_ROWS) {
  assert(row.label.length > 0, "data boundary label is non-empty");
  assert(row.localDefault.length > 0, "data boundary localDefault is non-empty");
  assert(row.optionalSync.length > 0, "data boundary optionalSync is non-empty");
  assert(row.neverFromAbout.length > 0, "data boundary neverFromAbout is non-empty");
}

// Standards nodes
assert(ABOUT_STANDARDS_NODES.length === 6, "standards nodes has exactly 6 items");
for (const node of ABOUT_STANDARDS_NODES) {
  assert(node.label.length > 0, "standards node label is non-empty");
  assert(node.body.length > 0, "standards node body is non-empty");
}

// Path cards
assert(ABOUT_PATH_CARDS.length === 5, "path cards has exactly 5 items");
const primaryPaths = ABOUT_PATH_CARDS.filter((c) => c.priority === "primary");
const secondaryPaths = ABOUT_PATH_CARDS.filter((c) => c.priority === "secondary");
const tertiaryPaths = ABOUT_PATH_CARDS.filter((c) => c.priority === "tertiary");
assert(primaryPaths.length === 1, "has exactly 1 primary path");
assert(primaryPaths[0].id === "protect_locally", "primary path is protect_locally");
assert(secondaryPaths.length === 2, "has exactly 2 secondary paths");
assert(tertiaryPaths.length === 2, "has exactly 2 tertiary paths");
assert(tertiaryPaths.some((c) => c.id === "affiliate_starter_kit"), "affiliate is tertiary");
assert(tertiaryPaths.some((c) => c.id === "standards_partner"), "partner is tertiary");

for (const card of ABOUT_PATH_CARDS) {
  assert(card.title.length > 0, "path card title is non-empty");
  assert(card.description.length > 0, "path card description is non-empty");
  assert(card.ctaLabel.length > 0, "path card CTA label is non-empty");
  assert(card.ctaHref.startsWith("https://"), "path card CTA uses HTTPS");
  assert(!card.ctaHref.includes("guard-token"), "path card CTA has no guard-token");
}

// Partner levels
assert(ABOUT_PARTNER_LEVELS.length === 3, "partner levels has exactly 3 items");
for (const level of ABOUT_PARTNER_LEVELS) {
  assert(level.name.length > 0, "partner level name is non-empty");
  assert(level.description.length > 0, "partner level description is non-empty");
}

// Affiliate terms
assert(ABOUT_AFFILIATE_TERMS.commissionRate.length > 0, "commission rate is non-empty");
assert(ABOUT_AFFILIATE_TERMS.commissionDuration.length > 0, "commission duration is non-empty");
assert(ABOUT_AFFILIATE_TERMS.cookieWindow.length > 0, "cookie window is non-empty");
assert(ABOUT_AFFILIATE_TERMS.qualificationNote.length > 0, "qualification note is non-empty");

// Allowed links
assert(Object.keys(ALLOWED_LINKS).length >= 10, "has at least 10 allowed link definitions");
for (const [id, cfg] of Object.entries(ALLOWED_LINKS)) {
  assert(cfg.host.length > 0, `${id} has a host`);
  assert(cfg.pathPrefix.length > 0, `${id} has a pathPrefix`);
  assert(cfg.pathPrefix.startsWith("/"), `${id} pathPrefix starts with /`);
}

// Banned phrases across all copy
assertNoBannedPhrases(collectAllCopy(), "all about copy");

// Affiliate copy is honest - test checks for these exact words
assert(
  ABOUT_AFFILIATE_SECTION_BODY.toLowerCase().includes("approved affiliates"),
  "affiliate body mentions approval requirement"
);
assert(
  ABOUT_AFFILIATE_SECTION_BODY.toLowerCase().includes("qualified paid"),
  "affiliate body mentions qualified paid referrals"
);

console.log("about-content.test.ts: all assertions passed");
