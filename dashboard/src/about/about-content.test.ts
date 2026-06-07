import {
  ABOUT_HERO_TITLE,
  ABOUT_HERO_SUBTITLE,
  ABOUT_HERO_BODY,
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
  ABOUT_TRUST_CARDS,
  ABOUT_PATH_CARDS,
  ABOUT_PARTNER_LEVELS,
  ABOUT_AFFILIATE_TERMS,
} from "./about-content";

function assert(condition: boolean, message: string): void {
  if (!condition) {
    throw new Error(message);
  }
}

// Hero content
assert(ABOUT_HERO_TITLE.length > 0, "hero title is non-empty");
assert(ABOUT_HERO_SUBTITLE.length > 0, "hero subtitle is non-empty");
assert(ABOUT_HERO_BODY.length > 0, "hero body is non-empty");
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
assert(ABOUT_PARTNER_CTA_HREF.startsWith("https://"), "partner CTA uses HTTPS");
assert(!ABOUT_PARTNER_CTA_HREF.includes("guard-token"), "partner CTA has no guard-token");

// Affiliate section
assert(ABOUT_AFFILIATE_SECTION_TITLE.length > 0, "affiliate title is non-empty");
assert(ABOUT_AFFILIATE_SECTION_BODY.length > 0, "affiliate body is non-empty");
assert(ABOUT_AFFILIATE_CTA.length > 0, "affiliate CTA label is non-empty");
assert(ABOUT_AFFILIATE_CTA_HREF.startsWith("https://"), "affiliate CTA uses HTTPS");
assert(!ABOUT_AFFILIATE_CTA_HREF.includes("guard-token"), "affiliate CTA has no guard-token");
assert(ABOUT_AFFILIATE_DISCLOSURE.length > 0, "affiliate disclosure is non-empty");

// Trust cards
assert(ABOUT_TRUST_CARDS.length === 4, "trust cards has exactly 4 items");
for (const card of ABOUT_TRUST_CARDS) {
  assert(card.title.length > 0, "trust card title is non-empty");
  assert(card.description.length > 0, "trust card description is non-empty");
}

// Path cards
assert(ABOUT_PATH_CARDS.length === 5, "path cards has exactly 5 items");
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

console.log("about-content.test.ts: all assertions passed");
