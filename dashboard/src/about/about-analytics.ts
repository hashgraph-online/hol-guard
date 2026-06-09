/**
 * About page analytics stub.
 * No remote tracking in the local dashboard.
 * All events use stable IDs only — never raw URLs, paths, or sensitive data.
 */

import type { AboutSectionId, AboutLinkId, AboutCtaId } from "./about-types";

export type AboutEvent =
  | { type: "about_page_viewed" }
  | { type: "about_section_viewed"; sectionId: AboutSectionId }
  | { type: "about_external_link_clicked"; linkId: AboutLinkId }
  | { type: "about_cta_clicked"; ctaId: AboutCtaId };

export function trackAboutEvent(event: AboutEvent): void {
  if (import.meta.env.DEV) {
    // eslint-disable-next-line no-console
    console.debug("[about]", event);
  }
}
