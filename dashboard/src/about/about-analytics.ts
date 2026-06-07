/**
 * About page analytics stub.
 * No remote tracking in the local dashboard.
 * All events are console-only in development.
 */

export type AboutEvent =
  | { type: "about_page_viewed" }
  | { type: "about_section_viewed"; sectionId: string }
  | { type: "about_external_link_clicked"; href: string }
  | { type: "about_cta_clicked"; ctaId: string };

export function trackAboutEvent(event: AboutEvent): void {
  if (import.meta.env.DEV) {
    // eslint-disable-next-line no-console
    console.debug("[about]", event);
  }
}
