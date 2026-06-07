/**
 * About page content version.
 * Bump when the content shape changes in a way that tests must validate.
 */
export const ABOUT_CONTENT_VERSION = "1.0.0";

export type AboutSection = {
  id: string;
  heading: string;
  body: string;
};

export type TrustCard = {
  title: string;
  description: string;
};

export type PathCard = {
  title: string;
  description: string;
  ctaLabel: string;
  ctaHref: string;
};

export type PartnerLevel = {
  name: string;
  description: string;
};

export type AffiliateTerms = {
  commissionRate: string;
  commissionDuration: string;
  cookieWindow: string;
  qualificationNote: string;
};
