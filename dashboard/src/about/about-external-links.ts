/**
 * Allowed external links for the About page.
 * All links must use HTTPS. No localhost, loopback, or unknown hosts.
 * Links are validated by stable linkId + href, not just hostname.
 */

import type { AboutLinkId } from "./about-types";
import { ALLOWED_LINKS } from "./about-content";

export class AboutExternalLinkError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "AboutExternalLinkError";
  }
}

function isPrivateHost(rawHostname: string): boolean {
  // Strip IPv6 brackets before checking
  const hostname = rawHostname.startsWith("[") && rawHostname.endsWith("]")
    ? rawHostname.slice(1, -1)
    : rawHostname;

  if (hostname === "localhost" || hostname.startsWith("127.") || hostname === "::1" || hostname === "0.0.0.0") {
    return true;
  }

  // RFC1918 private ranges
  if (hostname.startsWith("10.")) return true;
  if (hostname.startsWith("192.168.")) return true;

  // 172.16.0.0/12
  if (hostname.startsWith("172.")) {
    const secondOctet = parseInt(hostname.split(".")[1] ?? "", 10);
    if (secondOctet >= 16 && secondOctet <= 31) return true;
  }

  // Link-local
  if (hostname === "169.254.0.0" || hostname.startsWith("169.254.")) return true;
  if (hostname.endsWith(".local") || hostname.endsWith(".internal")) return true;

  // IPv6 link-local
  if (hostname.startsWith("fe80:")) return true;

  return false;
}

export function assertSafeAboutExternalUrl(
  linkId: AboutLinkId,
  raw: string
): {
  url: string;
  hostname: string;
  rel: string;
  target: string;
} {
  let parsed: URL;
  try {
    parsed = new URL(raw);
  } catch {
    throw new AboutExternalLinkError(`Invalid URL: ${raw}`);
  }

  if (parsed.protocol === "mailto:") {
    return {
      url: raw,
      hostname: "",
      rel: "",
      target: "",
    };
  }

  if (parsed.protocol !== "https:") {
    throw new AboutExternalLinkError(`URL must use HTTPS: ${raw}`);
  }

  if (parsed.username || parsed.password) {
    throw new AboutExternalLinkError(`URL must not contain credentials: ${raw}`);
  }

  if (isPrivateHost(parsed.hostname)) {
    throw new AboutExternalLinkError(`URL must not point to localhost or private host: ${raw}`);
  }

  const allowed = ALLOWED_LINKS[linkId];
  if (!allowed) {
    throw new AboutExternalLinkError(`Unknown link ID: ${linkId}`);
  }

  if (parsed.hostname !== allowed.host && !parsed.hostname.endsWith(`.${allowed.host}`)) {
    throw new AboutExternalLinkError(
      `Host mismatch for ${linkId}: expected ${allowed.host}, got ${parsed.hostname}`
    );
  }

  if (!parsed.pathname.startsWith(allowed.pathPrefix)) {
    throw new AboutExternalLinkError(
      `Path prefix mismatch for ${linkId}: expected ${allowed.pathPrefix}, got ${parsed.pathname}`
    );
  }

  const forbiddenParams = ["guard-token", "guardDaemon", "workspace", "device", "install", "user", "referral", "ref"];
  for (const param of forbiddenParams) {
    if (parsed.searchParams.has(param)) {
      throw new AboutExternalLinkError(`URL must not contain parameter ${param}: ${raw}`);
    }
  }

  return {
    url: raw,
    hostname: parsed.hostname,
    rel: "noopener noreferrer",
    target: "_blank",
  };
}

export function validateAboutExternalLinkOrThrow(linkId: AboutLinkId, raw: string): void {
  assertSafeAboutExternalUrl(linkId, raw);
}
