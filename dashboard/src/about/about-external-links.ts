/**
 * Allowed external hosts for the About page.
 * All links must use HTTPS. No localhost, loopback, or unknown hosts.
 */
const ALLOWED_HOSTS = new Set([
  "hol.org",
  "www.hol.org",
  "github.com",
  "x.com",
  "t.me",
]);

export class AboutExternalLinkError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "AboutExternalLinkError";
  }
}

function isLocalhost(hostname: string): boolean {
  return (
    hostname === "localhost" ||
    hostname === "127.0.0.1" ||
    hostname === "[::1]" ||
    hostname === "::1" ||
    hostname.startsWith("192.168.") ||
    hostname.startsWith("10.") ||
    hostname.startsWith("172.") ||
    hostname.endsWith(".local") ||
    hostname.endsWith(".internal")
  );
}

export function assertSafeAboutExternalUrl(raw: string): {
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

  if (isLocalhost(parsed.hostname)) {
    throw new AboutExternalLinkError(`URL must not point to localhost or loopback: ${raw}`);
  }

  if (!ALLOWED_HOSTS.has(parsed.hostname)) {
    throw new AboutExternalLinkError(`Unknown host not in allowlist: ${parsed.hostname}`);
  }

  const forbiddenParams = ["guard-token", "guardDaemon", "workspace", "device", "install", "user"];
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

export function validateAboutExternalLinkOrThrow(raw: string): void {
  assertSafeAboutExternalUrl(raw);
}
