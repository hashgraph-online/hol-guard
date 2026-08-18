export function canonicalizeGuardDaemonOrigin(rawUrl: string): string | null {
  try {
    const rawOrigin = rawUrl.trim();
    const url = new URL(rawOrigin);
    if (url.protocol !== "http:" || !["127.0.0.1", "[::1]"].includes(url.hostname)) {
      return null;
    }
    if (
      url.username ||
      url.password ||
      (url.pathname && url.pathname !== "/") ||
      url.search ||
      url.hash ||
      !url.port
    ) {
      return null;
    }
    const port = Number(url.port);
    if (!Number.isInteger(port) || port < 1 || port > 65_535) {
      return null;
    }
    const canonicalHost = url.hostname === "[::1]" ? "[::1]" : "127.0.0.1";
    const canonical = `http://${canonicalHost}:${port}`;
    return url.origin === canonical && (rawOrigin === canonical || rawOrigin === `${canonical}/`) ? canonical : null;
  } catch {
    return null;
  }
}

export function standardGuardDaemonOrigin(
  rawUrl: string,
  firstPort: number,
  portCount: number,
): string | null {
  const origin = canonicalizeGuardDaemonOrigin(rawUrl);
  if (!origin) return null;
  const port = Number(new URL(origin).port);
  return port >= firstPort && port < firstPort + portCount ? origin : null;
}
