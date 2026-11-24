"""Ordinary token-handling TypeScript that real sessions could not read.

Application source that issues, signs, verifies or forwards tokens names
credential-like identifiers on almost every line: ``token: z.string()``,
``const token = await signToken(id)``, ``` `${base}/open?token=${token}` ```,
``if (token === expected)``. The post-tool output scan used to stop agents on
that source as if it leaked a secret. Each file here reproduces one such shape
with synthetic names; none holds a credential, a key or a real value.

* a click-tracking redirect route that validates a token and a target;
* a reminder worker that builds links carrying signed tokens;
* an HMAC helper that signs and verifies attribution tokens and names its key
  only through the environment;
* a Python link helper that copies credential fields with a fallback
  (``password=dest.password or self.password)``) and tests them in block
  headers (``if self.password:``);
* a URL helper whose doc comment shows a call with ``{ token: "secret" }``;
* a release script that fills token variables from local tools
  (``GH_TOKEN=$(gh auth token)``) and sets a git credential helper that way.
"""

from __future__ import annotations

PORTAL = "portal"
ROUTE_PATH = f"{PORTAL}/app/api/click/route.ts"
WORKER_PATH = f"{PORTAL}/src/workers/reminder-worker.ts"
HELPER_PATH = f"{PORTAL}/src/lib/attribution-token.ts"
# One line from each file, for the oracles that compare exact bytes.
ROUTE_MARKER = "token: query.get('token') ?? '',"
WORKER_MARKER = "const openUrl = `${baseUrl}/open?token=${signedToken}&scope=reminder`;"
HELPER_MARKER = "const secret = process.env.ATTRIBUTION_TOKEN_SECRET ?? '';"

ROUTE_SOURCE = """\
import { NextResponse } from 'next/server';
import { z } from 'zod';

const querySchema = z.object({
  token: z.string().min(1),
  target: z.string().url(),
});

export async function GET(request: Request) {
  const query = new URL(request.url).searchParams;
  const parsed = querySchema.safeParse({
    token: query.get('token') ?? '',
    target: query.get('target') ?? '',
  });
  if (!parsed.success) {
    return NextResponse.redirect(new URL('/', request.url));
  }
  const token = parsed.data.token;
  await recordClick({ token: token.slice(0, 8), target: parsed.data.target });
  return NextResponse.redirect(parsed.data.target);
}
"""

WORKER_SOURCE = """\
type CreateOpenToken = (params: { userId: string; scope: 'reminder' }) => Promise<string>;

const isCreateOpenToken = (value: unknown): value is CreateOpenToken =>
  typeof value === 'function';

export async function sendReminders(users: User[], baseUrl: string) {
  const createOpenToken = await loadCreateOpenToken();
  for (const user of users) {
    const signedToken = await createOpenToken({
      userId: user.id,
      scope: 'reminder',
    });
    const openUrl = `${baseUrl}/open?token=${signedToken}&scope=reminder`;
    const stopUrl = `${baseUrl}/stop?token=${encodeURIComponent(signedToken)}`;
    await send(user.email, renderReminder({ openUrl, stopUrl }));
  }
}
"""

HELPER_SOURCE = """\
import { createHmac, timingSafeEqual } from 'crypto';

export function signAttributionToken(payload: string): string {
  const secret = process.env.ATTRIBUTION_TOKEN_SECRET ?? '';
  const body = Buffer.from(payload).toString('base64url');
  const signature = createHmac('sha256', secret).update(body).digest('base64url');
  const token = `${body}.${signature}`;
  return token;
}

export function verifyAttributionToken(token: string, expected: string): boolean {
  if (token === expected) {
    return true;
  }
  if (token == null) {
    logger.warn('Attribution token HMAC verification failed', { token: token.slice(0, 20) });
  }
  return timingSafeEqual(Buffer.from(token), Buffer.from(expected));
}
"""

SOURCES = {ROUTE_PATH: ROUTE_SOURCE, WORKER_PATH: WORKER_SOURCE, HELPER_PATH: HELPER_SOURCE}

FALLBACK_PATH = "scripts/links.py"
FALLBACK_SOURCE = """\
from urllib.parse import quote


class Link:
    def __init__(self, scheme, host, username=None, password=None):
        self.scheme = scheme
        self.host = host
        self.username = username
        self.password = password

    def navigate(self, dest):
        return Link(
            scheme=dest.scheme or self.scheme,
            host=dest.host or self.host,
            username=dest.username or self.username,
            password=dest.password or self.password)

    def userinfo(self):
        parts = [quote(self.username or "")]
        if self.password:
            parts.append(quote(self.password))
        return ":".join(parts)


def check_prompt(prompt, output):
    if prompt == "Confirm Password":
        assert "Confirm Password: " in output
"""
FALLBACK_SOURCES = {FALLBACK_PATH: FALLBACK_SOURCE}

EXAMPLE_PATH = f"{PORTAL}/src/lib/with-query.ts"
EXAMPLE_SOURCE = """\
export type QueryObject = Record<string, string | number | undefined>;

/**
 * Adds query parameters to a URL, replacing any that are already set.
 *
 * @example
 * ```js
 * withQuery("/foo?page=a", { token: "secret" }); // "/foo?page=a&token=secret"
 * ```
 */
export function withQuery(input: string, query: QueryObject): string {
  const [path, search = ""] = input.split("?");
  const params = new URLSearchParams(search);
  for (const [key, value] of Object.entries(query)) {
    if (value === undefined) {
      params.delete(key);
    } else {
      params.set(key, String(value));
    }
  }
  const joined = params.toString();
  return joined ? `${path}?${joined}` : path;
}
"""
EXAMPLE_SOURCES = {EXAMPLE_PATH: EXAMPLE_SOURCE}

SCRIPT_PATH = f"{PORTAL}/scripts/open-release-pr.sh"
SCRIPT_SOURCE = """\
#!/usr/bin/env bash
# Opens the weekly release pull request with tokens read from local tools.
set -euo pipefail

export GH_TOKEN=$(gh auth token)
REGISTRY_TOKEN="$(op read op://release/registry/token)"
SIGNING_KEY=$(security find-generic-password -s release-signing -w)
export REGISTRY_TOKEN SIGNING_KEY

git -c "credential.helper=!f() { echo username=release-bot; echo password=\\$(gh auth token); }; f" push origin HEAD
gh pr create --fill --base main
"""
SCRIPT_SOURCES = {SCRIPT_PATH: SCRIPT_SOURCE}
