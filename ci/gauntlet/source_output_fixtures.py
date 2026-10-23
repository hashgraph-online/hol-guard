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
  only through the environment.
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
