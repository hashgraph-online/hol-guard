/**
 * One authored, actionable message per connector-discovery failure.
 *
 * The Extensions page used to answer every failed host scan with the same
 * sentence, so a reader could not tell a busy daemon from an unreadable
 * harness config, and the error object was dropped before anyone could see
 * which one fired. Discovery now carries its code to the banner, and this
 * module turns that code into a next action the reader can actually take.
 *
 * Only messages Guard authored reach the banner: a `DiscoveryFailure` this
 * repository wrote, or a daemon reply whose code is one Guard sends. Anything
 * else - a dropped connection, a proxy's HTML error page - falls back, so no
 * foreign text is rendered as guidance.
 */

export class DiscoveryFailure extends Error {
  readonly code: string;
  constructor(code: string, message: string) {
    super(message);
    this.name = "DiscoveryFailure";
    this.code = code;
  }
}

/**
 * Replies the local-CLI routes fall back to. They name custom extensions,
 * which is the wrong surface for a host scan, so they are replaced here.
 */
const GENERIC_API_MESSAGES = new Set([
  "Guard could not update this custom extension.",
  "Guard could not load custom extensions.",
]);

export const CONFIGURED_CONNECTIONS_FALLBACK =
  "Guard could not check host configuration. Known connections remain available. "
  + "Choose Check for connectors again; if that keeps failing, restart Guard.";

export const CODEX_HOST_FALLBACK =
  "Guard could not read the Codex app inventory. Known connections remain available. "
  + "Choose Check for connectors again; if that keeps failing, reopen the Codex app.";

/**
 * Codes the daemon answers `/v1/local-clis/refresh-job` with before a job
 * exists, plus the two service-level replies that carry no discovery wording.
 */
const START_FAILURE_MESSAGES: Record<string, string> = {
  discovery_busy: "Guard is already refreshing other connections. Wait a few seconds, then choose Check for connectors again.",
  discovery_retry_backoff: "The last connector scan failed. Wait ten seconds, then choose Check for connectors again.",
  discovery_unavailable: "Guard is shutting down, so it cannot scan for connectors. Reopen Guard, then check again.",
  discovery_job_unavailable: "This connector scan expired. Choose Check for connectors again to start a new one.",
  discovery_job_id_conflict: "Another connector scan is already running under this identity. Wait a few seconds, then check again.",
  invalid_discovery_job: "Guard could not track this connector scan. Reload this page, then check again.",
  local_cli_unavailable: "Guard's extension service is not answering, so host connections could not be read. Restart Guard, then check again.",
  local_cli_request_failed: "Guard's connector scan returned no result. Reload this page, then choose Check for connectors again.",
};

/**
 * Codes whose daemon-authored message is Guard's own wording for a surface
 * this module has none for. `readJson` builds `LocalCliApiError` out of the
 * response body, so any other code's message is untrusted text and must not
 * render as guidance.
 */
const TRUSTED_MESSAGE_CODES = new Set(["session_expired"]);

function errorCode(error: unknown): string {
  const code = (error as { code?: unknown } | null | undefined)?.code;
  return typeof code === "string" ? code : "";
}

/** The authored guidance for a failed discovery, or `fallback` when Guard wrote none. */
export function discoveryFailureMessage(error: unknown, fallback: string): string {
  if (error instanceof DiscoveryFailure) return error.message;
  const code = errorCode(error);
  if (!code) return fallback;
  // An own-key lookup only: an inherited key such as `__proto__` is not a
  // message Guard wrote, and reading one would put a function in the banner.
  if (Object.prototype.hasOwnProperty.call(START_FAILURE_MESSAGES, code)) {
    const authored = START_FAILURE_MESSAGES[code];
    if (typeof authored === "string" && authored) return authored;
  }
  if (!TRUSTED_MESSAGE_CODES.has(code)) return fallback;
  // A daemon reply Guard authored for this code (a 401 session message, for
  // example) is better than a generic banner; its own fallbacks are not.
  const message = error instanceof Error ? error.message.trim() : "";
  return message && !GENERIC_API_MESSAGES.has(message) ? message : fallback;
}
