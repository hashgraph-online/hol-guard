import { fetchReleaseFeedApi } from "../guard-api";
import type { ReleaseDetail, ReleaseFeedFailure, ReleaseIndex } from "./releases-types";

/**
 * Release archive reads. The daemon is the transport and the native runtime is
 * the parser: by the time a body reaches here it has already been projected
 * field by field, so this module only decides what a status code means for the
 * screen and refuses a body that is not the document it asked for.
 */

export type ReleaseIndexResult =
  | { status: "ok"; index: ReleaseIndex }
  | { status: "failed"; failure: ReleaseFeedFailure };

export type ReleaseDetailResult =
  | { status: "ok"; detail: ReleaseDetail }
  | { status: "failed"; failure: ReleaseFeedFailure };

/**
 * One screen of history. hol.org serves at most 20 releases per public page and
 * clamps a larger ask without saying so, so ask for exactly what it will send.
 * Everything downstream reads the page size off the answer, not off this number.
 */
export const RELEASES_PAGE_SIZE = 20;

/** The daemon's answer when the archive is switched off on this device. */
const CAPABILITY_UNAVAILABLE = "release_feed_capability_unavailable";

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

async function errorCode(response: Response): Promise<string | null> {
  try {
    const payload: unknown = await response.json();
    return isRecord(payload) && typeof payload.error === "string" ? payload.error : null;
  } catch {
    return null;
  }
}

async function failureForResponse(response: Response): Promise<ReleaseFeedFailure> {
  if (response.status === 404) return "not-found";
  if (response.status === 501) return "unsupported";
  // A 503 carries two different answers: the archive switched off on this
  // device, and an upstream read that failed. Only one of them is hol.org's
  // doing, and only one of them is worth retrying.
  if (response.status === 503 && (await errorCode(response)) === CAPABILITY_UNAVAILABLE) {
    return "disabled";
  }
  return "unavailable";
}

async function readDocument(
  path: string,
  kind: "index" | "detail",
  signal?: AbortSignal,
): Promise<{ status: "ok"; document: Record<string, unknown> } | { status: "failed"; failure: ReleaseFeedFailure }> {
  let response: Response;
  try {
    response = await fetchReleaseFeedApi(path, { signal, redirect: "error" });
  } catch {
    // No answer at all: the daemon is down or the browser could not reach it.
    return { status: "failed", failure: "offline" };
  }
  if (!response.ok) {
    return { status: "failed", failure: await failureForResponse(response) };
  }
  let payload: unknown;
  try {
    payload = await response.json();
  } catch {
    return { status: "failed", failure: "unavailable" };
  }
  if (!isRecord(payload) || payload.kind !== kind) {
    return { status: "failed", failure: "unavailable" };
  }
  return { status: "ok", document: payload };
}

export async function fetchReleaseIndex(
  options: { page?: number; signal?: AbortSignal } = {},
): Promise<ReleaseIndexResult> {
  const page = Number.isInteger(options.page) && (options.page as number) >= 1 ? (options.page as number) : 1;
  const result = await readDocument(
    `/v1/releases/index?page=${page}&pageSize=${RELEASES_PAGE_SIZE}`,
    "index",
    options.signal,
  );
  if (result.status === "failed") {
    return result;
  }
  return { status: "ok", index: result.document as unknown as ReleaseIndex };
}

export async function fetchReleaseDetail(
  slug: string,
  options: { signal?: AbortSignal } = {},
): Promise<ReleaseDetailResult> {
  // A slug is a minted key, never a path; the daemon rejects anything else and
  // so does this, so a bad one never becomes a request.
  if (!/^[a-z0-9][a-z0-9.-]{0,127}$/.test(slug)) {
    return { status: "failed", failure: "not-found" };
  }
  const result = await readDocument(`/v1/releases/release?slug=${slug}`, "detail", options.signal);
  if (result.status === "failed") {
    return result;
  }
  return { status: "ok", detail: result.document as unknown as ReleaseDetail };
}
