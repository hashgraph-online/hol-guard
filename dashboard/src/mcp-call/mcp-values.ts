import type { McpValueKind } from "./mcp-call-types";

const EMAIL = /^[^\s@<>,;]+@[^\s@<>,;]+\.[^\s@<>,;]+$/;
const LONG_TEXT_CHARS = 120;
const MAX_ADDRESSES = 12;

/** The addresses in `to@x.com, cc@y.com`, or null when any part is not an address. */
export function emailAddresses(value: string): string[] | null {
  const parts = value
    .split(/[,;]/)
    .map((part) => part.trim())
    .filter((part) => part.length > 0);
  if (parts.length === 0 || parts.length > MAX_ADDRESSES) return null;
  return parts.every((part) => EMAIL.test(part)) ? parts : null;
}

/** A web address split so the host and port, the part that says where it goes, can stand out. Null for anything else. */
export function linkParts(value: string): { host: string; rest: string } | null {
  if (!/^https?:\/\//i.test(value) || /\s/.test(value)) return null;
  try {
    const url = new URL(value);
    if (url.hostname.length === 0) return null;
    const rest = `${url.pathname === "/" ? "" : url.pathname}${url.search}${url.hash}`;
    // `host` keeps a non-default port: the port says which service answers.
    return { host: url.host, rest };
  } catch {
    return null;
  }
}

/** Reads a value's shape. Only the text itself is looked at, never what the agent says it is. */
export function valueKindOf(value: string): McpValueKind {
  if (emailAddresses(value) !== null) return "email";
  if (linkParts(value) !== null) return "url";
  if (value.length > LONG_TEXT_CHARS || value.includes("\n")) return "long";
  return "text";
}
