// Per-event protection proof states for one app.
//
// The daemon derives every state from its evidence. This module checks the
// shape and supplies the labels. The labels must match
// tests/fixtures/harness-protection-states.v1.json, which the CLI and the
// native runtime also test against. An unknown or missing state renders as
// "Protection unknown", never as a proven state.

export type ProtectionState =
  | "configured"
  | "transport_ready"
  | "live_block_proven"
  | "live_allow_proven"
  | "observe_only"
  | "partial"
  | "unsupported"
  | "stale";

export type ProtectionTone = "success" | "warning" | "neutral" | "danger";

export type EventProtection = {
  event: string;
  /** Tool names when the contract splits one hook event into rows by tool. */
  tools: string[];
  /** The product surface when one event is published as a row per surface. */
  surface: string | null;
  transport: string | null;
  mode: string | null;
  state: ProtectionState;
  reason: string | null;
};

export const PROTECTION_STATE_COPY: Record<ProtectionState, { label: string; tone: ProtectionTone }> = {
  configured: { label: "Configured, not proven", tone: "warning" },
  transport_ready: { label: "Hook answers, block not proven", tone: "warning" },
  live_block_proven: { label: "Live block proven", tone: "success" },
  live_allow_proven: { label: "Live allow proven, block not proven", tone: "warning" },
  observe_only: { label: "Observe only", tone: "neutral" },
  partial: { label: "Partly proven", tone: "warning" },
  unsupported: { label: "Not supported", tone: "danger" },
  stale: { label: "Evidence out of date", tone: "danger" },
};

export const UNKNOWN_PROTECTION_LABEL = "Protection unknown";

const EVENT_REASON_COPY: Record<string, string> = {
  no_enforceable_boundary: "This app offers no event Guard can stop here.",
  runs_after_execution: "Runs after the action, so it can record but not stop it.",
  no_live_evidence: "No live run has proven a block on this event yet.",
  version_not_in_evidence: "This exact app version has no live evidence.",
  observation_stale: "The last version check is out of date.",
  no_evidence_for_this_build: "No live evidence for this Guard release on this platform.",
};

function isState(value: unknown): value is ProtectionState {
  return typeof value === "string" && Object.prototype.hasOwnProperty.call(PROTECTION_STATE_COPY, value);
}

function optionalText(value: unknown): string | null {
  return typeof value === "string" && value.length > 0 ? value : null;
}

export function normalizeProtectionState(value: unknown): ProtectionState | null {
  return isState(value) ? value : null;
}

/** Entries with an unknown state or no event name are dropped. */
export function normalizeEventStates(value: unknown): EventProtection[] {
  if (!Array.isArray(value)) return [];
  return value.flatMap((item) => {
    if (typeof item !== "object" || item === null) return [];
    const entry = item as Record<string, unknown>;
    const event = optionalText(entry.event);
    if (!event || !isState(entry.state)) return [];
    const tools = Array.isArray(entry.tools)
      ? entry.tools.filter((tool): tool is string => typeof tool === "string" && tool.length > 0)
      : [];
    return [{
      event,
      tools,
      surface: optionalText(entry.surface),
      transport: optionalText(entry.transport),
      mode: optionalText(entry.mode),
      state: entry.state,
      reason: optionalText(entry.reason),
    }];
  });
}

/** The event name, with its tools or surface when the event is split by either. */
export function eventProtectionName(item: EventProtection): string {
  const name = item.tools.length > 0 ? `${item.event} [${item.tools.join(", ")}]` : item.event;
  return item.surface ? `${name} · ${item.surface}` : name;
}

export function protectionStateLabel(state: ProtectionState | null): string {
  return state ? PROTECTION_STATE_COPY[state].label : UNKNOWN_PROTECTION_LABEL;
}

export function protectionStateTone(state: ProtectionState | null): ProtectionTone {
  return state ? PROTECTION_STATE_COPY[state].tone : "warning";
}

export function eventReasonCopy(reason: string | null): string | null {
  return reason ? EVENT_REASON_COPY[reason] ?? null : null;
}
