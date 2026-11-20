import type { ReactNode } from "react";
import type { AboutRuntimeSummary } from "../about-types";
import { formatAboutCount } from "../about-format";

/**
 * Fig. 1 — this device, drawn as a labeled system diagram.
 *
 * The page's claims about where data lives are only worth something if the
 * reader can see the boundary they describe. The diagram draws that boundary:
 * the agents, Guard and the stored records sit inside it, the sync gate sits on
 * its edge carrying this install's real sync state, and Guard Cloud and hol.org
 * are outside. The numbered callouts point at the Trust Contract claims below.
 */

type SyncState = "on" | "stalled" | "pairing" | "off" | "unavailable";

/**
 * What the figure may claim about sync. Unknown states claim nothing.
 *
 * A pairing alone never proves a transfer: the gate opens only when Guard
 * Cloud is paired and current sync health says uploads are landing. A device
 * waiting on its first sync, or one whose connection needs a retry, reports
 * `paired_waiting`, so that state is drawn closed.
 */
export function resolveSyncState(runtimeSummary: AboutRuntimeSummary | null): SyncState {
  switch (runtimeSummary?.cloudState) {
    case "paired_active":
      switch (runtimeSummary.syncHealth) {
        case "healthy":
        case "pending":
          return "on";
        case "failed":
        case "degraded":
        case "stale":
          return "stalled";
        case "disabled":
          return "off";
        default:
          return "unavailable";
      }
    case "paired_waiting":
      return "pairing";
    case "local_only":
      return "off";
    default:
      return "unavailable";
  }
}

export const SYNC_STATE_LABEL: Record<SyncState, string> = {
  on: "On",
  stalled: "Not syncing",
  pairing: "First sync",
  off: "Off",
  unavailable: "Unavailable",
};

const SYNC_CAPTION: Record<SyncState, string> = {
  on: "Sync is on, so policy summaries and receipt history cross the gate to Guard Cloud.",
  stalled: "Guard Cloud is connected, but recent syncs have not landed, so nothing is crossing the gate right now.",
  pairing: "This device is paired with Guard Cloud and waiting for its first sync; nothing has crossed the gate yet.",
  off: "Sync is off, so nothing on this device crosses the gate.",
  unavailable: "Guard could not report its sync state, so this figure makes no claim about the gate.",
};

export function MachineFigure({
  runtimeSummary,
}: {
  runtimeSummary: AboutRuntimeSummary | null;
}) {
  const sync = resolveSyncState(runtimeSummary);
  const open = sync === "on";

  return (
    <figure aria-labelledby="about-figure-caption" className="about-figure">
      {/* Wide screens: the device frame, then the gate straddling its right
          edge, a crossing line, and the outside column. The middle row holds
          the gate, the line and Guard Cloud on one centre line; the equal
          rows around it keep that line at the frame's vertical centre. */}
      <div className="grid lg:grid-cols-[minmax(0,1fr)_5rem_2.5rem_minmax(0,11rem)] lg:grid-rows-[minmax(0,1fr)_auto_minmax(0,1fr)]">
        <DevicePerimeter runtimeSummary={runtimeSummary} />
        <SyncGate sync={sync} />
        <Crossing open={open} />
        <OutsideNode title="Guard Cloud" className="lg:col-start-4 lg:row-start-2 lg:self-center">
          Team policy and shared history, when you opt in.
        </OutsideNode>
        <OutsideNode
          title="hol.org"
          callout={4}
          className="mt-3 lg:col-start-4 lg:row-start-3 lg:mt-0 lg:self-end"
        >
          Links only; this page sends nothing.
        </OutsideNode>
      </div>
      <figcaption
        id="about-figure-caption"
        className="mt-4 max-w-[68ch] text-sm leading-6 text-brand-dark/75"
      >
        <span className="font-semibold text-brand-dark">Fig. 1</span> This device, and what can leave it.{" "}
        {SYNC_CAPTION[sync]}
      </figcaption>
    </figure>
  );
}

function DevicePerimeter({ runtimeSummary }: { runtimeSummary: AboutRuntimeSummary | null }) {
  const pending = runtimeSummary?.pendingCount ?? 0;
  return (
    <div className="relative rounded-2xl border border-brand-dark/25 px-4 pb-8 pt-6 sm:px-6 sm:pt-7 lg:row-span-3 lg:pb-6 lg:pr-24">
      <p className="absolute -top-2.5 left-4 bg-white px-2 text-xs font-semibold text-brand-dark sm:left-6">
        This device
      </p>

      {/* One continuous rail runs beside the nodes (under them on wide
          screens) and enters each one; about-page.css draws it. */}
      <ol className="about-flow">
        <FlowNode title="Agents and MCP tools">
          Ask to run, edit or connect.
        </FlowNode>
        <FlowNode title="HOL Guard" emphasis arrow>
          Checks each action first.
          {runtimeSummary ? (
            <span className="mt-3 flex flex-col gap-1.5">
              <Readout label="Guard version" value={runtimeSummary.guardVersion ?? "Unknown"} />
              <Readout
                label="Local protection"
                value={pending > 0 ? `${pending} pending` : "Active"}
                attention={pending > 0}
              />
            </span>
          ) : null}
        </FlowNode>
        <FlowNode title="Your decision" callout={1} arrow>
          {/* The path forks here: one branch runs, the other waits. */}
          <span className="relative flex flex-col gap-1 pl-3">
            <span
              aria-hidden="true"
              className="absolute bottom-[0.7rem] left-0 top-[0.7rem] w-0.5 bg-brand-blue"
            />
            <Outcome lead="Clear">runs</Outcome>
            <Outcome lead="Unclear">waits for you</Outcome>
          </span>
        </FlowNode>
      </ol>

      <div className="mt-6 border-t border-dashed border-brand-dark/20 pt-4">
        <p className="text-xs font-semibold text-brand-dark">Stored on this device</p>
        <ul className="mt-1 flex flex-wrap gap-x-5 sm:grid sm:grid-cols-3 sm:divide-x sm:divide-brand-dark/12">
          <StoreItem callout={1} title="Approvals and policy" />
          <StoreItem
            callout={2}
            title="Receipts"
            value={runtimeSummary ? formatAboutCount(runtimeSummary.receiptCount) : undefined}
          />
          <StoreItem title="Runtime state" />
        </ul>
      </div>
    </div>
  );
}

function FlowNode({
  title,
  children,
  emphasis = false,
  arrow = false,
  callout,
}: {
  title: string;
  children: ReactNode;
  emphasis?: boolean;
  arrow?: boolean;
  callout?: number;
}) {
  return (
    <li
      className={`relative rounded-xl border p-3 sm:p-3.5 ${
        emphasis ? "border-brand-blue/50 bg-[#f1f6ff]" : "border-brand-dark/12 bg-surface-1"
      }`}
    >
      <span className="flex items-center justify-between gap-2">
        <span className="text-sm font-semibold text-brand-dark">{title}</span>
        {callout ? <Callout n={callout} /> : null}
      </span>
      <span className="mt-1 block text-sm leading-6 text-brand-dark/75">{children}</span>
      {arrow ? <ArrowHead /> : null}
    </li>
  );
}

/** The head of the rail where it enters this node: from the left on phones, from below on wide screens. */
function ArrowHead() {
  return (
    <svg
      aria-hidden="true"
      viewBox="0 0 10 10"
      className="about-arrowhead absolute -left-2.5 top-[1.375rem] size-2.5 -translate-y-1/2 text-brand-blue md:left-1/2 md:top-full md:-translate-x-1/2 md:translate-y-0 md:-rotate-90"
    >
      <path d="M1 1 9 5 1 9Z" fill="currentColor" />
    </svg>
  );
}

function Outcome({ lead, children }: { lead: string; children: ReactNode }) {
  return (
    <span className="flex items-baseline gap-2">
      <span aria-hidden="true" className="-ml-3 h-0.5 w-3 shrink-0 translate-y-[-0.2rem] bg-brand-blue" />
      <span>
        <span className="font-semibold text-brand-dark">{lead}</span> {children}
      </span>
    </span>
  );
}

function StoreItem({
  title,
  callout,
  value,
}: {
  title: string;
  callout?: number;
  value?: string;
}) {
  return (
    <li className="flex items-center gap-2 py-1 sm:min-h-9 sm:px-4 sm:py-2 sm:first:pl-0 sm:last:pr-0">
      {callout ? <Callout n={callout} /> : null}
      {/* Title and value share one element so they read as one phrase. */}
      <span className="flex min-w-0 flex-1 items-baseline justify-between gap-2">
        <span className="text-sm font-medium text-brand-dark">{title}</span>
        {value !== undefined ? (
          <span className="font-mono text-sm font-semibold tabular-nums text-brand-dark">{value}</span>
        ) : null}
      </span>
    </li>
  );
}

/** The gate sits on the device's edge: it breaks the frame line it stands on. */
function SyncGate({ sync }: { sync: SyncState }) {
  const open = sync === "on";
  return (
    <div className="relative z-10 -mt-5 flex justify-center lg:col-start-2 lg:row-start-2 lg:mt-0 lg:-ml-20 lg:w-40 lg:self-center">
      <div
        className={`w-full max-w-60 rounded-xl border bg-white p-3 lg:max-w-none ${
          open ? "border-2 border-brand-blue" : "border-dashed border-brand-dark/40"
        }`}
      >
        <span className="flex items-center justify-between gap-2">
          <span className="text-sm font-semibold text-brand-dark">Sync gate</span>
          <Callout n={3} />
        </span>
        <span className="mt-2 block">
          <Readout
            label="Sync"
            value={SYNC_STATE_LABEL[sync]}
            attention={sync === "pairing" || sync === "stalled"}
          />
        </span>
        <span className="mt-2 block text-xs leading-5 text-brand-dark/75">{GATE_CARRIES[sync]}</span>
      </div>
    </div>
  );
}

const GATE_CARRIES: Record<SyncState, string> = {
  on: "Carries policy summaries and receipt history.",
  stalled: "Would carry policy summaries and receipt history once sync recovers.",
  pairing: "Waiting for the first sync to land.",
  off: "Would carry policy summaries and receipt history.",
  unavailable: "Would carry policy summaries and receipt history.",
};

function OutsideNode({
  title,
  callout,
  children,
  className = "",
}: {
  title: string;
  callout?: number;
  children: ReactNode;
  className?: string;
}) {
  return (
    <div className={`rounded-xl border border-dashed border-brand-dark/25 p-3 ${className}`}>
      <span className="flex items-center justify-between gap-2">
        <span className="text-sm font-semibold text-brand-dark">{title}</span>
        {callout ? <Callout n={callout} /> : null}
      </span>
      <span className="mt-1 block text-xs leading-5 text-brand-dark/75">{children}</span>
    </div>
  );
}

/** The line from the gate to Guard Cloud. Solid blue only when data crosses it. */
function Crossing({ open }: { open: boolean }) {
  return (
    <div aria-hidden="true" className="flex items-center justify-center lg:col-start-3 lg:row-start-2">
      <span
        className={`block h-6 w-0 border-l-2 lg:h-0 lg:w-full lg:border-l-0 lg:border-t-2 ${
          open ? "border-brand-blue" : "border-dashed border-brand-dark/30"
        }`}
      />
    </div>
  );
}

/** Label and value read together as one phrase, e.g. "Sync" + "Off". */
function Readout({
  label,
  value,
  attention = false,
}: {
  label: string;
  value: string;
  attention?: boolean;
}) {
  return (
    <span className="flex items-baseline justify-between gap-3 text-xs">
      <span className="text-brand-dark/75">{label}</span>
      <span
        className={`font-semibold tabular-nums text-brand-dark ${attention ? "rounded-full bg-brand-attention-bg px-2" : ""}`}
      >
        {value}
      </span>
    </span>
  );
}

/** A numbered marker tying a part of the figure to a Trust Contract claim. */
export function Callout({ n }: { n: number }) {
  return (
    <span className="inline-flex size-5 shrink-0 items-center justify-center rounded-full bg-brand-dark text-[11px] font-semibold tabular-nums text-white">
      <span className="sr-only">Claim </span>
      {n}
    </span>
  );
}
