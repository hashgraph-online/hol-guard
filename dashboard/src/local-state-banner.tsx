import { ActionButton, Badge, SectionLabel, Surface } from "./approval-center-primitives";
import type { GuardLocalStateSummary } from "./guard-types";

type LocalState =
  | { kind: "loading" }
  | { kind: "error"; message: string }
  | { kind: "ready"; item: GuardLocalStateSummary };

function headlineTone(state: string): "default" | "success" | "warning" | "info" | "destructive" {
  if (state === "blocked") {
    return "destructive";
  }
  if (state === "stale") {
    return "warning";
  }
  if (state === "connected") {
    return "info";
  }
  if (state === "protected") {
    return "success";
  }
  return "default";
}

function headlineLabel(state: string): string {
  if (state === "blocked") {
    return "Needs review";
  }
  if (state === "stale") {
    return "Needs sync";
  }
  if (state === "connected") {
    return "Connected";
  }
  if (state === "protected") {
    return "Protected";
  }
  if (state === "setup") {
    return "Setup";
  }
  return "Local only";
}

export function LocalStateBanner(props: { localState: LocalState }) {
  if (props.localState.kind === "loading") {
    return (
      <Surface tone="accent">
        <div className="space-y-3">
          <div className="guard-skeleton h-4 w-32" />
          <div className="guard-skeleton h-16 w-full" />
        </div>
      </Surface>
    );
  }
  if (props.localState.kind === "error") {
    return (
      <Surface tone="warning">
        <SectionLabel>Guard status</SectionLabel>
        <p className="mt-2 text-sm text-brand-dark/70">{props.localState.message}</p>
      </Surface>
    );
  }

  const { item } = props.localState;
  const primaryLink = item.guidance.primary_link;

  return (
    <Surface tone="accent">
      <div className="flex flex-col gap-4 lg:flex-row lg:items-end lg:justify-between">
        <div className="space-y-2">
          <div className="flex flex-wrap items-center gap-2">
            <SectionLabel>Guard status</SectionLabel>
            <Badge tone={headlineTone(item.headline_state)}>{headlineLabel(item.headline_state)}</Badge>
          </div>
          <h1 className="text-2xl font-semibold tracking-tight text-brand-dark">{item.guidance.title}</h1>
          <p className="max-w-3xl text-sm leading-6 text-brand-dark/70">{item.guidance.body}</p>
          {item.guidance.command ? (
            <p className="font-mono text-xs text-brand-dark/60">{item.guidance.command}</p>
          ) : null}
        </div>
        <div className="flex flex-wrap gap-3">
          {primaryLink ? <ActionButton href={primaryLink}>Open shared view</ActionButton> : null}
          {item.portal_links.home ? (
            <ActionButton href={item.portal_links.home} variant="outline">
              Guard Home
            </ActionButton>
          ) : null}
          {item.portal_links.inbox ? (
            <ActionButton href={item.portal_links.inbox} variant="outline">
              Guard Inbox
            </ActionButton>
          ) : null}
          {item.portal_links.fleet ? (
            <ActionButton href={item.portal_links.fleet} variant="outline">
              Guard Fleet
            </ActionButton>
          ) : null}
        </div>
      </div>
    </Surface>
  );
}
