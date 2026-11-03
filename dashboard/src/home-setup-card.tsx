import { useCallback } from "react";
import { HiMiniArrowRight, HiMiniCheckCircle, HiMiniLockClosed } from "react-icons/hi2";

import { ABOUT_LOCAL_SECTION_BODY, ABOUT_LOCAL_SECTION_TITLE } from "./about/about-content";
import { ActionButton, SectionLabel, Tag } from "./approval-center-primitives";
import { harnessDisplayName } from "./approval-center-utils";
import { isConnectableAppHarness } from "./apps/harness-setup-target";
import { SUPPORTED_APPS_FULL } from "./apps/app-catalog";
import type { GuardManagedInstall } from "./guard-types";

export type HomeSetupApp = {
  harness: string;
  name: string;
  state: "found" | "partial";
};

/**
 * Apps Guard already knows about on this machine: ones it has seen activity from
 * (found) and ones with a managed install that is not active yet (partial).
 */
export function resolveSetupApps(managedInstalls: GuardManagedInstall[], observedHarnesses: string[]): HomeSetupApp[] {
  const apps = new Map<string, HomeSetupApp>();
  for (const install of managedInstalls) {
    if (!isConnectableAppHarness(install.harness) || install.active) continue;
    apps.set(install.harness, { harness: install.harness, name: harnessDisplayName(install.harness), state: "partial" });
  }
  for (const harness of observedHarnesses) {
    if (!isConnectableAppHarness(harness) || apps.has(harness)) continue;
    apps.set(harness, { harness, name: harnessDisplayName(harness), state: "found" });
  }
  return Array.from(apps.values()).sort((a, b) => a.name.localeCompare(b.name));
}

export function buildSetupAppsCopy(apps: HomeSetupApp[]): string {
  if (apps.length === 0) {
    return "Guard hasn’t seen an AI app on this computer yet. Protect lists the apps installed here and connects one in a few seconds.";
  }
  return "Guard found these on this computer. Connecting takes a few seconds and doesn’t change how the app works.";
}

export function HomeSetupCard(props: {
  apps: HomeSetupApp[];
  onConnectHarness: (harness: string) => void;
  onOpenProtect: () => void;
}) {
  const noApps = props.apps.length === 0;
  return (
    <section className="guard-fade-in rounded-2xl border border-brand-blue/15 bg-white shadow-sm" aria-label="Get set up">
      <div className="border-b border-slate-100 px-5 py-4">
        <SectionLabel>Get set up</SectionLabel>
        <p className="mt-1 text-sm text-slate-500">Three steps. Guard only changes something after you approve it.</p>
      </div>
      <ol className="divide-y divide-slate-100">
        <li className="flex items-start gap-4 px-5 py-4">
          <span className="mt-0.5 inline-flex h-7 w-7 shrink-0 items-center justify-center rounded-full bg-brand-green-bg text-brand-green-text">
            <HiMiniCheckCircle className="h-4 w-4" aria-hidden="true" />
          </span>
          <div className="min-w-0 flex-1">
            <p className="text-sm font-semibold text-brand-dark">Install Guard on this computer</p>
            <p className="mt-0.5 text-sm text-slate-500">Done. Guard is running and this dashboard is live.</p>
          </div>
          <Tag tone="green">Done</Tag>
        </li>
        <li className="px-5 py-4">
          <div className="flex items-start gap-4">
            <span className="mt-0.5 inline-flex h-7 w-7 shrink-0 items-center justify-center rounded-full bg-brand-blue text-xs font-bold text-white">2</span>
            <div className="min-w-0 flex-1">
              <p className="text-sm font-semibold text-brand-dark">Connect an AI app</p>
              <p className="mt-0.5 text-sm text-slate-500">{buildSetupAppsCopy(props.apps)}</p>
              {props.apps.length > 0 ? (
                <div className="mt-3 grid gap-2 sm:grid-cols-2" role="list" aria-label="Apps found on this computer">
                  {props.apps.map((app) => (
                    <SetupAppRow key={app.harness} app={app} onConnectHarness={props.onConnectHarness} />
                  ))}
                </div>
              ) : null}
              <div className="mt-3">
                <ActionButton variant={noApps ? "primary" : "quiet"} className={noApps ? undefined : "-ml-3"} onClick={props.onOpenProtect}>
                  {noApps ? "Set up an app in Protect" : "See every app in Protect"}
                  <HiMiniArrowRight className="ml-2 h-4 w-4" aria-hidden="true" />
                </ActionButton>
              </div>
              <p className="mt-3 text-xs text-slate-500">{SUPPORTED_APPS_FULL}</p>
            </div>
          </div>
        </li>
        <li className="flex items-start gap-4 px-5 py-4">
          <span className="mt-0.5 inline-flex h-7 w-7 shrink-0 items-center justify-center rounded-full bg-slate-100 text-xs font-bold text-slate-500">3</span>
          <div className="min-w-0 flex-1">
            <p className="text-sm font-semibold text-brand-dark">Keep working</p>
            <p className="mt-0.5 text-sm text-slate-500">Guard stays quiet until an app tries something new. Then it pauses and asks you here.</p>
          </div>
        </li>
      </ol>
    </section>
  );
}

function SetupAppRow(props: { app: HomeSetupApp; onConnectHarness: (harness: string) => void }) {
  const handleConnect = useCallback(() => props.onConnectHarness(props.app.harness), [props.onConnectHarness, props.app.harness]);
  return (
    <div role="listitem" className="flex items-center justify-between gap-3 rounded-xl border border-slate-200 bg-white px-3 py-2.5">
      <div className="flex min-w-0 items-center gap-2.5">
        <span className="inline-flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-surface-2 font-mono text-[11px] font-bold text-brand-dark" aria-hidden="true">
          {props.app.name.slice(0, 2)}
        </span>
        <div className="min-w-0">
          <p className="truncate text-sm font-medium text-brand-dark">{props.app.name}</p>
          <p className="text-xs text-slate-500">{props.app.state === "partial" ? "Setup not finished" : "Found on this computer"}</p>
        </div>
      </div>
      <ActionButton onClick={handleConnect}>{props.app.state === "partial" ? "Finish setup" : "Connect"}</ActionButton>
    </div>
  );
}

export function WhatStaysLocalCard() {
  return (
    <section className="rounded-2xl border border-brand-purple/15 bg-brand-purple/[0.04] p-5 shadow-sm sm:p-6" aria-label={ABOUT_LOCAL_SECTION_TITLE}>
      <div className="flex items-start gap-3">
        <span className="inline-flex h-10 w-10 shrink-0 items-center justify-center rounded-full bg-white/80 text-brand-purple">
          <HiMiniLockClosed className="h-5 w-5" aria-hidden="true" />
        </span>
        <div className="min-w-0 flex-1">
          <SectionLabel>{ABOUT_LOCAL_SECTION_TITLE}</SectionLabel>
          <p className="mt-2 text-sm text-muted-foreground">{ABOUT_LOCAL_SECTION_BODY}</p>
        </div>
      </div>
    </section>
  );
}
