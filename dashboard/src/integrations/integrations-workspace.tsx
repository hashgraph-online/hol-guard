import { useCallback, useEffect, useState } from "react";
import { HiMiniArrowLeft, HiMiniArrowTopRightOnSquare, HiMiniCheckBadge } from "react-icons/hi2";

import { EXTENSION_CHIP_CLASS, EXTENSION_PANEL_CLASS, EXTENSION_ROW_CLASS } from "../protection-center/protection-surface";
import { ExtensionsLoadError, ExtensionsLoadingState, ExtensionsNotFound } from "../protection-center/protection-workspace-states";
import {
  capabilityChecks,
  capabilityLabel,
  effectLabel,
  factDescription,
  factIsOptIn,
  providerErrorMessage,
  providerStateLabel,
  surfaceLabel,
} from "./integrations-copy";
import { followExtensionsLink, INTEGRATIONS_HREF, navigateExtensions, providerHref, type IntegrationsRoute } from "./integrations-route";
import {
  fetchProviderDetail,
  fetchProviderList,
  ProviderIntegrationApiError,
  safeHttpsUrl,
  type ProviderDetail,
  type ProviderState,
  type ProviderSummary,
} from "./provider-integrations-api";

type Load<T> = { kind: "loading" } | { kind: "error"; code: string } | { kind: "ready"; value: T };

function useLoad<T>(read: () => Promise<T>): [Load<T>, () => void] {
  const [state, setState] = useState<Load<T>>({ kind: "loading" });
  const [attempt, setAttempt] = useState(0);
  useEffect(() => {
    let live = true;
    setState({ kind: "loading" });
    read().then(
      (value) => live && setState({ kind: "ready", value }),
      (error: unknown) =>
        live && setState({ kind: "error", code: error instanceof ProviderIntegrationApiError ? error.code : "provider_request_failed" }),
    );
    return () => {
      live = false;
    };
  }, [read, attempt]);
  return [state, useCallback(() => setAttempt((value) => value + 1), [])];
}

function BackLink(props: { href: string; label: string }) {
  return (
    <a
      href={props.href}
      onClick={(event) => followExtensionsLink(event, props.href)}
      className="inline-flex min-h-11 items-center gap-1.5 text-sm font-medium text-brand-blue"
    >
      <HiMiniArrowLeft className="size-4" aria-hidden="true" />
      {props.label}
    </a>
  );
}

const STATE_TONE: Record<ProviderState, string> = {
  connected: "guard-extensions-tone-safe",
  not_connected: "",
  key_invalid: "guard-extensions-tone-danger",
  disabled: "guard-extensions-tone-attention",
};

export function ProviderStateChip(props: { state: ProviderState }) {
  return <span className={`${EXTENSION_CHIP_CLASS} ${STATE_TONE[props.state]}`}>{providerStateLabel(props.state)}</span>;
}

export function VerificationLabel(props: { verified: boolean; publisher?: string }) {
  if (props.verified) {
    return (
      <span className="inline-flex items-center gap-1 text-sm text-brand-dark/80">
        <HiMiniCheckBadge className="size-4 text-brand-blue" aria-hidden="true" />
        {props.publisher ? `Verified publisher: ${props.publisher}` : "Verified publisher"}
      </span>
    );
  }
  return (
    <span className="text-sm text-brand-dark/70">
      {props.publisher ? `Published by ${props.publisher}. HOL has not verified this publisher.` : "Unverified publisher"}
    </span>
  );
}

export function ProviderListView(props: { providers: ProviderSummary[] }) {
  return (
    <div className="mx-auto max-w-4xl space-y-4">
      <BackLink href="/extensions" label="Extensions" />
      <header>
        <h1 className="text-2xl font-semibold text-brand-dark">Integrations</h1>
        <p className="mt-1 text-sm text-brand-dark/70">
          Connect a security provider to add its checks to Guard. Guard sends a provider only the facts its page lists.
        </p>
      </header>
      {props.providers.length === 0 ? (
        <div className={EXTENSION_PANEL_CLASS}>
          <p className="text-sm text-brand-dark/80">No provider integrations ship with this version of Guard yet.</p>
        </div>
      ) : (
        <section aria-labelledby="integrations-browser" className={EXTENSION_PANEL_CLASS}>
          <h2 id="integrations-browser" className="text-base font-semibold text-brand-dark">
            {surfaceLabel("browser")}
          </h2>
          <ul className="mt-3 space-y-2">
            {props.providers.map((provider) => (
              <li key={provider.id}>
                <a
                  href={providerHref(provider.id)}
                  onClick={(event) => followExtensionsLink(event, providerHref(provider.id))}
                  className={`${EXTENSION_ROW_CLASS} flex min-h-11 flex-wrap items-center justify-between gap-3`}
                >
                  <span className="min-w-0">
                    <span className="block font-medium text-brand-dark">{provider.name}</span>
                    <span className="block text-sm text-brand-dark/70">{provider.summary}</span>
                    <span className="mt-1 block text-xs text-brand-dark/60">
                      {provider.capabilities.map(capabilityLabel).join(", ")}
                    </span>
                  </span>
                  <ProviderStateChip state={provider.state} />
                </a>
              </li>
            ))}
          </ul>
        </section>
      )}
    </div>
  );
}

function ExternalLink(props: { href: string | null; label: string }) {
  const href = safeHttpsUrl(props.href);
  if (!href) return null;
  return (
    <a href={href} target="_blank" rel="noopener noreferrer" className="inline-flex min-h-11 items-center gap-1 text-sm font-medium text-brand-blue">
      {props.label}
      <HiMiniArrowTopRightOnSquare className="size-4" aria-hidden="true" />
    </a>
  );
}

export function ProviderDetailView(props: { detail: ProviderDetail; onConnect?: () => void }) {
  const { detail } = props;
  const { summary } = detail;
  const [showCli, setShowCli] = useState(false);
  const optInNote = (fact: string) =>
    !factIsOptIn(fact) ? "" : detail.enabledOptInFacts.includes(fact) ? " (you turned this on)" : " (only if you turn it on)";
  const connectLabel = summary.state === "connected" ? "Replace key" : "Connect";
  return (
    <div className="mx-auto max-w-4xl space-y-4">
      <BackLink href={INTEGRATIONS_HREF} label="Integrations" />
      <header className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0">
          <h1 className="text-2xl font-semibold text-brand-dark">{summary.name}</h1>
          <p className="mt-1 text-sm text-brand-dark/70">{summary.summary}</p>
          <div className="mt-2">
            <VerificationLabel verified={summary.verified} publisher={detail.publisherName} />
          </div>
        </div>
        <div className="flex items-center gap-3">
          <ProviderStateChip state={summary.state} />
          <button
            type="button"
            onClick={() => (props.onConnect ? props.onConnect() : setShowCli(true))}
            className="min-h-11 rounded-xl bg-brand-blue px-4 text-sm font-semibold text-white"
          >
            {connectLabel}
          </button>
        </div>
      </header>
      {showCli && !props.onConnect ? (
        <div className={EXTENSION_PANEL_CLASS} role="status">
          <p className="text-sm text-brand-dark/80">Connect from a terminal. Guard asks for the key there and never shows it again.</p>
          <code className="mt-2 block font-mono text-sm break-all text-brand-dark">hol-guard integrations connect {summary.id}</code>
        </div>
      ) : null}
      <section aria-labelledby="provider-checks" className={EXTENSION_PANEL_CLASS}>
        <h2 id="provider-checks" className="text-base font-semibold text-brand-dark">What it checks</h2>
        <ul className="mt-3 space-y-3">
          {detail.settings.map((setting) => (
            <li key={setting.capability}>
              <p className="font-medium text-brand-dark">{capabilityLabel(setting.capability)}</p>
              {capabilityChecks(setting.capability) ? (
                <p className="text-sm text-brand-dark/70">{capabilityChecks(setting.capability)}</p>
              ) : null}
              {summary.state === "connected" ? (
                <p className="mt-1 text-xs text-brand-dark/60">
                  {effectLabel(setting.effect)}
                  {setting.requireFreshCheck ? " · waits for a fresh check" : ""}
                </p>
              ) : null}
            </li>
          ))}
        </ul>
      </section>
      <section aria-labelledby="provider-shares" className={EXTENSION_PANEL_CLASS}>
        <h2 id="provider-shares" className="text-base font-semibold text-brand-dark">What leaves this device</h2>
        <p className="mt-1 text-sm text-brand-dark/70">Each lookup sends only these facts. Page contents and form data stay here. Your API key goes only to the provider's hosts, to authenticate each lookup.</p>
        <ul className="mt-3 list-disc space-y-1 pl-5 text-sm text-brand-dark">
          {detail.shares.map((fact) => (
            <li key={fact}>
              {factDescription(fact)}
              {optInNote(fact)}
            </li>
          ))}
        </ul>
        <p className="mt-3 text-sm text-brand-dark/70">
          Guard calls only {detail.hosts.length === 1 ? "this host" : "these hosts"}:{" "}
          <span className="font-mono break-all">{detail.hosts.join(", ")}</span>
        </p>
      </section>
      <section aria-labelledby="provider-publisher" className={EXTENSION_PANEL_CLASS}>
        <h2 id="provider-publisher" className="text-base font-semibold text-brand-dark">Publisher and terms</h2>
        <p className="mt-1 text-sm text-brand-dark/80">{detail.publisherName}</p>
        <div className="mt-2 flex flex-wrap gap-x-4">
          <ExternalLink href={detail.publisherUrl} label="Publisher site" />
          <ExternalLink href={detail.privacyUrl} label="Privacy policy" />
          <ExternalLink href={detail.termsUrl} label="Terms" />
        </div>
      </section>
    </div>
  );
}

function IntegrationsListPage() {
  const [state, retry] = useLoad(fetchProviderList);
  if (state.kind === "loading") return <ExtensionsLoadingState label="Loading integrations" />;
  if (state.kind === "error") {
    return <ExtensionsLoadError title="Integrations unavailable" detail={providerErrorMessage(state.code)} onRetry={retry} />;
  }
  return <ProviderListView providers={state.value} />;
}

function ProviderDetailPage(props: { providerId: string }) {
  const read = useCallback(() => fetchProviderDetail(props.providerId), [props.providerId]);
  const [state, retry] = useLoad(read);
  if (state.kind === "loading") return <ExtensionsLoadingState label="Loading provider" />;
  if (state.kind === "error" && state.code === "provider_not_found") {
    return (
      <ExtensionsNotFound
        title="Provider not found"
        detail={providerErrorMessage(state.code)}
        onBack={() => navigateExtensions(INTEGRATIONS_HREF)}
      />
    );
  }
  if (state.kind === "error") {
    return <ExtensionsLoadError title="Provider unavailable" detail={providerErrorMessage(state.code)} onRetry={retry} />;
  }
  return <ProviderDetailView detail={state.value} />;
}

export function IntegrationsWorkspace(props: { route: IntegrationsRoute }) {
  return props.route.kind === "integrations" ? (
    <IntegrationsListPage />
  ) : (
    <ProviderDetailPage key={props.route.providerId} providerId={props.route.providerId} />
  );
}
