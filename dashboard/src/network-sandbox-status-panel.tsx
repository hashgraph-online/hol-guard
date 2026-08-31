import { useCallback, useEffect, useState, type ReactNode } from "react";
import {
  HiMiniArrowPath,
  HiMiniCheckCircle,
  HiMiniExclamationTriangle,
  HiMiniGlobeAlt,
  HiMiniShieldExclamation,
} from "react-icons/hi2";
import { SectionLabel } from "./approval-center-primitives";
import {
  containmentPresentationState,
  networkPresentationState,
  nextProofClockDelay,
  useNetworkSandboxStatus,
  type NetworkSandboxStatusState,
  type ProofPresentationState,
} from "./network-sandbox-status";

type StatusCopy = {
  label: string;
  detail: string;
};

export function qualifyLastKnownUnsupported(
  copy: StatusCopy,
  loadState: NetworkSandboxStatusState["network"]["loadState"],
): StatusCopy {
  if (loadState !== "stale") return copy;
  return {
    label: "Unsupported · last checked",
    detail: `${copy.detail} The latest status check did not complete.`,
  };
}

const STATUS_STYLE: Record<ProofPresentationState, string> = {
  checking: "bg-slate-100 text-slate-600",
  ready: "bg-emerald-50 text-emerald-700",
  unsupported: "bg-slate-100 text-slate-600",
  unavailable: "bg-amber-50 text-amber-700",
  stale: "bg-amber-50 text-amber-700",
  error: "bg-red-50 text-red-700",
};

export function networkStatusCopy(state: ProofPresentationState): StatusCopy {
  if (state === "ready") {
    return {
      label: "Active",
      detail: "Guard has current, independently observed proof that a local provider is enforcing network boundaries.",
    };
  }
  if (state === "unsupported") {
    return {
      label: "Unsupported",
      detail: "Selective network isolation is not available on this operating system.",
    };
  }
  if (state === "stale") {
    return {
      label: "Proof needs refresh",
      detail: "The last provider proof is no longer current. Guard is not treating selective network isolation as active.",
    };
  }
  if (state === "error") {
    return {
      label: "Couldn’t check",
      detail: "Guard could not read network provider status. No network-isolation claim is being made.",
    };
  }
  if (state === "unavailable") {
    return {
      label: "Not active",
      detail: "No independently verified network provider is active. Other Guard protections continue separately.",
    };
  }
  return {
    label: "Checking",
    detail: "Guard is checking for current, independently observed network enforcement.",
  };
}

export function containmentStatusCopy(state: ProofPresentationState): StatusCopy {
  if (state === "ready") {
    return {
      label: "Available",
      detail: "A current local probe confirms supported actions can run inside a bounded sandbox.",
    };
  }
  if (state === "unsupported") {
    return {
      label: "Unsupported",
      detail: "Bounded local execution is not available on this operating system.",
    };
  }
  if (state === "stale") {
    return {
      label: "Proof needs refresh",
      detail: "The last sandbox probe is no longer current. Guard will not rely on it as positive proof.",
    };
  }
  if (state === "error") {
    return {
      label: "Couldn’t check",
      detail: "Guard could not read sandbox health. It is not claiming contained execution is available.",
    };
  }
  if (state === "unavailable") {
    return {
      label: "Not available",
      detail: "The local sandbox probe did not confirm enforcement. Guard will not rely on it as positive proof.",
    };
  }
  return {
    label: "Checking",
    detail: "Guard is running a local sandbox compatibility check.",
  };
}

function StatusIcon(props: { state: ProofPresentationState }) {
  if (props.state === "ready") {
    return <HiMiniCheckCircle className="size-5 text-emerald-600" aria-hidden="true" />;
  }
  if (props.state === "checking") {
    return <HiMiniArrowPath className="size-5 animate-spin text-slate-500 motion-reduce:animate-none" aria-hidden="true" />;
  }
  if (props.state === "error") {
    return <HiMiniShieldExclamation className="size-5 text-red-600" aria-hidden="true" />;
  }
  if (props.state === "unsupported") {
    return <HiMiniShieldExclamation className="size-5 text-slate-500" aria-hidden="true" />;
  }
  return <HiMiniExclamationTriangle className="size-5 text-amber-600" aria-hidden="true" />;
}

function StatusRow(props: {
  title: string;
  description: string;
  state: ProofPresentationState;
  copy: StatusCopy;
  icon: ReactNode;
}) {
  return (
    <div className="grid gap-3 py-4 sm:grid-cols-[minmax(0,0.85fr)_minmax(0,1.25fr)] sm:items-start sm:gap-6">
      <div className="flex min-w-0 items-start gap-3">
        <span className="mt-0.5 flex size-9 shrink-0 items-center justify-center rounded-xl bg-slate-50 text-slate-500" aria-hidden="true">
          {props.icon}
        </span>
        <div className="min-w-0">
          <h3 className="text-sm font-semibold text-brand-dark">{props.title}</h3>
          <p className="mt-0.5 text-xs leading-5 text-slate-500">{props.description}</p>
        </div>
      </div>
      <div className="flex min-w-0 items-start gap-3 sm:justify-self-stretch">
        <StatusIcon state={props.state} />
        <div className="min-w-0">
          <span className={`inline-flex rounded-full px-2.5 py-1 text-xs font-semibold ${STATUS_STYLE[props.state]}`}>
            {props.copy.label}
          </span>
          <p className="mt-2 max-w-[70ch] text-sm leading-6 text-slate-600">{props.copy.detail}</p>
        </div>
      </div>
    </div>
  );
}

type NetworkSandboxStatusPanelViewProps = {
  state: NetworkSandboxStatusState;
  onRefresh: () => void;
  nowEpochMs: number;
};

export function NetworkSandboxStatusPanelView(props: NetworkSandboxStatusPanelViewProps) {
  const { state } = props;
  const nowEpochMs = props.nowEpochMs;
  const networkState = networkPresentationState(state.network, nowEpochMs);
  const containmentState = containmentPresentationState(state.containment, nowEpochMs);
  const networkCopy = networkState === "unsupported"
    ? qualifyLastKnownUnsupported(networkStatusCopy(networkState), state.network.loadState)
    : networkStatusCopy(networkState);
  const containmentCopy = containmentState === "unsupported"
    ? qualifyLastKnownUnsupported(containmentStatusCopy(containmentState), state.containment.loadState)
    : containmentStatusCopy(containmentState);
  const refreshing = state.network.refreshing || state.containment.refreshing;

  return (
    <section className="rounded-2xl border border-slate-200 bg-white px-4 py-5 sm:px-6" aria-labelledby="network-sandbox-heading">
      <div className="flex flex-col gap-4 sm:flex-row sm:items-start sm:justify-between">
        <div>
          <SectionLabel>Execution boundaries</SectionLabel>
          <h2 id="network-sandbox-heading" className="mt-1 text-lg font-semibold text-brand-dark">
            Network &amp; sandboxing
          </h2>
          <p className="mt-1 max-w-[70ch] text-sm leading-6 text-slate-500">
            Live proof from this machine. Each boundary is checked independently and may have a different status.
          </p>
        </div>
        <button
          type="button"
          onClick={props.onRefresh}
          disabled={refreshing}
          className="inline-flex min-h-11 shrink-0 items-center justify-center gap-2 rounded-xl border border-slate-200 bg-white px-4 text-sm font-semibold text-brand-dark transition-colors hover:bg-slate-50 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand-blue focus-visible:ring-offset-2 disabled:cursor-wait disabled:opacity-60"
        >
          <HiMiniArrowPath className={`size-4 ${refreshing ? "animate-spin motion-reduce:animate-none" : ""}`} aria-hidden="true" />
          {refreshing ? "Refreshing…" : "Refresh status"}
        </button>
      </div>

      <div className="mt-4 divide-y divide-slate-100 border-y border-slate-100" aria-live="polite" aria-busy={refreshing}>
        <StatusRow
          title="Selective network isolation"
          description="When available, limits where supported processes may connect."
          state={networkState}
          copy={networkCopy}
          icon={<HiMiniGlobeAlt className="size-5" />}
        />
        <StatusRow
          title="Contained-action sandboxing"
          description="When available, runs supported actions with bounded file and network access."
          state={containmentState}
          copy={containmentCopy}
          icon={<HiMiniShieldExclamation className="size-5" />}
        />
      </div>
      <p className="mt-3 text-xs leading-5 text-slate-500">
        These checks report verified local capability. They do not mean every app action is isolated.
      </p>
    </section>
  );
}

export function NetworkSandboxStatusPanel() {
  const { state, refresh } = useNetworkSandboxStatus();
  const [nowEpochMs, setNowEpochMs] = useState(() => Date.now());

  const handleRefresh = useCallback(() => {
    void refresh().finally(() => setNowEpochMs(Date.now()));
  }, [refresh]);

  useEffect(() => {
    let timer = 0;
    const scheduleClock = () => {
      const currentEpochMs = Date.now();
      setNowEpochMs(currentEpochMs);
      timer = window.setTimeout(scheduleClock, nextProofClockDelay(state, currentEpochMs));
    };
    scheduleClock();
    return () => window.clearTimeout(timer);
  }, [state]);

  return (
    <NetworkSandboxStatusPanelView
      state={state}
      onRefresh={handleRefresh}
      nowEpochMs={nowEpochMs}
    />
  );
}
