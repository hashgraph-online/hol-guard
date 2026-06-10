import { HiMiniCheckCircle, HiMiniCloud, HiMiniComputerDesktop } from "react-icons/hi2";
import type { SupplyChainCapabilityItem, SupplyChainCloudCapabilitiesState } from "./supply-chain-cloud-capabilities";

type SupplyChainCloudCapabilitiesPanelProps = {
  state: SupplyChainCloudCapabilitiesState;
};

type CapabilityListProps = {
  heading: string;
  icon: typeof HiMiniComputerDesktop;
  items: SupplyChainCapabilityItem[];
};

function CapabilityList({ heading, icon: Icon, items }: CapabilityListProps) {
  return (
    <div className="min-w-0 rounded-xl border border-slate-100 bg-white/80 p-4">
      <div className="mb-3 flex items-center gap-2">
        <Icon className="h-4 w-4 shrink-0 text-slate-500" aria-hidden="true" />
        <h3 className="text-sm font-semibold text-brand-dark">{heading}</h3>
      </div>
      <ul className="space-y-2">
        {items.map((item) => (
          <li key={item.label} className="flex min-w-0 items-start gap-2 text-xs leading-relaxed">
            <HiMiniCheckCircle
              className={`mt-0.5 h-3.5 w-3.5 shrink-0 ${
                item.available ? "text-brand-green" : "text-slate-300"
              }`}
              aria-hidden="true"
            />
            <span className={item.available ? "text-slate-600" : "text-slate-400"}>{item.label}</span>
          </li>
        ))}
      </ul>
    </div>
  );
}

function panelToneClass(tone: SupplyChainCloudCapabilitiesState["tone"]): string {
  if (tone === "green") {
    return "border-brand-green/20 bg-brand-green/[0.04]";
  }
  if (tone === "blue") {
    return "border-brand-blue/20 bg-brand-blue/[0.04]";
  }
  return "border-slate-200 bg-slate-50/80";
}

export function SupplyChainCloudCapabilitiesPanel({ state }: SupplyChainCloudCapabilitiesPanelProps) {
  return (
    <section
      className={`rounded-2xl border px-4 py-4 ${panelToneClass(state.tone)}`}
      aria-label="Local and Guard Cloud capabilities"
      data-testid="supply-chain-cloud-capabilities"
    >
      <div className="min-w-0 space-y-1">
        <p className="text-sm font-medium text-brand-dark">{state.title}</p>
        <p className="text-xs leading-relaxed text-slate-600">{state.detail}</p>
      </div>
      <div className="mt-4 grid min-w-0 gap-3 md:grid-cols-2">
        <CapabilityList
          heading={state.localHeading}
          icon={HiMiniComputerDesktop}
          items={state.localCapabilities}
        />
        <CapabilityList
          heading={state.cloudHeading}
          icon={HiMiniCloud}
          items={state.cloudCapabilities}
        />
      </div>
    </section>
  );
}
