import type { SupplyChainCapabilityItem, SupplyChainCloudCapabilitiesState } from "./supply-chain-cloud-capabilities";
import { SupplyChainDetailSection } from "./supply-chain-detail-section";

type SupplyChainCloudCapabilitiesPanelProps = {
  state: SupplyChainCloudCapabilitiesState;
};

type CapabilityListProps = {
  heading: string;
  items: SupplyChainCapabilityItem[];
};

function CapabilityList({ heading, items }: CapabilityListProps) {
  return (
    <div className="min-w-0">
      <h4 className="text-xs font-medium text-slate-600">{heading}</h4>
      {/* Available is the normal case, so it carries no mark; only the
          exceptions say so, in words. */}
      <ul className="mt-2 space-y-1">
        {items.map((item) => (
          <li key={item.label} className="min-w-0 text-sm leading-6">
            <span className={item.available ? "text-brand-dark" : "text-slate-500"}>{item.label}</span>
            {item.available ? null : (
              <span className="ml-2 text-xs font-medium text-slate-500">Not available</span>
            )}
          </li>
        ))}
      </ul>
    </div>
  );
}

export function SupplyChainCloudCapabilitiesPanel({ state }: SupplyChainCloudCapabilitiesPanelProps) {
  return (
    <SupplyChainDetailSection
      id="supply-chain-cloud-heading"
      title={state.title}
      lead={state.detail}
      aria-label="Local and Guard Cloud capabilities"
      data-testid="supply-chain-cloud-capabilities"
    >
      <div className="grid min-w-0 gap-x-10 gap-y-4 sm:grid-cols-2">
        <CapabilityList heading={state.localHeading} items={state.localCapabilities} />
        <CapabilityList heading={state.cloudHeading} items={state.cloudCapabilities} />
      </div>
    </SupplyChainDetailSection>
  );
}
