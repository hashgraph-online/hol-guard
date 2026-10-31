import { ABOUT_TRUST_CONTRACT_CLAIMS } from "../about-content";
import { Callout } from "./machine-figure";

/**
 * The legend to Fig. 1. Each claim carries the number of the callout that
 * marks it on the figure, so the promise and the part of the device it is
 * about can be read together.
 */
export function TrustContractPanel() {
  return (
    <div>
      <h2 id="about-trust-heading" className="text-2xl font-semibold tracking-[-0.02em] text-brand-dark">
        Trust Contract
      </h2>
      <ol className="mt-5 grid gap-x-8 border-t border-brand-dark/10 sm:grid-cols-2 xl:grid-cols-4">
        {ABOUT_TRUST_CONTRACT_CLAIMS.map((claim, index) => (
          <li key={claim.id} className="border-b border-brand-dark/10 py-4 xl:border-b-0">
            <div className="flex items-center gap-2.5">
              <Callout n={index + 1} />
              <h3 className="text-sm font-semibold text-brand-dark">{claim.title}</h3>
            </div>
            <p className="mt-2 text-sm leading-6 text-brand-dark/75">{claim.body}</p>
            <p className="mt-2 text-xs font-semibold text-brand-dark">{claim.proofLabel}</p>
          </li>
        ))}
      </ol>
    </div>
  );
}
