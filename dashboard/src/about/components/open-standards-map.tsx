import { ABOUT_STANDARDS_NODES } from "../about-content";
import { AboutSectionHeading } from "./about-section-heading";

export function OpenStandardsMap() {
  // The heading sits beside the list on wide screens so this section breaks
  // the stacked heading-then-grid rhythm of its neighbours.
  return (
    <div className="lg:grid lg:grid-cols-[minmax(0,18rem)_minmax(0,1fr)] lg:gap-x-12">
      <AboutSectionHeading
        id="about-open-standards-heading"
        title="Open standards map"
        lead="HOL builds directional infrastructure for the agent internet. These are the areas we are working on."
      />
      {/* Six areas of one programme, read in any order: a plain grid
          rather than numbered steps or six identical boxes. */}
      <ul className="mt-6 grid gap-x-10 border-t border-brand-dark/10 sm:grid-cols-2 lg:mt-1">
        {ABOUT_STANDARDS_NODES.map((node) => (
          <li key={node.id} className="border-b border-brand-dark/10 py-3">
            <h3 className="text-sm font-semibold text-brand-dark">{node.label}</h3>
            <p className="mt-0.5 text-sm leading-6 text-brand-dark/75">{node.body}</p>
          </li>
        ))}
      </ul>
    </div>
  );
}
