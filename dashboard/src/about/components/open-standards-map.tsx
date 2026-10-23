import { ABOUT_STANDARDS_NODES } from "../about-content";
import { AboutSectionHeading } from "./about-section-heading";

export function OpenStandardsMap() {
  return (
    <div>
      <AboutSectionHeading
        id="about-open-standards-heading"
        title="Open standards map"
        lead="HOL builds directional infrastructure for the agent internet. These are the areas we are working on."
      />
      {/* A numbered list, not six identical boxes: these are areas of one
          programme, and the page already numbers the partner levels this way. */}
      <ol className="mt-6 grid gap-x-10 border-t border-brand-dark/10 sm:grid-cols-2">
        {ABOUT_STANDARDS_NODES.map((node, index) => (
          <li
            key={node.id}
            className="flex items-start gap-3 border-b border-brand-dark/10 py-4"
          >
            <span
              className="mt-px font-mono text-xs font-semibold tabular-nums text-brand-blue"
              aria-hidden="true"
            >
              {String(index + 1).padStart(2, "0")}
            </span>
            <div className="min-w-0">
              <h3 className="text-sm font-semibold text-brand-dark">{node.label}</h3>
              <p className="mt-1 text-sm leading-6 text-brand-dark/75">{node.body}</p>
            </div>
          </li>
        ))}
      </ol>
    </div>
  );
}
