import { Surface, SectionLabel } from "../../approval-center-primitives";
import { ABOUT_STANDARDS_NODES } from "../about-content";

export function OpenStandardsMap() {
  return (
    <div>
      <SectionLabel>Open standards map</SectionLabel>
      <p className="mt-2 max-w-2xl text-base leading-relaxed text-brand-dark/75">
        HOL builds directional infrastructure for the agent internet. These are the areas we are working on.
      </p>
      <div className="mt-6 grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
        {ABOUT_STANDARDS_NODES.map((node, index) => (
          <Surface
            key={node.id}
            className="relative overflow-hidden"
            tone={index === 0 ? "accent" : "default"}
          >
            <div className="flex items-start gap-3">
              <span className="mt-0.5 inline-flex h-7 w-7 shrink-0 items-center justify-center rounded-md bg-brand-blue/10 text-brand-blue font-mono text-xs font-bold">
                {String(index + 1).padStart(2, "0")}
              </span>
              <div>
                <h3 className="text-sm font-semibold text-brand-dark">
                  {node.label}
                </h3>
                <p className="mt-1 text-xs leading-relaxed text-brand-dark/60">
                  {node.body}
                </p>
              </div>
            </div>
          </Surface>
        ))}
      </div>
    </div>
  );
}
