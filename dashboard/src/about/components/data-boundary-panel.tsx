import { Surface } from "../../approval-center-primitives";
import { ABOUT_DATA_BOUNDARY_ROWS } from "../about-content";
import { AboutSectionHeading } from "./about-section-heading";

export function DataBoundaryPanel() {
  return (
    <div>
      <AboutSectionHeading
        id="about-data-boundary-heading"
        title="Where your data goes"
        lead="Guard keeps your decisions on this device. Sync is strictly opt-in."
      />
      <div className="mt-6 hidden md:block">
        <div className="overflow-hidden rounded-xl border border-brand-dark/10">
          <div className="grid grid-cols-[1fr_180px_180px_180px] border-b border-brand-dark/10 bg-surface-1 px-4 py-2.5">
            <span className="text-[11px] font-semibold uppercase tracking-wider text-brand-dark/75">Data</span>
            <span className="text-[11px] font-semibold uppercase tracking-wider text-brand-dark/75">Local by default</span>
            <span className="text-[11px] font-semibold uppercase tracking-wider text-brand-dark/75">Syncs only when enabled</span>
            <span className="text-[11px] font-semibold uppercase tracking-wider text-brand-dark/75">Never send from About</span>
          </div>
          {ABOUT_DATA_BOUNDARY_ROWS.map((row) => (
            <div
              key={row.id}
              className="grid grid-cols-[1fr_180px_180px_180px] border-b border-brand-dark/10 px-4 py-3 last:border-b-0"
            >
              <span className="text-sm font-medium text-brand-dark">{row.label}</span>
              <span className="text-sm text-brand-dark/75">{row.localDefault}</span>
              <span className="text-sm text-brand-dark/75">{row.optionalSync}</span>
              <span className="text-sm text-brand-dark/75">{row.neverFromAbout}</span>
            </div>
          ))}
        </div>
      </div>
      <div className="mt-6 space-y-3 md:hidden">
        {ABOUT_DATA_BOUNDARY_ROWS.map((row) => (
          <Surface key={row.id} className="!p-4">
            <p className="mb-2 text-sm font-semibold text-brand-dark">{row.label}</p>
            <div className="space-y-1.5">
              <div className="flex justify-between gap-2">
                <span className="text-[11px] font-semibold uppercase tracking-wider text-brand-dark/75">Local</span>
                <span className="text-right text-sm text-brand-dark/75">{row.localDefault}</span>
              </div>
              <div className="flex justify-between gap-2">
                <span className="text-[11px] font-semibold uppercase tracking-wider text-brand-dark/75">Sync</span>
                <span className="text-right text-sm text-brand-dark/75">{row.optionalSync}</span>
              </div>
              <div className="flex justify-between gap-2">
                <span className="text-[11px] font-semibold uppercase tracking-wider text-brand-dark/75">Never</span>
                <span className="text-right text-sm text-brand-dark/75">{row.neverFromAbout}</span>
              </div>
            </div>
          </Surface>
        ))}
      </div>
    </div>
  );
}
