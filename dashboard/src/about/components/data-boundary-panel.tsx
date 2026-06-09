import { Surface, SectionLabel } from "../../approval-center-primitives";
import { ABOUT_DATA_BOUNDARY_ROWS } from "../about-content";

export function DataBoundaryPanel() {
  return (
    <div>
      <SectionLabel>Where your data goes</SectionLabel>
      <p className="mt-2 max-w-2xl text-base leading-relaxed text-brand-dark/75">
        Guard keeps your decisions on this device. Sync is strictly opt-in.
      </p>
      <div className="mt-6 hidden md:block">
        <div className="overflow-hidden rounded-xl border border-slate-100">
          <div className="grid grid-cols-[1fr_180px_180px_180px] border-b border-slate-100 bg-slate-50/60 px-4 py-2.5">
            <span className="text-[11px] font-semibold uppercase tracking-wider text-slate-500">Data</span>
            <span className="text-[11px] font-semibold uppercase tracking-wider text-slate-500">Local by default</span>
            <span className="text-[11px] font-semibold uppercase tracking-wider text-slate-500">Syncs only when enabled</span>
            <span className="text-[11px] font-semibold uppercase tracking-wider text-slate-500">Never send from About</span>
          </div>
          {ABOUT_DATA_BOUNDARY_ROWS.map((row) => (
            <div
              key={row.id}
              className="grid grid-cols-[1fr_180px_180px_180px] border-b border-slate-100 px-4 py-3 last:border-b-0"
            >
              <span className="text-sm font-medium text-brand-dark">{row.label}</span>
              <span className="text-sm text-brand-dark/70">{row.localDefault}</span>
              <span className="text-sm text-brand-dark/70">{row.optionalSync}</span>
              <span className="text-sm text-brand-dark/70">{row.neverFromAbout}</span>
            </div>
          ))}
        </div>
      </div>
      <div className="mt-6 space-y-3 md:hidden">
        {ABOUT_DATA_BOUNDARY_ROWS.map((row) => (
          <Surface key={row.id} className="!p-4">
            <p className="text-sm font-semibold text-brand-dark mb-2">{row.label}</p>
            <div className="space-y-1.5">
              <div className="flex justify-between gap-2">
                <span className="text-[11px] font-semibold uppercase tracking-wider text-slate-400">Local</span>
                <span className="text-sm text-brand-dark/70 text-right">{row.localDefault}</span>
              </div>
              <div className="flex justify-between gap-2">
                <span className="text-[11px] font-semibold uppercase tracking-wider text-slate-400">Sync</span>
                <span className="text-sm text-brand-dark/70 text-right">{row.optionalSync}</span>
              </div>
              <div className="flex justify-between gap-2">
                <span className="text-[11px] font-semibold uppercase tracking-wider text-slate-400">Never</span>
                <span className="text-sm text-brand-dark/70 text-right">{row.neverFromAbout}</span>
              </div>
            </div>
          </Surface>
        ))}
      </div>
    </div>
  );
}
