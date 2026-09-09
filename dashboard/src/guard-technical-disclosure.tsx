import { useId, useRef, useState, type ReactNode } from "react";
import type { GuardPresentationMode } from "./guard-types";

export function GuardTechnicalDisclosure({ mode, children }: { mode: GuardPresentationMode; children: ReactNode }) {
  const [open, setOpen] = useState(mode === "technical");
  const id = useId();
  const button = useRef<HTMLButtonElement>(null);
  return (
    <div className="mt-4 border-t border-slate-200 pt-3" data-guard-technical-disclosure>
      <button ref={button} type="button" aria-expanded={open} aria-controls={id}
        className="min-h-11 rounded-lg px-2 text-sm font-semibold text-brand-blue focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand-blue"
        onClick={() => { if (open) button.current?.focus(); setOpen((value) => !value); }}>
        {open ? "Hide technical details" : "Show technical details"}
      </button>
      <div id={id} hidden={!open}>{open ? children : null}</div>
    </div>
  );
}
