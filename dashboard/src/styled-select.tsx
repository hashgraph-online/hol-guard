import type { SelectHTMLAttributes } from "react";
import { HiMiniChevronDown } from "react-icons/hi2";

/**
 * The dashboard's select treatment. Native selects rendered with bare
 * padding show raw OS chrome (arrow, popup, focus ring) that clashes with
 * every other control; this wrapper keeps the native element — keyboard,
 * screen-reader, and mobile behavior intact — and gives it the shared
 * border, radius, chevron, and focus ring.
 */
export function StyledSelect(props: SelectHTMLAttributes<HTMLSelectElement> & { wrapperClassName?: string }) {
  const { className, wrapperClassName, children, ...rest } = props;
  return (
    <span className={`relative inline-flex ${wrapperClassName ?? ""}`}>
      <select
        {...rest}
        className={`min-h-9 appearance-none rounded-xl border border-slate-200 bg-white py-2 pl-3 pr-8 text-sm text-brand-dark transition-colors hover:border-brand-blue/30 focus:border-brand-blue focus:outline-none focus:ring-2 focus:ring-brand-blue/20 disabled:cursor-not-allowed disabled:opacity-50 ${className ?? ""}`}
      >
        {children}
      </select>
      <HiMiniChevronDown className="pointer-events-none absolute right-2.5 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-400" aria-hidden="true" />
    </span>
  );
}
