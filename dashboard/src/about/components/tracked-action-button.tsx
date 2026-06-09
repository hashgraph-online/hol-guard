import { useCallback, type ReactNode } from "react";
import { trackAboutEvent } from "../about-analytics";
import { assertSafeAboutExternalUrl } from "../about-external-links";
import type { AboutLinkId } from "../about-types";

export function TrackedExternalButton({
  linkId,
  href,
  children,
  variant = "primary",
}: {
  linkId: AboutLinkId;
  href: string;
  children: ReactNode;
  variant?: "primary" | "outline";
}) {
  let safe: { rel: string; target: string } | null = null;
  let errorReason = "";
  try {
    safe = assertSafeAboutExternalUrl(linkId, href);
  } catch (e) {
    errorReason = e instanceof Error ? e.message : "Invalid URL";
  }

  const handleClick = useCallback(() => {
    trackAboutEvent({ type: "about_external_link_clicked", linkId });
  }, [linkId]);

  const base =
    "inline-flex items-center justify-center rounded-lg text-sm font-semibold transition-colors duration-150 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand-blue/40 focus-visible:ring-offset-2";
  const size = "min-h-11 h-auto px-4 py-2";
  const tone =
    variant === "outline"
      ? "border border-slate-200 bg-white hover:bg-slate-50 text-slate-900"
      : "bg-brand-blue text-white shadow-lg shadow-brand-blue/20 hover:bg-brand-blue/90";

  if (!safe) {
    return (
      <span
        className={`${base} ${size} ${tone} opacity-50 cursor-not-allowed`}
        title={errorReason}
      >
        {children}
      </span>
    );
  }

  return (
    <a
      href={href}
      target={safe.target}
      rel={safe.rel}
      onClick={handleClick}
      className={`${base} ${size} ${tone} no-underline`}
    >
      {children}
    </a>
  );
}
