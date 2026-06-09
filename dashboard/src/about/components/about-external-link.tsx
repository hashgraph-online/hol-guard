import { useCallback, type ReactNode } from "react";
import { HiMiniArrowTopRightOnSquare } from "react-icons/hi2";
import { assertSafeAboutExternalUrl } from "../about-external-links";
import { trackAboutEvent } from "../about-analytics";
import type { AboutLinkId } from "../about-types";

export function AboutExternalLink({
  linkId,
  href,
  children,
  className,
}: {
  linkId: AboutLinkId;
  href: string;
  children: ReactNode;
  className?: string;
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

  if (!safe) {
    return (
      <span
        className={[`text-slate-400 cursor-not-allowed`, className ?? ""].join(" ")}
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
      className={[
        `inline-flex items-center gap-1 transition-colors hover:text-brand-blue`,
        `focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand-blue/40 focus-visible:ring-offset-2`,
        className ?? "",
      ].join(" ")}
    >
      {children}
      <HiMiniArrowTopRightOnSquare className="h-3.5 w-3.5 opacity-60" aria-hidden="true" />
    </a>
  );
}
